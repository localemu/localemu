"""
Hooks that register dashboard routes and the activity-recording handler on
infrastructure start.
"""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PARITY-C1: CloudTrail -> EventBridge forwarding
# ---------------------------------------------------------------------------
# Mapping of LocalEmu/botocore service names to ARN partition service segments.
# Used only for best-effort resource ARN enrichment on the EventBridge entry
# (the full CloudTrail JSON already contains the authoritative resources list).
_EVB_RESOURCE_ARN_BUILDERS = {
    "s3": lambda params, region, account: (
        [f"arn:aws:s3:::{params['Bucket']}"] if params.get("Bucket") else []
    ),
    "sqs": lambda params, region, account: (
        [f"arn:aws:sqs:{region}:{account}:{params['QueueName']}"]
        if params.get("QueueName")
        else []
    ),
    "sns": lambda params, region, account: (
        [f"arn:aws:sns:{region}:{account}:{params['Name']}"]
        if params.get("Name")
        else []
    ),
    "dynamodb": lambda params, region, account: (
        [f"arn:aws:dynamodb:{region}:{account}:table/{params['TableName']}"]
        if params.get("TableName")
        else []
    ),
    "lambda": lambda params, region, account: (
        [f"arn:aws:lambda:{region}:{account}:function:{params['FunctionName']}"]
        if params.get("FunctionName")
        else []
    ),
}


def _build_eventbridge_resources(
    service_name: str,
    service_request: dict,
    region: str,
    account_id: str,
) -> list[str]:
    """Best-effort resource ARN list for the EventBridge entry."""
    try:
        builder = _EVB_RESOURCE_ARN_BUILDERS.get((service_name or "").lower())
        if not builder:
            return []
        return builder(service_request or {}, region or "us-east-1",
                       account_id or "000000000000")
    except Exception:
        return []


def _emit_cloudtrail_to_eventbridge(
    service_name: str,
    account_id: str,
    region: str,
    event,
    service_request: dict,
) -> None:
    """Forward a CloudTrail management event to the default EventBridge bus.

    Mirrors real AWS: every management API call recorded to CloudTrail is ALSO
    published to the default event bus so customers can match on it with
    EventBridge rules.

    Safety invariants:
      * Recursion guard: skip when the source service is EventBridge itself
        (``service_name == "events"``) — otherwise ``put_events`` would record
        its own call and infinitely loop.
      * Never propagate failures — a broken EventBridge delivery MUST NOT
        break the original request.
      * The caller already gated on trail logging state; this function is
        only invoked when at least one trail is logging.
    """
    # Recursion guard — do not publish EventBridge's own put_events calls.
    if (service_name or "").lower() == "events":
        return

    try:
        from localemu.aws.connect import connect_to

        entry = {
            "Source": f"aws.{service_name.lower()}",
            "DetailType": "AWS API Call via CloudTrail",
            "Detail": event.to_cloudtrail_event_json(),
            "Time": event.event_time,
        }
        resources = _build_eventbridge_resources(
            service_name, service_request, region, account_id
        )
        if resources:
            entry["Resources"] = resources

        events_client = connect_to(
            aws_access_key_id=account_id or "000000000000",
            region_name=region or "us-east-1",
        ).events
        events_client.put_events(Entries=[entry])
    except Exception:
        LOG.debug(
            "CloudTrail->EventBridge forwarding failed for %s.%s",
            service_name,
            getattr(event, "event_name", "?"),
            exc_info=True,
        )


def _is_loopback_request(request) -> bool:
    """Whether the inbound HTTP request originated on the same host.

    Same-host callers (the LocalEmu CLI, host-side scripts hitting
    127.0.0.1:4566) are trusted because they share the kernel namespace with
    the LocalEmu process. Any other ``remote_addr`` is by definition outside
    the trust boundary — Docker port-forwards from 0.0.0.0:4566 routinely
    expose the gateway to the host LAN.
    """
    import ipaddress

    raw = (request.remote_addr or "").strip()
    if not raw:
        return False
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


def _persistence_api_enabled(request) -> bool:
    """Authorize a request to a state-mutating ``/_localemu/state/*`` endpoint.

    Every external request that could reach the gateway
    used to be able to POST ``/_localemu/state/load`` and wipe every
    backend's state. We accept only:

      * loopback callers (same-host CLI / scripts), OR
      * explicit opt-in via ``PERSISTENCE_API_OPEN=1`` for deployments that
        intentionally expose the persistence control plane (e.g. CI control
        rigs running on a separate host).
    """
    import os as _os

    if _is_loopback_request(request):
        return True
    return _os.environ.get("PERSISTENCE_API_OPEN", "").strip().lower() in {"1", "true"}


def _is_dashboard_authorized(request) -> bool:
    """Authorize any inbound dashboard API request.

    The dashboard exposes both read endpoints (resource lists,
    CloudTrail, activity feed) and seven mutating action routes (Lambda
    invoke, SQS send, SNS publish, EventBridge PutEvents, Secrets
    rotate, DynamoDB put/scan). With the gateway bound on
    ``0.0.0.0:4566`` an unauthenticated POST from anywhere on the LAN
    could drive any of those, and a malicious browser tab on the
    developer's own laptop could CSRF them with ``text/plain`` bodies
    (no preflight).

    Accept only loopback callers by default; the ``DASHBOARD_API_OPEN``
    env var is the opt-out for the small set of deployments that
    intentionally proxy the dashboard from off-host (e.g. a bastion or
    shared lab box).
    """
    import os as _os

    if _is_loopback_request(request):
        return True
    return _os.environ.get("DASHBOARD_API_OPEN", "").strip().lower() in {"1", "true"}


def _dashboard_origin_ok(request) -> bool:
    """Reject CSRF candidates by inspecting ``Origin`` / ``Referer``.

    Browsers send ``Origin`` on cross-origin POST, PUT, DELETE. A page
    on ``https://evil.example`` POSTing to our ``/_localemu/api/...``
    will carry ``Origin: https://evil.example``. Allow only same-origin
    (no Origin header, or one whose host is loopback / matches the
    request host).
    """
    headers = getattr(request, "headers", {}) or {}
    origin = headers.get("Origin") or headers.get("origin") or ""
    if not origin:
        # No Origin header -- not a fetch from a browser (CLI / curl).
        return True
    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _dashboard_forbidden(reason: str):
    """403 response shared by the loopback / CSRF gates."""
    from localemu.http import Response
    return Response.for_json(
        {"error": "Forbidden", "message": reason}, status=403
    )


class _GatedResource:
    """Wraps a dashboard resource so every HTTP method is loopback-gated.

    Rolo's Router (`localemu.http.Resource`) finds endpoint methods by
    walking the wrapped object for ``on_get`` / ``on_post`` / ``on_put``
    etc. We expose the same surface, but each method first runs the
    loopback + CSRF gate and short-circuits to 403 on failure.

    Read methods (``on_get``, ``on_head``) only enforce the loopback
    check. Write methods additionally enforce the Origin allow-list and
    a Content-Type allow-list on the body parser (the latter is in
    actions._parse_body).
    """

    _READ_METHODS = ("on_get", "on_head", "on_options")

    def __init__(self, inner):
        self._inner = inner
        for name in dir(inner):
            if name.startswith("on_") and callable(getattr(inner, name)):
                self._wrap(name)

    def _wrap(self, name: str) -> None:
        inner_method = getattr(self._inner, name)
        is_read = name in self._READ_METHODS

        def wrapped(request, *args, **kwargs):
            if not _is_dashboard_authorized(request):
                return _dashboard_forbidden(
                    "Dashboard API is restricted to loopback callers. "
                    "Set DASHBOARD_API_OPEN=1 to expose it."
                )
            if not is_read and not _dashboard_origin_ok(request):
                return _dashboard_forbidden(
                    "Cross-origin request rejected. Dashboard mutating "
                    "endpoints require a same-origin Origin header."
                )
            return inner_method(request, *args, **kwargs)

        setattr(self, name, wrapped)


def _register_persistence_endpoints(router):
    """Register ``/_localemu/state/{save,load,status}``.

    Endpoints are only mounted when ``PERSISTENCE=1`` (otherwise the
    underlying orchestrators have nothing to do). Every handler then enforces
    :func:`_persistence_api_enabled` on the inbound request so unauthenticated
    POSTs can't wipe live state from off-host callers.
    """
    import json
    import os

    from localemu.http import Resource, Response

    def _forbidden(reason: str) -> Response:
        return Response.for_json(
            {"error": "Forbidden", "message": reason}, status=403
        )

    class StateSaveResource:
        def on_post(self, request):
            if not _persistence_api_enabled(request):
                return _forbidden(
                    "Persistence API is restricted to loopback callers. "
                    "Set PERSISTENCE_API_OPEN=1 to expose it."
                )
            from localemu import config
            from localemu.state.persistence import SaveOrchestrator

            result = SaveOrchestrator().save(config.dirs.data)
            return Response.for_json(result)

    class StateLoadResource:
        def on_post(self, request):
            if not _persistence_api_enabled(request):
                return _forbidden(
                    "Persistence API is restricted to loopback callers. "
                    "Set PERSISTENCE_API_OPEN=1 to expose it."
                )
            from localemu import config
            from localemu.state.persistence import LoadOrchestrator

            ok = LoadOrchestrator().load(config.dirs.data)
            return Response.for_json({"loaded": ok})

    class StateStatusResource:
        def on_get(self, request):
            if not _persistence_api_enabled(request):
                return _forbidden(
                    "Persistence API is restricted to loopback callers. "
                    "Set PERSISTENCE_API_OPEN=1 to expose it."
                )
            from localemu import config

            state_dir = os.path.join(config.dirs.data, "state")
            manifest_path = os.path.join(state_dir, "_manifest.json")
            if os.path.exists(manifest_path):
                with open(manifest_path) as f:
                    manifest = json.load(f)
                api_dir = os.path.join(state_dir, "api_states")
                sizes = {}
                if os.path.isdir(api_dir):
                    for fn in os.listdir(api_dir):
                        sizes[fn] = os.path.getsize(os.path.join(api_dir, fn))
                manifest["file_sizes"] = sizes
                return Response.for_json(manifest)
            return Response.for_json({"persisted": False})

    router.add(Resource("/_localemu/state/save", StateSaveResource()))
    router.add(Resource("/_localemu/state/load", StateLoadResource()))
    router.add(Resource("/_localemu/state/status", StateStatusResource()))


# Idempotency guard for register_dashboard. on_infra_start can fire
# more than once across a single process — for example a persistence
# reload triggers a second start phase, and any hot-reload tooling does
# the same. Without this flag the dashboard routes were re-added on
# every invocation; the Router silently kept the FIRST handler and
# dropped the second, but the wasted churn made debugging
# route-shadowing bugs much harder.
_dashboard_registered = False


@hooks.on_infra_start()
def register_dashboard():
    """Wire up all dashboard-related routes into the internal API router."""
    global _dashboard_registered
    if _dashboard_registered:
        LOG.debug("LocalEmu dashboard already registered — skipping re-registration")
        return

    from localemu.http import Resource
    from localemu.services.internal import get_internal_apis

    from .actions import ActionsResource
    from .api import (
        AcmCertificateDetailResource,
        ActivityResource,
        ApiGatewayV2DetailResource,
        AthenaWorkgroupDetailResource,
        BatchDetailResource,
        CloudFormationStackDetailResource,
        CloudTrailDetailResource,
        CloudTrailResource,
        CloudWatchLogGroupDetailResource,
        CognitoUserPoolDetailResource,
        DashboardResource,
        DynamoDBItemsResource,
        DynamoDBTableDetailResource,
        Ec2InstanceDetailResource,
        EcrRepositoryDetailResource,
        EcsClusterDetailResource,
        EfsFileSystemDetailResource,
        EksClusterDetailResource,
        ElbV2LoadBalancerDetailResource,
        EventBridgeRulesResource,
        FirehoseDeliveryStreamDetailResource,
        GlueDetailResource,
        IamEntityDetailResource,
        KinesisStreamDetailResource,
        KmsKeyDetailResource,
        LambdaFunctionDetailResource,
        LogEventsResource,
        MqBrokerDetailResource,
        MskClusterDetailResource,
        OpenSearchDomainDetailResource,
        OverviewResource,
        PipeDetailResource,
        RdsInstanceDetailResource,
        RegistryResource,
        ResourcesResource,
        Route53ZoneDetailResource,
        S3ObjectsResource,
        SchedulerScheduleDetailResource,
        SecretsManagerSecretDetailResource,
        SnsSubscriptionsResource,
        SqsMessagesResource,
        SqsQueueDetailResource,
        StaticResource,
        StepFunctionsStateMachineDetailResource,
        VpcDetailResource,
        Wafv2WebAclDetailResource,
    )
    # Importing the registry module populates SERVICE_REGISTRY at boot.
    from . import registry  # noqa: F401
    from .sse import StreamResource, StreamStatsResource

    router = get_internal_apis()
    # Loopback-gate every dashboard route: an unwrapped /_localemu/api/*
    # endpoint reachable from off-host means anyone on the LAN can drive
    # the mutating action verbs (invoke / send / publish / rotate / put)
    # and read CloudTrail with no challenge. _GatedResource also enforces
    # an Origin allow-list on writes for CSRF defence-in-depth.
    G = _GatedResource
    router.add(Resource("/_localemu/dashboard", G(DashboardResource())))
    router.add(Resource("/_localemu/api/overview", G(OverviewResource())))
    router.add(Resource("/_localemu/api/registry", G(RegistryResource())))
    router.add(Resource("/_localemu/api/resources/<service>", G(ResourcesResource())))
    router.add(Resource("/_localemu/api/resources/logs/<path:log_group>", G(LogEventsResource())))
    router.add(Resource("/_localemu/api/resources/s3/<bucket>", G(S3ObjectsResource())))
    router.add(Resource("/_localemu/api/resources/dynamodb/<table>", G(DynamoDBItemsResource())))
    router.add(Resource("/_localemu/api/resources/sqs/<queue>", G(SqsMessagesResource())))
    router.add(Resource("/_localemu/api/resources/kms/<key_id>", G(KmsKeyDetailResource())))
    router.add(Resource("/_localemu/api/resources/iam/<kind>/<path:key>", G(IamEntityDetailResource())))
    router.add(Resource("/_localemu/api/resources/stepfunctions/<path:sm_arn>", G(StepFunctionsStateMachineDetailResource())))
    router.add(Resource("/_localemu/api/resources/secretsmanager/<path:name>", G(SecretsManagerSecretDetailResource())))
    router.add(Resource("/_localemu/api/resources/lambda/<name>", G(LambdaFunctionDetailResource())))
    router.add(Resource("/_localemu/api/resources/rds/<db_id>", G(RdsInstanceDetailResource())))
    router.add(Resource("/_localemu/api/resources/ec2/<instance_id>", G(Ec2InstanceDetailResource())))
    router.add(Resource("/_localemu/api/resources/vpc/<vpc_id>", G(VpcDetailResource())))
    router.add(Resource("/_localemu/api/resources/sqs/<queue>/detail", G(SqsQueueDetailResource())))
    router.add(Resource("/_localemu/api/resources/apigatewayv2/<api_id>", G(ApiGatewayV2DetailResource())))
    router.add(Resource("/_localemu/api/resources/dynamodb/<name>/detail", G(DynamoDBTableDetailResource())))
    router.add(Resource("/_localemu/api/resources/logs/<path:log_group>/detail", G(CloudWatchLogGroupDetailResource())))
    router.add(Resource("/_localemu/api/resources/eks/<name>", G(EksClusterDetailResource())))
    router.add(Resource("/_localemu/api/resources/ecs/<name>", G(EcsClusterDetailResource())))
    router.add(Resource("/_localemu/api/resources/athena/<workgroup>", G(AthenaWorkgroupDetailResource())))
    router.add(Resource("/_localemu/api/resources/cloudformation/<name>", G(CloudFormationStackDetailResource())))
    router.add(Resource("/_localemu/api/resources/elbv2/<name>", G(ElbV2LoadBalancerDetailResource())))
    router.add(Resource("/_localemu/api/resources/route53/<zone_id>", G(Route53ZoneDetailResource())))
    router.add(Resource("/_localemu/api/resources/cognito-idp/<pool_id>", G(CognitoUserPoolDetailResource())))
    router.add(Resource("/_localemu/api/resources/kinesis/<name>/detail", G(KinesisStreamDetailResource())))
    router.add(Resource("/_localemu/api/resources/firehose/<name>", G(FirehoseDeliveryStreamDetailResource())))
    router.add(Resource("/_localemu/api/resources/kafka/<path:arn>", G(MskClusterDetailResource())))
    router.add(Resource("/_localemu/api/resources/mq/<broker_id>", G(MqBrokerDetailResource())))
    router.add(Resource("/_localemu/api/resources/acm/<path:arn>", G(AcmCertificateDetailResource())))
    router.add(Resource("/_localemu/api/resources/efs/<fs_id>", G(EfsFileSystemDetailResource())))
    router.add(Resource("/_localemu/api/resources/opensearch/<name>", G(OpenSearchDomainDetailResource())))
    router.add(Resource("/_localemu/api/resources/ecr/<path:name>", G(EcrRepositoryDetailResource())))
    router.add(Resource("/_localemu/api/resources/batch/<path:name>", G(BatchDetailResource())))
    router.add(Resource("/_localemu/api/resources/pipes/<name>", G(PipeDetailResource())))
    router.add(Resource("/_localemu/api/resources/scheduler/<group>/<name>", G(SchedulerScheduleDetailResource())))
    router.add(Resource("/_localemu/api/resources/scheduler/<group>", G(SchedulerScheduleDetailResource())))
    router.add(Resource("/_localemu/api/resources/wafv2/<key>", G(Wafv2WebAclDetailResource())))
    router.add(Resource("/_localemu/api/resources/glue/<kind>/<path:key>", G(GlueDetailResource())))
    router.add(Resource("/_localemu/api/resources/sns/<topic>/subscriptions", G(SnsSubscriptionsResource())))
    router.add(Resource("/_localemu/api/resources/events/<bus>/rules", G(EventBridgeRulesResource())))
    router.add(Resource("/_localemu/api/cloudtrail", G(CloudTrailResource())))
    router.add(Resource("/_localemu/api/cloudtrail/<request_id>", G(CloudTrailDetailResource())))
    router.add(Resource("/_localemu/api/activity", G(ActivityResource())))
    router.add(Resource("/_localemu/api/actions/<service>/<action>", G(ActionsResource())))
    router.add(Resource("/_localemu/api/stream", G(StreamResource())))
    router.add(Resource("/_localemu/api/stream/stats", G(StreamStatsResource())))
    router.add(Resource("/_localemu/dashboard/static/<path:path>", G(StaticResource())))

    # Persistence REST API — manual save / load / status.
    # Only register if PERSISTENCE=1; the orchestrators have nothing to do
    # otherwise and exposing the routes would waste audit surface.
    from localemu import config as _lemu_config

    if _lemu_config.PERSISTENCE:
        _register_persistence_endpoints(router)

    # Activity recording lives in the CloudTrail service itself
    # (see ``localemu.services.cloudtrail.recording_hook``) so the dashboard
    # only READS from the event store via its API resources. We still
    # trigger the hook registration here as a belt-and-braces — the
    # underlying register call is idempotent via a tag-string attribute on
    # the handler list, so doing it from both sites yields exactly one
    # handler.
    try:
        from localemu.services.cloudtrail.recording_hook import (
            register_recording_hook,
        )
        register_recording_hook()
    except Exception:
        LOG.debug(
            "Dashboard could not register CloudTrail recording hook",
            exc_info=True,
        )

    _dashboard_registered = True
    LOG.info("LocalEmu dashboard registered at /_localemu/dashboard")

