"""CloudTrail recording-hook, owned by the CloudTrail service itself.

Historically this handler lived as a closure inside
``localemu.dashboard.plugins.register_dashboard``. That coupling meant :

* If the dashboard plugin was disabled, CloudTrail silently stopped
  recording events.
* The duplicate-registration guard compared function-object identity
  against a fresh closure, so repeated ``register_dashboard()`` calls
  registered the handler multiple times.

The current shape :

* The hook is a **named module-level function** living with the
  CloudTrail service.
* It carries a string attribute ``_le_handler_tag`` that the registrar
  checks against, so identity survives reloads / re-imports.
* The CloudTrail service registers it via its lifecycle hook.
"""

from __future__ import annotations

import logging
import threading

LOG = logging.getLogger(__name__)

# Real AWS's CloudTrail-to-EventBridge delivery is not synchronous with the
# originating API call - AWS documents this as an eventually-consistent
# pipeline, commonly on the order of tens of seconds to a few minutes,
# layered on top of the archive's own batching delay. Delivering
# synchronously (as this used to) makes LocalEmu's default bus visibly
# noisier than real AWS within the first seconds of a request: any
# unfiltered (no-EventPattern) rule/archive on the default bus would see
# CloudTrail-forwarded copies of a test's own setup calls (e.g. CreateQueue)
# land instantly, before a genuinely-user-facing PutEvents-driven event
# count check has even run once - something real AWS's own latency would
# never allow. Forwarding on a short background delay restores that
# ordering property without adding a real dependency on wall-clock timing
# for the common case (direct PutEvents delivery to archives is unaffected
# and stays synchronous).
#
# The delays are measured, not guessed. On a real AWS account (us-east-1,
# 20 to 40 events per API, delivery timed from the API call to the
# EventBridge target) latency differs by service: IAM, STS, Secrets Manager,
# EC2 and ECR deliver in a few seconds, S3 and SSM in 5 to 8 s, CloudWatch
# Logs in 13 s, Lambda, DynamoDB, SQS and SNS in 16 to 18 s.
# Each service below uses its measured median (the slowest API of that
# service when several were measured). Services without a measurement use
# the default, which is the median of all measured events.
_EVB_FORWARDING_DELAY_SECONDS = 5.3

_EVB_FORWARDING_DELAY_BY_SERVICE = {
    "iam": 2.4,
    "sts": 2.1,
    "secretsmanager": 1.8,
    "ec2": 3.4,
    "ecr": 3.4,
    "ssm": 5.3,
    "s3": 7.7,
    "logs": 12.6,
    "sqs": 16.5,
    "sns": 16.3,
    "lambda": 17.5,
    "dynamodb": 18.0,
}


def _forwarding_delay(service_name: str) -> float:
    return _EVB_FORWARDING_DELAY_BY_SERVICE.get(
        (service_name or "").lower(), _EVB_FORWARDING_DELAY_SECONDS
    )


# ---------------------------------------------------------------------------
# CloudTrail -> EventBridge forwarding helpers.
#
# Mirrors real AWS: every recorded management event is also published to
# the default event bus so EventBridge rules can match on it. Best-effort,
# never propagates failures.
# ---------------------------------------------------------------------------
_EVB_RESOURCE_ARN_BUILDERS = {
    "s3": lambda p, r, a: (
        [f"arn:aws:s3:::{p['Bucket']}"] if p.get("Bucket") else []
    ),
    "sqs": lambda p, r, a: (
        [f"arn:aws:sqs:{r}:{a}:{p['QueueName']}"] if p.get("QueueName") else []
    ),
    "sns": lambda p, r, a: (
        [f"arn:aws:sns:{r}:{a}:{p['Name']}"] if p.get("Name") else []
    ),
    "dynamodb": lambda p, r, a: (
        [f"arn:aws:dynamodb:{r}:{a}:table/{p['TableName']}"]
        if p.get("TableName") else []
    ),
    "lambda": lambda p, r, a: (
        [f"arn:aws:lambda:{r}:{a}:function:{p['FunctionName']}"]
        if p.get("FunctionName") else []
    ),
}


def _build_eventbridge_resources(
    service_name: str,
    service_request: dict,
    region: str,
    account_id: str,
) -> list[str]:
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
    if (service_name or "").lower() == "events":
        return
    # Real AWS's default (free) CloudTrail-to-EventBridge integration only
    # relays Management events to the account's default bus. Data events
    # (S3 object ops, SQS message ops, DynamoDB item ops, ...) require an
    # explicit opt-in AWS doesn't apply automatically, so they must not be
    # forwarded here either - otherwise high-frequency data-plane traffic
    # (e.g. SQS long-polling) floods any catch-all rule/archive on the bus.
    if getattr(event, "event_category", "Management") != "Management":
        return
    try:
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
    except Exception:
        LOG.debug(
            "CloudTrail->EventBridge forwarding failed to build entry for %s.%s",
            service_name,
            getattr(event, "event_name", "?"),
            exc_info=True,
        )
        return

    event_name = getattr(event, "event_name", "?")

    def _deliver() -> None:
        try:
            from localemu.aws.connect import connect_to

            events_client = connect_to(
                aws_access_key_id=account_id or "000000000000",
                region_name=region or "us-east-1",
            ).events
            events_client.put_events(Entries=[entry])
        except Exception:
            LOG.debug(
                "CloudTrail->EventBridge forwarding failed for %s.%s",
                service_name,
                event_name,
                exc_info=True,
            )

    timer = threading.Timer(_forwarding_delay(service_name), _deliver)
    timer.daemon = True
    timer.start()


# ---------------------------------------------------------------------------
# The recording handler - NAMED module-level function.
#
# We tag this function with a string attribute
# ``_le_handler_tag = "cloudtrail-activity-recorder"``. The registrar (see
# ``register_recording_hook`` below) checks for that tag rather than function
# identity, so that hot reloads importing a fresh module object still
# recognise an already-registered handler.
# ---------------------------------------------------------------------------
def _caller_identity(access_key_id: str, account_id: str, region: str) -> tuple[dict | None, str | None]:
    """CloudTrail's ``userIdentity`` for the caller and its ``Username``, from the IAM state.

    Temporary credentials are reported as an assumed role (with the role as session issuer), the
    account's own keys as Root, unsigned calls as the anonymous principal. ``(None, None)`` when
    the key cannot be resolved, which keeps the legacy "IAM user named after the key" shape.
    """
    try:
        from localemu.constants import ANONYMOUS_ACCESS_KEY_ID
        from localemu.services.iam_enforcement.identity import resolve_caller

        if not access_key_id or access_key_id == ANONYMOUS_ACCESS_KEY_ID:
            return {"type": "AWSAccount", "principalId": "", "accountId": "ANONYMOUS_PRINCIPAL"}, "ANONYMOUS_PRINCIPAL"
        caller = resolve_caller(access_key_id, account_id, "us-east-1")
        if caller is None:
            return None, None
        base = {"accountId": caller.account_id, "accessKeyId": access_key_id}
        if caller.principal_type == "Root":
            return {"type": "Root", "principalId": caller.account_id, "arn": caller.arn, **base}, "root"
        if caller.principal_type == "User":
            return {"type": "IAMUser", "principalId": access_key_id, "arn": caller.arn, "userName": caller.username, **base}, caller.username
        if caller.principal_type == "AssumedRole":
            issuer = f"arn:aws:iam::{caller.account_id}:role/{caller.role_name}"
            return {
                "type": "AssumedRole",
                "principalId": f"{caller.role_name}:{caller.session_name}",
                "arn": caller.arn,
                "sessionContext": {
                    "sessionIssuer": {"type": "Role", "arn": issuer, "accountId": caller.account_id, "userName": caller.role_name},
                    "attributes": {"mfaAuthenticated": "false"},
                },
                **base,
            }, caller.session_name
    except Exception:  # noqa: BLE001
        LOG.debug("CloudTrail: could not resolve caller identity", exc_info=True)
    return None, None


def cloudtrail_activity_handler(chain, context, response):
    """Record API activity to the CloudTrail event store (single source of truth)."""
    try:
        if not (context.service and context.operation):
            return
        service_name = context.service.service_name
        operation_name = context.operation.name
        account_id = str(getattr(context, "account_id", "") or "")
        region = str(getattr(context, "region", "") or "")

        user_agent = ""
        try:
            if hasattr(context, "request") and context.request:
                user_agent = (
                    context.request.headers.get("User-Agent", "")
                    if hasattr(context.request, "headers")
                    else ""
                )
        except Exception:
            pass

        # Skip dashboard self-recording. The dashboard makes reentrant
        # boto3 calls when listing SNS subscriptions, peeking SQS
        # messages and a few other read-only helpers. Without this
        # guard each dashboard tick would inflate CloudTrail with
        # ListSubscriptionsByTopic / ReceiveMessage / ListRules rows
        # the user never made.
        if user_agent.startswith(_DASHBOARD_USER_AGENT_PREFIX) or _is_internal_dashboard_call():
            return

        # Skip LocalEmu's own internal service-to-service traffic (EventBridge
        # target delivery, the SQS approximate-metrics publisher, etc). These
        # calls go over a real HTTP round-trip to LocalEmu's own gateway (a
        # thread-local suppression flag set by the originating thread would
        # not survive that hop, since the request is actually handled by a
        # different worker thread), so - like the dashboard case above - they
        # are tagged via a `user_agent_extra` marker that travels with the
        # request itself. Real AWS's equivalent internal plumbing (delivering
        # a matched rule's event to its target, a service publishing its own
        # CloudWatch metrics) happens entirely inside AWS's own control plane
        # and is never visible on the customer's CloudTrail; forwarding it
        # here would flood any catch-all EventBridge rule/archive.
        if _INTERNAL_CALL_USER_AGENT_MARKER in user_agent:
            return

        access_key_id = ""
        try:
            auth_header = context.request.headers.get("Authorization", "")
            if "Credential=" in auth_header:
                cred_part = auth_header.split("Credential=")[1].split(",")[0]
                access_key_id = cred_part.split("/")[0]
        except Exception:
            pass

        error_code = None
        error_message = None
        try:
            exc = getattr(context, "service_exception", None)
            if exc:
                error_code = getattr(exc, "code", None) or type(exc).__name__
                error_message = str(exc)
            elif response.status_code >= 400:
                error_code = str(response.status_code)
        except Exception:
            pass

        request_id = str(getattr(context, "request_id", "") or "")

        # Trail logging state and event-selector filtering.
        should_record = True
        try:
            import moto.backends as moto_backends

            from localemu.services.cloudtrail.event_store import _is_read_only

            ct_backend = moto_backends.get_backend("cloudtrail")[
                account_id or "000000000000"][region or "us-east-1"]
            trails = getattr(ct_backend, "trails", {})
            if trails:
                is_read = _is_read_only(operation_name)
                any_trail_accepts = False
                for t in trails.values():
                    if not getattr(t, "is_logging", True):
                        continue
                    selectors = getattr(t, "event_selectors", None) or []
                    if not selectors:
                        any_trail_accepts = True
                        break
                    for sel in selectors:
                        rw_type = sel.get("ReadWriteType", "All")
                        if rw_type == "All":
                            any_trail_accepts = True
                            break
                        elif rw_type == "ReadOnly" and is_read:
                            any_trail_accepts = True
                            break
                        elif rw_type == "WriteOnly" and not is_read:
                            any_trail_accepts = True
                            break
                    if any_trail_accepts:
                        break
                should_record = any_trail_accepts
        except Exception:
            pass

        if not should_record:
            return

        try:
            from localemu.services.cloudtrail.event_store import (
                create_event_from_context,
                get_event_store,
            )

            service_request = getattr(context, "service_request", None) or {}
            service_response = getattr(context, "service_response", None) or {}
            if not isinstance(service_response, dict):
                service_response = None

            source_ip = "127.0.0.1"
            if context.request:
                source_ip = getattr(context.request, "remote_addr", None) or "127.0.0.1"

            user_identity, identity_name = _caller_identity(access_key_id, account_id, region)
            event = create_event_from_context(
                service_name=service_name,
                operation_name=operation_name,
                account_id=account_id,
                region=region,
                source_ip=source_ip,
                user_agent=user_agent,
                request_id=request_id,
                access_key_id=access_key_id,
                username=identity_name or access_key_id or "localemu",
                user_identity=user_identity,
                error_code=error_code,
                error_message=error_message,
                service_request=service_request,
                response_elements=service_response,
                http_status_code=response.status_code,
            )
            get_event_store().record(event)

            # Publish to the dashboard event bus so live SSE subscribers see
            # the call within milliseconds, and so the count cache can
            # invalidate on Create/Delete/Put/Update operations. Failures
            # never break the request path.
            try:
                from localemu.dashboard.bus import (
                    is_mutating,
                    publish_activity,
                    publish_resource_changed,
                )
                from localemu.dashboard.api import _count_cache

                publish_activity(
                    service=service_name,
                    operation=operation_name,
                    status=response.status_code,
                    request_id=request_id,
                    account_id=account_id,
                    region=region,
                    source_ip=source_ip,
                )
                if (
                    is_mutating(operation_name)
                    and 200 <= response.status_code < 300
                ):
                    publish_resource_changed(
                        service=service_name,
                        operation=operation_name,
                        resource_id="",
                        region=region,
                        account_id=account_id,
                    )
                    _count_cache.pop(service_name, None)
            except Exception:
                LOG.debug("dashboard bus publish failed", exc_info=True)

            _emit_cloudtrail_to_eventbridge(
                service_name=service_name,
                account_id=account_id,
                region=region,
                event=event,
                service_request=service_request,
            )
        except Exception:
            LOG.debug("CloudTrail event recording failed", exc_info=True)
    except Exception:
        LOG.debug("Activity recording handler failed", exc_info=True)


# Tag the handler with a stable string so duplicate-registration
# detection survives module reloads / fresh imports.
cloudtrail_activity_handler._le_handler_tag = "cloudtrail-activity-recorder"  # type: ignore[attr-defined]


_HANDLER_TAG = "cloudtrail-activity-recorder"


_DASHBOARD_USER_AGENT_PREFIX = "LocalEmu-Dashboard/"

# Substring (not prefix - botocore appends `user_agent_extra` to the end of
# the existing User-Agent string, it doesn't replace it) tagging boto3
# clients LocalEmu itself constructs for internal service-to-service calls
# (e.g. EventBridge delivering a matched event to a target, a service
# publishing its own CloudWatch metrics). Set via
# `Config(user_agent_extra=INTERNAL_CALL_USER_AGENT_EXTRA)` on the client.
INTERNAL_CALL_USER_AGENT_EXTRA = "LocalEmu-Internal/service-call"
_INTERNAL_CALL_USER_AGENT_MARKER = INTERNAL_CALL_USER_AGENT_EXTRA

# Threading-local flag used by the dashboard's reentrant boto3 helpers
# to suppress CloudTrail recording. A simple int counter so nested
# context managers compose. ContextVar would also work but a thread-
# local matches the rest of the project's idioms and avoids picking up
# accidental cross-thread leakage from asyncio-based callers.
import threading as _threading

_internal_dashboard_call = _threading.local()


def _is_internal_dashboard_call() -> bool:
    return getattr(_internal_dashboard_call, "depth", 0) > 0


class suppress_recording:
    """Context manager: skip CloudTrail recording for reentrant calls.

    Used by the dashboard when it calls boto3 to read state for its own
    list panels (e.g. peeking SQS messages, listing SNS subscriptions).
    Without this guard every dashboard refresh would inflate CloudTrail
    with rows the user never issued.
    """

    def __enter__(self):
        _internal_dashboard_call.depth = getattr(_internal_dashboard_call, "depth", 0) + 1
        return self

    def __exit__(self, exc_type, exc, tb):
        _internal_dashboard_call.depth = max(0, getattr(_internal_dashboard_call, "depth", 0) - 1)
        return False


def register_recording_hook() -> None:
    """Register the CloudTrail activity-recording response handler.

    Idempotent via the ``_le_handler_tag`` string attribute, NOT via
    function-object identity (which fails across reloads because a fresh
    closure is a new object each time).
    """
    from localemu.aws.handlers import run_custom_response_handlers

    for existing in run_custom_response_handlers.handlers:
        if getattr(existing, "_le_handler_tag", None) == _HANDLER_TAG:
            return
    run_custom_response_handlers.handlers.append(cloudtrail_activity_handler)
    LOG.debug("CloudTrail activity-recording hook registered")


def unregister_recording_hook() -> None:
    """Remove the CloudTrail activity-recording handler (service stop)."""
    try:
        from localemu.aws.handlers import run_custom_response_handlers
    except Exception:
        return
    run_custom_response_handlers.handlers[:] = [
        h for h in run_custom_response_handlers.handlers
        if getattr(h, "_le_handler_tag", None) != _HANDLER_TAG
    ]
