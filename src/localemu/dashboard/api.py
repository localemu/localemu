"""
Dashboard backend API for the LocalEmu Control Center.

Provides REST endpoints for:
- System overview (version, uptime, services)
- Per-service resource listing
- Real-time activity feed
- Static asset serving
- Dashboard HTML serving
"""

from __future__ import annotations

import collections
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from localemu.http import Request, Response

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level start time (set once at import)
# ---------------------------------------------------------------------------
_start_time = time.time()


# ---------------------------------------------------------------------------
# Moto backend iteration helper — iterates ALL accounts and ALL regions
# ---------------------------------------------------------------------------

def _iter_moto_backends(service_name: str):
    """Yield ``(account_id, region, backend)`` for every instantiated
    account/region combination in the given moto BackendDict.

    This replaces the previous pattern of hard-coding
    ``backend[DEFAULT_AWS_ACCOUNT_ID]["us-east-1"]`` which missed resources
    created in other regions or under non-default account IDs.
    """
    import moto.backends as moto_backends

    backend_dict = moto_backends.get_backend(service_name)

    # The ``backend_dict`` itself is a mapping
    # ``BackendDict[account_id, AccountSpecificBackend[region, BaseBackend]]``
    # for the requested service. Iterating it directly yields the correct
    # (account, region, backend) tuples AND is naturally service-scoped, so
    # we use it as the canonical source.
    #
    # We must not trigger lazy instantiation of new backends — reading
    # ``backend_dict[account][region]`` on an absent key DOES create an
    # empty backend in moto, which pollutes ``_instances`` with ghosts.
    # So we iterate only already-materialised entries.

    # ``BackendDict`` subclasses ``dict`` for the account layer — if it has
    # already been touched by CreateX handlers, its keys are the instantiated
    # account IDs. Iterating it via ``.items()`` does NOT lazily create new
    # backends, but reading a missing key would. Use ``.items()`` safely.
    try:
        account_items = list(backend_dict.items())
    except Exception:
        LOG.warning(
            "BackendDict.items() raised for service %s -- count/list paths "
            "will see no resources for this service until the next refresh",
            service_name,
            exc_info=True,
        )
        account_items = []

    if account_items:
        for account_id, region_map in account_items:
            if not isinstance(region_map, dict):
                continue
            try:
                region_items = list(region_map.items())
            except Exception:
                LOG.warning(
                    "AccountSpecificBackend.items() raised for service %s account %s",
                    service_name, account_id, exc_info=True,
                )
                continue
            for region, backend in region_items:
                yield account_id, region, backend
        return

    # Fallback: consult the class-level ``_instances`` list. In moto 5.x this
    # is a list of ``BackendDict`` objects (one per service the process has
    # touched), NOT a flat list of backend instances. Filter by service and
    # then iterate as above.
    instances = getattr(type(backend_dict), "_instances", None) \
        or getattr(backend_dict, "_instances", None)
    if isinstance(instances, list):
        for entry in list(instances):
            # A ``BackendDict`` carries its service name.
            entry_service = getattr(entry, "service_name", None)
            if entry_service and entry_service != service_name:
                continue
            if isinstance(entry, dict):
                for account_id, region_map in list(entry.items()):
                    if not isinstance(region_map, dict):
                        continue
                    for region, backend in list(region_map.items()):
                        yield account_id, region, backend
                continue
            # Very old moto may still yield flat BaseBackend instances.
            acct = getattr(entry, "account_id", None)
            reg = getattr(entry, "region_name", None) or getattr(entry, "region", None)
            if acct and reg:
                yield acct, reg, entry
        return

    # Last resort: nested dict (oldest moto shape).
    if isinstance(instances, dict):
        for account_id, region_map in list(instances.items()):
            if not isinstance(region_map, dict):
                continue
            for region, backend in list(region_map.items()):
                yield account_id, region, backend


# ---------------------------------------------------------------------------
# Safe int parse helper
# ---------------------------------------------------------------------------

def _safe_int(value: str, default: int, minimum: int = 1, maximum: int = 10000) -> int:
    """Parse *value* as int, returning *default* on failure or out-of-range."""
    try:
        n = int(value)
    except (ValueError, TypeError):
        return default
    return max(minimum, min(n, maximum))


# Identifier keys we want to keep in the slim summary returned by the
# CloudTrail list endpoint. The full request_parameters dict can be 40+
# entries (think S3 PutObject), but the dashboard only needs the resource
# id for per-resource drill-downs (e.g. show only Invokes of *this*
# function). Any non-listed key is dropped from the summary; the detail
# endpoint still returns the full payload.
_SUMMARY_REQUEST_PARAM_KEYS = frozenset({
    "functionName", "bucketName", "key", "queueName", "queueUrl",
    "topicArn", "tableName", "streamName", "stateMachineArn",
    "ruleName", "name", "clusterName", "dbInstanceIdentifier",
    "domainName", "secretId", "userPoolId", "restApiId", "apiId",
    "logGroupName", "logStreamName",
})


def _slim_request_params(params):
    if not params or not isinstance(params, dict):
        return {}
    return {k: params[k] for k in _SUMMARY_REQUEST_PARAM_KEYS if k in params}


def _json_response(data: dict, status: int = 200) -> Response:
    """Create a JSON Response with Cache-Control header for dashboard polling."""
    import json

    from localemu.utils.common import CustomEncoder

    body = json.dumps(data, cls=CustomEncoder)
    resp = Response(body, status=status, content_type="application/json")
    resp.headers["Cache-Control"] = "max-age=3"
    return resp


def _etag_response(
    data: dict,
    etag: str,
    request: Request,
    cache_max_age: int = 0,
) -> Response:
    """JSON response that supports ``If-None-Match`` -> 304 Not Modified.

    Snapshot endpoints set ``etag`` from the bus generation counter for
    the relevant tag. When the client sends back the same value in
    ``If-None-Match``, we save the JSON serialisation cost AND the
    network bandwidth: a 304 with no body.
    """
    try:
        if_none_match = (request.headers.get("If-None-Match") or "").strip()
    except Exception:
        if_none_match = ""
    if if_none_match and if_none_match == etag:
        resp = Response("", status=304)
        resp.headers["ETag"] = etag
        # The browser must still revalidate next time; this response is
        # informational only and SHOULD NOT be cached as a final value.
        resp.headers["Cache-Control"] = f"private, max-age={cache_max_age}"
        return resp

    resp = _json_response(data, status=200)
    resp.headers["ETag"] = etag
    if cache_max_age:
        resp.headers["Cache-Control"] = f"private, max-age={cache_max_age}"
    return resp

# ---------------------------------------------------------------------------
# Activity ring-buffer
# ---------------------------------------------------------------------------
_activity_log: collections.deque = collections.deque(maxlen=500)
_activity_lock = threading.Lock()


_activity_seq = 0


def record_activity(
    service: str,
    operation: str,
    status: int,
    account_id: str = "",
    region: str = "",
    source_ip: str = "127.0.0.1",
    user_agent: str = "",
    request_id: str = "",
) -> None:
    """Called from the handler chain to record API activity.

    Two side effects:

    1. The ring buffer (``_activity_log``) keeps the last N events so
       ``GET /api/activity?since=<id>`` can serve delta requests with
       no extra storage.
    2. The event bus broadcasts the entry to every SSE subscriber so
       live dashboards see the call within milliseconds, and so the
       per-service count cache can invalidate when the operation is
       state-mutating.
    """
    from .bus import is_mutating, publish_activity, publish_resource_changed

    global _activity_seq
    with _activity_lock:
        _activity_seq += 1
        seq = _activity_seq
        rid = request_id or str(uuid.uuid4())
        _activity_log.appendleft(
            {
                "id": seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": service,
                "operation": operation,
                "status": status,
                "account_id": account_id,
                "region": region,
                "source_ip": source_ip or "127.0.0.1",
                "user_agent": user_agent,
                "request_id": rid,
            }
        )
    # Publish AFTER the lock to keep slow subscribers from
    # back-pressuring the request pipeline.
    try:
        publish_activity(
            service=service,
            operation=operation,
            status=status,
            request_id=rid,
            account_id=account_id,
            region=region,
            source_ip=source_ip,
        )
        if is_mutating(operation) and 200 <= status < 300:
            publish_resource_changed(
                service=service,
                operation=operation,
                resource_id="",
                region=region,
                account_id=account_id,
            )
            # Invalidate the server-side count cache for this service
            # so the next /api/overview reflects the change.
            _count_cache.pop(service, None)
    except Exception:
        LOG.debug("bus publish failed for %s.%s", service, operation, exc_info=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_enabled_features() -> dict[str, bool]:
    """Return a dict of notable feature flags."""
    from localemu import config

    return {
        "persistence": bool(getattr(config, "PERSISTENCE", False)),
        "lambda_docker": bool(getattr(config, "LAMBDA_RUNTIME_EXECUTOR", "") == "docker"),
        "debug": bool(getattr(config, "DEBUG", False)),
    }


_count_cache: dict[str, tuple[float, int]] = {}  # service → (timestamp, count)
_COUNT_CACHE_TTL = 5.0  # seconds


def _count_resources(service_name: str) -> int:
    """
    Best-effort count of resources currently held by *service_name*.
    Returns 0 if the service store is unavailable or not yet loaded.
    Cached with 5-second TTL to avoid expensive iteration on every request (3.2 fix).
    """
    cached = _count_cache.get(service_name)
    if cached and (time.time() - cached[0]) < _COUNT_CACHE_TTL:
        return cached[1]

    count = _count_resources_uncached(service_name)
    _count_cache[service_name] = (time.time(), count)
    return count


def _count_resources_uncached(service_name: str) -> int:
    try:
        if service_name == "s3":
            from localemu.services.s3.models import s3_stores

            total = 0
            for _account_id, _region, store in s3_stores.iter_stores():
                total += len(store.buckets)
            return total

        if service_name == "sqs":
            from localemu.services.sqs.models import sqs_stores

            total = 0
            for _account_id, _region, store in sqs_stores.iter_stores():
                total += len(store.queues)
            return total

        if service_name == "lambda":
            from localemu.services.lambda_.invocation.models import lambda_stores

            total = 0
            for _account_id, _region, store in lambda_stores.iter_stores():
                total += len(store.functions)
            return total

        if service_name == "cloudwatch":
            return _count_cloudwatch()

        if service_name == "dynamodb":
            return _count_dynamodb_tables()

        if service_name == "sns":
            return _count_sns_topics()

        if service_name == "logs":
            return _count_log_groups()

        if service_name == "ecs":
            return _count_ecs()

        if service_name == "eks":
            return _count_eks()

        if service_name == "ec2":
            return _count_ec2()

        if service_name == "rds":
            return _count_rds()

        if service_name == "opensearch":
            return _count_opensearch()

        if service_name == "cloudtrail":
            try:
                from localemu.services.cloudtrail.event_store import get_event_store
                return get_event_store().get_event_count()
            except Exception:
                return len(_activity_log)

        if service_name == "secretsmanager":
            return _count_secretsmanager()

        if service_name == "stepfunctions":
            return _count_stepfunctions()

        if service_name == "kinesis":
            return _count_kinesis()

        if service_name == "events":
            return _count_events()

        if service_name == "apigateway":
            return _count_apigateway()

        if service_name == "apigatewayv2":
            return _count_apigatewayv2()

        if service_name == "iam":
            return _count_iam()

        if service_name == "vpc":
            return _count_vpc()

        if service_name == "route53":
            return _count_route53()

        if service_name == "elbv2":
            return _count_elbv2()

        if service_name == "kms":
            return _count_kms()

        if service_name == "ssm":
            return _count_ssm()

        if service_name == "cognito-idp":
            return _count_cognito_idp()

        if service_name == "ecr":
            return _count_ecr()

        if service_name == "batch":
            return _count_batch()

        if service_name == "pipes":
            return _count_pipes()

        if service_name == "scheduler":
            return _count_scheduler()

        if service_name == "wafv2":
            return _count_wafv2()

        if service_name == "glue":
            return _count_glue()

    except Exception:
        # Upgrade from debug to warning so the next regression that
        # makes a healthy backend look empty is actually visible in
        # logs. The dashboard still reports 0 to the caller; this
        # logging change just stops silent failures.
        LOG.warning(
            "could not count resources for %s (sidebar will report 0)",
            service_name, exc_info=True,
        )

    return 0


def _count_route53() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("route53"):
        total += len(getattr(backend, "zones", {}))
    return total


def _count_elbv2() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("elbv2"):
        total += len(getattr(backend, "load_balancers", {}))
    return total


def _count_kms() -> int:
    # KMS is fully native in LocalEmu; moto.kms is never instantiated.
    # Walking _iter_moto_backends("kms") used to return 0 even when
    # keys existed.
    from localemu.services.kms.models import kms_stores

    total = 0
    for _acct, _region, store in kms_stores.iter_stores():
        total += len(store.keys)
    return total


def _count_ssm() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("ssm"):
        raw = getattr(backend, "_parameters", None) or getattr(backend, "parameters", {})
        try:
            total += sum(1 for _ in (raw.keys() if hasattr(raw, "keys") else []))
        except Exception:
            continue
    return total


def _count_cognito_idp() -> int:
    """Count Cognito user pools across all accounts/regions.

    Without this, the sidebar's visibility rule (alwaysShow OR count>0)
    hides cognito-idp even after the user has created a pool, because
    the count falls through to 0.
    """
    total = 0
    for _acct, _region, backend in _iter_moto_backends("cognito-idp"):
        pools = getattr(backend, "user_pools", None)
        if pools is None:
            continue
        try:
            total += len(pools)
        except Exception:
            continue
    return total


def _count_cloudwatch() -> int:
    """Count CloudWatch alarms + dashboards across all accounts/regions."""
    total = 0
    for _acct, _region, backend in _iter_moto_backends("cloudwatch"):
        total += len(backend.alarms) + len(backend.dashboards)
    return total


def _count_dynamodb_tables() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("dynamodb"):
        total += len(backend.tables)
    return total


def _count_sns_topics() -> int:
    from localemu.services.sns.models import sns_stores

    total = 0
    for _account_id, _region, store in sns_stores.iter_stores():
        total += len(store.topics)
    return total


def _count_log_groups() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("logs"):
        total += len(backend.groups)
    return total


def _count_ecs() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("ecs"):
        total += len(backend.clusters)
    return total


def _count_eks() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("eks"):
        total += len(backend.clusters)
    return total


def _count_ec2() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("ec2"):
        for _res_id, reservation in backend.reservations.items():
            total += len(reservation.instances)
    return total


def _count_rds() -> int:
    # Count both DB instances and Aurora clusters. The previous count
    # ignored backend.clusters, so Aurora clusters were invisible in
    # the sidebar even when DescribeDBClusters returned them.
    total = 0
    for _acct, _region, backend in _iter_moto_backends("rds"):
        total += len(getattr(backend, "databases", {}))
        total += len(getattr(backend, "clusters", {}))
    return total


def _count_opensearch() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("opensearch"):
        total += len(backend.domains)
    return total


def _count_secretsmanager() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("secretsmanager"):
        total += len(backend.secrets)
    return total


def _count_stepfunctions() -> int:
    # Step Functions is fully native in LocalEmu; state lives in
    # sfn_stores, not moto. The previous _iter_moto_backends walk
    # returned 0 even after CreateStateMachine succeeded.
    from localemu.services.stepfunctions.backend.models import sfn_stores

    total = 0
    for _acct, _region, store in sfn_stores.iter_stores():
        total += len(store.state_machines)
    return total


def _count_kinesis() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("kinesis"):
        total += len(backend.streams)
    return total


def _count_events() -> int:
    # EventBridge uses LocalEmu's native AccountRegionBundle store, not moto.
    # The earlier _iter_moto_backends("events") call always returned an empty
    # iterator, so the sidebar count was permanently 0 even when buses and
    # rules existed.
    from localemu.services.events.models import events_stores

    total = 0
    for _acct, _region, store in events_stores.iter_stores():
        for _name, bus in store.event_buses.items():
            total += len(bus.rules)
    return total


def _count_apigateway() -> int:
    # API Gateway v1 (REST APIs) uses LocalEmu's native store.
    from localemu.services.apigateway.models import apigateway_stores

    total = 0
    for _acct, _region, store in apigateway_stores.iter_stores():
        total += len(store.rest_apis)
    return total


def _count_apigatewayv2() -> int:
    # API Gateway v2 (HTTP / WebSocket) is moto-backed.
    total = 0
    for _acct, _region, backend in _iter_moto_backends("apigatewayv2"):
        total += len(backend.apis)
    return total


def _count_iam() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("iam"):
        total += (
            len(backend.users)
            + len(backend.roles)
            + len(backend.instance_profiles)
            + len(getattr(backend, "groups", {}))
        )
    return total


def _count_vpc() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("ec2"):
        total += len(backend.vpcs)
    return total


def _count_ecr() -> int:
    total = 0
    for _acct, _region, backend in _iter_moto_backends("ecr"):
        total += len(getattr(backend, "repositories", {}) or {})
    return total


def _count_batch() -> int:
    """Compute envs + queues + job defs + jobs across regions."""
    total = 0
    for _acct, _region, backend in _iter_moto_backends("batch"):
        total += len(getattr(backend, "_compute_environments", {}) or {})
        total += len(getattr(backend, "_job_queues", {}) or {})
        total += len(getattr(backend, "_job_definitions", {}) or {})
        total += len(getattr(backend, "_jobs", {}) or {})
    return total


def _count_pipes() -> int:
    """EventBridge Pipes across regions (moto-backed)."""
    total = 0
    for _acct, _region, backend in _iter_moto_backends("pipes"):
        total += len(getattr(backend, "pipes", {}) or {})
    return total


def _count_scheduler() -> int:
    """Sum schedules across moto's scheduler backend.

    The schedules live on each ``ScheduleGroup`` instance (``g.schedules``
    is a ``dict[name, Schedule]``). The backend's top-level
    ``schedules`` attribute is unrelated bookkeeping and is empty.
    """
    total = 0
    for _acct, _region, backend in _iter_moto_backends("scheduler"):
        for _gname, group in (getattr(backend, "schedule_groups", {}) or {}).items():
            scheds = getattr(group, "schedules", {}) or {}
            try:
                total += len(scheds)
            except TypeError:
                continue
    return total


def _count_wafv2() -> int:
    """Web ACLs + IP sets + rule groups across regions."""
    total = 0
    for _acct, _region, backend in _iter_moto_backends("wafv2"):
        total += len(getattr(backend, "wacls", {}) or {})
        total += len(getattr(backend, "ip_sets", {}) or {})
        total += len(getattr(backend, "rule_groups", {}) or {})
    return total


def _count_glue() -> int:
    """Sum every Glue Data Catalog primitive across regions.

    Mirrors what the user sees in the real Glue console left-nav:
    databases, tables (across all databases), crawlers, jobs, triggers,
    workflows, connections, and registries (schemas summed under each
    registry). Job-runs are intentionally excluded from the sidebar
    count -- they are inspected from the parent job drill.
    """
    total = 0
    for _acct, _region, backend in _iter_moto_backends("glue"):
        databases = getattr(backend, "databases", {}) or {}
        total += len(databases)
        for db in databases.values():
            total += len(getattr(db, "tables", {}) or {})
        total += len(getattr(backend, "crawlers", {}) or {})
        total += len(getattr(backend, "jobs", {}) or {})
        total += len(getattr(backend, "triggers", {}) or {})
        total += len(getattr(backend, "workflows", {}) or {})
        total += len(getattr(backend, "connections", {}) or {})
        registries = getattr(backend, "registries", {}) or {}
        total += len(registries)
        for reg in registries.values():
            total += len(getattr(reg, "schemas", {}) or {})
    return total


def _get_dashboard_html() -> str:
    """Read the dashboard HTML from the static package."""
    import importlib.resources as pkg_resources

    import localemu.dashboard.static as static_pkg

    ref = pkg_resources.files(static_pkg).joinpath("index.html")
    return ref.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Resource classes (follow the same pattern as HealthResource)
# ---------------------------------------------------------------------------


class OverviewResource:
    """``GET /_localemu/api/overview`` — system summary.

    ETag-based conditional GET: the dashboard polls this on a 60 s
    safety interval and pushes invalidation via SSE in between. With
    a matching ``If-None-Match`` header the response is a 304 with
    no body, so the polling cost is one HTTP header round trip.
    """

    def on_get(self, request: Request):
        LOG.debug("Dashboard API request: GET /overview from %s", request.remote_addr)
        from localemu import config, constants
        from localemu.services.plugins import SERVICE_PLUGINS

        from .bus import get_bus

        # ETag derived from the global generation. Any publish() bumps
        # it, so the next poll sees a fresh tag and we serve real data;
        # if nothing happened, we return 304.
        etag = get_bus().etag_for("*")

        states = SERVICE_PLUGINS.get_states()

        service_data: dict[str, dict] = {}
        for svc_name, state in sorted(states.items()):
            count = _count_resources(svc_name)
            service_data[svc_name] = {
                "status": state.value if hasattr(state, "value") else str(state),
                "resources": count,
            }

        # VPC is part of EC2, not a separate plugin -- inject manually
        vpc_count = _count_vpc()
        service_data["vpc"] = {"status": "available", "resources": vpc_count}

        payload = {
            "version": constants.VERSION,
            "uptime_seconds": int(time.time() - _start_time),
            "port": config.GATEWAY_LISTEN[0].port,
            "features": _get_enabled_features(),
            "services": service_data,
        }
        return _etag_response(payload, etag, request, cache_max_age=10)


class RegistryResource:
    """``GET /_localemu/api/registry`` -- service registry dump.

    The frontend reads this once at boot to populate every per-service
    UI map (label, group, columns, empty state, tier, banner, ...).
    Replaces the hard-coded per-service maps in ``services.js``.
    """

    def on_get(self, request: Request):
        from .registry import all_specs

        payload = {
            "services": [spec.to_dict() for spec in all_specs()],
        }
        return _json_response(payload)


class ResourcesResource:
    """``GET /_localemu/api/resources/<service>`` — per-service resource list.

    Per-service ETag from the bus's ``resources:<svc>`` tag. The bus
    bumps the generation on every state-mutating event for ``<svc>``,
    so the dashboard's next conditional GET either returns 304 or a
    fresh list.
    """

    def on_get(self, request: Request, service: str = ""):
        LOG.debug("Dashboard API request: GET /resources/%s from %s", service, request.remote_addr)
        offset = _safe_int(request.args.get("offset", "0"), 0, minimum=0, maximum=100000)
        limit = _safe_int(request.args.get("limit", "200"), 200, minimum=1, maximum=1000)

        from .bus import get_bus

        etag = get_bus().etag_for(f"resources:{service}")

        try:
            items = self._list_resources(service)
        except Exception:
            LOG.debug("error listing resources for %s", service, exc_info=True)
            return _json_response({"service": service, "resources": None, "error": "backend error", "total": 0})
        total = len(items)
        items = items[offset:offset + limit]
        return _etag_response(
            {
                "service": service, "resources": items, "error": None,
                "total": total, "offset": offset, "limit": limit,
            },
            etag,
            request,
            cache_max_age=10,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _list_resources(service: str) -> list[dict]:
        if service == "s3":
            return ResourcesResource._list_s3()
        if service == "sqs":
            return ResourcesResource._list_sqs()
        if service == "lambda":
            return ResourcesResource._list_lambda()
        if service == "dynamodb":
            return ResourcesResource._list_dynamodb()
        if service == "sns":
            return ResourcesResource._list_sns()
        if service == "logs":
            return ResourcesResource._list_logs()
        if service == "ecs":
            return ResourcesResource._list_ecs()
        if service == "eks":
            return ResourcesResource._list_eks()
        if service == "ec2":
            return ResourcesResource._list_ec2()
        if service == "rds":
            return ResourcesResource._list_rds()
        if service == "opensearch":
            return ResourcesResource._list_opensearch()
        if service == "secretsmanager":
            return ResourcesResource._list_secretsmanager()
        if service == "stepfunctions":
            return ResourcesResource._list_stepfunctions()
        if service == "kinesis":
            return ResourcesResource._list_kinesis()
        if service == "events":
            return ResourcesResource._list_events()
        if service == "apigateway":
            return ResourcesResource._list_apigateway()
        if service == "apigatewayv2":
            return ResourcesResource._list_apigatewayv2()
        if service == "iam":
            return ResourcesResource._list_iam()
        if service == "vpc":
            return ResourcesResource._list_vpc()
        if service == "security-groups":
            return ResourcesResource._list_security_groups()
        if service == "nat-gateways":
            return ResourcesResource._list_nat_gateways()
        if service == "vpc-peering":
            return ResourcesResource._list_vpc_peering()
        if service == "vpc-endpoints":
            return ResourcesResource._list_vpc_endpoints()
        if service == "route53":
            return ResourcesResource._list_route53()
        if service == "elbv2":
            return ResourcesResource._list_elbv2()
        if service == "kms":
            return ResourcesResource._list_kms()
        if service == "ssm":
            return ResourcesResource._list_ssm()
        if service == "cloudtrail":
            return ResourcesResource._list_cloudtrail()
        if service == "ecr":
            return ResourcesResource._list_ecr()
        if service == "batch":
            return ResourcesResource._list_batch()
        if service == "pipes":
            return ResourcesResource._list_pipes()
        if service == "scheduler":
            return ResourcesResource._list_scheduler()
        if service == "wafv2":
            return ResourcesResource._list_wafv2()
        if service == "glue":
            return ResourcesResource._list_glue()
        return []

    @staticmethod
    def _list_s3() -> list[dict]:
        """List every bucket across accounts and regions.

        Keyed by (account, name) so multi-account local setups do not
        hide the second account's bucket of the same name behind a
        global-name dedup. ``objects`` walks ``bucket.objects.values()``
        rather than the private ``_store`` dict so versioned buckets
        report the count of live objects, not the count of versions
        plus delete markers.
        """
        from localemu.services.s3.models import S3DeleteMarker, s3_stores

        buckets: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for account_id, _region, store in s3_stores.iter_stores():
            for name, bucket in store.buckets.items():
                key = (account_id, name)
                if key in seen:
                    continue
                seen.add(key)
                object_count = 0
                if hasattr(bucket, "objects"):
                    try:
                        object_count = sum(
                            1
                            for obj in bucket.objects.values()
                            if not isinstance(obj, S3DeleteMarker)
                        )
                    except Exception:
                        object_count = 0
                buckets.append(
                    {
                        "name": name,
                        "account": account_id,
                        "objects": object_count,
                        "region": bucket.bucket_region or "",
                    }
                )
        return buckets

    @staticmethod
    def _list_sqs() -> list[dict]:
        from localemu.services.sqs.models import sqs_stores

        queues: list[dict] = []
        for _account_id, region, store in sqs_stores.iter_stores():
            for name, queue in store.queues.items():
                try:
                    messages = queue.approximate_number_of_messages
                except Exception:
                    messages = "-"
                queues.append(
                    {
                        "name": name,
                        "messages": messages,
                        "url": getattr(queue, "url", ""),
                        "region": region,
                    }
                )
        return queues

    @staticmethod
    def _list_lambda() -> list[dict]:
        from localemu.services.lambda_.invocation.models import lambda_stores

        functions: list[dict] = []
        for _account_id, _region, store in lambda_stores.iter_stores():
            for fn_name, fn in store.functions.items():
                latest = fn.latest()
                if latest:
                    # VersionState is a dataclass wrapping a State enum;
                    # extract the plain string (e.g. "Active") from the
                    # nested enum so the frontend doesn't see the repr.
                    state_obj = latest.config.state
                    if hasattr(state_obj, "state"):
                        # state_obj is VersionState -> .state is State enum
                        state_str = str(state_obj.state.value) if hasattr(state_obj.state, "value") else str(state_obj.state)
                    elif hasattr(state_obj, "value"):
                        state_str = str(state_obj.value)
                    else:
                        state_str = str(state_obj)

                    functions.append(
                        {
                            "name": fn_name,
                            "runtime": latest.config.runtime or "",
                            "handler": latest.config.handler or "",
                            "memory": latest.config.memory_size,
                            "timeout": latest.config.timeout,
                            "state": state_str,
                            "role": latest.config.role or "",
                        }
                    )
        return functions

    @staticmethod
    def _list_dynamodb() -> list[dict]:
        # DynamoDB tables are region-scoped: the same name in two
        # different regions are two distinct resources. Do NOT dedup by
        # name -- carry per-row region so the UI can distinguish.
        tables: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("dynamodb"):
            for name, table in backend.tables.items():
                key_schema = []
                if hasattr(table, "hash_key_attr"):
                    key_schema.append({"attribute": table.hash_key_attr, "type": "HASH"})
                if hasattr(table, "range_key_attr") and table.range_key_attr:
                    key_schema.append({"attribute": table.range_key_attr, "type": "RANGE"})
                tables.append(
                    {
                        "name": name,
                        "item_count": len(table.items) if hasattr(table, "items") else 0,
                        "key_schema": key_schema,
                        "region": region,
                    }
                )
        return tables

    @staticmethod
    def _list_sns() -> list[dict]:
        from localemu.services.sns.models import sns_stores

        topics: list[dict] = []
        for _account_id, region, store in sns_stores.iter_stores():
            for arn, topic in store.topics.items():
                sub_arns = topic.get("subscriptions", []) if isinstance(topic, dict) else getattr(topic, "subscriptions", [])
                sub_count = len(sub_arns) if sub_arns else 0

                # Resolve subscription details from the store-level subscriptions dict
                sub_details: list[dict] = []
                all_subs = store.subscriptions
                for sub_arn in (sub_arns or []):
                    sub = all_subs.get(sub_arn)
                    if sub:
                        sub_details.append(
                            {
                                "protocol": sub.get("Protocol", ""),
                                "endpoint": sub.get("Endpoint", ""),
                                "arn": sub_arn,
                            }
                        )

                # arn is required by the SNS Publish modal so cross-region
                # topics work. The previous row omitted it, forcing the
                # action handler to synthesise an ARN with DEFAULT_REGION,
                # which silently routed Publish to us-east-1 for any topic
                # created elsewhere.
                topics.append(
                    {
                        "name": arn.rsplit(":", 1)[-1] if ":" in arn else arn,
                        "arn": arn,
                        "subscriptions": sub_count,
                        "subscription_details": sub_details,
                        "region": region,
                    }
                )
        return topics

    @staticmethod
    def _list_logs() -> list[dict]:
        groups: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("logs"):
            for name, group in backend.groups.items():
                stream_count = len(group.streams) if hasattr(group, "streams") else 0
                retention = getattr(group, "retention_in_days", None)
                stored = getattr(group, "stored_bytes", 0)
                groups.append(
                    {
                        "name": name,
                        "streams": stream_count,
                        "retention": retention if retention else "-",
                        "stored_bytes": stored,
                        "region": region,
                    }
                )
        return groups

    @staticmethod
    def _list_ecs() -> list[dict]:
        clusters: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ecs"):
            for name, cluster in backend.clusters.items():
                task_count = len(backend.tasks.get(cluster.arn, []))
                clusters.append(
                    {
                        "name": name,
                        "status": getattr(cluster, "status", "ACTIVE"),
                        "tasks": task_count,
                        "region": region,
                    }
                )
        return clusters

    @staticmethod
    def _list_eks() -> list[dict]:
        clusters: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("eks"):
            for name, cluster in backend.clusters.items():
                clusters.append(
                    {
                        "name": name,
                        "status": getattr(cluster, "status", "UNKNOWN"),
                        "endpoint": getattr(cluster, "endpoint", ""),
                        "region": region,
                    }
                )
        return clusters

    @staticmethod
    def _list_ec2() -> list[dict]:
        instances: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for _res_id, reservation in backend.reservations.items():
                for inst in reservation.instances:
                    instances.append(
                        {
                            "instance_id": inst.id,
                            "state": inst._state.name if hasattr(inst, "_state") else "unknown",
                            "instance_type": getattr(inst, "instance_type", ""),
                            "region": region,
                        }
                    )
        return instances

    @staticmethod
    def _list_rds() -> list[dict]:
        # Surface both DB instances and Aurora clusters with a ``kind``
        # discriminator. Aurora clusters appear in backend.clusters and
        # were previously invisible to the dashboard.
        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("rds"):
            for name, db in getattr(backend, "databases", {}).items():
                endpoint = getattr(db, "address", "") or "localhost"
                port = getattr(db, "port", None)
                master_user = getattr(db, "master_username", "")
                db_name = getattr(db, "db_name", "")
                engine_version = getattr(db, "engine_version", "")

                try:
                    from localemu.services.rds.provider import _db_manager
                    if _db_manager:
                        info = _db_manager.get_instance_info(name)
                        if info and info.host_port:
                            port = info.host_port
                            endpoint = "localhost"
                except Exception:
                    pass

                connection = f"{endpoint}:{port}" if port else "-"

                rows.append(
                    {
                        "name": name,
                        "kind": "instance",
                        "engine": f"{getattr(db, 'engine', '')} {engine_version}".strip(),
                        "status": getattr(db, "status", ""),
                        "instance_class": getattr(db, "db_instance_class", ""),
                        "endpoint": connection,
                        "user": master_user,
                        "database": db_name or "-",
                        "region": region,
                    }
                )

            for cluster_id, cluster in getattr(backend, "clusters", {}).items():
                endpoint = getattr(cluster, "endpoint", "") or ""
                reader_endpoint = getattr(cluster, "reader_endpoint", "") or ""
                port = getattr(cluster, "port", None)
                connection = f"{endpoint}:{port}" if endpoint and port else (endpoint or "-")
                members = getattr(cluster, "cluster_members", []) or []
                rows.append(
                    {
                        "name": cluster_id,
                        "kind": "cluster",
                        "engine": f"{getattr(cluster, 'engine', '')} {getattr(cluster, 'engine_version', '')}".strip(),
                        "status": getattr(cluster, "status", ""),
                        "instance_class": "-",
                        "endpoint": connection,
                        "reader_endpoint": reader_endpoint,
                        "user": getattr(cluster, "master_username", ""),
                        "database": getattr(cluster, "database_name", "") or "-",
                        "members": len(members),
                        "region": region,
                    }
                )
        return rows

    @staticmethod
    def _list_opensearch() -> list[dict]:
        """List OpenSearch domains from Moto's backend.

        The OpenSearch Docker provider (opensearch.docker.provider) uses
        call_moto() for all domain CRUD.  Moto stores the domain objects
        in opensearch_backends[account_id][region].domains.  The Docker
        cluster manager (if enabled) adds real container endpoints.
        """
        domains: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("opensearch"):
            for name, domain in backend.domains.items():
                # engine_version is a Moto EngineVersion object with .options attr
                engine_obj = getattr(domain, "engine_version", None)
                engine = getattr(engine_obj, "options", "") if engine_obj else ""

                # endpoint is None without Docker; endpoints.vpc has the fake hostname
                endpoint = getattr(domain, "endpoint", None) or ""
                if not endpoint:
                    endpoints_dict = getattr(domain, "endpoints", {}) or {}
                    endpoint = endpoints_dict.get("vpc", "-")

                cluster_cfg = getattr(domain, "cluster_config", {}) or {}
                instance_type = cluster_cfg.get("InstanceType", "")
                instance_count = cluster_cfg.get("InstanceCount", 1)
                processing = getattr(domain, "processing", False)
                status = "processing" if processing else "active"

                # If Docker backend is active, get real container endpoint
                try:
                    from localemu.services.opensearch.docker.provider import _cluster_manager
                    if _cluster_manager:
                        info = _cluster_manager.get_cluster_info(name)
                        if info and hasattr(info, "host_port"):
                            endpoint = f"localhost:{info.host_port}"
                except Exception:
                    pass

                domains.append(
                    {
                        "name": name,
                        "engine": engine,
                        "status": status,
                        "endpoint": endpoint,
                        "instance_type": instance_type,
                        "instances": instance_count,
                        "region": region,
                    }
                )
        return domains


    @staticmethod
    def _list_secretsmanager() -> list[dict]:
        secrets: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("secretsmanager"):
            for name, secret in backend.secrets.items():
                description = getattr(secret, "description", "") or ""
                last_changed = getattr(secret, "last_changed_date", None)
                secrets.append(
                    {
                        "name": name,
                        "description": description,
                        "last_changed": str(last_changed) if last_changed else "-",
                        "region": region,
                    }
                )
        return secrets

    @staticmethod
    def _list_stepfunctions() -> list[dict]:
        # Step Functions state lives in the native sfn_stores. The
        # previous moto walk returned an empty list even after
        # CreateStateMachine because moto.stepfunctions is never used.
        from localemu.services.stepfunctions.backend.models import sfn_stores

        machines: list[dict] = []
        for _acct, region, store in sfn_stores.iter_stores():
            for arn, sm in store.state_machines.items():
                machines.append(
                    {
                        "name": getattr(sm, "name", arn.rsplit(":", 1)[-1]),
                        "status": "ACTIVE",
                        "type": getattr(sm, "sm_type", "STANDARD"),
                        "arn": arn,
                        "role_arn": getattr(sm, "role_arn", "") or "",
                        "region": region,
                    }
                )
        return machines

    @staticmethod
    def _list_kinesis() -> list[dict]:
        streams: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("kinesis"):
            for name, stream in backend.streams.items():
                shard_count = len(getattr(stream, "shards", {}))
                status = getattr(stream, "status", "ACTIVE")
                streams.append(
                    {
                        "name": name,
                        "shards": shard_count,
                        "status": status,
                        "region": region,
                    }
                )
        return streams

    @staticmethod
    def _list_events() -> list[dict]:
        # EventBridge state lives in LocalEmu's native AccountRegionBundle
        # store. The previous moto-backend walk was a no-op, which is why
        # buses and rules deployed with Terraform did not show up here.
        from localemu.services.events.models import events_stores

        rules: list[dict] = []
        for _acct, region, store in events_stores.iter_stores():
            for bus_name, bus in store.event_buses.items():
                for rule_name, rule in bus.rules.items():
                    state = getattr(rule, "state", "ENABLED")
                    targets = getattr(rule, "targets", [])
                    rules.append(
                        {
                            "name": rule_name,
                            "bus": bus_name,
                            "state": state,
                            "targets": len(targets) if targets else 0,
                            "region": region,
                        }
                    )
        return rules

    @staticmethod
    def _list_apigateway() -> list[dict]:
        # API Gateway v1 (REST APIs) uses LocalEmu's native store.
        from localemu.services.apigateway.models import apigateway_stores

        apis: list[dict] = []
        for _acct, region, store in apigateway_stores.iter_stores():
            for api_id, container in store.rest_apis.items():
                rest_api = getattr(container, "rest_api", None) or container
                name = getattr(rest_api, "name", api_id)
                description = getattr(rest_api, "description", "") or ""
                apis.append({
                    "name": name,
                    "api_id": api_id,
                    "protocol": "REST",
                    "description": description,
                    "region": region,
                })
        return apis

    @staticmethod
    def _list_apigatewayv2() -> list[dict]:
        # API Gateway v2 (HTTP / WebSocket) is moto-backed.
        apis: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("apigatewayv2"):
            for api_id, api in backend.apis.items():
                name = getattr(api, "name", api_id)
                protocol = getattr(api, "protocol_type", "HTTP")
                routes = getattr(api, "routes", {}) or {}
                stages = getattr(api, "stages", {}) or {}
                apis.append({
                    "name": name,
                    "api_id": api_id,
                    "protocol": protocol,
                    "routes": len(routes),
                    "stages": len(stages),
                    "region": region,
                })
        return apis

    @staticmethod
    def _list_iam() -> list[dict]:
        resources: list[dict] = []
        for _acct, _region, backend in _iter_moto_backends("iam"):
            # Users
            for _uid, user in backend.users.items():
                policies = list(getattr(user, "policies", {}).keys())
                managed = list(getattr(user, "managed_policies", {}).keys())
                key_count = len([k for k in getattr(user, "access_keys", []) if k.status == "Active"])
                groups = list(getattr(user, "group_list", []))
                resources.append({
                    "type": "User",
                    "name": user.name,
                    "arn": user.arn,
                    "policies": len(policies) + len(managed),
                    "access_keys": key_count,
                    "groups": groups,
                    "detail": f"{len(policies)} inline, {len(managed)} managed",
                })

            # Roles
            for _rid, role in backend.roles.items():
                policies = list(getattr(role, "policies", {}).keys())
                managed = list(getattr(role, "managed_policies", {}).keys())
                resources.append({
                    "type": "Role",
                    "name": role.name,
                    "arn": role.arn,
                    "policies": len(policies) + len(managed),
                    "detail": f"{len(policies)} inline, {len(managed)} managed",
                })

            # Instance Profiles
            for _pid, profile in backend.instance_profiles.items():
                role_names = [r.name for r in profile.roles]
                resources.append({
                    "type": "InstanceProfile",
                    "name": profile.name,
                    "arn": profile.arn,
                    "policies": 0,
                    "detail": f"roles: {', '.join(role_names) if role_names else 'none'}",
                })

            # Groups
            for _gname, group in getattr(backend, "groups", {}).items():
                policies = list(getattr(group, "policies", {}).keys())
                managed = list(getattr(group, "managed_policies", {}).keys())
                resources.append({
                    "type": "Group",
                    "name": group.name,
                    "arn": getattr(group, "arn", ""),
                    "policies": len(policies) + len(managed),
                    "detail": f"{len(policies)} inline, {len(managed)} managed",
                })

        return resources

    @staticmethod
    def _list_vpc() -> list[dict]:
        """List VPCs with subnets, gateways, and Docker network status."""
        resources: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for vpc_id, vpc in backend.vpcs.items():
                cidr = getattr(vpc, "cidr_block", "")
                is_default = getattr(vpc, "is_default", False)

                # Count subnets in this VPC
                subnet_count = 0
                for _az, az_subnets in backend.subnets.items():
                    if isinstance(az_subnets, dict):
                        for sub in az_subnets.values():
                            if hasattr(sub, "vpc_id") and sub.vpc_id == vpc_id:
                                subnet_count += 1

                # Check IGW attachment
                igw_attached = False
                for igw in backend.internet_gateways.values():
                    attachments = getattr(igw, "vpc", None)
                    if attachments and (attachments == vpc_id or getattr(attachments, "id", "") == vpc_id):
                        igw_attached = True
                        break

                # Check Docker network
                docker_network = "-"
                try:
                    from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                    net = get_vpc_network_manager().get_network_for_vpc(vpc_id)
                    if net:
                        docker_network = net
                except Exception:
                    pass

                resources.append({
                    "name": vpc_id,
                    "cidr": cidr,
                    "subnets": subnet_count,
                    "igw": "attached" if igw_attached else "none",
                    "default": "yes" if is_default else "no",
                    "docker_network": docker_network,
                    "region": region,
                })

        return resources

    @staticmethod
    def _list_security_groups() -> list[dict]:
        """List security groups with ingress/egress rule details."""
        groups: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for sg_id, sg_data in backend.groups.items():
                if isinstance(sg_data, dict):
                    for _vpc_id, sg in sg_data.items():
                        ingress = getattr(sg, "ingress_rules", [])
                        egress = getattr(sg, "egress_rules", [])
                        ingress_summary = ", ".join(
                            f"{r.ip_protocol} {r.from_port}-{r.to_port}"
                            for r in ingress if hasattr(r, "ip_protocol")
                        )[:80] or "-"
                        groups.append({
                            "name": sg.name,
                            "id": sg.id,
                            "vpc": sg.vpc_id or "-",
                            "ingress": f"{len(ingress)} rules",
                            "egress": f"{len(egress)} rules",
                            "detail": ingress_summary,
                            "region": region,
                        })
        return groups

    @staticmethod
    def _list_nat_gateways() -> list[dict]:
        """List NAT Gateways with state and network info."""
        gateways: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for nat_id, ng in backend.nat_gateways.items():
                # Get public IP from address set
                public_ip = "-"
                addr_set = getattr(ng, "address_set", [])
                if addr_set:
                    for addr in addr_set:
                        ip = addr.get("publicIp") if isinstance(addr, dict) else getattr(addr, "public_ip", "")
                        if ip:
                            public_ip = ip
                            break

                gateways.append({
                    "name": nat_id,
                    "vpc": getattr(ng, "vpc_id", "-"),
                    "subnet": getattr(ng, "subnet_id", "-"),
                    "state": getattr(ng, "state", "-"),
                    "public_ip": public_ip,
                    "type": getattr(ng, "connectivity_type", "public"),
                    "region": region,
                })
        return gateways

    @staticmethod
    def _list_vpc_peering() -> list[dict]:
        """List VPC Peering connections with status."""
        peerings: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for pcx_id, pcx in backend.vpc_pcxs.items():
                requester = getattr(pcx, "vpc", None)
                accepter = getattr(pcx, "peer_vpc", None)
                status = getattr(pcx, "_status", None)
                peerings.append({
                    "name": pcx_id,
                    "requester": getattr(requester, "id", "-") if requester else "-",
                    "accepter": getattr(accepter, "id", "-") if accepter else "-",
                    "status": getattr(status, "code", "-") if status else "-",
                    "region": region,
                })
        return peerings

    @staticmethod
    def _list_vpc_endpoints() -> list[dict]:
        """List VPC Endpoints with service and type."""
        endpoints: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ec2"):
            for vpce_id, ep in backend.vpc_end_points.items():
                # Try to get proxy IP from VPC Endpoint manager
                proxy_ip = "-"
                try:
                    from localemu.services.ec2.docker.vpc_endpoint import get_vpc_endpoint_manager
                    ip = get_vpc_endpoint_manager().get_endpoint_ip(vpce_id)
                    if ip:
                        proxy_ip = ip
                except Exception:
                    pass

                endpoints.append({
                    "name": vpce_id,
                    "vpc": getattr(ep, "vpc_id", "-"),
                    "service": getattr(ep, "service_name", "-"),
                    "type": getattr(ep, "type", "-"),
                    "state": getattr(ep, "state", "-"),
                    "proxy": proxy_ip,
                    "region": region,
                })
        return endpoints

    @staticmethod
    def _list_route53() -> list[dict]:
        """Hosted zones (Route 53 is a global service in moto)."""
        zones: list[dict] = []
        for _acct, _region, backend in _iter_moto_backends("route53"):
            for zone_id, zone in getattr(backend, "zones", {}).items():
                name = getattr(zone, "name", zone_id)
                rrset_count = len(getattr(zone, "rrsets", []) or [])
                private = bool(getattr(zone, "private_zone", False))
                zones.append({
                    "name": name,
                    "id": zone_id,
                    "type": "Private" if private else "Public",
                    "records": rrset_count,
                    "region": "global",
                })
        return zones

    @staticmethod
    def _list_elbv2() -> list[dict]:
        """ELBv2 load balancers (Application + Network) across regions."""
        lbs: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("elbv2"):
            for lb_arn, lb in getattr(backend, "load_balancers", {}).items():
                name = getattr(lb, "name", lb_arn.split("/")[-2] if "/" in lb_arn else lb_arn)
                scheme = getattr(lb, "scheme", "-")
                lb_type = getattr(lb, "load_balancer_type", "-")
                state = getattr(lb, "state", None)
                state_str = getattr(state, "code", state) if state is not None else "-"
                dns = getattr(lb, "dns_name", "-")
                lbs.append({
                    "name": name,
                    "arn": lb_arn,
                    "type": lb_type,
                    "scheme": scheme,
                    "state": str(state_str),
                    "dns": dns,
                    "region": region,
                })
        return lbs

    @staticmethod
    def _list_kms() -> list[dict]:
        """KMS customer-managed keys (CMKs) across regions.

        Walks LocalEmu's native ``kms_stores``. moto.kms is never
        instantiated -- every Create/Encrypt/Decrypt lands in
        ``kms_stores`` via ``localemu.services.kms.provider``.
        """
        from localemu.services.kms.models import kms_stores

        keys: list[dict] = []
        for _acct, region, store in kms_stores.iter_stores():
            # Build a key_id -> [alias_name, ...] index once per store.
            alias_index: dict[str, list[str]] = {}
            for alias_name, alias in (store.aliases or {}).items():
                target = getattr(alias, "target_key_id", None) or getattr(alias, "key_id", None)
                if not target:
                    continue
                alias_index.setdefault(target, []).append(alias_name)
            for key_id, key in store.keys.items():
                metadata = getattr(key, "metadata", None) or {}
                aliases = alias_index.get(key_id, [])
                multi_region = bool(metadata.get("MultiRegion"))
                keys.append({
                    "name": metadata.get("Description") or key_id,
                    "key_id": key_id,
                    "alias": ", ".join(aliases) if aliases else "-",
                    "state": str(metadata.get("KeyState", "-")),
                    "spec": str(metadata.get("KeySpec", "-")),
                    "usage": str(metadata.get("KeyUsage", "-")),
                    "origin": str(metadata.get("Origin", "-")),
                    "multi_region": "Yes" if multi_region else "No",
                    "region": region,
                })
        return keys

    @staticmethod
    def _list_ssm() -> list[dict]:
        """SSM Parameter Store entries (path, type, last modified)."""
        params: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ssm"):
            # moto's SSM backend stores parameters in a TreeBackend mapping
            # name -> list[ParameterValue] (versions).
            raw = getattr(backend, "_parameters", None) or getattr(backend, "parameters", {})
            try:
                items = raw.items() if hasattr(raw, "items") else []
            except Exception:
                items = []
            for name, versions in items:
                if not versions:
                    continue
                latest = versions[-1] if isinstance(versions, list) else versions
                params.append({
                    "name": name,
                    "type": str(getattr(latest, "type", "-")),
                    "version": getattr(latest, "version", "-"),
                    "last_modified": str(getattr(latest, "last_modified_date", "-")),
                    "region": region,
                })
        return params

    @staticmethod
    def _list_cloudtrail() -> list[dict]:
        """Recent CloudTrail events as a flat list (most-recent first).

        This is a slim projection over the shared event store so the
        sidebar tile and the per-service list page match up. The full
        CloudTrail panel still lives at /_localemu/api/cloudtrail with
        pagination + filtering.
        """
        from localemu.services.cloudtrail.event_store import get_event_store
        store = get_event_store()
        events = store.get_recent(limit=200)
        out: list[dict] = []
        for evt in events:
            ts = evt.event_time
            out.append({
                "name": getattr(evt, "event_name", "") or "-",
                "source": (getattr(evt, "event_source", "") or "").replace(".amazonaws.com", ""),
                "user": getattr(evt, "username", "") or "-",
                "request_id": getattr(evt, "request_id", "") or "-",
                "time": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                "region": getattr(evt, "aws_region", "") or "-",
            })
        return out

    @staticmethod
    def _list_ecr() -> list[dict]:
        """ECR repositories across regions (one row per repo)."""
        repos: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("ecr"):
            for name, repo in (getattr(backend, "repositories", {}) or {}).items():
                images = getattr(repo, "images", []) or []
                tag_count = 0
                for img in images:
                    tag_count += len(getattr(img, "image_tags", []) or [])
                repos.append({
                    "name": name,
                    "uri": getattr(repo, "uri", ""),
                    "arn": getattr(repo, "arn", ""),
                    "tag_mutability": str(getattr(repo, "image_tag_mutability", "-")),
                    "scan_on_push": bool(
                        (getattr(repo, "image_scanning_configuration", {}) or {})
                        .get("scanOnPush", False)
                    ),
                    "images": len(images),
                    "tags": tag_count,
                    "created_at": str(getattr(repo, "created_at", "") or ""),
                    "region": region,
                })
        return repos

    @staticmethod
    def _list_batch() -> list[dict]:
        """Flat row list: compute envs, queues, job definitions, jobs.

        Each row carries ``kind`` so the dashboard can group them in the UI.
        """
        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("batch"):
            for name, env in (getattr(backend, "_compute_environments", {}) or {}).items():
                rows.append({
                    "name": name,
                    "kind": "compute-env",
                    "arn": getattr(env, "arn", ""),
                    "type": getattr(env, "env_type", "-"),
                    "state": getattr(env, "state", "-"),
                    "region": region,
                })
            for name, q in (getattr(backend, "_job_queues", {}) or {}).items():
                rows.append({
                    "name": getattr(q, "name", name),
                    "kind": "job-queue",
                    "arn": getattr(q, "arn", ""),
                    "type": "-",
                    "state": getattr(q, "state", "-"),
                    "region": region,
                })
            for jd_id, jd in (getattr(backend, "_job_definitions", {}) or {}).items():
                rows.append({
                    "name": getattr(jd, "name", jd_id),
                    "kind": "job-def",
                    "arn": getattr(jd, "arn", ""),
                    "type": getattr(jd, "type", "-"),
                    "state": "-",
                    "region": region,
                })
            for job_id, job in (getattr(backend, "_jobs", {}) or {}).items():
                rows.append({
                    "name": getattr(job, "job_name", job_id),
                    "kind": "job",
                    "arn": getattr(job, "job_id", job_id),
                    "type": "-",
                    "state": str(getattr(job, "status", "-")),
                    "region": region,
                })
        return rows

    @staticmethod
    def _list_pipes() -> list[dict]:
        """EventBridge Pipes — moto metadata + runtime worker state."""
        from localemu.services.pipes.pipe_manager import PipeManager

        runtime_state: dict[str, str] = {}
        try:
            for worker in PipeManager.instance().all():
                runtime_state[worker.pipe_arn] = str(
                    getattr(worker, "current_state", "-")
                )
        except Exception:
            runtime_state = {}

        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("pipes"):
            for name, pipe in (getattr(backend, "pipes", {}) or {}).items():
                arn = getattr(pipe, "arn", "")
                rows.append({
                    "name": name,
                    "arn": arn,
                    "source": getattr(pipe, "source", "-"),
                    "target": getattr(pipe, "target", "-"),
                    "desired_state": getattr(pipe, "desired_state", "-"),
                    "current_state": runtime_state.get(arn) or getattr(pipe, "current_state", "-"),
                    "region": region,
                })
        return rows

    @staticmethod
    def _list_scheduler() -> list[dict]:
        """EventBridge Scheduler schedules across groups and regions."""
        from localemu.services.scheduler.job_scheduler import SchedulerJobScheduler

        runtime: dict[str, dict] = {}
        try:
            for arn, job in SchedulerJobScheduler.instance()._jobs.items():
                runtime[arn] = {
                    "next_fire": job.next_fire.isoformat() if job.next_fire else "-",
                    "state": job.state,
                }
        except Exception:
            runtime = {}

        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("scheduler"):
            for gname, group in (getattr(backend, "schedule_groups", {}) or {}).items():
                scheds = getattr(group, "schedules", {}) or {}
                for sched in (scheds.values() if hasattr(scheds, "values") else scheds):
                    arn = getattr(sched, "arn", "")
                    rt = runtime.get(arn, {})
                    target = getattr(sched, "target", {}) or {}
                    rows.append({
                        "name": getattr(sched, "name", ""),
                        "group": gname or "default",
                        "arn": arn,
                        "expression": getattr(sched, "schedule_expression", "-"),
                        "timezone": getattr(sched, "schedule_expression_timezone", "UTC"),
                        "state": rt.get("state") or getattr(sched, "state", "-"),
                        "next_fire": rt.get("next_fire", "-"),
                        "target": target.get("Arn", "-") if isinstance(target, dict) else "-",
                        "region": region,
                    })
        return rows

    @staticmethod
    def _list_wafv2() -> list[dict]:
        """WAFv2 rows: web ACLs, IP sets, regex sets, rule groups.

        ``kind`` discriminator lets the dashboard group them visually.
        """
        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("wafv2"):
            for arn, acl in (getattr(backend, "wacls", {}) or {}).items():
                rows.append({
                    "name": getattr(acl, "name", ""),
                    "kind": "web-acl",
                    "arn": arn,
                    "id": getattr(acl, "id", ""),
                    "scope": getattr(acl, "scope", "-"),
                    "rules": len(getattr(acl, "rules", []) or []),
                    "associated": len(getattr(acl, "associated_resources", []) or []),
                    "region": region,
                })
            for arn, ip_set in (getattr(backend, "ip_sets", {}) or {}).items():
                rows.append({
                    "name": getattr(ip_set, "name", ""),
                    "kind": "ip-set",
                    "arn": arn,
                    "id": getattr(ip_set, "ip_set_id", ""),
                    "scope": getattr(ip_set, "scope", "-"),
                    "rules": len(getattr(ip_set, "addresses", []) or []),
                    "associated": 0,
                    "region": region,
                })
            for arn, rg in (getattr(backend, "rule_groups", {}) or {}).items():
                rows.append({
                    "name": getattr(rg, "name", ""),
                    "kind": "rule-group",
                    "arn": arn,
                    "id": getattr(rg, "id", ""),
                    "scope": getattr(rg, "scope", "-"),
                    "rules": len(getattr(rg, "rules", []) or []),
                    "associated": 0,
                    "region": region,
                })
        return rows

    @staticmethod
    def _list_glue() -> list[dict]:
        """Flat row list spanning every Glue primitive.

        Each row carries a ``kind`` discriminator so the dashboard can
        group them and route the click to the right drill view. The
        ``key`` field is the kind-scoped identifier the detail route
        consumes (``database/<db>/<table>``, ``schema/<reg>/<name>``,
        or just the resource name for everything else).
        """
        rows: list[dict] = []
        for _acct, region, backend in _iter_moto_backends("glue"):
            databases = getattr(backend, "databases", {}) or {}
            for db_name, db in databases.items():
                tables = getattr(db, "tables", {}) or {}
                rows.append({
                    "name": db_name,
                    "kind": "database",
                    "key": db_name,
                    "extra": str(len(tables)) + " tables",
                    "status": "-",
                    "region": region,
                })
                for tbl_name, tbl in tables.items():
                    versions = getattr(tbl, "versions", {}) or {}
                    cur = str(getattr(tbl, "_current_version", 1))
                    table_input = versions.get(cur, {}) if isinstance(versions, dict) else {}
                    col_count = 0
                    storage = (table_input or {}).get("StorageDescriptor") or {}
                    col_count = len(storage.get("Columns") or [])
                    rows.append({
                        "name": tbl_name,
                        "kind": "table",
                        "key": db_name + "/" + tbl_name,
                        "extra": db_name + " \u00b7 " + str(col_count) + " cols",
                        "status": "-",
                        "region": region,
                    })

            for name, c in (getattr(backend, "crawlers", {}) or {}).items():
                rows.append({
                    "name": name,
                    "kind": "crawler",
                    "key": name,
                    "extra": (getattr(c, "database_name", "") or "-") + " \u00b7 " + (getattr(c, "schedule", "") or "on demand"),
                    "status": getattr(c, "status", "-"),
                    "region": region,
                })

            for name, j in (getattr(backend, "jobs", {}) or {}).items():
                rows.append({
                    "name": name,
                    "kind": "job",
                    "key": name,
                    "extra": (getattr(j, "glue_version", "") or "-") + " \u00b7 " + str(len(getattr(j, "job_runs", []) or [])) + " runs",
                    "status": "-",
                    "region": region,
                })

            for name, t in (getattr(backend, "triggers", {}) or {}).items():
                rows.append({
                    "name": name,
                    "kind": "trigger",
                    "key": name,
                    "extra": getattr(t, "trigger_type", "-"),
                    "status": getattr(t, "state", "-"),
                    "region": region,
                })

            for name, w in (getattr(backend, "workflows", {}) or {}).items():
                rows.append({
                    "name": name,
                    "kind": "workflow",
                    "key": name,
                    "extra": str(len(getattr(w, "runs", {}) or {})) + " runs",
                    "status": "-",
                    "region": region,
                })

            for name, conn in (getattr(backend, "connections", {}) or {}).items():
                props = getattr(conn, "connection_properties", {}) or {}
                rows.append({
                    "name": name,
                    "kind": "connection",
                    "key": name,
                    "extra": str(props.get("CONNECTION_TYPE") or "-"),
                    "status": getattr(conn, "status", "-"),
                    "region": region,
                })

            registries = getattr(backend, "registries", {}) or {}
            for reg_name, reg in registries.items():
                schemas = getattr(reg, "schemas", {}) or {}
                rows.append({
                    "name": reg_name,
                    "kind": "registry",
                    "key": reg_name,
                    "extra": str(len(schemas)) + " schemas",
                    "status": getattr(reg, "status", "-"),
                    "region": region,
                })
                for schema_name, schema in schemas.items():
                    rows.append({
                        "name": schema_name,
                        "kind": "schema",
                        "key": reg_name + "/" + schema_name,
                        "extra": (getattr(schema, "data_format", "") or "-") + " \u00b7 " + str(getattr(schema, "latest_schema_version", 1)),
                        "status": getattr(schema, "schema_status", "-"),
                        "region": region,
                    })

        return rows


class RdsInstanceDetailResource:
    """``GET /_localemu/api/resources/rds/<db_id>`` -- one RDS instance.

    The killer item is the Connection info card: host, port, master
    username, master password (read from the Docker label), database
    name, copyable psql / mysql shell command, and a URL-form
    connection string for Python / Node / Go / Rust SDKs. Plus the
    Docker container name so the user can tail logs with
    ``docker logs <name>``.
    """

    def on_get(self, request: Request, db_id: str = ""):
        from urllib.parse import unquote
        db_id = unquote(db_id or "")

        for _acct, region, backend in _iter_moto_backends("rds"):
            db = (getattr(backend, "databases", {}) or {}).get(db_id)
            if db is None:
                continue

            engine = (getattr(db, "engine", "") or "").lower()
            engine_version = getattr(db, "engine_version", "") or ""
            host = getattr(db, "address", "") or "localhost"
            port = getattr(db, "port", None)
            user = getattr(db, "master_username", "") or ""
            db_name = getattr(db, "db_name", "") or ""

            container_name = None
            container_image = None
            container_ip = None
            password = ""

            # Pull the real Docker port + password from the manager
            # when RDS_DOCKER_BACKEND=1 is on. Without it, host stays
            # as the moto-synthesised address and password is empty
            # (the user supplied it at create-db-instance time but
            # moto does not persist it).
            docker_available = False
            try:
                from localemu.services.rds.provider import _db_manager
                if _db_manager:
                    info = _db_manager.get_instance_info(db_id)
                    if info:
                        docker_available = True
                        if info.host_port:
                            port = info.host_port
                            host = "localhost"
                        password = info.master_password or ""
                        container_name = info.container_name
                        container_image = info.image
                        container_ip = info.container_ip or None
                        if info.db_name:
                            db_name = info.db_name
            except Exception:
                docker_available = False

            # Build the actually-useful connection strings + commands.
            shell_cmd = None
            url_cmd = None
            default_db = db_name or _default_db_name(engine)
            if "postgres" in engine:
                shell_cmd = f"PGPASSWORD={password or '<password>'} psql -h {host} -p {port or 5432} -U {user} -d {default_db}"
                url_cmd = f"postgresql://{user}:{password or '<password>'}@{host}:{port or 5432}/{default_db}"
            elif "mysql" in engine or "maria" in engine:
                shell_cmd = f"mysql -h {host} -P {port or 3306} -u {user} -p'{password or '<password>'}' {default_db}"
                url_cmd = f"mysql://{user}:{password or '<password>'}@{host}:{port or 3306}/{default_db}"

            return _json_response({
                "name": db_id,
                "engine": engine,
                "engine_version": engine_version,
                "status": getattr(db, "status", ""),
                "instance_class": getattr(db, "db_instance_class", ""),
                "storage_gb": getattr(db, "allocated_storage", None),
                "storage_type": getattr(db, "storage_type", ""),
                "iops": getattr(db, "iops", None),
                "multi_az": bool(getattr(db, "multi_az", False)),
                "publicly_accessible": bool(getattr(db, "publicly_accessible", False)),
                "backup_retention_period": getattr(db, "backup_retention_period", 0),
                "preferred_backup_window": getattr(db, "preferred_backup_window", "") or "",
                "preferred_maintenance_window": getattr(db, "preferred_maintenance_window", "") or "",
                "ca_certificate_identifier": getattr(db, "ca_certificate_identifier", "") or "",
                "kms_key_id": getattr(db, "kms_key_id", None),
                "storage_encrypted": bool(getattr(db, "storage_encrypted", False)),
                "deletion_protection": bool(getattr(db, "deletion_protection", False)),
                "auto_minor_version_upgrade": bool(getattr(db, "auto_minor_version_upgrade", True)),
                "tags": getattr(db, "tags", []) or [],
                "vpc_security_groups": getattr(db, "vpc_security_group_ids", []) or [],
                "subnet_group": getattr(getattr(db, "db_subnet_group", None), "subnet_name", None),
                # moto exposes db_parameter_groups as an instance method, not a
                # property: getattr(...) returns the bound method, and iterating
                # it raises "'method' object is not iterable". Call it when
                # callable, fall through to whatever attribute value otherwise
                # (some moto versions and Aurora paths return a list directly).
                "parameter_groups": _rds_parameter_group_names(db),
                "region": region,
                # Connection info -- the killer card
                "host": host,
                "port": port,
                "master_username": user,
                "master_password": password,
                "database_name": db_name or None,
                "shell_command": shell_cmd,
                "connection_url": url_cmd,
                "docker_available": docker_available,
                "docker_container_name": container_name,
                "docker_container_image": container_image,
                "docker_container_ip": container_ip,
                "docker_logs_command": f"docker logs -f {container_name}" if container_name else None,
            })

        # Try Aurora clusters next
        for _acct, region, backend in _iter_moto_backends("rds"):
            cluster = (getattr(backend, "clusters", {}) or {}).get(db_id)
            if cluster is None:
                continue
            members = [getattr(m, "db_cluster_identifier", "") for m in (getattr(cluster, "cluster_members", []) or [])]
            return _json_response({
                "name": db_id,
                "kind": "cluster",
                "engine": getattr(cluster, "engine", ""),
                "engine_version": getattr(cluster, "engine_version", ""),
                "status": getattr(cluster, "status", ""),
                "endpoint": getattr(cluster, "endpoint", "") or "",
                "reader_endpoint": getattr(cluster, "reader_endpoint", "") or "",
                "port": getattr(cluster, "port", None),
                "master_username": getattr(cluster, "master_username", ""),
                "database_name": getattr(cluster, "database_name", "") or "",
                "members": members,
                "region": region,
                "tags": getattr(cluster, "tags", []) or [],
            })

        return _json_response({"error": "not found", "name": db_id}, status=404)


def _default_db_name(engine: str) -> str:
    e = (engine or "").lower()
    if "postgres" in e:
        return "postgres"
    if "mysql" in e or "maria" in e:
        return "mysql"
    return ""


class VpcDetailResource:
    """``GET /_localemu/api/resources/vpc/<vpc_id>`` — full VPC topology.

    Returns the same row data the list endpoint emits plus every related
    object the user would expect on a VPC detail page on real AWS:
    subnets, route tables (with rules), internet gateways, NAT gateways,
    security groups (with ingress/egress), network ACLs (with entries),
    VPC endpoints, peering connections, and the Docker network LocalEmu
    materialised for this VPC.
    """

    def on_get(self, request: Request, vpc_id: str = ""):
        from urllib.parse import unquote
        vpc_id = unquote(vpc_id or "")

        for _acct, region, backend in _iter_moto_backends("ec2"):
            vpc = (getattr(backend, "vpcs", {}) or {}).get(vpc_id)
            if vpc is None:
                continue

            # ---- Subnets in this VPC ----
            subnets: list[dict] = []
            for _az, az_subnets in (getattr(backend, "subnets", {}) or {}).items():
                if not isinstance(az_subnets, dict):
                    continue
                for sub in az_subnets.values():
                    if getattr(sub, "vpc_id", None) != vpc_id:
                        continue
                    subnets.append({
                        "subnet_id": getattr(sub, "id", ""),
                        "cidr": getattr(sub, "cidr_block", ""),
                        "availability_zone": getattr(sub, "availability_zone", ""),
                        "available_ips": getattr(sub, "available_ip_addresses_count", None),
                        "map_public_ip": bool(getattr(sub, "map_public_ip_on_launch", False)),
                        "default_for_az": bool(getattr(sub, "default_for_az", False)),
                    })

            # ---- Route tables in this VPC ----
            route_tables: list[dict] = []
            for rt_id, rt in (getattr(backend, "route_tables", {}) or {}).items():
                if getattr(rt, "vpc_id", None) != vpc_id:
                    continue
                routes: list[dict] = []
                rt_routes = getattr(rt, "routes", {}) or {}
                for _key, route in (rt_routes.items() if hasattr(rt_routes, "items") else enumerate(rt_routes)):
                    target = (
                        getattr(route, "gateway_id", None)
                        or getattr(route, "instance_id", None)
                        or getattr(route, "nat_gateway_id", None)
                        or getattr(route, "vpc_peering_connection_id", None)
                        or getattr(route, "transit_gateway_id", None)
                        or "local"
                    )
                    routes.append({
                        "destination": getattr(route, "destination_cidr_block", None)
                        or getattr(route, "destination_prefix_list_id", None)
                        or getattr(route, "destination_ipv6_cidr_block", None)
                        or "-",
                        "target": target,
                        "state": getattr(route, "state", "active"),
                    })
                associations = []
                for assoc_id, sub_id in (getattr(rt, "associations", {}) or {}).items():
                    associations.append({"association_id": assoc_id, "subnet_id": sub_id})
                route_tables.append({
                    "route_table_id": rt_id,
                    "main": bool(getattr(rt, "main_association_id", None)) or bool(getattr(rt, "main", False)),
                    "routes": routes,
                    "associations": associations,
                })

            # ---- Internet gateways attached to this VPC ----
            igws: list[dict] = []
            for igw_id, igw in (getattr(backend, "internet_gateways", {}) or {}).items():
                attached = getattr(igw, "vpc", None)
                attached_id = getattr(attached, "id", attached) if attached else None
                if attached_id == vpc_id:
                    igws.append({
                        "internet_gateway_id": igw_id,
                        "state": "available",
                    })

            # ---- NAT gateways in this VPC ----
            nats: list[dict] = []
            for nat_id, ng in (getattr(backend, "nat_gateways", {}) or {}).items():
                if getattr(ng, "vpc_id", None) != vpc_id:
                    continue
                public_ip = "-"
                addr_set = getattr(ng, "address_set", []) or []
                for addr in addr_set:
                    ip = addr.get("publicIp") if isinstance(addr, dict) else getattr(addr, "public_ip", "")
                    if ip:
                        public_ip = ip
                        break
                nats.append({
                    "nat_gateway_id": nat_id,
                    "subnet_id": getattr(ng, "subnet_id", "-"),
                    "state": getattr(ng, "state", "-"),
                    "public_ip": public_ip,
                    "connectivity_type": getattr(ng, "connectivity_type", "public"),
                })

            # ---- Security groups in this VPC ----
            sgs: list[dict] = []
            for _sg_id, sg_data in (getattr(backend, "groups", {}) or {}).items():
                if not isinstance(sg_data, dict):
                    continue
                for _vpc, sg in sg_data.items():
                    if getattr(sg, "vpc_id", None) != vpc_id:
                        continue
                    def _rules(rs):
                        out = []
                        for r in (rs or []):
                            out.append({
                                "protocol": getattr(r, "ip_protocol", "-"),
                                "from_port": getattr(r, "from_port", None),
                                "to_port": getattr(r, "to_port", None),
                                "cidr": (getattr(r, "ip_ranges", None) or [{}])[0].get("CidrIp", "")
                                if isinstance((getattr(r, "ip_ranges", None) or [{}])[0], dict) else "",
                            })
                        return out
                    sgs.append({
                        "group_id": getattr(sg, "id", ""),
                        "name": getattr(sg, "name", ""),
                        "description": getattr(sg, "description", ""),
                        "ingress": _rules(getattr(sg, "ingress_rules", [])),
                        "egress": _rules(getattr(sg, "egress_rules", [])),
                    })

            # ---- Network ACLs in this VPC ----
            nacls: list[dict] = []
            for nacl_id, nacl in (getattr(backend, "network_acls", {}) or {}).items():
                if getattr(nacl, "vpc_id", None) != vpc_id:
                    continue
                entries = []
                for entry in (getattr(nacl, "network_acl_entries", []) or []):
                    entries.append({
                        "rule_number": getattr(entry, "rule_number", None),
                        "protocol": getattr(entry, "protocol", "-"),
                        "rule_action": getattr(entry, "rule_action", "-"),
                        "egress": bool(getattr(entry, "egress", False)),
                        "cidr": getattr(entry, "cidr_block", "-"),
                    })
                associations = []
                for assoc in (getattr(nacl, "associations", {}) or {}).values():
                    if hasattr(assoc, "subnet_id"):
                        associations.append({"subnet_id": assoc.subnet_id})
                    elif isinstance(assoc, dict):
                        associations.append({"subnet_id": assoc.get("subnet_id")})
                nacls.append({
                    "network_acl_id": nacl_id,
                    "default": bool(getattr(nacl, "default", False)),
                    "entries": entries,
                    "associations": associations,
                })

            # ---- VPC endpoints in this VPC ----
            endpoints: list[dict] = []
            for vpce_id, ep in (getattr(backend, "vpc_end_points", {}) or {}).items():
                if getattr(ep, "vpc_id", None) != vpc_id:
                    continue
                endpoints.append({
                    "endpoint_id": vpce_id,
                    "service_name": getattr(ep, "service_name", "-"),
                    "type": getattr(ep, "type", "-"),
                    "state": getattr(ep, "state", "-"),
                })

            # ---- Peerings touching this VPC ----
            peerings: list[dict] = []
            for pcx_id, pcx in (getattr(backend, "vpc_pcxs", {}) or {}).items():
                req = getattr(pcx, "vpc", None)
                acc = getattr(pcx, "peer_vpc", None)
                req_id = getattr(req, "id", None)
                acc_id = getattr(acc, "id", None)
                if vpc_id not in (req_id, acc_id):
                    continue
                status = getattr(pcx, "_status", None)
                peerings.append({
                    "peering_id": pcx_id,
                    "requester_vpc": req_id or "-",
                    "accepter_vpc": acc_id or "-",
                    "status": getattr(status, "code", "-") if status else "-",
                })

            # ---- LocalEmu Docker network for this VPC ----
            docker_network = None
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                docker_network = get_vpc_network_manager().get_network_for_vpc(vpc_id)
            except Exception:
                pass

            return _json_response({
                "vpc_id": vpc_id,
                "cidr": getattr(vpc, "cidr_block", ""),
                "is_default": bool(getattr(vpc, "is_default", False)),
                "state": getattr(vpc, "state", "available"),
                "instance_tenancy": getattr(vpc, "instance_tenancy", "default"),
                "dhcp_options_id": getattr(vpc, "dhcp_options_id", None),
                "tags": [
                    {"Key": k, "Value": v}
                    for k, v in (getattr(vpc, "get_tags", lambda: {})() or {}).items()
                ] if callable(getattr(vpc, "get_tags", None)) else [],
                "subnets": subnets,
                "route_tables": route_tables,
                "internet_gateways": igws,
                "nat_gateways": nats,
                "security_groups": sgs,
                "network_acls": nacls,
                "vpc_endpoints": endpoints,
                "peerings": peerings,
                "docker_network": docker_network,
                "region": region,
            })

        return _json_response({"error": "not found", "vpc_id": vpc_id}, status=404)


def _rds_parameter_group_names(db) -> list[str]:
    """Resolve the list of parameter-group names from a moto RDS DB instance.

    Some moto versions expose ``db_parameter_groups`` as a bound method
    (``def db_parameter_groups(self): ...``), others as a plain list
    attribute, others not at all. The dashboard detail handler used to do a
    naive ``[p for p in getattr(db, "db_parameter_groups", []) or []]``,
    which iterated the method object on builds that expose the method form
    and raised ``'method' object is not iterable``. Resolve all three
    shapes here.
    """
    attr = getattr(db, "db_parameter_groups", None)
    if attr is None:
        return []
    if callable(attr):
        try:
            attr = attr()
        except Exception:
            return []
    if not attr:
        return []
    out: list[str] = []
    for p in attr:
        name = getattr(p, "name", None) or getattr(p, "db_parameter_group_name", None) or ""
        if name:
            out.append(name)
    return out


class KinesisStreamDetailResource:
    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("kinesis"):
            stream = (getattr(backend, "streams", {}) or {}).get(name)
            if stream is None:
                continue
            shards = []
            for shard_id, shard in (getattr(stream, "shards", {}) or {}).items():
                shards.append({
                    "id": shard_id,
                    "parent_shard_id": getattr(shard, "parent_shard_id", None),
                    "ending_hash_key": getattr(shard, "ending_hash_key", None),
                    "starting_sequence_number": getattr(shard, "starting_sequence_number", None),
                    "ending_sequence_number": getattr(shard, "ending_sequence_number", None),
                })
            consumers = []
            for c in (getattr(stream, "consumers", []) or []):
                consumers.append({
                    "name": getattr(c, "consumer_name", "") or "",
                    "arn": getattr(c, "consumer_arn", "") or "",
                    "status": getattr(c, "consumer_status", "") or "",
                    "creation_timestamp": str(getattr(c, "creation_timestamp", "") or ""),
                })
            return _json_response({
                "name": name,
                "arn": getattr(stream, "arn", "") or "",
                "status": getattr(stream, "status", "ACTIVE"),
                "stream_mode": getattr(stream, "stream_mode", "PROVISIONED"),
                "retention_hours": getattr(stream, "retention_period_hours", 24),
                "encryption_type": getattr(stream, "encryption_type", "NONE"),
                "key_id": getattr(stream, "key_id", None),
                "shards": shards,
                "consumers": consumers,
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class FirehoseDeliveryStreamDetailResource:
    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("firehose"):
            stream = (getattr(backend, "delivery_streams", {}) or {}).get(name)
            if stream is None:
                continue
            destinations = []
            for d in (getattr(stream, "destinations", []) or []):
                if isinstance(d, dict):
                    destinations.append(d)
                else:
                    destinations.append({"raw": str(d)})
            return _json_response({
                "name": name,
                "arn": getattr(stream, "delivery_stream_arn", "") or "",
                "status": getattr(stream, "delivery_stream_status", "ACTIVE"),
                "type": getattr(stream, "delivery_stream_type", "DirectPut"),
                "created": str(getattr(stream, "create_timestamp", "") or ""),
                "last_updated": str(getattr(stream, "last_update_timestamp", "") or ""),
                "encryption": getattr(stream, "delivery_stream_encryption_configuration", {}) or {},
                "version_id": getattr(stream, "version_id", None),
                "destinations": destinations,
                "tags": getattr(stream, "tags", []) or [],
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class MskClusterDetailResource:
    def on_get(self, request: Request, arn: str = ""):
        from urllib.parse import unquote
        arn = unquote(arn or "")
        for _acct, region, backend in _iter_moto_backends("kafka"):
            cluster = None
            for c_arn, c in (getattr(backend, "clusters", {}) or {}).items():
                if c_arn == arn or getattr(c, "cluster_name", "") == arn:
                    cluster = c
                    arn = c_arn
                    break
            if cluster is None:
                continue
            broker_info = None
            try:
                from localemu.services.plugins import SERVICE_PLUGINS
                plugin = SERVICE_PLUGINS.get("kafka")
                provider = getattr(plugin, "instance", None) if plugin else None
                mgr = getattr(provider, "_cluster_manager", None) if provider else None
                if mgr:
                    info = mgr.get_cluster_info(getattr(cluster, "cluster_name", ""))
                    if info:
                        broker_info = {
                            "container_name": getattr(info, "container_name", ""),
                            "bootstrap_brokers": getattr(info, "bootstrap_brokers", "")
                                or "localhost:" + str(getattr(info, "host_port", "")),
                            "host_port": getattr(info, "host_port", None),
                        }
            except Exception:
                broker_info = None
            return _json_response({
                "name": getattr(cluster, "cluster_name", "") or "",
                "arn": arn,
                "type": getattr(cluster, "cluster_type", "PROVISIONED"),
                "state": getattr(cluster, "state", "ACTIVE"),
                "kafka_version": getattr(cluster, "kafka_version", "") or "",
                "broker_count": len(getattr(cluster, "broker_node_group_info", {}).get("client_subnets", [])) if isinstance(getattr(cluster, "broker_node_group_info", None), dict) else 0,
                "broker_node_group_info": getattr(cluster, "broker_node_group_info", {}) or {},
                "encryption_info": getattr(cluster, "encryption_info", {}) or {},
                "current_version": getattr(cluster, "current_version", "") or "",
                "tags": getattr(cluster, "tags", {}) or {},
                "broker_info": broker_info,
                "region": region,
            })
        return _json_response({"error": "not found", "arn": arn}, status=404)


class MqBrokerDetailResource:
    def on_get(self, request: Request, broker_id: str = ""):
        for _acct, region, backend in _iter_moto_backends("mq"):
            broker = (getattr(backend, "brokers", {}) or {}).get(broker_id)
            if broker is None:
                continue
            container_info = None
            try:
                from localemu.services.plugins import SERVICE_PLUGINS
                plugin = SERVICE_PLUGINS.get("mq")
                provider = getattr(plugin, "instance", None) if plugin else None
                mgr = getattr(provider, "_broker_manager", None) if provider else None
                if mgr:
                    info = mgr.get_broker_info(broker_id)
                    if info:
                        container_info = {
                            "container_name": getattr(info, "container_name", ""),
                            "host_port": getattr(info, "host_port", None),
                            "management_port": getattr(info, "management_port", None),
                            "management_url": getattr(info, "management_url", ""),
                            "image": getattr(info, "image", ""),
                        }
            except Exception:
                container_info = None
            return _json_response({
                "broker_id": broker_id,
                "name": getattr(broker, "broker_name", "") or "",
                "engine_type": getattr(broker, "engine_type", "") or "",
                "engine_version": getattr(broker, "engine_version", "") or "",
                "deployment_mode": getattr(broker, "deployment_mode", "") or "",
                "broker_instances": getattr(broker, "broker_instances", []) or [],
                "users": [getattr(u, "username", "") for u in (getattr(broker, "users", []) or [])],
                "broker_state": getattr(broker, "broker_state", "RUNNING"),
                "created": str(getattr(broker, "created", "") or ""),
                "configurations": getattr(broker, "configurations", {}) or {},
                "host_instance_type": getattr(broker, "host_instance_type", "") or "",
                "container": container_info,
                "region": region,
            })
        return _json_response({"error": "not found", "broker_id": broker_id}, status=404)


class AcmCertificateDetailResource:
    def on_get(self, request: Request, arn: str = ""):
        from urllib.parse import unquote
        arn = unquote(arn or "")
        for _acct, region, backend in _iter_moto_backends("acm"):
            for cert_arn, cert in (getattr(backend, "_certificates", {}) or getattr(backend, "certificates", {}) or {}).items():
                if cert_arn != arn:
                    continue
                cd = getattr(cert, "describe", None)
                if callable(cd):
                    try:
                        return _json_response({"detail": cd(), "region": region})
                    except Exception:
                        pass
                return _json_response({
                    "arn": cert_arn,
                    "domain_name": getattr(cert, "common_name", "") or "",
                    "subject_alternative_names": getattr(cert, "sans", []) or [],
                    "status": getattr(cert, "status", "ISSUED"),
                    "type": getattr(cert, "type", "AMAZON_ISSUED"),
                    "key_algorithm": getattr(cert, "key_algorithm", "") or "",
                    "signature_algorithm": getattr(cert, "signature_algorithm", "") or "",
                    "in_use_by": getattr(cert, "in_use_by", []) or [],
                    "not_before": str(getattr(cert, "not_before", "") or ""),
                    "not_after": str(getattr(cert, "not_after", "") or ""),
                    "issued_at": str(getattr(cert, "issued_at", "") or ""),
                    "tags": getattr(cert, "tags", []) or [],
                    "region": region,
                })
        return _json_response({"error": "not found", "arn": arn}, status=404)


class EfsFileSystemDetailResource:
    def on_get(self, request: Request, fs_id: str = ""):
        for _acct, region, backend in _iter_moto_backends("efs"):
            fs = (getattr(backend, "file_systems_by_id", {}) or {}).get(fs_id)
            if fs is None:
                continue
            return _json_response({
                "file_system_id": fs_id,
                "name": getattr(fs, "name", "") or "",
                "performance_mode": getattr(fs, "performance_mode", "") or "",
                "throughput_mode": getattr(fs, "throughput_mode", "") or "",
                "encrypted": bool(getattr(fs, "encrypted", False)),
                "kms_key_id": getattr(fs, "kms_key_id", None),
                "size_in_bytes": getattr(fs, "size_in_bytes", {}) or {},
                "creation_time": str(getattr(fs, "creation_time", "") or ""),
                "life_cycle_state": getattr(fs, "life_cycle_state", "available"),
                "tags": getattr(fs, "_tags", []) or getattr(fs, "tags", []) or [],
                "lifecycle_policies": list(getattr(fs, "lifecycle_policies", []) or []),
                "backup_policy_status": getattr(getattr(fs, "backup_policy", None), "status", "DISABLED"),
                "region": region,
            })
        return _json_response({"error": "not found", "fs_id": fs_id}, status=404)


class AthenaWorkgroupDetailResource:
    """``GET /_localemu/api/resources/athena/<workgroup>`` -- workgroup + recent queries.

    Lists the most recent query executions including the rewritten
    SQL, the state, runtime, output S3 location, and the first N
    result rows from the LocalEmu DuckDB-backed registry.
    """

    def on_get(self, request: Request, workgroup: str = ""):
        from urllib.parse import unquote
        workgroup = unquote(workgroup or "primary")

        for _acct, region, backend in _iter_moto_backends("athena"):
            wg = (getattr(backend, "work_groups", {}) or {}).get(workgroup)
            executions = []
            for exec_id, ex in (getattr(backend, "executions", {}) or {}).items():
                if getattr(ex, "workgroup", None) is not None:
                    wg_name = getattr(ex.workgroup, "name", "primary") if hasattr(ex.workgroup, "name") else (ex.workgroup or "primary")
                else:
                    wg_name = "primary"
                if wg_name != workgroup:
                    continue
                executions.append({
                    "id": exec_id,
                    "query": getattr(ex, "query", "") or "",
                    "state": getattr(ex, "status", "") or "",
                    "start_time": str(getattr(ex, "start_time", "") or ""),
                    "stop_time": str(getattr(ex, "end_time", "") or ""),
                    "output_location": getattr(ex, "output_location", "") or "",
                    "data_scanned_bytes": getattr(ex, "data_scanned_in_bytes", None),
                    "engine_execution_time_ms": getattr(ex, "engine_execution_time_in_millis", None),
                })
            executions.sort(key=lambda e: e["start_time"] or "", reverse=True)

            # Pull a row preview from the LocalEmu DuckDB-backed registry
            # for the most recent execution that actually has results.
            preview_rows = []
            preview_columns = []
            preview_exec_id = None
            try:
                from localemu.services.athena.registry import get_registry
                reg = get_registry()
                for ex in executions[:10]:
                    result = reg.get(ex["id"]) if reg else None
                    if result and getattr(result, "rows", None):
                        preview_rows = list(result.rows[:50])
                        preview_columns = [getattr(c, "name", "?") for c in (result.columns or [])]
                        preview_exec_id = ex["id"]
                        break
            except Exception:
                preview_rows = []

            if wg is not None:
                config = getattr(wg, "configuration", None) or {}
                wg_info = {
                    "name": workgroup,
                    "description": getattr(wg, "description", "") or "",
                    "state": getattr(wg, "state", "ENABLED"),
                    "creation_time": str(getattr(wg, "creation_time", "") or ""),
                    "configuration": config,
                }
            else:
                wg_info = {"name": workgroup, "state": "NOT_FOUND"}

            return _json_response({
                "workgroup": wg_info,
                "executions": executions[:50],
                "executions_total": len(executions),
                "preview_exec_id": preview_exec_id,
                "preview_columns": preview_columns,
                "preview_rows": preview_rows,
                "region": region,
            })
        return _json_response({"error": "athena backend not available"}, status=404)


class CloudFormationStackDetailResource:
    """``GET /_localemu/api/resources/cloudformation/<name>`` -- one CFN stack."""

    def on_get(self, request: Request, name: str = ""):
        try:
            from localemu.services.cloudformation.stores import cfn_stores
        except Exception:
            return _json_response({"error": "cloudformation backend not available"}, status=404)

        for _acct, region, store in cfn_stores.iter_stores():
            stack = (getattr(store, "stacks", {}) or {}).get(name)
            if stack is None:
                continue
            events = []
            for ev in (getattr(stack, "events", []) or [])[-100:]:
                events.append({
                    "timestamp": str(getattr(ev, "timestamp", "") or ""),
                    "logical_resource_id": getattr(ev, "logical_resource_id", "") or "",
                    "resource_type": getattr(ev, "resource_type", "") or "",
                    "resource_status": getattr(ev, "resource_status", "") or "",
                    "resource_status_reason": getattr(ev, "resource_status_reason", "") or "",
                })
            resources = []
            for res in (getattr(stack, "resources", []) or []):
                if isinstance(res, dict):
                    resources.append(res)
                else:
                    resources.append({
                        "logical_id": getattr(res, "logical_id", "") or "",
                        "physical_id": getattr(res, "physical_resource_id", "") or "",
                        "type": getattr(res, "resource_type", "") or "",
                        "status": getattr(res, "resource_status", "") or "",
                    })
            return _json_response({
                "name": name,
                "stack_id": getattr(stack, "stack_id", "") or "",
                "status": getattr(stack, "status", "") or "",
                "status_reason": getattr(stack, "status_reason", "") or "",
                "description": getattr(stack, "description", "") or "",
                "creation_time": str(getattr(stack, "creation_time", "") or ""),
                "last_updated_time": str(getattr(stack, "last_updated_time", "") or ""),
                "parameters": getattr(stack, "parameters", {}) or {},
                "outputs": getattr(stack, "outputs", []) or [],
                "tags": getattr(stack, "tags", {}) or {},
                "capabilities": list(getattr(stack, "capabilities", []) or []),
                "notification_arns": list(getattr(stack, "notification_arns", []) or []),
                "events": events,
                "resources": resources,
                "template_body": getattr(stack, "template_body", "") or "",
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class ElbV2LoadBalancerDetailResource:
    """``GET /_localemu/api/resources/elbv2/<name>`` -- one load balancer."""

    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("elbv2"):
            for lb_arn, lb in (getattr(backend, "load_balancers", {}) or {}).items():
                if getattr(lb, "name", "") != name and lb_arn != name:
                    continue
                listeners = []
                for l_arn, l in (getattr(lb, "listeners", {}) or {}).items():
                    listeners.append({
                        "arn": l_arn,
                        "port": getattr(l, "port", None),
                        "protocol": getattr(l, "protocol", "") or "",
                        "ssl_policy": getattr(l, "ssl_policy", "") or "",
                        "default_actions": getattr(l, "default_actions", []) or [],
                        "certificates": getattr(l, "certificates", []) or [],
                    })
                tgs = []
                for tg in (getattr(backend, "target_groups", {}) or {}).values():
                    associated = lb_arn in (getattr(tg, "load_balancer_arns", []) or [])
                    if not associated:
                        continue
                    tgs.append({
                        "arn": getattr(tg, "arn", "") or "",
                        "name": getattr(tg, "name", "") or "",
                        "protocol": getattr(tg, "protocol", "") or "",
                        "port": getattr(tg, "port", None),
                        "vpc_id": getattr(tg, "vpc_id", "") or "",
                        "target_type": getattr(tg, "target_type", "") or "",
                        "health_check_protocol": getattr(tg, "healthcheck_protocol", "") or "",
                        "targets": [
                            {"id": getattr(t, "id", "") or t.get("Id", ""),
                             "port": getattr(t, "port", None) or t.get("Port", None)}
                            for t in (getattr(tg, "targets", {}) or {}).values()
                        ] if isinstance(getattr(tg, "targets", None), dict) else [],
                    })
                state = getattr(lb, "state", None)
                state_str = getattr(state, "code", state) if state is not None else "-"
                return _json_response({
                    "name": getattr(lb, "name", ""),
                    "arn": lb_arn,
                    "dns_name": getattr(lb, "dns_name", "") or "",
                    "type": getattr(lb, "load_balancer_type", "") or "",
                    "scheme": getattr(lb, "scheme", "") or "",
                    "state": str(state_str),
                    "vpc_id": getattr(lb, "vpc_id", "") or "",
                    "subnets": list(getattr(lb, "subnets", []) or []),
                    "availability_zones": getattr(lb, "availability_zones", []) or [],
                    "security_groups": list(getattr(lb, "security_groups", []) or []),
                    "ip_address_type": getattr(lb, "ip_address_type", "") or "",
                    "created_time": str(getattr(lb, "created_time", "") or ""),
                    "listeners": listeners,
                    "target_groups": tgs,
                    "region": region,
                })
        return _json_response({"error": "not found", "name": name}, status=404)


class Route53ZoneDetailResource:
    """``GET /_localemu/api/resources/route53/<zone_id>`` -- one hosted zone."""

    def on_get(self, request: Request, zone_id: str = ""):
        for _acct, _region, backend in _iter_moto_backends("route53"):
            zone = (getattr(backend, "zones", {}) or {}).get(zone_id)
            if zone is None:
                continue
            records = []
            for rs in (getattr(zone, "rrsets", []) or []):
                records.append({
                    "name": getattr(rs, "name", "") or "",
                    "type": getattr(rs, "type_", "") or getattr(rs, "type", "") or "",
                    "ttl": getattr(rs, "ttl", None),
                    "values": list(getattr(rs, "records", []) or []),
                    "alias_target": getattr(rs, "alias_target", None),
                    "set_identifier": getattr(rs, "set_identifier", None),
                })
            return _json_response({
                "id": zone_id,
                "name": getattr(zone, "name", "") or "",
                "comment": getattr(zone, "comment", "") or "",
                "private_zone": bool(getattr(zone, "private_zone", False)),
                "rrset_count": len(records),
                "delegation_set_id": getattr(zone, "delegation_set", None),
                "vpcs": getattr(zone, "vpcs", []) or [],
                "records": records,
                "region": "global",
            })
        return _json_response({"error": "not found", "id": zone_id}, status=404)


class CognitoUserPoolDetailResource:
    """``GET /_localemu/api/resources/cognito-idp/<pool_id>`` -- one user pool."""

    def on_get(self, request: Request, pool_id: str = ""):
        for _acct, region, backend in _iter_moto_backends("cognito-idp"):
            pool = (getattr(backend, "user_pools", {}) or {}).get(pool_id)
            if pool is None:
                continue
            clients = []
            for cid, c in (getattr(pool, "clients", {}) or {}).items():
                clients.append({
                    "id": cid,
                    "name": getattr(c, "client_name", "") or "",
                    "auth_flows": getattr(c, "explicit_auth_flows", []) or [],
                    "callback_urls": getattr(c, "callback_urls", []) or [],
                    "logout_urls": getattr(c, "logout_urls", []) or [],
                    "allowed_oauth_flows": getattr(c, "allowed_oauth_flows", []) or [],
                    "allowed_oauth_scopes": getattr(c, "allowed_oauth_scopes", []) or [],
                })
            users_list = []
            for uname, u in (getattr(pool, "users", {}) or {}).items():
                users_list.append({
                    "username": uname,
                    "status": getattr(u, "status", "") or "",
                    "enabled": bool(getattr(u, "enabled", True)),
                    "attributes": [
                        {"name": a.get("Name"), "value": a.get("Value")}
                        for a in (getattr(u, "attributes", []) or [])
                    ],
                    "created": str(getattr(u, "create_date", "") or ""),
                })
            groups_list = []
            for gname, g in (getattr(pool, "groups", {}) or {}).items():
                groups_list.append({
                    "name": gname,
                    "description": getattr(g, "description", "") or "",
                    "precedence": getattr(g, "precedence", None),
                    "role_arn": getattr(g, "role_arn", "") or "",
                })
            return _json_response({
                "id": pool_id,
                "name": getattr(pool, "name", "") or "",
                "arn": getattr(pool, "arn", "") or "",
                "creation_date": str(getattr(pool, "creation_date", "") or ""),
                "mfa_configuration": getattr(pool, "mfa_config", "") or "OFF",
                "schema_attributes": getattr(pool, "schema_attributes", []) or [],
                "policies": getattr(pool, "policies", {}) or {},
                "lambda_config": getattr(pool, "lambda_config", {}) or {},
                "auto_verified_attributes": getattr(pool, "auto_verified_attributes", []) or [],
                "username_attributes": getattr(pool, "username_attributes", []) or [],
                "clients": clients,
                "users": users_list,
                "groups": groups_list,
                "region": region,
            })
        return _json_response({"error": "not found", "id": pool_id}, status=404)


class EcsClusterDetailResource:
    """``GET /_localemu/api/resources/ecs/<name>`` -- one ECS cluster.

    Surfaces moto cluster fields plus the LocalEmu DockerTaskManager
    info (docker_name, host_ports, exit_code) when tasks were
    launched into real Docker containers.
    """

    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("ecs"):
            cluster = (getattr(backend, "clusters", {}) or {}).get(name)
            if cluster is None:
                continue
            services = []
            for svc_name, svc in (getattr(backend, "services", {}) or {}).items():
                if getattr(svc, "cluster", None) and getattr(svc.cluster, "name", "") != name:
                    continue
                services.append({
                    "name": getattr(svc, "name", svc_name),
                    "arn": getattr(svc, "arn", "") or "",
                    "task_definition": getattr(svc, "task_definition", "") or "",
                    "desired_count": getattr(svc, "desired_count", 0),
                    "running_count": getattr(svc, "running_count", 0),
                    "pending_count": getattr(svc, "pending_count", 0),
                    "launch_type": getattr(svc, "launch_type", "") or "",
                    "status": getattr(svc, "status", "ACTIVE"),
                })
            tasks = []
            for task in (getattr(backend, "tasks", {}).get(cluster.name, {}) or {}).values():
                tasks.append({
                    "arn": getattr(task, "task_arn", "") or "",
                    "task_definition": getattr(task, "task_definition_arn", "") or "",
                    "last_status": getattr(task, "last_status", "") or "",
                    "desired_status": getattr(task, "desired_status", "") or "",
                    "started_by": getattr(task, "started_by", "") or "",
                    "started_at": str(getattr(task, "started_at", "") or ""),
                    "launch_type": getattr(task, "launch_type", "") or "",
                })
            instances = []
            for ci in (getattr(backend, "container_instances", {}).get(cluster.name, {}) or {}).values():
                instances.append({
                    "arn": getattr(ci, "container_instance_arn", "") or "",
                    "ec2_instance_id": getattr(ci, "ec2_instance_id", "") or "",
                    "status": getattr(ci, "status", "ACTIVE"),
                    "agent_connected": bool(getattr(ci, "agent_connected", True)),
                    "running_tasks_count": getattr(ci, "running_tasks_count", 0),
                    "pending_tasks_count": getattr(ci, "pending_tasks_count", 0),
                })
            return _json_response({
                "name": name,
                "arn": getattr(cluster, "arn", "") or "",
                "status": getattr(cluster, "status", "ACTIVE"),
                "tags": getattr(cluster, "tags", {}) or {},
                "settings": getattr(cluster, "settings", []) or [],
                "configuration": getattr(cluster, "configuration", {}) or {},
                "capacity_providers": list(getattr(cluster, "capacity_providers", []) or []),
                "default_capacity_provider_strategy": list(getattr(cluster, "default_capacity_provider_strategy", []) or []),
                "registered_container_instances_count": len(instances),
                "running_tasks_count": sum(t.get("last_status") == "RUNNING" for t in tasks),
                "pending_tasks_count": sum(t.get("last_status") == "PENDING" for t in tasks),
                "active_services_count": len([s for s in services if s.get("status") == "ACTIVE"]),
                "services": services,
                "tasks": tasks,
                "container_instances": instances,
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class EksClusterDetailResource:
    """``GET /_localemu/api/resources/eks/<name>`` -- one EKS cluster.

    Returns moto metadata plus the LocalEmu k3d cluster info
    (k3d_name, api_port, kubeconfig) when EKS_K8S_PROVIDER=k3d.
    The kubeconfig is included verbatim so the user can Copy then
    paste into KUBECONFIG=... to talk to the real running cluster.
    """

    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("eks"):
            cluster = (getattr(backend, "clusters", {}) or {}).get(name)
            if cluster is None:
                continue
            k3d_info = None
            try:
                from localemu.services.plugins import SERVICE_PLUGINS
                eks_plugin = SERVICE_PLUGINS.get("eks")
                provider = getattr(eks_plugin, "instance", None) if eks_plugin else None
                mgr = getattr(provider, "_cluster_manager", None) if provider else None
                if mgr:
                    info = mgr.get_cluster_info(name)
                    if info:
                        k3d_info = {
                            "k3d_name": info.k3d_name,
                            "api_port": info.api_port,
                            "kubeconfig": info.kubeconfig or "",
                        }
            except Exception:
                k3d_info = None
            return _json_response({
                "name": name,
                "arn": getattr(cluster, "arn", "") or "",
                "status": getattr(cluster, "status", "ACTIVE"),
                "version": getattr(cluster, "version", "") or "",
                "endpoint": getattr(cluster, "endpoint", "") or "",
                "role_arn": getattr(cluster, "role_arn", "") or "",
                "resources_vpc_config": getattr(cluster, "resources_vpc_config", {}) or {},
                "logging": getattr(cluster, "logging", {}) or {},
                "identity": getattr(cluster, "identity", {}) or {},
                "platform_version": getattr(cluster, "platform_version", "") or "",
                "tags": getattr(cluster, "tags", {}) or {},
                "k3d": k3d_info,
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class OpenSearchDomainDetailResource:
    """``GET /_localemu/api/resources/opensearch/<name>`` -- one domain."""

    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("opensearch"):
            domain = (getattr(backend, "domains", {}) or {}).get(name)
            if domain is None:
                continue
            engine_obj = getattr(domain, "engine_version", None)
            engine = getattr(engine_obj, "options", "") if engine_obj else ""
            endpoints = getattr(domain, "endpoints", {}) or {}
            endpoint = getattr(domain, "endpoint", None) or endpoints.get("vpc") or endpoints.get("primary") or ""
            container_info = None
            try:
                from localemu.services.plugins import SERVICE_PLUGINS
                os_plugin = SERVICE_PLUGINS.get("opensearch")
                provider = getattr(os_plugin, "instance", None) if os_plugin else None
                mgr = getattr(provider, "_cluster_manager", None) if provider else None
                if mgr:
                    info = mgr.get_cluster_info(name)
                    if info:
                        container_info = {
                            "container_name": getattr(info, "container_name", ""),
                            "host_port": getattr(info, "host_port", None),
                            "image": getattr(info, "image", ""),
                            "dashboards_url": getattr(info, "dashboards_url", "") or (
                                f"http://localhost:{getattr(info, 'host_port', '')}/_dashboards/" if getattr(info, "host_port", None) else ""
                            ),
                        }
            except Exception:
                container_info = None
            return _json_response({
                "name": name,
                "arn": getattr(domain, "arn", "") or "",
                "engine": engine,
                "endpoint": endpoint,
                "endpoints": endpoints,
                "cluster_config": getattr(domain, "cluster_config", {}) or {},
                "ebs_options": getattr(domain, "ebs_options", {}) or {},
                "encryption_at_rest_options": getattr(domain, "encryption_at_rest_options", {}) or {},
                "node_to_node_encryption_options": getattr(domain, "node_to_node_encryption_options", {}) or {},
                "advanced_security_options": getattr(domain, "advanced_security_options", {}) or {},
                "vpc_options": getattr(domain, "vpc_options", {}) or {},
                "snapshot_options": getattr(domain, "snapshot_options", {}) or {},
                "log_publishing_options": getattr(domain, "log_publishing_options", {}) or {},
                "processing": bool(getattr(domain, "processing", False)),
                "tags": getattr(domain, "tags", []) or [],
                "container": container_info,
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class DynamoDBTableDetailResource:
    """``GET /_localemu/api/resources/dynamodb/<name>/detail`` -- one DDB table."""

    def on_get(self, request: Request, name: str = ""):
        for _acct, region, backend in _iter_moto_backends("dynamodb"):
            table = (getattr(backend, "tables", {}) or {}).get(name)
            if table is None:
                continue
            gsi = []
            for g in (getattr(table, "global_indexes", []) or []):
                gsi.append({
                    "name": getattr(g, "name", ""),
                    "schema": getattr(g, "schema", []),
                    "projection": getattr(g, "projection", {}),
                    "throughput": getattr(g, "throughput", {}),
                    "status": getattr(g, "status", "ACTIVE"),
                })
            lsi = []
            for l in (getattr(table, "indexes", []) or []):
                lsi.append({
                    "name": getattr(l, "name", ""),
                    "schema": getattr(l, "schema", []),
                    "projection": getattr(l, "projection", {}),
                })
            streams = None
            if getattr(table, "stream_specification", None):
                streams = {
                    "enabled": getattr(table.stream_specification, "stream_enabled", False),
                    "view_type": getattr(table.stream_specification, "stream_view_type", ""),
                }
            return _json_response({
                "name": name,
                "arn": getattr(table, "table_arn", "") or "",
                "status": getattr(table, "status", "ACTIVE"),
                "item_count": len(getattr(table, "items", []) or []) if hasattr(table, "items") else 0,
                "table_size_bytes": getattr(table, "table_size_bytes", 0),
                "billing_mode": getattr(table, "billing_mode", "PROVISIONED"),
                "throughput": getattr(table, "throughput", {}) or {},
                "key_schema": [
                    {"AttributeName": k, "KeyType": v}
                    for k, v in [
                        (getattr(table, "hash_key_attr", None), "HASH"),
                        (getattr(table, "range_key_attr", None), "RANGE"),
                    ] if k
                ],
                "attribute_definitions": getattr(table, "attr", []) or [],
                "global_secondary_indexes": gsi,
                "local_secondary_indexes": lsi,
                "stream_specification": streams,
                "sse_description": getattr(table, "sse_description", None),
                "ttl": getattr(table, "ttl", {}) or {},
                "deletion_protection": getattr(table, "deletion_protection_enabled", False),
                "tags": getattr(table, "tags", []) or [],
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class CloudWatchLogGroupDetailResource:
    """``GET /_localemu/api/resources/logs/<log_group>/detail`` -- log group config + streams."""

    def on_get(self, request: Request, log_group: str = ""):
        from urllib.parse import unquote
        log_group = unquote(log_group or "")
        if not log_group.startswith("/"):
            log_group = "/" + log_group

        for _acct, region, backend in _iter_moto_backends("logs"):
            group = (getattr(backend, "groups", {}) or {}).get(log_group)
            if group is None:
                continue
            streams = []
            for sname, stream in (getattr(group, "streams", {}) or {}).items():
                streams.append({
                    "name": sname,
                    "arn": getattr(stream, "arn", "") or "",
                    "creation_time": getattr(stream, "creation_time", None),
                    "first_event_timestamp": getattr(stream, "first_event_timestamp", None),
                    "last_event_timestamp": getattr(stream, "last_event_timestamp", None),
                    "last_ingestion_time": getattr(stream, "last_ingestion_time", None),
                    "stored_bytes": getattr(stream, "stored_bytes", 0),
                    "events": len(getattr(stream, "events", []) or []),
                })
            metric_filters = []
            for mf in (getattr(group, "metric_filters", []) or []):
                metric_filters.append({
                    "name": getattr(mf, "filter_name", ""),
                    "pattern": getattr(mf, "filter_pattern", ""),
                    "transformations": getattr(mf, "metric_transformations", []),
                })
            sub_filters = []
            for sf in (getattr(group, "subscription_filters", {}) or {}).values():
                sub_filters.append({
                    "name": getattr(sf, "name", ""),
                    "pattern": getattr(sf, "filter_pattern", ""),
                    "destination": getattr(sf, "destination_arn", ""),
                    "role": getattr(sf, "role_arn", ""),
                })
            return _json_response({
                "name": log_group,
                "arn": getattr(group, "arn", "") or "",
                "retention_in_days": getattr(group, "retention_in_days", None),
                "stored_bytes": getattr(group, "stored_bytes", 0),
                "kms_key_id": getattr(group, "kms_key_id", None),
                "log_class": getattr(group, "log_class", "STANDARD"),
                "creation_time": getattr(group, "creation_time", None),
                "tags": getattr(group, "tags", {}) or {},
                "streams": streams,
                "metric_filters": metric_filters,
                "subscription_filters": sub_filters,
                "region": region,
            })
        return _json_response({"error": "not found", "log_group": log_group}, status=404)


class ApiGatewayV2DetailResource:
    """``GET /_localemu/api/resources/apigatewayv2/<api_id>`` -- one HTTP/WebSocket API."""

    def on_get(self, request: Request, api_id: str = ""):
        for _acct, region, backend in _iter_moto_backends("apigatewayv2"):
            api = (getattr(backend, "apis", {}) or {}).get(api_id)
            if api is None:
                continue

            routes = []
            for rid, r in (getattr(api, "routes", {}) or {}).items():
                routes.append({
                    "id": rid,
                    "route_key": getattr(r, "route_key", "") or "",
                    "target": getattr(r, "target", "") or "",
                    "authorization_type": getattr(r, "authorization_type", "") or "",
                    "authorizer_id": getattr(r, "authorizer_id", "") or "",
                    "api_key_required": bool(getattr(r, "api_key_required", False)),
                })
            integrations = []
            for iid, ig in (getattr(api, "integrations", {}) or {}).items():
                integrations.append({
                    "id": iid,
                    "type": getattr(ig, "integration_type", "") or "",
                    "uri": getattr(ig, "integration_uri", "") or "",
                    "method": getattr(ig, "integration_method", "") or "",
                    "payload_format_version": getattr(ig, "payload_format_version", "") or "",
                    "connection_type": getattr(ig, "connection_type", "") or "",
                    "timeout_ms": getattr(ig, "timeout_in_millis", None),
                })
            stages = []
            for sname, s in (getattr(api, "stages", {}) or {}).items():
                stages.append({
                    "name": sname,
                    "auto_deploy": bool(getattr(s, "auto_deploy", False)),
                    "deployment_id": getattr(s, "deployment_id", "") or "",
                    "default_route_settings": getattr(s, "default_route_settings", {}) or {},
                    "description": getattr(s, "description", "") or "",
                    "stage_variables": getattr(s, "stage_variables", {}) or {},
                })
            authorizers = []
            for aid, a in (getattr(api, "authorizers", {}) or {}).items():
                authorizers.append({
                    "id": aid,
                    "name": getattr(a, "name", "") or "",
                    "type": getattr(a, "authorizer_type", "") or "",
                    "identity_source": getattr(a, "identity_source", []) or [],
                    "authorizer_uri": getattr(a, "authorizer_uri", "") or "",
                    "jwt_configuration": getattr(a, "jwt_configuration", {}) or {},
                })

            return _json_response({
                "api_id": api_id,
                "name": getattr(api, "name", "") or "",
                "protocol_type": getattr(api, "protocol_type", "") or "",
                "api_endpoint": getattr(api, "api_endpoint", "") or "",
                "arn": getattr(api, "arn", "") or "",
                "description": getattr(api, "description", "") or "",
                "version": getattr(api, "version", "") or "",
                "route_selection_expression": getattr(api, "route_selection_expression", "") or "",
                "api_key_selection_expression": getattr(api, "api_key_selection_expression", "") or "",
                "disable_execute_api_endpoint": bool(getattr(api, "disable_execute_api_endpoint", False)),
                "cors_configuration": getattr(api, "cors_configuration", {}) or {},
                "tags": getattr(api, "tags", {}) or {},
                "routes": routes,
                "integrations": integrations,
                "stages": stages,
                "authorizers": authorizers,
                "region": region,
            })
        return _json_response({"error": "not found", "api_id": api_id}, status=404)


class SqsQueueDetailResource:
    """``GET /_localemu/api/resources/sqs/<queue>/detail`` -- queue config + counts.

    Distinct from SqsMessagesResource (which peeks at messages); this
    endpoint returns the queue configuration, attributes, redrive
    policy, encryption settings, access policy, and live count
    sparkline data.
    """

    def on_get(self, request: Request, queue: str = ""):
        from urllib.parse import unquote
        from localemu.services.sqs.models import sqs_stores

        queue = unquote(queue or "")
        for _account_id, region, store in sqs_stores.iter_stores():
            q = (store.queues or {}).get(queue)
            if q is None:
                continue
            attrs = dict(getattr(q, "attributes", {}) or {})
            import json as _json
            policy_raw = attrs.get("Policy", "") or ""
            try:
                policy = _json.loads(policy_raw) if policy_raw else None
            except Exception:
                policy = policy_raw
            redrive_raw = attrs.get("RedrivePolicy", "") or ""
            try:
                redrive = _json.loads(redrive_raw) if redrive_raw else None
            except Exception:
                redrive = redrive_raw
            return _json_response({
                "name": queue,
                "url": getattr(q, "url", "") or "",
                "arn": attrs.get("QueueArn", "") or "",
                "type": "FIFO" if (getattr(q, "fifo_queue", False) or queue.endswith(".fifo")) else "Standard",
                "region": region,
                "visibility_timeout": int(attrs.get("VisibilityTimeout", 30) or 30),
                "delay_seconds": int(attrs.get("DelaySeconds", 0) or 0),
                "message_retention_period": int(attrs.get("MessageRetentionPeriod", 345600) or 345600),
                "maximum_message_size": int(attrs.get("MaximumMessageSize", 262144) or 262144),
                "receive_message_wait_time_seconds": int(attrs.get("ReceiveMessageWaitTimeSeconds", 0) or 0),
                "kms_master_key_id": attrs.get("KmsMasterKeyId", "") or "",
                "kms_data_key_reuse_period_seconds": attrs.get("KmsDataKeyReusePeriodSeconds", None),
                "sqs_managed_sse": attrs.get("SqsManagedSseEnabled", "false"),
                "content_based_deduplication": attrs.get("ContentBasedDeduplication", "false"),
                "deduplication_scope": attrs.get("DeduplicationScope", ""),
                "fifo_throughput_limit": attrs.get("FifoThroughputLimit", ""),
                "approximate_number_of_messages": int(getattr(q, "approximate_number_of_messages", 0) or 0),
                "approximate_number_of_messages_delayed": int(getattr(q, "approximate_number_of_messages_delayed", 0) or 0),
                "approximate_number_of_messages_not_visible": int(getattr(q, "approximate_number_of_messages_not_visible", 0) or 0),
                "tags": getattr(q, "tags", {}) or {},
                "policy": policy,
                "redrive_policy": redrive,
                "created_timestamp": attrs.get("CreatedTimestamp", "") or "",
                "last_modified_timestamp": attrs.get("LastModifiedTimestamp", "") or "",
            })
        return _json_response({"error": "not found", "name": queue}, status=404)


class Ec2InstanceDetailResource:
    """``GET /_localemu/api/resources/ec2/<instance_id>`` -- one EC2 instance.

    Surfaces the moto instance metadata PLUS the LocalEmu Docker
    container facts (container name, SSH host port, IMDS host port,
    console output) that uniquely set LocalEmu apart from a pure
    metadata emulator.
    """

    def on_get(self, request: Request, instance_id: str = ""):
        from urllib.parse import unquote
        instance_id = unquote(instance_id or "")

        for _acct, region, backend in _iter_moto_backends("ec2"):
            for _res_id, reservation in (getattr(backend, "reservations", {}) or {}).items():
                for inst in reservation.instances:
                    if getattr(inst, "id", None) != instance_id:
                        continue
                    sgs = []
                    for sg in (getattr(inst, "security_groups", []) or []):
                        sgs.append({
                            "id": getattr(sg, "id", "") or getattr(sg, "group_id", ""),
                            "name": getattr(sg, "name", "") or getattr(sg, "group_name", ""),
                        })
                    block_devs = []
                    try:
                        for name, bd in (getattr(inst, "block_device_mapping", {}) or {}).items():
                            block_devs.append({
                                "device_name": name,
                                "volume_id": getattr(bd, "volume_id", ""),
                                "status": getattr(bd, "status", ""),
                                "delete_on_termination": getattr(bd, "delete_on_termination", False),
                            })
                    except Exception:
                        pass

                    container_info = None
                    console_output = ""
                    try:
                        # The vm_manager lives on the EC2 provider
                        # singleton when EC2_VM_MANAGER=docker (default).
                        from localemu.services.plugins import SERVICE_PLUGINS
                        ec2_plugin = SERVICE_PLUGINS.get("ec2")
                        provider = getattr(ec2_plugin, "instance", None) if ec2_plugin else None
                        mgr = getattr(provider, "_vm_manager", None) if provider else None
                        if mgr:
                            info = mgr.get_instance_info(instance_id)
                            if info:
                                container_info = {
                                    "container_name": info.container_name,
                                    "image": info.image,
                                    "ssh_port": info.ssh_port,
                                    "imds_port": info.imds_port,
                                    "private_ip": info.private_ip,
                                    "key_name": info.key_name,
                                    "vpc_id": info.vpc_id,
                                }
                                console_output = mgr.get_console_output(instance_id) or ""
                    except Exception:
                        LOG.debug("vm_manager not available for %s", instance_id, exc_info=True)
                        container_info = None

                    return _json_response({
                        "instance_id": instance_id,
                        "state": inst._state.name if hasattr(inst, "_state") else "unknown",
                        "instance_type": getattr(inst, "instance_type", ""),
                        "image_id": getattr(inst, "image_id", "") or "",
                        "private_ip": getattr(inst, "private_ip_address", "") or "",
                        "public_ip": getattr(inst, "public_ip", "") or "",
                        "private_dns": getattr(inst, "private_dns", "") or "",
                        "public_dns": getattr(inst, "public_dns", "") or "",
                        "availability_zone": getattr(inst, "placement", "") or "",
                        "subnet_id": getattr(inst, "subnet_id", "") or "",
                        "vpc_id": getattr(inst, "vpc_id", "") or "",
                        "key_name": getattr(inst, "key_name", "") or "",
                        "iam_instance_profile": getattr(inst, "iam_instance_profile", None),
                        "launch_time": str(getattr(inst, "launch_time", "") or ""),
                        "monitoring": getattr(inst, "monitoring", None),
                        "ebs_optimized": getattr(inst, "ebs_optimized", False),
                        "tenancy": getattr(inst, "placement_tenancy", None),
                        "security_groups": sgs,
                        "block_devices": block_devs,
                        "tags": [
                            {"Key": k, "Value": v}
                            for k, v in (getattr(inst, "tags", {}) or {}).items()
                        ] if isinstance(getattr(inst, "tags", None), dict) else list(getattr(inst, "tags", []) or []),
                        "user_data": getattr(inst, "user_data", "") or "",
                        "container": container_info,
                        "console_output": console_output,
                        "region": region,
                    })
        return _json_response({"error": "not found", "instance_id": instance_id}, status=404)


class LambdaFunctionDetailResource:
    """``GET /_localemu/api/resources/lambda/<name>`` -- one Lambda function.

    Surfaces all the config the existing list page hides: env, layers,
    aliases, versions, URL configs, permissions, ESM bindings, VPC,
    SnapStart, tracing, logging, ephemeral storage.
    """

    def on_get(self, request: Request, name: str = ""):
        from urllib.parse import unquote
        from localemu.services.lambda_.invocation.models import lambda_stores

        name = unquote(name or "")
        for _acct, region, store in lambda_stores.iter_stores():
            fn = (store.functions or {}).get(name)
            if fn is None:
                continue
            latest = fn.latest() if hasattr(fn, "latest") else None
            cfg = latest.config if latest else None

            def _layers():
                if not cfg:
                    return []
                out = []
                for layer in (cfg.layers or []):
                    out.append({
                        "arn": getattr(layer, "layer_version_arn", "") or "",
                        "name": getattr(layer, "name", "") or "",
                        "version": getattr(layer, "version", 1),
                    })
                return out

            def _env():
                if not cfg or not cfg.environment:
                    return {}
                return dict(cfg.environment)

            url_configs = []
            for k, uc in (getattr(fn, "function_url_configs", {}) or {}).items():
                url_configs.append({
                    "qualifier": k,
                    "url": getattr(uc, "url", ""),
                    "auth_type": getattr(uc, "auth_type", "AWS_IAM"),
                })

            aliases = []
            for alias_name, alias in (getattr(fn, "aliases", {}) or {}).items():
                aliases.append({
                    "name": alias_name,
                    "version": getattr(alias, "function_version", ""),
                    "description": getattr(alias, "description", "") or "",
                })

            versions = list((getattr(fn, "versions", {}) or {}).keys())

            permissions = []
            for k, p in (getattr(fn, "permissions", {}) or {}).items():
                permissions.append({
                    "qualifier": k,
                    "policy": getattr(p, "policy", ""),
                })

            esms = []
            for esm_uuid, esm in (getattr(store, "event_source_mappings", {}) or {}).items():
                if getattr(esm, "function_name", None) == name or getattr(esm, "function_arn", "").endswith(":" + name):
                    esms.append({
                        "uuid": esm_uuid,
                        "source": getattr(esm, "event_source_arn", "") or "",
                        "state": getattr(esm, "state", "") or "Enabled",
                        "batch_size": getattr(esm, "batch_size", "-"),
                    })

            state_obj = cfg.state if cfg else None
            state_str = "-"
            if state_obj is not None:
                inner = getattr(state_obj, "state", None)
                state_str = str(getattr(inner, "value", inner)) if inner else str(state_obj)

            return _json_response({
                "name": name,
                "function_arn": getattr(cfg, "function_arn", "") if cfg else "",
                "runtime": (cfg.runtime if cfg else "") or "-",
                "handler": (cfg.handler if cfg else "") or "-",
                "memory_size": cfg.memory_size if cfg else 0,
                "timeout": cfg.timeout if cfg else 0,
                "role": (cfg.role if cfg else "") or "",
                "package_type": str(cfg.package_type) if cfg else "Zip",
                "architectures": [str(a) for a in (cfg.architectures or [])] if cfg else [],
                "ephemeral_storage": int(getattr(cfg, "ephemeral_storage", 0) or 0) if cfg else 0,
                "tracing_config_mode": str(getattr(cfg, "tracing_config_mode", "PassThrough")) if cfg else "-",
                "snap_start": getattr(cfg, "snap_start", None).__dict__ if (cfg and getattr(cfg, "snap_start", None)) else None,
                "environment": _env(),
                "layers": _layers(),
                "dead_letter_arn": getattr(cfg, "dead_letter_arn", None) if cfg else None,
                "vpc_config": getattr(cfg, "vpc_config", None).__dict__ if (cfg and getattr(cfg, "vpc_config", None)) else None,
                "last_modified": getattr(cfg, "last_modified", "") if cfg else "",
                "state": state_str,
                "revision_id": getattr(cfg, "revision_id", "") if cfg else "",
                "url_configs": url_configs,
                "aliases": aliases,
                "versions": versions,
                "permissions": permissions,
                "event_source_mappings": esms,
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class SecretsManagerSecretDetailResource:
    """``GET /_localemu/api/resources/secretsmanager/<name>`` -- one secret.

    Returns metadata, versions (with stages), rotation config and
    replication regions. Secret value is NOT included by default; the
    UI exposes a separate Reveal action via the existing
    rotate-secret/get-secret-value endpoints when the user asks.
    """

    def on_get(self, request: Request, name: str = ""):
        from urllib.parse import unquote
        from localemu.services.cloudtrail.recording_hook import suppress_recording
        from localemu.aws.connect import connect_to
        from localemu.constants import DEFAULT_AWS_ACCOUNT_ID

        name = unquote(name or "")
        for _acct, region, backend in _iter_moto_backends("secretsmanager"):
            secret = (getattr(backend, "secrets", {}) or {}).get(name)
            if secret is None:
                continue
            versions = []
            for vid, v in (getattr(secret, "versions", {}) or {}).items():
                versions.append({
                    "version_id": vid,
                    "stages": list(v.get("version_stages", [])),
                    "created": str(v.get("createdate", "") or ""),
                })
            # Pull policy via boto3 (suppress recording so the dashboard
            # does not pollute CloudTrail).
            policy_text = ""
            try:
                with suppress_recording():
                    client = connect_to(aws_access_key_id=DEFAULT_AWS_ACCOUNT_ID, region_name=region).secretsmanager
                    policy_text = (client.get_resource_policy(SecretId=name).get("ResourcePolicy", "")) or ""
            except Exception:
                policy_text = ""
            try:
                import json as _json
                policy = _json.loads(policy_text) if policy_text else {}
            except Exception:
                policy = policy_text
            return _json_response({
                "name": getattr(secret, "name", name),
                "arn": getattr(secret, "arn", "") or "",
                "description": getattr(secret, "description", "") or "",
                "kms_key_id": getattr(secret, "kms_key_id", None),
                "rotation_enabled": bool(getattr(secret, "rotation_enabled", False)),
                "rotation_lambda_arn": getattr(secret, "rotation_lambda_arn", "") or "",
                "rotation_rules": getattr(secret, "rotation_rules", None),
                "last_changed_date": str(getattr(secret, "last_changed_date", "") or ""),
                "last_rotated_date": str(getattr(secret, "last_rotated_date", "") or ""),
                "next_rotation_date": str(getattr(secret, "next_rotation_date", "") or ""),
                "deletion_date": str(getattr(secret, "deleted_date", "") or ""),
                "versions": versions,
                "tags": getattr(secret, "tags", []) or [],
                "resource_policy": policy,
                "replicas": [
                    {
                        "region": r.region,
                        "status": getattr(r, "status", "InSync"),
                        "kms_key_id": getattr(r, "kms_key_id", None),
                    }
                    for r in (getattr(secret, "replicas", []) or [])
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "name": name}, status=404)


class StepFunctionsStateMachineDetailResource:
    """``GET /_localemu/api/resources/stepfunctions/<sm_arn>`` -- one state machine.

    Returns the parsed ASL definition, executions list, and key
    metadata so the drill can render the AWS-Console-equivalent page.
    """

    def on_get(self, request: Request, sm_arn: str = ""):
        import json as _json
        from urllib.parse import unquote
        from localemu.services.stepfunctions.backend.models import sfn_stores

        sm_arn = unquote(sm_arn or "")
        for _acct, region, store in sfn_stores.iter_stores():
            sm = store.state_machines.get(sm_arn)
            if sm is None:
                continue
            try:
                definition = _json.loads(sm.definition) if isinstance(sm.definition, str) else sm.definition
            except Exception:
                definition = sm.definition
            executions = []
            for exec_arn, ex in (store.executions or {}).items():
                if getattr(ex, "state_machine_arn", None) != sm_arn:
                    continue
                executions.append({
                    "name": getattr(ex, "name", ""),
                    "arn": exec_arn,
                    "status": str(getattr(ex, "exec_status", "RUNNING") or "RUNNING"),
                    "start_date": str(getattr(ex, "start_date", "") or ""),
                    "stop_date": str(getattr(ex, "stop_date", "") or ""),
                    "input": getattr(ex, "input_data", None),
                    "output": getattr(ex, "output", None),
                    "error": getattr(ex, "error", None),
                    "cause": getattr(ex, "cause", None),
                })
            # Sort newest-first
            executions.sort(key=lambda e: e["start_date"] or "", reverse=True)
            return _json_response({
                "name": sm.name,
                "arn": sm.arn,
                "type": str(getattr(sm, "sm_type", "STANDARD") or "STANDARD"),
                "role_arn": getattr(sm, "role_arn", "") or "",
                "create_date": str(getattr(sm, "create_date", "") or ""),
                "definition": definition,
                "revision_id": getattr(sm, "revision_id", None),
                "tags": getattr(sm, "tags", []) or [],
                "region": region,
                "executions": executions[:50],
                "executions_total": len(executions),
            })
        return _json_response({"error": "not found", "arn": sm_arn}, status=404)


class IamEntityDetailResource:
    """``GET /_localemu/api/resources/iam/<kind>/<key>`` -- IAM entity detail.

    Kind is one of: roles, users, groups, policies, instance-profiles.
    Returns the full record including attached + inline policy
    documents, trust relationship, tags, last activity and (for roles
    and users) CloudTrail-derived Access Advisor data.
    """

    def on_get(self, request: Request, kind: str = "", key: str = ""):
        import json as _json
        from urllib.parse import unquote
        kind = (kind or "").lower()
        key = unquote(key or "")

        for _acct, _region, backend in _iter_moto_backends("iam"):
            if kind == "roles":
                role = (backend.roles or {}).get(key) or next(
                    (r for r in (backend.roles or {}).values() if getattr(r, "name", None) == key), None
                )
                if role is None:
                    continue
                inline = {}
                for pname, doc in (getattr(role, "policies", {}) or {}).items():
                    try:
                        inline[pname] = _json.loads(doc) if isinstance(doc, str) else doc
                    except Exception:
                        inline[pname] = doc
                managed = []
                for pname, mp in (getattr(role, "managed_policies", {}) or {}).items():
                    versions = getattr(mp, "versions", None) or []
                    doc = None
                    for v in versions:
                        if getattr(v, "is_default_version", False):
                            doc = getattr(v, "document", None)
                            break
                    if doc is None and versions:
                        doc = getattr(versions[0], "document", None)
                    try:
                        parsed = _json.loads(doc) if isinstance(doc, str) else doc
                    except Exception:
                        parsed = doc
                    managed.append({
                        "name": pname,
                        "arn": getattr(mp, "arn", "") or "",
                        "document": parsed,
                        "default_version_id": getattr(mp, "default_version_id", "v1"),
                    })
                trust_raw = getattr(role, "assume_role_policy_document", "") or ""
                try:
                    trust = _json.loads(trust_raw) if isinstance(trust_raw, str) else trust_raw
                except Exception:
                    trust = trust_raw
                last_used = getattr(role, "last_used", None)
                return _json_response({
                    "kind": "role",
                    "name": role.name,
                    "arn": role.arn,
                    "id": getattr(role, "id", ""),
                    "path": getattr(role, "path", "/"),
                    "description": getattr(role, "description", "") or "",
                    "max_session_duration": getattr(role, "max_session_duration", 3600),
                    "permissions_boundary": getattr(role, "permissions_boundary", None),
                    "trust_policy": trust,
                    "inline_policies": inline,
                    "managed_policies": managed,
                    "tags": list(getattr(role, "tags", {}).values()) if isinstance(getattr(role, "tags", None), dict) else list(getattr(role, "tags", []) or []),
                    "last_used": str(last_used) if last_used else None,
                    "create_date": str(getattr(role, "create_date", "") or ""),
                })

            if kind == "users":
                user = (backend.users or {}).get(key) or next(
                    (u for u in (backend.users or {}).values() if getattr(u, "name", None) == key), None
                )
                if user is None:
                    continue
                inline = {}
                for pname, doc in (getattr(user, "policies", {}) or {}).items():
                    try:
                        inline[pname] = _json.loads(doc) if isinstance(doc, str) else doc
                    except Exception:
                        inline[pname] = doc
                managed = []
                for pname, mp in (getattr(user, "managed_policies", {}) or {}).items():
                    managed.append({
                        "name": pname,
                        "arn": getattr(mp, "arn", "") or "",
                    })
                access_keys = []
                for ak in (getattr(user, "access_keys", []) or []):
                    last_used_meta = getattr(ak, "last_used", None) or {}
                    access_keys.append({
                        "access_key_id": getattr(ak, "access_key_id", ""),
                        "status": getattr(ak, "status", "Active"),
                        "created": str(getattr(ak, "create_date", "") or ""),
                        "last_used": getattr(last_used_meta, "_timestamp", None) and str(last_used_meta._timestamp) or "-",
                        "last_used_service": getattr(last_used_meta, "service", None) or "-",
                        "last_used_region": getattr(last_used_meta, "region", None) or "-",
                    })
                groups = []
                for gname in (getattr(user, "group_list", []) or []):
                    groups.append(gname)
                mfa = []
                for md in (getattr(user, "mfa_devices", []) or []):
                    mfa.append({
                        "serial_number": getattr(md, "serial_number", ""),
                        "enable_date": str(getattr(md, "enable_date", "") or ""),
                    })
                return _json_response({
                    "kind": "user",
                    "name": user.name,
                    "arn": user.arn,
                    "id": getattr(user, "id", ""),
                    "path": getattr(user, "path", "/"),
                    "create_date": str(getattr(user, "create_date", "") or ""),
                    "inline_policies": inline,
                    "managed_policies": managed,
                    "access_keys": access_keys,
                    "groups": groups,
                    "mfa_devices": mfa,
                    "permissions_boundary": getattr(user, "permissions_boundary", None),
                    "tags": list(getattr(user, "tags", {}).values()) if isinstance(getattr(user, "tags", None), dict) else list(getattr(user, "tags", []) or []),
                })

            if kind == "groups":
                group = (getattr(backend, "groups", {}) or {}).get(key) or next(
                    (g for g in (getattr(backend, "groups", {}) or {}).values() if getattr(g, "name", None) == key), None
                )
                if group is None:
                    continue
                inline = {}
                for pname, doc in (getattr(group, "policies", {}) or {}).items():
                    try:
                        inline[pname] = _json.loads(doc) if isinstance(doc, str) else doc
                    except Exception:
                        inline[pname] = doc
                managed = []
                for pname, mp in (getattr(group, "managed_policies", {}) or {}).items():
                    managed.append({"name": pname, "arn": getattr(mp, "arn", "") or ""})
                users = []
                for u in (backend.users or {}).values():
                    if group.name in (getattr(u, "group_list", []) or []):
                        users.append(getattr(u, "name", ""))
                return _json_response({
                    "kind": "group",
                    "name": group.name,
                    "arn": getattr(group, "arn", "") or "",
                    "path": getattr(group, "path", "/"),
                    "create_date": str(getattr(group, "create_date", "") or ""),
                    "users": users,
                    "inline_policies": inline,
                    "managed_policies": managed,
                })

            if kind == "policies":
                # Customer-managed only; AWS-managed are 1473 policies.
                policy = None
                for p in (getattr(backend, "managed_policies", {}) or {}).values():
                    if getattr(p, "name", None) == key or getattr(p, "arn", None) == key:
                        policy = p
                        break
                if policy is None:
                    continue
                versions = []
                for v in (getattr(policy, "versions", None) or []):
                    doc = getattr(v, "document", None)
                    try:
                        parsed = _json.loads(doc) if isinstance(doc, str) else doc
                    except Exception:
                        parsed = doc
                    versions.append({
                        "version_id": getattr(v, "version_id", ""),
                        "is_default": getattr(v, "is_default_version", False),
                        "create_date": str(getattr(v, "create_date", "") or ""),
                        "document": parsed,
                    })
                return _json_response({
                    "kind": "policy",
                    "name": policy.name,
                    "arn": getattr(policy, "arn", "") or "",
                    "description": getattr(policy, "description", "") or "",
                    "default_version_id": getattr(policy, "default_version_id", "v1"),
                    "attachment_count": getattr(policy, "attachment_count", 0),
                    "create_date": str(getattr(policy, "create_date", "") or ""),
                    "update_date": str(getattr(policy, "update_date", "") or ""),
                    "versions": versions,
                })

        return _json_response({"error": "not found", "kind": kind, "key": key}, status=404)


class KmsKeyDetailResource:
    """``GET /_localemu/api/resources/kms/<key_id>`` -- one KMS key full detail."""

    def on_get(self, request: Request, key_id: str = ""):
        from localemu.services.kms.models import kms_stores

        for _acct, region, store in kms_stores.iter_stores():
            key = store.keys.get(key_id)
            if key is None:
                continue
            metadata = dict(getattr(key, "metadata", None) or {})
            policy_raw = getattr(key, "policy", "") or ""
            try:
                import json as _json
                policy = _json.loads(policy_raw) if policy_raw else {}
            except Exception:
                policy = policy_raw
            # Find aliases that target this key.
            aliases = []
            for alias_name, alias in (store.aliases or {}).items():
                target = getattr(alias, "target_key_id", None) or getattr(alias, "key_id", None)
                if target == key_id:
                    aliases.append(alias_name)
            # Grants on this key.
            grants = []
            for grant_id, grant in (store.grants or {}).items():
                if getattr(grant, "key_id", None) == key_id:
                    grants.append({
                        "grant_id": grant_id,
                        "grantee_principal": getattr(grant, "grantee_principal", "-"),
                        "retiring_principal": getattr(grant, "retiring_principal", "-"),
                        "operations": list(getattr(grant, "operations", []) or []),
                        "name": getattr(grant, "name", "-"),
                        "constraints": getattr(grant, "constraints", {}) or {},
                    })
            return _json_response({
                "key_id": key_id,
                "region": region,
                "metadata": metadata,
                "aliases": aliases,
                "policy": policy,
                "grants": grants,
                "rotation_enabled": bool(getattr(key, "is_key_rotation_enabled", False)),
                "rotation_period_in_days": getattr(key, "rotation_period_in_days", 365),
                "next_rotation_date": str(getattr(key, "next_rotation_date", "") or ""),
            })
        return _json_response({"error": "not found", "key_id": key_id}, status=404)


class LogEventsResource:
    """``GET /_localemu/api/resources/logs/<log_group>`` — log events for a group."""

    def on_get(self, request: Request, log_group: str = ""):
        LOG.debug("Dashboard API request: GET /resources/logs/%s from %s", log_group, request.remote_addr)
        try:
            events = self._get_log_events(log_group)
        except Exception:
            LOG.debug("error fetching log events for %s", log_group, exc_info=True)
            return _json_response({"log_group": log_group, "events": None, "error": "backend error"})
        return _json_response({"log_group": log_group, "events": events, "error": None})

    @staticmethod
    def _get_log_events(log_group_name: str) -> list[dict]:
        events: list[dict] = []
        for _acct, _region, backend in _iter_moto_backends("logs"):
            # Log group names start with / (e.g. /aws/lambda/func) but the URL
            # path captures it without the leading slash.  Try both forms.
            group = backend.groups.get(log_group_name) or backend.groups.get(f"/{log_group_name}")
            if not group:
                continue

            streams = group.streams if hasattr(group, "streams") else {}
            for stream_name, stream in streams.items():
                stored_events = getattr(stream, "events", [])
                for evt in stored_events[-50:]:
                    ts = getattr(evt, "timestamp", None)
                    msg = getattr(evt, "message", "")
                    events.append(
                        {
                            "timestamp": ts,
                            "message": msg,
                            "stream": stream_name,
                        }
                    )

        # Sort by timestamp descending, most recent first
        events.sort(key=lambda e: e.get("timestamp") or 0, reverse=True)
        return events[:200]


def _s3_object_row(key: str, obj, version_id):
    """Build the per-row dict the dashboard expects for one S3 object.

    ``obj`` is an S3Object model instance. ``version_id`` is the bucket's
    version id when listing a versioned bucket, or ``None`` for a flat
    bucket. The version id is appended to the displayed key as
    ``"<key>@<version>"`` so each row stays uniquely identifiable.
    """
    last_mod = getattr(obj, "last_modified", None)
    display_key = key if version_id is None or version_id == "null" else f"{key}@{version_id}"
    return {
        "key": display_key,
        "size": getattr(obj, "size", 0) or 0,
        "last_modified": last_mod.isoformat() if last_mod else "",
    }


class S3ObjectsResource:
    """``GET /_localemu/api/resources/s3/<bucket>`` — objects in a specific S3 bucket."""

    def on_get(self, request: Request, bucket: str = ""):
        LOG.debug("Dashboard API request: GET /resources/s3/%s from %s", bucket, request.remote_addr)
        offset = _safe_int(request.args.get("offset", "0"), 0, minimum=0, maximum=100000)
        limit = _safe_int(request.args.get("limit", "200"), 200, minimum=1, maximum=1000)
        try:
            objects = self._list_objects(bucket)
        except Exception:
            LOG.debug("error listing S3 objects for %s", bucket, exc_info=True)
            return _json_response({"bucket": bucket, "objects": None, "error": "backend error"})
        total = len(objects)
        objects = objects[offset:offset + limit]
        return _json_response({"bucket": bucket, "objects": objects, "error": None, "total": total})

    @staticmethod
    def _list_objects(bucket_name: str) -> list[dict]:
        from localemu.services.s3.models import s3_stores

        for _account_id, _region, store in s3_stores.iter_stores():
            bucket = store.buckets.get(bucket_name)
            if bucket and hasattr(bucket, "objects"):
                objects: list[dict] = []
                for key, raw in bucket.objects._store.items():
                    # Versioned buckets store dict[VersionId, S3Object]
                    # under each key. Unversioned buckets store the object
                    # directly. Normalise to one row per version with the
                    # version id appended to the displayed key so size /
                    # timestamps are meaningful in both layouts.
                    if isinstance(raw, dict):
                        for version_id, obj in raw.items():
                            objects.append(_s3_object_row(str(key), obj, version_id))
                    else:
                        objects.append(_s3_object_row(str(key), raw, None))
                return objects
        return []


class DynamoDBItemsResource:
    """``GET /_localemu/api/resources/dynamodb/<table>`` — items in a DynamoDB table."""

    def on_get(self, request: Request, table: str = ""):
        LOG.debug("Dashboard API request: GET /resources/dynamodb/%s from %s", table, request.remote_addr)
        limit = _safe_int(request.args.get("limit", "100"), 100, minimum=1, maximum=1000)
        try:
            items = self._list_items(table, max_items=limit)
        except Exception:
            LOG.debug("error listing DynamoDB items for %s", table, exc_info=True)
            return _json_response({"table": table, "items": None, "error": "backend error"})
        return _json_response({"table": table, "items": items, "error": None, "total": len(items)})

    @staticmethod
    def _list_items(table_name: str, max_items: int = 100) -> list[dict]:
        # Find the table across all accounts/regions
        table = None
        for _acct, _region, backend in _iter_moto_backends("dynamodb"):
            table = backend.tables.get(table_name)
            if table:
                break
        if not table:
            return []

        result: list[dict] = []
        count = 0
        # Moto stores items in table.item_count or via all_items().
        # table.all_items() returns a generator of DynamoItem objects.
        try:
            all_items = table.all_items()
        except AttributeError:
            return []

        for item in all_items:
            if count >= max_items:
                break
            # DynamoItem has .to_json() or .attrs which is a dict of DynamoType
            if hasattr(item, "to_json"):
                result.append(item.to_json().get("Attributes", item.to_json()))
            elif hasattr(item, "attrs"):
                row = {}
                for attr_name, attr_val in item.attrs.items():
                    row[attr_name] = attr_val.to_json() if hasattr(attr_val, "to_json") else str(attr_val)
                result.append(row)
            else:
                result.append({"_raw": str(item)})
            count += 1
        return result


class SqsMessagesResource:
    """``GET /_localemu/api/resources/sqs/<queue>`` -- non-destructive message peek.

    Returns up to ``limit`` messages currently visible on the queue without
    deleting them. Uses ``ReceiveMessage`` with ``VisibilityTimeout=0`` so
    the peek does not hide messages from real consumers.
    """

    def on_get(self, request: Request, queue: str = ""):
        LOG.debug("Dashboard API request: GET /resources/sqs/%s from %s", queue, request.remote_addr)
        limit = _safe_int(request.args.get("limit", "10"), 10, minimum=1, maximum=20)
        try:
            messages = self._peek_messages(queue, limit)
        except Exception:
            LOG.debug("error peeking SQS queue %s", queue, exc_info=True)
            return _json_response({"queue": queue, "messages": None, "error": "backend error"})
        return _json_response({"queue": queue, "messages": messages, "error": None, "total": len(messages)})

    @staticmethod
    def _peek_messages(queue_name: str, limit: int) -> list[dict]:
        from localemu.aws.connect import connect_to
        from localemu.constants import DEFAULT_AWS_ACCOUNT_ID
        from localemu.services.cloudtrail.recording_hook import suppress_recording

        # Find the queue across all regions to learn the right URL.
        from localemu.services.sqs.models import sqs_stores
        target_region = None
        for _account_id, region, store in sqs_stores.iter_stores():
            if queue_name in store.queues:
                target_region = region
                break
        if target_region is None:
            return []

        # Skip CloudTrail recording on the dashboard's own peek call
        # so the panel does not pollute the user's audit trail.
        with suppress_recording():
            client = connect_to(
                aws_access_key_id=DEFAULT_AWS_ACCOUNT_ID,
                region_name=target_region,
            ).sqs
            url = client.get_queue_url(QueueName=queue_name)["QueueUrl"]
            resp = client.receive_message(
                QueueUrl=url,
                MaxNumberOfMessages=min(limit, 10),
                VisibilityTimeout=0,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
                WaitTimeSeconds=0,
            )
        out: list[dict] = []
        for m in resp.get("Messages", []) or []:
            # Return the full receipt handle. DeleteMessage requires the
            # exact handle the broker issued; truncating it (as the
            # previous code did) made per-row Delete unimplementable.
            # The dashboard UI masks long handles at render time.
            out.append(
                {
                    "message_id": m.get("MessageId"),
                    "body": m.get("Body"),
                    "md5_of_body": m.get("MD5OfBody"),
                    "attributes": m.get("Attributes") or {},
                    "message_attributes": m.get("MessageAttributes") or {},
                    "receipt_handle": m.get("ReceiptHandle") or "",
                }
            )
        return out


class SnsSubscriptionsResource:
    """``GET /_localemu/api/resources/sns/<topic>/subscriptions``."""

    def on_get(self, request: Request, topic: str = ""):
        LOG.debug("Dashboard API request: GET /resources/sns/%s/subscriptions", topic)
        try:
            subs = self._list_subscriptions(topic)
        except Exception:
            LOG.debug("error listing SNS subs for %s", topic, exc_info=True)
            return _json_response({"topic": topic, "subscriptions": None, "error": "backend error"})
        return _json_response({"topic": topic, "subscriptions": subs, "error": None, "total": len(subs)})

    @staticmethod
    def _list_subscriptions(topic_name: str) -> list[dict]:
        # Locate the topic ARN across regions, then call ListSubscriptionsByTopic.
        from localemu.aws.connect import connect_to
        from localemu.constants import DEFAULT_AWS_ACCOUNT_ID
        from localemu.services.cloudtrail.recording_hook import suppress_recording
        from localemu.services.sns.models import sns_stores

        topic_arn = None
        target_region = None
        for _account_id, region, store in sns_stores.iter_stores():
            for arn, _topic in store.topics.items():
                # SNS ARN format: arn:aws:sns:<region>:<account>:<topic-name>
                if arn.rsplit(":", 1)[-1] == topic_name or arn == topic_name:
                    topic_arn = arn
                    target_region = region
                    break
            if topic_arn:
                break
        if not topic_arn:
            return []

        with suppress_recording():
            client = connect_to(
                aws_access_key_id=DEFAULT_AWS_ACCOUNT_ID,
                region_name=target_region,
            ).sns
            resp = client.list_subscriptions_by_topic(TopicArn=topic_arn)

            out: list[dict] = []
            for s in resp.get("Subscriptions", []) or []:
                entry = {
                    "subscription_arn": s.get("SubscriptionArn"),
                    "protocol": s.get("Protocol"),
                    "endpoint": s.get("Endpoint"),
                    "topic_arn": s.get("TopicArn"),
                }
                sub_arn = s.get("SubscriptionArn")
                # Filter policies + DLQs are attributes; fetch them when the
                # subscription has actually been confirmed (a Pending one has no ARN).
                if sub_arn and sub_arn != "PendingConfirmation":
                    try:
                        attrs = client.get_subscription_attributes(SubscriptionArn=sub_arn).get("Attributes", {})
                        if attrs.get("FilterPolicy"):
                            entry["filter_policy"] = attrs.get("FilterPolicy")
                        if attrs.get("RedrivePolicy"):
                            entry["redrive_policy"] = attrs.get("RedrivePolicy")
                        if attrs.get("RawMessageDelivery"):
                            entry["raw_message_delivery"] = attrs.get("RawMessageDelivery")
                    except Exception:
                        pass
                out.append(entry)
            return out


class EventBridgeRulesResource:
    """``GET /_localemu/api/resources/events/<bus>/rules`` -- rules + targets per bus."""

    def on_get(self, request: Request, bus: str = ""):
        LOG.debug("Dashboard API request: GET /resources/events/%s/rules", bus)
        try:
            rules = self._list_rules(bus or "default")
        except Exception:
            LOG.debug("error listing events rules for bus %s", bus, exc_info=True)
            return _json_response({"bus": bus, "rules": None, "error": "backend error"})
        return _json_response({"bus": bus, "rules": rules, "error": None, "total": len(rules)})

    @staticmethod
    def _list_rules(bus_name: str) -> list[dict]:
        """Rules + targets for ``bus_name`` across every account/region.

        Reads the native ``events_stores`` directly instead of going
        through boto3. Bypassing the gateway avoids two problems:

          1. The previous boto3 walk hard-coded five regions and missed
             buses in any other region (ap-*, eu-central-*, sa-*).
          2. Every reentrant boto3 call was recorded by CloudTrail,
             which inflated the event store with ListRules /
             ListTargetsByRule rows on every dashboard tick.

        Reads the model directly: same per-region scoping as the list
        page, no CloudTrail noise.
        """
        from localemu.services.events.models import events_stores

        out: list[dict] = []
        for _acct, _region, store in events_stores.iter_stores():
            bus = store.event_buses.get(bus_name)
            if bus is None:
                continue
            for rule_name, rule in getattr(bus, "rules", {}).items():
                entry = {
                    "name": rule_name,
                    "state": getattr(rule, "state", None),
                    "description": getattr(rule, "description", None),
                    "schedule_expression": getattr(rule, "schedule_expression", None),
                    "event_pattern": getattr(rule, "event_pattern", None),
                    "event_bus_name": bus_name,
                    "targets": [],
                }
                for t in getattr(rule, "targets", []) or []:
                    if isinstance(t, dict):
                        entry["targets"].append({
                            "id": t.get("Id") or t.get("id"),
                            "arn": t.get("Arn") or t.get("arn"),
                            "role_arn": t.get("RoleArn") or t.get("role_arn"),
                            "input": t.get("Input") or t.get("input"),
                            "input_path": t.get("InputPath") or t.get("input_path"),
                        })
                    else:
                        entry["targets"].append({
                            "id": getattr(t, "id", None) or getattr(t, "Id", None),
                            "arn": getattr(t, "arn", None) or getattr(t, "Arn", None),
                            "role_arn": getattr(t, "role_arn", None) or getattr(t, "RoleArn", None),
                            "input": getattr(t, "input", None) or getattr(t, "Input", None),
                            "input_path": getattr(t, "input_path", None) or getattr(t, "InputPath", None),
                        })
                out.append(entry)
        return out


class CloudTrailDetailResource:
    """``GET /_localemu/api/cloudtrail/<request_id>`` — full detail for a single CloudTrail event."""

    def on_get(self, request: Request, request_id: str = ""):
        LOG.debug("Dashboard API request: GET /cloudtrail/%s from %s", request_id, request.remote_addr)
        # Try the shared CloudTrail event store first (O(1) lookup)
        try:
            from localemu.services.cloudtrail.event_store import get_event_store

            evt = get_event_store().get_by_request_id(request_id)
            if evt:
                detail = evt.to_lookup_event()
                # Add extra fields the dashboard expects
                detail["service"] = evt.event_source.removesuffix(".amazonaws.com")
                detail["responseCode"] = evt.http_status_code
                return _json_response(detail)
        except Exception:
            pass

        # Fallback to legacy activity log
        with _activity_lock:
            for evt in _activity_log:
                if evt.get("request_id") == request_id:
                    svc = evt.get("service", "unknown")
                    return _json_response({
                        "eventTime": evt.get("timestamp", ""),
                        "eventSource": svc + ".amazonaws.com",
                        "eventName": evt.get("operation", ""),
                        "sourceIPAddress": evt.get("source_ip", "127.0.0.1"),
                        "userAgent": evt.get("user_agent", ""),
                        "requestId": evt.get("request_id", ""),
                        "awsRegion": evt.get("region", "us-east-1"),
                        "responseCode": evt.get("status", 0),
                        "accountId": evt.get("account_id", ""),
                        "service": svc,
                    })
        return _json_response({"error": "not found", "request_id": request_id}, status=404)


class CloudTrailResource:
    """``GET /_localemu/api/cloudtrail`` — CloudTrail-formatted event history.

    Reads from the shared CloudTrail event store (same data that
    ``aws cloudtrail lookup-events`` returns).
    """

    def on_get(self, request: Request):
        LOG.debug("Dashboard API request: GET /cloudtrail from %s", request.remote_addr)
        limit = _safe_int(request.args.get("limit", "100"), 100)
        offset = _safe_int(request.args.get("offset", "0"), 0, minimum=0, maximum=100000)
        service_filter = request.args.get("service", "")
        account_filter = request.args.get("account", "")
        user_filter = request.args.get("user", "")

        # Read from shared CloudTrail event store
        try:
            from localemu.services.cloudtrail.event_store import get_event_store

            store = get_event_store()
            # True total comes from the store, not from the windowed slice.
            # Computing it from the slice was the source of the dashboard
            # showing "200 events" when the store actually had thousands.
            total = store.get_event_count()

            if service_filter or account_filter or user_filter:
                # Any filter forces a full-store walk so we can give an
                # honest filtered total. Pull a wide window and filter in
                # Python -- matches the existing `service_filter` path.
                events = store.get_recent(limit=total)
                if service_filter:
                    events = [
                        e for e in events
                        if e.event_source.removesuffix(".amazonaws.com").lower() == service_filter.lower()
                    ]
                if account_filter:
                    events = [e for e in events if (e.account_id or "") == account_filter]
                if user_filter:
                    events = [
                        e for e in events
                        if (getattr(e, "username", "") or "").lower() == user_filter.lower()
                    ]
                total = len(events)
                events = events[offset:offset + limit]
            else:
                events = store.get_recent(limit=limit + offset)[offset:offset + limit]

            trail_events = []
            for evt in events:
                trail_events.append({
                    "eventTime": evt.event_time.isoformat(),
                    "eventSource": evt.event_source,
                    "eventName": evt.event_name,
                    "sourceIPAddress": evt.source_ip,
                    "userAgent": evt.user_agent,
                    "requestId": evt.request_id,
                    "awsRegion": evt.aws_region,
                    "responseCode": evt.http_status_code,
                    "accountId": evt.account_id,
                    "readOnly": evt.read_only,
                    "errorCode": evt.error_code,
                    "resources": evt.resources,
                    "requestParameters": _slim_request_params(evt.request_parameters),
                })
            return _json_response({"events": trail_events, "error": None, "total": total})
        except Exception:
            pass

        # Fallback to legacy activity log
        with _activity_lock:
            raw_events = list(_activity_log)

        if service_filter:
            raw_events = [
                e for e in raw_events
                if (e.get("service") or "").lower() == service_filter.lower()
            ]

        total = len(raw_events)
        raw_events = raw_events[offset:offset + limit]

        trail_events = []
        for evt in raw_events:
            svc = evt.get("service", "unknown")
            trail_events.append(
                {
                    "eventTime": evt.get("timestamp", ""),
                    "eventSource": svc + ".amazonaws.com",
                    "eventName": evt.get("operation", ""),
                    "sourceIPAddress": evt.get("source_ip", "127.0.0.1"),
                    "userAgent": evt.get("user_agent", ""),
                    "requestId": evt.get("request_id", ""),
                    "awsRegion": evt.get("region", "us-east-1"),
                    "responseCode": evt.get("status", 0),
                    "accountId": evt.get("account_id", ""),
                }
            )
        return _json_response({"events": trail_events, "error": None, "total": total})


class ActivityResource:
    """``GET /_localemu/api/activity`` — recent API activity feed.

    Two modes:

    1. ``GET /api/activity?limit=N`` returns the last N events (default).
       Used on initial dashboard load.
    2. ``GET /api/activity?since=<request_id>`` returns ONLY events
       newer than the request_id cursor. Used as a polling fallback
       when SSE is unavailable: idle polling that finds no new events
       returns an empty array (~30 bytes).

    Primary source is the shared CloudTrailEventStore. Falls back to
    the legacy ring-buffer if the store is unavailable.
    """

    def on_get(self, request: Request):
        LOG.debug("Dashboard API request: GET /activity from %s", request.remote_addr)
        limit = _safe_int(request.args.get("limit", "100"), 100)
        offset = _safe_int(request.args.get("offset", "0"), 0, minimum=0, maximum=100000)
        since = (request.args.get("since") or "").strip()
        try:
            from localemu.services.cloudtrail.event_store import get_event_store

            all_events = get_event_store().get_recent(limit=max(limit + offset, 500))
            serialised = [e.to_dashboard_event() for e in all_events]
            if since:
                # Cursor is the request_id of the most recent event the
                # client has already seen. Everything before that id in
                # the list is newer (events are most-recent-first).
                trimmed: list[dict] = []
                for evt in serialised:
                    if evt.get("request_id") == since:
                        break
                    trimmed.append(evt)
                return _json_response({
                    "events": trimmed,
                    "error": None,
                    "total": len(trimmed),
                    "since": since,
                })
            total = len(serialised)
            page = serialised[offset:offset + limit]
            return _json_response({
                "events": page,
                "error": None,
                "total": total,
            })
        except Exception:
            pass
        # Fallback to legacy ring-buffer (carries ``id`` for since-cursor).
        with _activity_lock:
            all_events = list(_activity_log)
        if since:
            trimmed_legacy: list[dict] = []
            for evt in all_events:
                if str(evt.get("request_id")) == since:
                    break
                trimmed_legacy.append(evt)
            return _json_response({
                "events": trimmed_legacy,
                "error": None,
                "total": len(trimmed_legacy),
                "since": since,
            })
        total = len(all_events)
        page = all_events[offset:offset + limit]
        return _json_response({"events": page, "error": None, "total": total})


class StaticResource:
    """``GET /_localemu/dashboard/static/<path:path>`` — serve dashboard static assets."""

    def on_get(self, request: Request, path: str = ""):
        import localemu.dashboard.static as static_module

        try:
            return Response.for_resource(static_module, path)
        except FileNotFoundError:
            return Response("Not found", status=404)


class EcrRepositoryDetailResource:
    """``GET /_localemu/api/resources/ecr/<name>`` — one ECR repository.

    Returns repo metadata plus the image list (digest + tags + pushed-at
    + manifest media type). The dashboard renders a Connection / docker
    pull tile so the user can copy the image URI directly.
    """

    def on_get(self, request: Request, name: str = ""):
        from urllib.parse import unquote
        name = unquote(name or "")

        for _acct, region, backend in _iter_moto_backends("ecr"):
            repo = (getattr(backend, "repositories", {}) or {}).get(name)
            if repo is None:
                continue

            images: list[dict] = []
            for img in getattr(repo, "images", []) or []:
                digest = None
                try:
                    digest = img.get_image_digest()
                except Exception:
                    digest = getattr(img, "_image_digest", None) or ""
                images.append({
                    "digest": digest or "",
                    "tags": list(getattr(img, "image_tags", []) or []),
                    "manifest_media_type": getattr(img, "image_manifest_media_type", "") or "",
                    "pushed_at": getattr(img, "image_pushed_at", None),
                })

            return _json_response({
                "name": name,
                "arn": getattr(repo, "arn", ""),
                "uri": getattr(repo, "uri", ""),
                "registry_id": getattr(repo, "registry_id", ""),
                "image_tag_mutability": str(getattr(repo, "image_tag_mutability", "-")),
                "image_scanning_configuration": getattr(repo, "image_scanning_configuration", {}) or {},
                "encryption_configuration": getattr(repo, "encryption_configuration", {}) or {},
                "policy": getattr(repo, "policy", None),
                "lifecycle_policy": getattr(repo, "lifecycle_policy", None),
                "images": images,
                "created_at": str(getattr(repo, "created_at", "") or ""),
                "region": region,
            })

        return _json_response({"error": "not found", "name": name}, status=404)


class BatchDetailResource:
    """``GET /_localemu/api/resources/batch/<name>`` — Batch resource detail.

    ``<name>`` can be a compute-env name, job-queue name, job-definition
    name, or a job ID. The first match wins. The response always carries
    a ``kind`` field so the drill UI can pick the right card layout.
    """

    def on_get(self, request: Request, name: str = ""):
        from urllib.parse import unquote
        name = unquote(name or "")

        for _acct, region, backend in _iter_moto_backends("batch"):
            env = (getattr(backend, "_compute_environments", {}) or {}).get(name)
            if env is not None:
                return _json_response({
                    "kind": "compute-env",
                    "name": name,
                    "arn": getattr(env, "arn", ""),
                    "type": getattr(env, "env_type", ""),
                    "state": getattr(env, "state", ""),
                    "service_role": getattr(env, "service_role", ""),
                    "compute_resources": getattr(env, "compute_resources", {}) or {},
                    "ecs_cluster_arn": getattr(env, "ecs_arn", ""),
                    "ecs_cluster_name": getattr(env, "ecs_name", ""),
                    "instances": [
                        getattr(i, "instance_id", str(i))
                        for i in (getattr(env, "instances", []) or [])
                    ],
                    "region": region,
                })

            for q_name, q in (getattr(backend, "_job_queues", {}) or {}).items():
                if q_name != name and getattr(q, "name", None) != name:
                    continue
                envs_order = []
                for entry in getattr(q, "env_order_json", []) or []:
                    if isinstance(entry, dict):
                        envs_order.append(entry)
                return _json_response({
                    "kind": "job-queue",
                    "name": getattr(q, "name", q_name),
                    "arn": getattr(q, "arn", ""),
                    "state": getattr(q, "state", ""),
                    "priority": getattr(q, "priority", None),
                    "schedule_policy": getattr(q, "schedule_policy", None),
                    "compute_environments": envs_order,
                    "region": region,
                })

            for jd_id, jd in (getattr(backend, "_job_definitions", {}) or {}).items():
                if jd_id != name and getattr(jd, "name", None) != name:
                    continue
                return _json_response({
                    "kind": "job-def",
                    "name": getattr(jd, "name", jd_id),
                    "arn": getattr(jd, "arn", ""),
                    "type": getattr(jd, "type", ""),
                    "revision": getattr(jd, "revision", 0),
                    "container_properties": getattr(jd, "container_properties", {}) or {},
                    "node_properties": getattr(jd, "node_properties", {}) or {},
                    "eks_properties": getattr(jd, "eks_properties", {}) or {},
                    "parameters": getattr(jd, "parameters", {}) or {},
                    "retry_strategy": getattr(jd, "retry_strategy", {}) or {},
                    "timeout": getattr(jd, "timeout", {}) or {},
                    "platform_capabilities": getattr(jd, "platform_capabilities", []) or [],
                    "propagate_tags": bool(getattr(jd, "propagate_tags", False)),
                    "region": region,
                })

            job = (getattr(backend, "_jobs", {}) or {}).get(name)
            if job is not None:
                return _json_response({
                    "kind": "job",
                    "name": getattr(job, "job_name", name),
                    "job_id": getattr(job, "job_id", name),
                    "arn": getattr(job, "arn", ""),
                    "status": str(getattr(job, "status", "")),
                    "status_reason": getattr(job, "status_reason", None),
                    "job_queue": getattr(getattr(job, "job_queue", None), "arn", ""),
                    "job_definition": getattr(getattr(job, "job_definition", None), "arn", ""),
                    "started_at": getattr(job, "started_at", None),
                    "stopped_at": getattr(job, "stopped_at", None),
                    "container_overrides": getattr(job, "container_overrides", {}) or {},
                    "depends_on": getattr(job, "depends_on", []) or [],
                    "region": region,
                })

        return _json_response({"error": "not found", "name": name}, status=404)


class PipeDetailResource:
    """``GET /_localemu/api/resources/pipes/<name>`` — one pipe.

    Combines moto metadata (source/target/parameters) with the live
    PipeWorker state from PipeManager so the user can see whether the
    poller is actually running.
    """

    def on_get(self, request: Request, name: str = ""):
        from urllib.parse import unquote
        name = unquote(name or "")

        for _acct, region, backend in _iter_moto_backends("pipes"):
            pipe = (getattr(backend, "pipes", {}) or {}).get(name)
            if pipe is None:
                continue

            arn = getattr(pipe, "arn", "")
            worker_state = None
            poller_thread_alive = None
            try:
                from localemu.services.pipes.pipe_manager import PipeManager
                worker = PipeManager.instance().get(arn)
                if worker is not None:
                    worker_state = str(getattr(worker, "current_state", "-"))
                    thread = getattr(worker, "_poller_thread", None)
                    poller_thread_alive = bool(thread and thread.is_alive())
            except Exception:
                pass

            return _json_response({
                "name": name,
                "arn": arn,
                "source": getattr(pipe, "source", ""),
                "target": getattr(pipe, "target", ""),
                "role_arn": getattr(pipe, "role_arn", ""),
                "description": getattr(pipe, "description", "") or "",
                "source_parameters": getattr(pipe, "source_parameters", None) or {},
                "enrichment": getattr(pipe, "enrichment", None),
                "enrichment_parameters": getattr(pipe, "enrichment_parameters", None) or {},
                "target_parameters": getattr(pipe, "target_parameters", None) or {},
                "log_configuration": getattr(pipe, "log_configuration", None) or {},
                "kms_key_identifier": getattr(pipe, "kms_key_identifier", None),
                "desired_state": getattr(pipe, "desired_state", ""),
                "current_state": getattr(pipe, "current_state", ""),
                "state_reason": getattr(pipe, "state_reason", None),
                "creation_time": str(getattr(pipe, "creation_time", "") or ""),
                "last_modified_time": str(getattr(pipe, "last_modified_time", "") or ""),
                "tags": getattr(pipe, "tags", {}) or {},
                "worker_state": worker_state,
                "poller_thread_alive": poller_thread_alive,
                "region": region,
            })

        return _json_response({"error": "not found", "name": name}, status=404)


class SchedulerScheduleDetailResource:
    """``GET /_localemu/api/resources/scheduler/<group>/<name>``.

    The dashboard accepts ``group/name`` (URL-encoded) so the route is
    unambiguous when two groups have a schedule with the same name. If
    ``group`` is omitted the resource searches every group.
    """

    def on_get(self, request: Request, group: str = "", name: str = ""):
        from urllib.parse import unquote
        group = unquote(group or "")
        name = unquote(name or "")

        # Single-arg variant: caller passed the schedule name as ``group``.
        if not name:
            name, group = group, ""

        runtime = {}
        try:
            from localemu.services.scheduler.job_scheduler import SchedulerJobScheduler
            for arn, job in SchedulerJobScheduler.instance()._jobs.items():
                runtime[arn] = job
        except Exception:
            runtime = {}

        for _acct, region, backend in _iter_moto_backends("scheduler"):
            for gname, grp in (getattr(backend, "schedule_groups", {}) or {}).items():
                if group and gname != group:
                    continue
                scheds = getattr(grp, "schedules", {}) or {}
                for sched in (scheds.values() if hasattr(scheds, "values") else scheds):
                    if getattr(sched, "name", None) != name:
                        continue

                    arn = getattr(sched, "arn", "")
                    job = runtime.get(arn)

                    return _json_response({
                        "name": name,
                        "group": gname,
                        "arn": arn,
                        "description": getattr(sched, "description", "") or "",
                        "schedule_expression": getattr(sched, "schedule_expression", ""),
                        "schedule_expression_timezone": getattr(
                            sched, "schedule_expression_timezone", "UTC",
                        ),
                        "flexible_time_window": getattr(sched, "flexible_time_window", {}) or {},
                        "target": getattr(sched, "target", {}) or {},
                        "state": getattr(sched, "state", ""),
                        "kms_key_arn": getattr(sched, "kms_key_arn", None),
                        "start_date": str(getattr(sched, "start_date", "") or ""),
                        "end_date": str(getattr(sched, "end_date", "") or ""),
                        "action_after_completion": getattr(sched, "action_after_completion", None),
                        "creation_date": getattr(sched, "creation_date", None),
                        "last_modified_date": getattr(sched, "last_modified_date", None),
                        "runtime": None if job is None else {
                            "next_fire": job.next_fire.isoformat() if job.next_fire else None,
                            "state": job.state,
                            "fired_once": bool(job.fired_once),
                            "currently_dispatching": bool(job.currently_dispatching),
                        },
                        "region": region,
                    })

        return _json_response({"error": "not found", "name": name, "group": group}, status=404)


class Wafv2WebAclDetailResource:
    """``GET /_localemu/api/resources/wafv2/<id_or_name>``.

    Resolves to a web ACL, IP set, regex set, or rule group by id or
    name (first match wins). The response carries ``kind`` so the
    dashboard picks the right tab layout.
    """

    def on_get(self, request: Request, key: str = ""):
        from urllib.parse import unquote
        key = unquote(key or "")

        for _acct, region, backend in _iter_moto_backends("wafv2"):
            for arn, acl in (getattr(backend, "wacls", {}) or {}).items():
                if key in (getattr(acl, "id", None), getattr(acl, "name", None), arn):
                    return _json_response({
                        "kind": "web-acl",
                        "name": getattr(acl, "name", ""),
                        "id": getattr(acl, "id", ""),
                        "arn": arn,
                        "scope": getattr(acl, "scope", ""),
                        "description": getattr(acl, "description", "") or "",
                        "default_action": getattr(acl, "default_action", {}) or {},
                        "visibility_config": getattr(acl, "visibility_config", {}) or {},
                        "rules": getattr(acl, "rules", []) or [],
                        "capacity": getattr(acl, "capacity", 0),
                        "associated_resources": list(getattr(acl, "associated_resources", []) or []),
                        "created_time": str(getattr(acl, "created_time", "") or ""),
                        "region": region,
                    })

            for arn, ip_set in (getattr(backend, "ip_sets", {}) or {}).items():
                if key in (getattr(ip_set, "ip_set_id", None), getattr(ip_set, "name", None), arn):
                    return _json_response({
                        "kind": "ip-set",
                        "name": getattr(ip_set, "name", ""),
                        "id": getattr(ip_set, "ip_set_id", ""),
                        "arn": arn,
                        "scope": getattr(ip_set, "scope", ""),
                        "description": getattr(ip_set, "description", "") or "",
                        "ip_address_version": getattr(ip_set, "ip_address_version", "IPV4"),
                        "addresses": list(getattr(ip_set, "addresses", []) or []),
                        "region": region,
                    })

            for arn, rg in (getattr(backend, "rule_groups", {}) or {}).items():
                if key in (getattr(rg, "id", None), getattr(rg, "name", None), arn):
                    return _json_response({
                        "kind": "rule-group",
                        "name": getattr(rg, "name", ""),
                        "id": getattr(rg, "id", ""),
                        "arn": arn,
                        "scope": getattr(rg, "scope", ""),
                        "description": getattr(rg, "description", "") or "",
                        "capacity": getattr(rg, "capacity", 0),
                        "visibility_config": getattr(rg, "visibility_config", {}) or {},
                        "rules": getattr(rg, "rules", []) or [],
                        "region": region,
                    })

        return _json_response({"error": "not found", "key": key}, status=404)


class GlueDetailResource:
    """``GET /_localemu/api/resources/glue/<kind>/<path:key>``.

    One handler with kind-routed dispatch: database / table / crawler /
    job / job-run / trigger / workflow / connection / registry / schema.
    Keys are kind-scoped:
        database  -> ``<db>``
        table     -> ``<db>/<table>``
        crawler   -> ``<name>``
        job       -> ``<name>``
        job-run   -> ``<job>/<run_id>``
        trigger   -> ``<name>``
        workflow  -> ``<name>``
        connection-> ``<name>``
        registry  -> ``<name>``
        schema    -> ``<registry>/<schema>``
    """

    def on_get(self, request: Request, kind: str = "", key: str = ""):
        from urllib.parse import unquote
        kind = unquote(kind or "")
        key = unquote(key or "")

        dispatch = {
            "database":   self._database,
            "table":      self._table,
            "crawler":    self._crawler,
            "job":        self._job,
            "job-run":    self._job_run,
            "trigger":    self._trigger,
            "workflow":   self._workflow,
            "connection": self._connection,
            "registry":   self._registry,
            "schema":     self._schema,
        }
        handler = dispatch.get(kind)
        if handler is None:
            return _json_response({"error": "unknown kind", "kind": kind}, status=404)
        return handler(key)

    def _database(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            db = (getattr(backend, "databases", {}) or {}).get(key)
            if db is None:
                continue
            tables = getattr(db, "tables", {}) or {}
            return _json_response({
                "kind": "database",
                "name": key,
                "catalog_id": getattr(db, "catalog_id", ""),
                "created_time": str(getattr(db, "created_time", "") or ""),
                "input": getattr(db, "input", {}) or {},
                "tables": [
                    {
                        "name": t_name,
                        "created_time": str(getattr(t, "created_time", "") or ""),
                        "updated_time": str(getattr(t, "updated_time", "") or ""),
                        "columns": _glue_table_column_count(t),
                        "partitions": len(getattr(t, "partitions", {}) or {}),
                    }
                    for t_name, t in tables.items()
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _table(self, key: str):
        db_name, _, tbl_name = key.partition("/")
        if not tbl_name:
            return _json_response({"error": "expected <database>/<table>", "key": key}, status=400)
        for _acct, region, backend in _iter_moto_backends("glue"):
            db = (getattr(backend, "databases", {}) or {}).get(db_name)
            if db is None:
                continue
            tbl = (getattr(db, "tables", {}) or {}).get(tbl_name)
            if tbl is None:
                continue
            versions = getattr(tbl, "versions", {}) or {}
            cur_ver = str(getattr(tbl, "_current_version", 1))
            cur_input = versions.get(cur_ver, {}) if isinstance(versions, dict) else {}
            storage = (cur_input or {}).get("StorageDescriptor") or {}
            partitions = getattr(tbl, "partitions", {}) or {}
            return _json_response({
                "kind": "table",
                "name": tbl_name,
                "database_name": db_name,
                "catalog_id": getattr(tbl, "catalog_id", ""),
                "created_time": str(getattr(tbl, "created_time", "") or ""),
                "updated_time": str(getattr(tbl, "updated_time", "") or ""),
                "current_version": cur_ver,
                "version_count": len(versions),
                "table_type": (cur_input or {}).get("TableType", "-"),
                "parameters": (cur_input or {}).get("Parameters", {}) or {},
                "partition_keys": (cur_input or {}).get("PartitionKeys", []) or [],
                "storage": {
                    "location": storage.get("Location", ""),
                    "input_format": storage.get("InputFormat", ""),
                    "output_format": storage.get("OutputFormat", ""),
                    "compressed": bool(storage.get("Compressed", False)),
                    "serde_info": storage.get("SerdeInfo") or {},
                },
                "columns": storage.get("Columns") or [],
                "partitions": [
                    {
                        "values": getattr(p, "values", []) or [],
                        "creation_time": str(getattr(p, "creation_time", "") or ""),
                        "last_access_time": str(getattr(p, "last_access_time", "") or ""),
                    }
                    for p in partitions.values()
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _crawler(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            c = (getattr(backend, "crawlers", {}) or {}).get(key)
            if c is None:
                continue
            crawls = getattr(c, "crawls", []) or []
            last = crawls[-1] if crawls else None
            return _json_response({
                "kind": "crawler",
                "name": key,
                "arn": getattr(c, "arn", ""),
                "role": getattr(c, "role", ""),
                "database_name": getattr(c, "database_name", ""),
                "description": getattr(c, "description", "") or "",
                "targets": getattr(c, "targets", {}) or {},
                "schedule": getattr(c, "schedule", "") or "on demand",
                "classifiers": getattr(c, "classifiers", []) or [],
                "table_prefix": getattr(c, "table_prefix", "") or "",
                "schema_change_policy": getattr(c, "schema_change_policy", {}) or {},
                "recrawl_policy": getattr(c, "recrawl_policy", {}) or {},
                "lineage_configuration": getattr(c, "lineage_configuration", {}) or {},
                "configuration": getattr(c, "configuration", "") or "",
                "status": getattr(c, "status", "-"),
                "creation_time": str(getattr(c, "creation_time", "") or ""),
                "last_updated": str(getattr(c, "last_updated", "") or ""),
                "version": getattr(c, "version", 1),
                "last_crawl": None if last is None else {
                    "crawl_id": getattr(last, "crawl_id", ""),
                    "status": getattr(last, "status", "-"),
                    "start_time": str(getattr(last, "start_time", "") or ""),
                    "end_time": str(getattr(last, "end_time", "") or ""),
                    "dpu_hour": getattr(last, "dpu_hour", 0),
                    "log_group": getattr(last, "log_group", ""),
                    "log_stream": getattr(last, "log_stream", ""),
                },
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _job(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            j = (getattr(backend, "jobs", {}) or {}).get(key)
            if j is None:
                continue
            return _json_response({
                "kind": "job",
                "name": key,
                "arn": getattr(j, "arn", ""),
                "description": getattr(j, "description", "") or "",
                "role": getattr(j, "role", ""),
                "log_uri": getattr(j, "log_uri", "") or "",
                "command": getattr(j, "command", {}) or {},
                "default_arguments": getattr(j, "default_arguments", {}) or {},
                "non_overridable_arguments": getattr(j, "non_overridable_arguments", {}) or {},
                "connections": getattr(j, "connections", {}) or {},
                "max_retries": getattr(j, "max_retries", 0),
                "allocated_capacity": getattr(j, "allocated_capacity", 0),
                "timeout": getattr(j, "timeout", 0),
                "max_capacity": getattr(j, "max_capacity", 0),
                "glue_version": getattr(j, "glue_version", "") or "",
                "number_of_workers": getattr(j, "number_of_workers", 0),
                "worker_type": getattr(j, "worker_type", "") or "",
                "execution_class": getattr(j, "execution_class", "") or "",
                "execution_property": getattr(j, "execution_property", {}) or {},
                "security_configuration": getattr(j, "security_configuration", "") or "",
                "notification_property": getattr(j, "notification_property", {}) or {},
                "source_control_details": getattr(j, "source_control_details", {}) or {},
                "created_on": str(getattr(j, "created_on", "") or ""),
                "last_modified_on": str(getattr(j, "last_modified_on", "") or ""),
                "job_runs": [
                    {
                        "id": getattr(r, "job_run_id", ""),
                        "status": getattr(r, "status", "-"),
                        "started_on": str(getattr(r, "started_on", "") or ""),
                        "completed_on": str(getattr(r, "completed_on", "") or ""),
                        "worker_type": getattr(r, "worker_type", ""),
                        "number_of_workers": getattr(r, "number_of_workers", 0),
                        "timeout": getattr(r, "timeout", 0),
                    }
                    for r in (getattr(j, "job_runs", []) or [])
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _job_run(self, key: str):
        job_name, _, run_id = key.partition("/")
        if not run_id:
            return _json_response({"error": "expected <job>/<run_id>", "key": key}, status=400)
        for _acct, region, backend in _iter_moto_backends("glue"):
            j = (getattr(backend, "jobs", {}) or {}).get(job_name)
            if j is None:
                continue
            for r in getattr(j, "job_runs", []) or []:
                if getattr(r, "job_run_id", None) != run_id:
                    continue
                return _json_response({
                    "kind": "job-run",
                    "job_name": job_name,
                    "id": run_id,
                    "previous_run_id": getattr(r, "previous_run_id", None),
                    "status": getattr(r, "status", "-"),
                    "arguments": getattr(r, "arguments", {}) or {},
                    "allocated_capacity": getattr(r, "allocated_capacity", 0),
                    "max_capacity": getattr(r, "max_capacity", 0),
                    "timeout": getattr(r, "timeout", 0),
                    "worker_type": getattr(r, "worker_type", "") or "",
                    "number_of_workers": getattr(r, "number_of_workers", 0),
                    "notification_property": getattr(r, "notification_property", {}) or {},
                    "security_configuration": getattr(r, "security_configuration", "") or "",
                    "started_on": str(getattr(r, "started_on", "") or ""),
                    "modified_on": str(getattr(r, "modified_on", "") or ""),
                    "completed_on": str(getattr(r, "completed_on", "") or ""),
                    "region": region,
                })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _trigger(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            t = (getattr(backend, "triggers", {}) or {}).get(key)
            if t is None:
                continue
            actions = getattr(t, "actions", []) or []
            return _json_response({
                "kind": "trigger",
                "name": key,
                "arn": getattr(t, "arn", ""),
                "workflow_name": getattr(t, "workflow_name", "") or "",
                "trigger_type": getattr(t, "trigger_type", ""),
                "state": getattr(t, "state", ""),
                "schedule": getattr(t, "schedule", "") or "",
                "description": getattr(t, "description", "") or "",
                "predicate": _glue_predicate_to_dict(getattr(t, "predicate", None)),
                "actions": [_glue_action_to_dict(a) for a in actions],
                "event_batching_condition": getattr(t, "event_batching_condition", {}) or {},
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _workflow(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            w = (getattr(backend, "workflows", {}) or {}).get(key)
            if w is None:
                continue
            runs = getattr(w, "runs", {}) or {}
            return _json_response({
                "kind": "workflow",
                "name": key,
                "description": getattr(w, "description", "") or "",
                "max_concurrent_runs": getattr(w, "max_concurrent_runs", None),
                "default_run_properties": getattr(w, "default_run_properties", {}) or {},
                "tags": getattr(w, "tags", {}) or {},
                "created_on": str(getattr(w, "created_on", "") or ""),
                "last_modified_on": str(getattr(w, "last_modified_on", "") or ""),
                "runs": [
                    {
                        "id": getattr(r, "run_id", ""),
                        "previous_run_id": getattr(r, "previous_run_id", None),
                        "status": getattr(r, "status", "-"),
                        "started_on": str(getattr(r, "started_on", "") or ""),
                        "completed_on": str(getattr(r, "completed_on", "") or ""),
                        "properties": getattr(r, "properties", {}) or {},
                    }
                    for r in runs.values()
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _connection(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            conn = (getattr(backend, "connections", {}) or {}).get(key)
            if conn is None:
                continue
            return _json_response({
                "kind": "connection",
                "name": key,
                "arn": getattr(conn, "arn", ""),
                "catalog_id": getattr(conn, "catalog_id", ""),
                "description": getattr(conn, "description", "") or "",
                "status": getattr(conn, "status", "-"),
                "connection_properties": getattr(conn, "connection_properties", {}) or {},
                "spark_properties": getattr(conn, "spark_properties", {}) or {},
                "athena_properties": getattr(conn, "athena_properties", {}) or {},
                "python_properties": getattr(conn, "python_properties", {}) or {},
                "connection_input": getattr(conn, "connection_input", {}) or {},
                "created_time": str(getattr(conn, "created_time", "") or ""),
                "updated_time": str(getattr(conn, "updated_time", "") or ""),
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _registry(self, key: str):
        for _acct, region, backend in _iter_moto_backends("glue"):
            reg = (getattr(backend, "registries", {}) or {}).get(key)
            if reg is None:
                continue
            schemas = getattr(reg, "schemas", {}) or {}
            return _json_response({
                "kind": "registry",
                "name": key,
                "arn": getattr(reg, "registry_arn", ""),
                "description": getattr(reg, "description", "") or "",
                "status": getattr(reg, "status", ""),
                "tags": getattr(reg, "tags", {}) or {},
                "created_time": str(getattr(reg, "created_time", "") or ""),
                "updated_time": str(getattr(reg, "updated_time", "") or ""),
                "schemas": [
                    {
                        "name": s_name,
                        "data_format": getattr(s, "data_format", "") or "",
                        "compatibility": getattr(s, "compatibility", "") or "",
                        "latest_version": getattr(s, "latest_schema_version", 1),
                        "status": getattr(s, "schema_status", "") or "",
                    }
                    for s_name, s in schemas.items()
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)

    def _schema(self, key: str):
        reg_name, _, schema_name = key.partition("/")
        if not schema_name:
            return _json_response({"error": "expected <registry>/<schema>", "key": key}, status=400)
        for _acct, region, backend in _iter_moto_backends("glue"):
            reg = (getattr(backend, "registries", {}) or {}).get(reg_name)
            if reg is None:
                continue
            schema = (getattr(reg, "schemas", {}) or {}).get(schema_name)
            if schema is None:
                continue
            schema_versions = getattr(schema, "schema_versions", {}) or {}
            return _json_response({
                "kind": "schema",
                "name": schema_name,
                "registry_name": reg_name,
                "schema_arn": getattr(schema, "schema_arn", ""),
                "registry_arn": getattr(schema, "registry_arn", ""),
                "description": getattr(schema, "description", "") or "",
                "data_format": getattr(schema, "data_format", "") or "",
                "compatibility": getattr(schema, "compatibility", "") or "",
                "schema_checkpoint": getattr(schema, "schema_checkpoint", 1),
                "latest_schema_version": getattr(schema, "latest_schema_version", 1),
                "next_schema_version": getattr(schema, "next_schema_version", 2),
                "schema_status": getattr(schema, "schema_status", ""),
                "schema_version_id": getattr(schema, "schema_version_id", ""),
                "created_time": str(getattr(schema, "created_time", "") or ""),
                "updated_time": str(getattr(schema, "updated_time", "") or ""),
                "versions": [
                    {
                        "id": v_id,
                        "status": getattr(v, "schema_version_status", "-"),
                        "version_number": getattr(v, "version_number", "-"),
                    }
                    for v_id, v in schema_versions.items()
                ],
                "region": region,
            })
        return _json_response({"error": "not found", "key": key}, status=404)


def _glue_table_column_count(table) -> int:
    """Count storage columns on the current version of a Glue table.

    moto stores the table_input under ``versions[str(current_version)]``
    and the column list lives at
    ``StorageDescriptor.Columns``. Missing keys are tolerated.
    """
    versions = getattr(table, "versions", {}) or {}
    cur = str(getattr(table, "_current_version", 1))
    payload = versions.get(cur, {}) if isinstance(versions, dict) else {}
    storage = (payload or {}).get("StorageDescriptor") or {}
    return len(storage.get("Columns") or [])


def _glue_predicate_to_dict(p):
    """Convert a moto ``Predicate`` to a plain JSON-safe dict.

    Returns ``None`` when the trigger has no predicate (e.g. SCHEDULED
    or ON_DEMAND triggers). Tolerates the dict shape that moto sometimes
    stores directly without wrapping in a Predicate.
    """
    if p is None:
        return None
    if isinstance(p, dict):
        return p
    return {
        "logical": getattr(p, "logical", None),
        "conditions": [
            {
                "logical_operator": getattr(c, "logical_operator", None),
                "job_name": getattr(c, "job_name", None),
                "state": getattr(c, "state", None),
                "crawler_name": getattr(c, "crawler_name", None),
                "crawl_state": getattr(c, "crawl_state", None),
            }
            for c in (getattr(p, "conditions", None) or [])
        ],
    }


def _glue_action_to_dict(a):
    """Convert a moto trigger ``Action`` to a JSON-safe dict.

    Tolerates the dict shape moto sometimes stores directly.
    """
    if isinstance(a, dict):
        return a
    return {
        "job_name": getattr(a, "job_name", None),
        "arguments": getattr(a, "arguments", None) or {},
        "timeout": getattr(a, "timeout", None),
        "security_configuration": getattr(a, "security_configuration", None),
        "notification_property": getattr(a, "notification_property", None) or {},
        "crawler_name": getattr(a, "crawler_name", None),
    }


class DashboardResource:
    """``GET /_localemu/dashboard`` — serve the main dashboard HTML.

    The dashboard is a development inspector served on loopback. Always
    serve a fresh copy so a LocalEmu upgrade is picked up on the next
    navigate without requiring users to hard-refresh.
    """

    def on_get(self, request: Request):
        try:
            html = _get_dashboard_html()
            resp = Response(html, content_type="text/html")
            resp.headers["Cache-Control"] = "no-store, must-revalidate"
            return resp
        except FileNotFoundError:
            return Response(
                "<h1>Dashboard not found</h1><p>index.html is missing.</p>",
                status=404,
                content_type="text/html",
            )
