"""Per-request telemetry for the LocalEmu console.

Two small handlers are added to the gateway's handler chain when the
dashboard registers:

* :func:`telemetry_request_start` (appended to ``preprocess_request``)
  stamps a monotonic start time on the request context.
* :func:`telemetry_response_handler` (appended to
  ``run_custom_response_handlers``) runs after every AWS API call. It
  measures the server-side handling time, resolves the calling principal,
  extracts the affected resource, tags IAM denials, and hands one record
  to the :class:`Telemetry` singleton.

The singleton feeds four console features from the same records:

* the requests-per-second chart (per-second buckets for 15 minutes),
* p50 / p99 latency (samples from the last 5 minutes),
* the live API-call feed (last 500 calls, also pushed over SSE as
  ``call`` events),
* the "recently changed resources" table (last 200 successful mutating
  calls that named a resource),
* the IAM-denial counter.

Which calls are recorded mirrors the CloudTrail recording hook
(``services/cloudtrail/recording_hook.py``): calls the dashboard makes on
its own behalf and LocalEmu's internal service-to-service calls are
skipped, so the feed and the CloudTrail view describe the same traffic.

IAM denials come from two places:

* ``IAM_ENFORCEMENT=1``: the enforcer raises ``AccessDenied`` (HTTP 403),
  visible on the context as ``service_exception``.
* ``IAM_ENFORCEMENT=soft``: the enforcer only logs
  ``IAM AUDIT DENY: ...`` and lets the call through. A logging filter on
  the enforcer's logger captures that message in a thread-local (the
  whole handler chain for one request runs on one thread) so the
  response handler can tag the call as an audit denial.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from typing import Any

LOG = logging.getLogger(__name__)

WINDOW_SECONDS = 900          # 15 min of per-second buckets
LATENCY_WINDOW_SECONDS = 300  # p50 / p99 over the last 5 min
SERVICE_WINDOW_MINUTES = 30   # per-service per-minute call counts
MAX_CALLS = 500
MAX_CHANGES = 200
MAX_DENIALS = 200
MAX_LATENCY_SAMPLES = 50_000

_DENIAL_CODES = frozenset({"AccessDenied", "AccessDeniedException"})


def _percentile(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


class Telemetry:
    """Thread-safe in-memory aggregation of recorded API calls."""

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        # int epoch second -> [calls, client_errors(4xx), server_errors(5xx), denied]
        self._seconds: collections.OrderedDict[int, list[int]] = collections.OrderedDict()
        self._latencies: collections.deque[tuple[float, float]] = collections.deque(
            maxlen=MAX_LATENCY_SAMPLES
        )
        self._calls: collections.deque[dict] = collections.deque(maxlen=MAX_CALLS)
        self._changes: collections.deque[dict] = collections.deque(maxlen=MAX_CHANGES)
        self._denials: collections.deque[dict] = collections.deque(maxlen=MAX_DENIALS)
        # (account, service) -> OrderedDict[int epoch minute -> calls]
        self._per_service: dict[tuple[str, str], collections.OrderedDict[int, int]] = {}
        self._seq = 0
        self.total_calls = 0
        self.total_errors = 0
        self.total_denied = 0
        self.started_at = clock()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, call: dict[str, Any]) -> dict[str, Any]:
        """Store one call. ``call`` must carry ``ts`` (epoch seconds),
        ``service``, ``operation``, ``status`` and may carry
        ``latency_ms``, ``account_id``, ``denied``, ``mutating`` and
        ``resource`` (``{"name": ..., "arn": ...}``). Returns the stored
        record with its ``seq`` assigned."""
        ts = float(call.get("ts") or self._clock())
        status = int(call.get("status") or 0)
        denied = call.get("denied")
        latency = call.get("latency_ms")
        sec = int(ts)
        minute = sec // 60
        key = (str(call.get("account_id") or ""), str(call.get("service") or ""))
        with self._lock:
            self._seq += 1
            rec = dict(call)
            rec["seq"] = self._seq
            rec["ts"] = ts

            bucket = self._seconds.get(sec)
            if bucket is None:
                bucket = [0, 0, 0, 0]
                self._seconds[sec] = bucket
            bucket[0] += 1
            if 400 <= status < 500:
                bucket[1] += 1
            elif status >= 500:
                bucket[2] += 1
            if denied:
                bucket[3] += 1
            self._prune_seconds(sec)

            if latency is not None:
                self._latencies.append((ts, float(latency)))

            per_min = self._per_service.get(key)
            if per_min is None:
                per_min = collections.OrderedDict()
                self._per_service[key] = per_min
            per_min[minute] = per_min.get(minute, 0) + 1
            while per_min and next(iter(per_min)) < minute - SERVICE_WINDOW_MINUTES:
                per_min.popitem(last=False)

            self._calls.append(rec)
            self.total_calls += 1
            if status >= 400:
                self.total_errors += 1
            if denied:
                self.total_denied += 1
                self._denials.append(rec)
            if (
                rec.get("mutating")
                and 200 <= status < 300
                and (rec.get("resource") or {}).get("name")
            ):
                self._changes.append(rec)
        return rec

    def _prune_seconds(self, now_sec: int) -> None:
        cutoff = now_sec - WINDOW_SECONDS
        while self._seconds:
            first = next(iter(self._seconds))
            if first >= cutoff:
                break
            self._seconds.popitem(last=False)

    def reset(self) -> None:
        with self._lock:
            self._seconds.clear()
            self._latencies.clear()
            self._calls.clear()
            self._changes.clear()
            self._denials.clear()
            self._per_service.clear()
            self.total_calls = self.total_errors = self.total_denied = 0

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def request_metrics(self, window: int = 300, now: float | None = None) -> dict[str, Any]:
        """Per-second series for the last ``window`` seconds plus summary
        numbers. The series ends at the current (partial) second."""
        window = max(10, min(int(window), WINDOW_SECONDS))
        now = self._clock() if now is None else now
        now_sec = int(now)
        with self._lock:
            seconds = dict(self._seconds)
            lat_cutoff = now - LATENCY_WINDOW_SECONDS
            lats = sorted(v for (t, v) in self._latencies if t >= lat_cutoff)
            denials = [d for d in self._denials if d["ts"] >= now - WINDOW_SECONDS]
            totals = {
                "calls": self.total_calls,
                "errors": self.total_errors,
                "denied": self.total_denied,
            }
        series = []
        for s in range(now_sec - window + 1, now_sec + 1):
            b = seconds.get(s)
            series.append({
                "t": s,
                "n": b[0] if b else 0,
                "e4": b[1] if b else 0,
                "e5": b[2] if b else 0,
                "denied": b[3] if b else 0,
            })

        def _sum(from_sec: int, idx: int) -> int:
            return sum(b[idx] for s, b in seconds.items() if from_sec <= s <= now_sec)

        last_full = seconds.get(now_sec - 1)
        last_10 = sum(b[0] for s, b in seconds.items() if now_sec - 10 <= s < now_sec)
        last_denial = denials[-1] if denials else None
        return {
            "now": now,
            "window": window,
            "series": series,
            "rps_last_second": last_full[0] if last_full else 0,
            "rps_10s_avg": round(last_10 / 10.0, 2),
            "requests_window": sum(p["n"] for p in series),
            "errors_15m": _sum(now_sec - WINDOW_SECONDS + 1, 1) + _sum(now_sec - WINDOW_SECONDS + 1, 2),
            "server_errors_15m": _sum(now_sec - WINDOW_SECONDS + 1, 2),
            "denied_15m": len(denials),
            "last_denial": _public(last_denial) if last_denial else None,
            "latency_samples": len(lats),
            "p50_ms": _round(_percentile(lats, 0.50)),
            "p99_ms": _round(_percentile(lats, 0.99)),
            "since_start": totals,
            "started_at": self.started_at,
        }

    def calls(
        self,
        limit: int = 200,
        since: int | None = None,
        account: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._calls)
        items.reverse()  # newest first
        out = []
        for rec in items:
            if since is not None and rec["seq"] <= since:
                break
            if account and rec.get("account_id") != account:
                continue
            out.append(_public(rec))
            if len(out) >= limit:
                break
        return out

    def changes(self, limit: int = 50, account: str | None = None) -> list[dict[str, Any]]:
        """Most recent change per resource (newest first)."""
        with self._lock:
            items = list(self._changes)
        items.reverse()
        seen: set[tuple] = set()
        out = []
        for rec in items:
            if account and rec.get("account_id") != account:
                continue
            res = rec.get("resource") or {}
            ident = (rec.get("account_id"), rec.get("service"), res.get("arn") or res.get("name"))
            if ident in seen:
                continue
            seen.add(ident)
            out.append(_public(rec))
            if len(out) >= limit:
                break
        return out

    def service_activity(
        self, minutes: int = 24, account: str | None = None, now: float | None = None,
    ) -> dict[str, list[int]]:
        """``{service: [calls per minute, oldest first]}`` for the last
        ``minutes`` minutes (the last bucket is the current minute)."""
        minutes = max(1, min(int(minutes), SERVICE_WINDOW_MINUTES))
        now_min = int((self._clock() if now is None else now) // 60)
        with self._lock:
            snapshot = {k: dict(v) for k, v in self._per_service.items()}
        out: dict[str, list[int]] = {}
        for (acct, svc), per_min in snapshot.items():
            if account and acct != account:
                continue
            row = out.setdefault(svc, [0] * minutes)
            for i, m in enumerate(range(now_min - minutes + 1, now_min + 1)):
                row[i] += per_min.get(m, 0)
        return out


def _round(v: float | None) -> float | None:
    return None if v is None else round(v, 2)


def _public(rec: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in rec.items() if not k.startswith("_")}


_TELEMETRY: Telemetry | None = None
_TELEMETRY_LOCK = threading.Lock()


def get_telemetry() -> Telemetry:
    global _TELEMETRY
    if _TELEMETRY is None:
        with _TELEMETRY_LOCK:
            if _TELEMETRY is None:
                _TELEMETRY = Telemetry()
    return _TELEMETRY


# ---------------------------------------------------------------------------
# Resource extraction
# ---------------------------------------------------------------------------

def _first(params: dict, *keys: str):
    for k in keys:
        v = params.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, list) and v and isinstance(v[0], str):
            return v[0]
    return None


def _tail(value: str, sep: str = "/") -> str:
    return value.rstrip(sep).rsplit(sep, 1)[-1]


def _find_arn(obj: Any, depth: int = 0) -> str | None:
    """First string value starting with ``arn:`` under a key ending in
    ``Arn`` / ``ARN`` (response shapes), searched two levels deep."""
    if depth > 2 or obj is None:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.startswith("arn:") and k.lower().endswith("arn"):
                return v
        for v in obj.values():
            if isinstance(v, (dict, list)):
                found = _find_arn(v, depth + 1)
                if found:
                    return found
    elif isinstance(obj, list) and obj:
        return _find_arn(obj[0], depth + 1)
    return None


def describe_resource(
    service: str,
    operation: str,
    params: dict | None,
    response: dict | None,
    region: str,
    account: str,
) -> dict[str, str] | None:
    """Best-effort ``{"name": ..., "arn": ...}`` for the resource a call
    touched, from the parsed request and (for creates) the response.
    Returns ``None`` when the call does not name a resource."""
    p = params if isinstance(params, dict) else {}
    r = response if isinstance(response, dict) else {}
    name: str | None = None
    arn: str | None = None
    try:
        if service == "s3":
            bucket = _first(p, "Bucket")
            if bucket:
                key = _first(p, "Key")
                name = f"{bucket}/{key}" if key else bucket
                arn = f"arn:aws:s3:::{name}"
        elif service == "dynamodb":
            table = _first(p, "TableName")
            if table:
                name = _tail(table)
                arn = table if table.startswith("arn:") else f"arn:aws:dynamodb:{region}:{account}:table/{table}"
        elif service == "sqs":
            url = _first(p, "QueueUrl") or r.get("QueueUrl")
            qname = _first(p, "QueueName") or (_tail(url) if isinstance(url, str) else None)
            if qname:
                name = qname
                arn = f"arn:aws:sqs:{region}:{account}:{qname}"
        elif service == "sns":
            topic = _first(p, "TopicArn") or r.get("TopicArn")
            if isinstance(topic, str) and topic:
                name, arn = _tail(topic, ":"), topic
            elif _first(p, "Name"):
                name = _first(p, "Name")
                arn = f"arn:aws:sns:{region}:{account}:{name}"
        elif service == "lambda":
            fn = _first(p, "FunctionName")
            if fn:
                name = fn.split(":function:", 1)[-1].split(":", 1)[0] if fn.startswith("arn:") else fn
                arn = r.get("FunctionArn") or f"arn:aws:lambda:{region}:{account}:function:{name}"
        elif service == "iam":
            for key, kind in (
                ("RoleName", "role"), ("UserName", "user"), ("GroupName", "group"),
                ("InstanceProfileName", "instance-profile"),
            ):
                v = _first(p, key)
                if v:
                    name, arn = v, f"arn:aws:iam::{account}:{kind}/{v}"
                    break
            if not name and _first(p, "PolicyArn"):
                arn = _first(p, "PolicyArn")
                name = _tail(arn)
            elif not name and _first(p, "PolicyName"):
                name = _first(p, "PolicyName")
        elif service == "ec2":
            # Creates name their new resource in the response (RunInstances
            # carries an ImageId in the request, which is not what changed).
            v = None
            inst = r.get("Instances")
            if isinstance(inst, list) and inst and isinstance(inst[0], dict):
                v = inst[0].get("InstanceId")
            for k in ("Vpc", "Subnet", "SecurityGroup", "NatGateway", "InternetGateway", "RouteTable", "Volume"):
                obj = r.get(k)
                if not v and isinstance(obj, dict):
                    v = obj.get(f"{k}Id")
            if not v and isinstance(r.get("GroupId"), str):
                v = r["GroupId"]
            if not v:
                v = _first(p, "InstanceIds", "InstanceId", "VpcId", "SubnetId", "GroupId", "VolumeId",
                           "NatGatewayId", "InternetGatewayId", "RouteTableId", "NetworkInterfaceId",
                           "ImageId", "KeyName")
            name = v
        elif service == "rds":
            name = _first(p, "DBInstanceIdentifier", "DBClusterIdentifier", "DBSubnetGroupName")
        elif service == "kms":
            name = _first(p, "KeyId", "AliasName")
            meta = r.get("KeyMetadata")
            if not name and isinstance(meta, dict):
                name, arn = meta.get("KeyId"), meta.get("Arn")
        elif service == "secretsmanager":
            name = _first(p, "SecretId", "Name")
            arn = r.get("ARN")
        elif service == "stepfunctions":
            v = _first(p, "stateMachineArn", "executionArn", "name")
            if v:
                name = _tail(v, ":") if v.startswith("arn:") else v
                arn = v if v.startswith("arn:") else r.get("stateMachineArn")
        elif service == "logs":
            name = _first(p, "logGroupName", "logGroupIdentifier")
        elif service == "kinesis":
            name = _first(p, "StreamName") or (_tail(_first(p, "StreamARN") or "") or None)
        elif service == "events":
            name = _first(p, "Name", "Rule", "EventBusName")
        elif service == "ssm":
            name = _first(p, "Name", "Names")
        elif service == "ecs":
            name = _first(p, "clusterName", "cluster", "serviceName", "family", "taskDefinition")
        elif service == "cloudformation":
            name = _first(p, "StackName")
        else:
            name = _first(
                p, "Name", "name", "ClusterName", "clusterName", "DomainName",
                "TableName", "StreamName", "DeliveryStreamName", "BrokerName",
                "UserPoolId", "IdentityPoolId", "RestApiId", "ApiId", "Id", "ResourceArn",
            )
    except Exception:
        LOG.debug("resource extraction failed for %s.%s", service, operation, exc_info=True)
    if not arn:
        arn = _find_arn(r)
        if arn and not name:
            name = _tail(_tail(arn, ":"))
    if not name:
        return None
    return {"name": str(name), "arn": str(arn or "")}


# ---------------------------------------------------------------------------
# Principal resolution
# ---------------------------------------------------------------------------

_PRINCIPAL_TTL = 10.0
_principal_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def resolve_principal(access_key: str, account_id: str, region: str) -> dict[str, str]:
    """``{"arn", "type", "access_key"}`` for the caller, using the same
    resolver the IAM enforcer uses. Unresolvable keys report type
    ``"unresolved"`` and no ARN (an unknown key is shown as itself rather
    than as an invented identity)."""
    if not access_key:
        return {"arn": "", "type": "anonymous", "access_key": ""}
    key = (access_key, account_id)
    now = time.time()
    cached = _principal_cache.get(key)
    if cached and now - cached[0] < _PRINCIPAL_TTL:
        return cached[1]
    result = {"arn": "", "type": "unresolved", "access_key": access_key}
    try:
        # resolve_caller indexes moto's iam_backends[account], which would
        # lazily create an IAM backend for an account that never used IAM.
        # Such an account has no IAM users or roles, so only the root /
        # anonymous checks (which need no backend) can match; skip the
        # lookup rather than create state as a side effect of observing.
        from moto.iam.models import iam_backends

        from localemu.services.iam_enforcement.identity import resolve_caller

        if account_id not in iam_backends:
            from localemu.constants import ANONYMOUS_ACCESS_KEY_ID
            from localemu.services.iam_enforcement.identity import _get_root_access_keys

            if access_key == ANONYMOUS_ACCESS_KEY_ID or access_key in _get_root_access_keys():
                caller = resolve_caller(access_key, account_id, region)
            else:
                caller = None
        else:
            caller = resolve_caller(access_key, account_id, region)
        if caller is not None:
            result = {
                "arn": caller.arn if caller.arn != "*" else "",
                "type": caller.principal_type,
                "access_key": access_key,
            }
    except Exception:
        LOG.debug("principal resolution failed", exc_info=True)
    if len(_principal_cache) > 2048:
        _principal_cache.clear()
    _principal_cache[key] = (now, result)
    return result


# ---------------------------------------------------------------------------
# Audit-mode denial capture (IAM_ENFORCEMENT=soft)
# ---------------------------------------------------------------------------

_tls = threading.local()
ENFORCER_LOGGER = "localemu.services.iam_enforcement.enforcer"


class _AuditDenyCapture(logging.Filter):
    """Attached to the IAM enforcer's logger. Never suppresses records;
    it only remembers the last denial message on the current thread."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.msg if isinstance(record.msg, str) else ""
            if msg.startswith("IAM AUDIT DENY"):
                _tls.denial = ("audit", record.getMessage().split(": ", 1)[-1])
            elif msg.startswith("IAM DENY"):
                _tls.denial = ("enforced", record.getMessage().split(": ", 1)[-1])
        except Exception:
            pass
        return True


_capture_filter = _AuditDenyCapture()


def install_denial_capture() -> None:
    logger = logging.getLogger(ENFORCER_LOGGER)
    if _capture_filter not in logger.filters:
        logger.addFilter(_capture_filter)


def _pop_denial() -> tuple[str, str] | None:
    d = getattr(_tls, "denial", None)
    _tls.denial = None
    return d


# ---------------------------------------------------------------------------
# Handler-chain hooks
# ---------------------------------------------------------------------------

def telemetry_request_start(chain, context, response) -> None:
    """Early request handler: stamp the start time, clear stale state."""
    try:
        context._le_console_t0 = time.perf_counter()  # type: ignore[attr-defined]
    except Exception:
        pass
    _tls.denial = None


telemetry_request_start._le_handler_tag = "console-telemetry-start"  # type: ignore[attr-defined]


CONSOLE_UA_MARKER = "LocalEmu-Console/"


def _should_skip(context, user_agent: str) -> bool:
    try:
        from localemu.services.cloudtrail.recording_hook import (
            _DASHBOARD_USER_AGENT_PREFIX,
            _INTERNAL_CALL_USER_AGENT_MARKER,
            _is_internal_dashboard_call,
        )
    except Exception:
        return False
    if user_agent.startswith(_DASHBOARD_USER_AGENT_PREFIX):
        return True
    if _INTERNAL_CALL_USER_AGENT_MARKER in user_agent:
        return True
    return _is_internal_dashboard_call()


def _access_key(context) -> str:
    try:
        auth = context.request.headers.get("Authorization", "") or ""
        if "Credential=" in auth:
            return auth.split("Credential=")[1].split(",")[0].split("/")[0]
        cred = context.request.args.get("X-Amz-Credential")
        if cred:
            return cred.split("/")[0]
    except Exception:
        pass
    return ""


def telemetry_response_handler(chain, context, response) -> None:
    """Response handler: build and record one call record."""
    try:
        if not (context.service and context.operation):
            _tls.denial = None
            return
        service = context.service.service_name
        operation = context.operation.name
        user_agent = ""
        try:
            user_agent = context.request.headers.get("User-Agent", "") or ""
        except Exception:
            pass
        denial = _pop_denial()
        if _should_skip(context, user_agent):
            return

        t0 = getattr(context, "_le_console_t0", None)
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2) if t0 else None
        status = int(getattr(response, "status_code", 0) or 0)
        account = str(getattr(context, "account_id", "") or "")
        region = str(getattr(context, "region", "") or "")

        error_code = error_message = None
        exc = getattr(context, "service_exception", None)
        if exc is not None:
            error_code = getattr(exc, "code", None) or type(exc).__name__
            error_message = str(getattr(exc, "message", "") or exc)[:500]

        denied = None
        denial_reason = None
        if status == 403 and error_code in _DENIAL_CODES:
            denied = "enforced"
            denial_reason = (denial[1] if denial else None) or error_message
        elif denial and denial[0] == "audit":
            denied = "audit"
            denial_reason = denial[1]

        from .bus import is_mutating

        params = getattr(context, "service_request", None)
        resp_body = getattr(context, "service_response", None)
        resource = describe_resource(service, operation, params, resp_body, region, account)
        principal = resolve_principal(_access_key(context), account, region)

        # LocalEmu-to-LocalEmu calls (connect_to clients carry the
        # x-localemu-data header): service integrations, event delivery,
        # the console's own actions. Recorded, but labelled with what made
        # them so the feed does not pass them off as the user's calls.
        internal = bool(getattr(context, "is_internal_call", False))
        via = None
        if CONSOLE_UA_MARKER in user_agent:
            via = "console"
        elif internal:
            irp = getattr(context, "internal_request_params", None) or {}
            via = irp.get("service_principal") or irp.get("source_arn") or "localemu"

        record = {
            "ts": time.time(),
            "service": service,
            "operation": operation,
            "status": status,
            "error_code": error_code,
            "error_message": error_message,
            "account_id": account,
            "region": region,
            "request_id": str(getattr(context, "request_id", "") or ""),
            "latency_ms": latency_ms,
            "principal": principal,
            "user_agent": user_agent[:200],
            "source_ip": getattr(context.request, "remote_addr", "") or "",
            "resource": resource,
            "mutating": bool(is_mutating(operation)),
            "denied": denied,
            "denial_reason": denial_reason,
            "internal": internal,
            "via": via,
        }
        stored = get_telemetry().record(record)

        try:
            from .bus import get_bus

            get_bus().publish(
                kind="call",
                tags=("call", f"service:{service}"),
                payload=_public(stored),
            )
        except Exception:
            LOG.debug("console call publish failed", exc_info=True)

        if stored["mutating"] and 200 <= status < 300:
            try:
                from .api import invalidate_count_cache

                invalidate_count_cache(service)
                if service == "ec2":
                    invalidate_count_cache("vpc")
            except Exception:
                pass
    except Exception:
        LOG.debug("console telemetry handler failed", exc_info=True)


telemetry_response_handler._le_handler_tag = "console-telemetry"  # type: ignore[attr-defined]


def register_telemetry_handlers() -> None:
    """Idempotently add the two handlers to the gateway chain."""
    from localemu.aws import handlers

    pre = handlers.preprocess_request.handlers
    if not any(getattr(h, "_le_handler_tag", None) == "console-telemetry-start" for h in pre):
        pre.insert(0, telemetry_request_start)
    post = handlers.run_custom_response_handlers.handlers
    if not any(getattr(h, "_le_handler_tag", None) == "console-telemetry" for h in post):
        post.append(telemetry_response_handler)
    install_denial_capture()
