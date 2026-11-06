"""HTTP endpoints added for the 1.4.0 console.

All read-only, all loopback-gated through ``plugins._GatedResource``:

* ``GET /_localemu/api/system``            instance health (version, uptime,
                                           endpoint, IAM mode, Docker, Ollama)
* ``GET /_localemu/api/metrics/requests``  requests/s series, errors, p50/p99,
                                           IAM denials (``?window=`` seconds)
* ``GET /_localemu/api/calls``             enriched recent API calls
                                           (``?limit=&since=<seq>&account=``)
* ``GET /_localemu/api/changes``           recently changed resources
                                           (``?limit=&account=``)
* ``GET /_localemu/api/metrics/services``  per-service calls per minute
                                           (``?minutes=&account=``)
"""
from __future__ import annotations

from localemu.http import Request

from .api import _json_response, _safe_int, _valid_account_param
from .telemetry import get_telemetry


class SystemResource:
    def on_get(self, request: Request):
        from .system import system_snapshot

        host_url = None
        try:
            host_url = request.host_url
        except Exception:
            pass
        return _json_response(system_snapshot(host_url))


class RequestMetricsResource:
    def on_get(self, request: Request):
        window = _safe_int(request.args.get("window", "300"), 300, minimum=10, maximum=900)
        return _json_response(get_telemetry().request_metrics(window=window))


class CallsResource:
    def on_get(self, request: Request):
        limit = _safe_int(request.args.get("limit", "200"), 200, minimum=1, maximum=500)
        since_raw = request.args.get("since")
        since = _safe_int(since_raw, 0, minimum=0, maximum=2**62) if since_raw else None
        account = _valid_account_param(request.args.get("account"))
        t = get_telemetry()
        calls = t.calls(limit=limit, since=since, account=account)
        return _json_response({
            "calls": calls,
            "buffer_size": 500,
            "total_since_start": t.total_calls,
        })


class ChangesResource:
    def on_get(self, request: Request):
        limit = _safe_int(request.args.get("limit", "50"), 50, minimum=1, maximum=200)
        account = _valid_account_param(request.args.get("account"))
        return _json_response({"changes": get_telemetry().changes(limit=limit, account=account)})


class ServiceActivityResource:
    def on_get(self, request: Request):
        minutes = _safe_int(request.args.get("minutes", "24"), 24, minimum=1, maximum=30)
        account = _valid_account_param(request.args.get("account"))
        return _json_response({
            "minutes": minutes,
            "services": get_telemetry().service_activity(minutes=minutes, account=account),
        })
