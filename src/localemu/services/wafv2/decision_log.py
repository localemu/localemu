"""In-memory, queryable per-request WAFv2 decision log.

Same shape and lifetime as ``iam_enforcement.decision_log`` (a bounded
ring buffer, newest first, reset on server restart) - not reused
directly because its fields are IAM-shaped (principal_arn/action/
resource), not request-shaped.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

_MAX_DECISIONS = 2000
_lock = threading.Lock()
_decisions: deque[dict[str, Any]] = deque(maxlen=_MAX_DECISIONS)
_next_id = 0


def record_decision(
    *,
    decision: str,
    web_acl_arn: str,
    resource_arn: str,
    rule_name: str | None,
    method: str,
    uri_path: str,
    source_ip: str,
    counted_rules: list[str] | None = None,
) -> None:
    global _next_id
    with _lock:
        _next_id += 1
        _decisions.appendleft({
            "id": _next_id,
            "timestamp": time.time(),
            "decision": decision,
            "web_acl_arn": web_acl_arn,
            "resource_arn": resource_arn,
            "matched_rule": rule_name,
            "method": method,
            "uri_path": uri_path,
            "source_ip": source_ip,
            "counted_rules": counted_rules or [],
        })


def query_decisions(
    *,
    limit: int = 100,
    resource_arn: str | None = None,
    decision: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, _MAX_DECISIONS))
    with _lock:
        snapshot = list(_decisions)
    results = []
    for entry in snapshot:
        if resource_arn and entry["resource_arn"] != resource_arn:
            continue
        if decision and entry["decision"] != decision:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def clear_decisions() -> None:
    with _lock:
        _decisions.clear()
