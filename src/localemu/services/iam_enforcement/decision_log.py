"""In-memory, queryable per-request IAM authorization decision log.

DEBUG-level log lines already show the reasoning for each decision, but
a blue team / lab needs something it can actually query via the API -
"show me every decision for this principal/action" - not grep a server
log file. This is a bounded ring buffer (newest first), not a
persisted audit trail: it resets on server restart, same lifetime as
every other in-memory LocalEmu store.
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
    principal_arn: str,
    account_id: str | None,
    action: str,
    resource: str,
    reason: str,
    source: str | None = None,
    statement: dict | None = None,
) -> None:
    global _next_id
    with _lock:
        _next_id += 1
        _decisions.appendleft({
            "id": _next_id,
            "timestamp": time.time(),
            "decision": decision,
            "principal_arn": principal_arn,
            "account_id": account_id,
            "action": action,
            "resource": resource,
            "reason": reason,
            "source": source,
            "matched_statement": statement,
        })


def query_decisions(
    *,
    limit: int = 100,
    principal_arn: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    decision: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, _MAX_DECISIONS))
    with _lock:
        snapshot = list(_decisions)
    results = []
    for entry in snapshot:
        if principal_arn and entry["principal_arn"] != principal_arn:
            continue
        if action and entry["action"] != action:
            continue
        if resource and entry["resource"] != resource:
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


def total_recorded() -> int:
    with _lock:
        return len(_decisions)
