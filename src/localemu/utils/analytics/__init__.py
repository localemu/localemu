"""LocalEmu does not collect telemetry. This module is an inert no-op shim.

Historical context: this directory inherited a full analytics pipeline from the
LocalStack codebase (HTTP client to an external events endpoint, persistent
salted machine fingerprint at ~/.cache/localemu/machine.json, per-service
counters, a runtime hook that reported environment variables, and a
ServiceRequestAggregator that batched AWS API call metadata). All of that has
been removed.

What remains in this file is a tiny compatibility layer so that legacy
``from localemu.utils.analytics import log`` and ``get_session_id`` import
sites continue to resolve — both are no-ops that never touch the network and
never write to disk.
"""

from __future__ import annotations


class _NoOpLog:
    """No-op replacement for the former EventLogger.

    Accepts any ``event(name, **kwargs)`` or ``event(name, payload)`` shape so
    historical call sites keep working without raising. Does nothing.
    """

    def event(self, *args, **kwargs) -> None:
        return None


log = _NoOpLog()


_SESSION_ID = "00000000-0000-0000-0000-000000000000"


def get_session_id() -> str:
    """Return a stable constant session ID. No machine fingerprint, no persistence."""
    return _SESSION_ID
