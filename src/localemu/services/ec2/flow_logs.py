"""VPC Flow Log subscription registry.

Closes the "flow log destination hardcoded to /localemu/vpc-flow-logs"
gap by tracking the per-FlowLog destination the user actually asked
for in ``CreateFlowLogs`` and exposing a router the
:class:`FlowLogRecorder` uses to fan a captured ``FlowLogEntry`` out
to the right CloudWatch log group(s) — one per matching subscription.

Scope of this MVP:

* CloudWatch Logs destinations (the format covered by the previous
  hard-coded path). S3 + Firehose destinations are accepted at
  registration time but currently delivered to a per-FlowLog CWL
  fallback stream until the dedicated dispatchers land.
* ``ResourceType`` = NetworkInterface matches by ENI id directly.
  Subnet- and VPC-scoped subscriptions resolve the entry's ENI →
  subnet/vpc via :class:`AddressIndex` at flush time.
* ``TrafficType`` filtering (ACCEPT / REJECT / ALL).
* Default v2 log layout. Custom ``LogFormat`` is preserved on the
  subscription so the dispatcher can render it once we wire format
  compilation.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Literal

LOG = logging.getLogger(__name__)

# Backwards-compat: when no subscription matches an entry, fall back
# to this group so dashboards built against the legacy path keep
# seeing records. Tarek can opt out via FLOW_LOGS_LEGACY_GROUP=0.
LEGACY_GROUP = "/localemu/vpc-flow-logs"


ResourceType = Literal["VPC", "Subnet", "NetworkInterface"]
TrafficType = Literal["ACCEPT", "REJECT", "ALL"]
DestinationType = Literal[
    "cloud-watch-logs", "s3", "kinesis-data-firehose",
]


@dataclass(frozen=True)
class FlowLogSubscription:
    """One ``CreateFlowLogs`` call → one subscription per ResourceId.

    Immutable so :meth:`FlowLogSubscriptionRegistry.matches_eni` can
    return references without copying. ``log_group`` is the
    user-supplied CWL group name (or ``LEGACY_GROUP`` when the user
    asked for S3/Firehose — we fall back to a stream named after the
    flow log id under the legacy group until the real dispatchers
    land)."""
    flow_log_id: str
    account_id: str
    region: str
    resource_type: ResourceType
    resource_id: str  # one of vpc-..., subnet-..., eni-...
    traffic_type: TrafficType
    destination_type: DestinationType
    log_group: str
    s3_destination: str | None = None
    log_format: str | None = None


class FlowLogSubscriptionRegistry:
    """Process-wide registry. Thread-safe. The provider populates it
    on ``CreateFlowLogs`` and drains it on ``DeleteFlowLogs``; the
    recorder reads it on flush.

    ENI → subnet → vpc resolution for non-ENI scopes is delegated
    to the AddressIndex so we don't duplicate the mapping."""

    def __init__(self) -> None:
        self._by_id: dict[str, FlowLogSubscription] = {}
        self._lock = threading.RLock()

    # -- write path ---------------------------------------------------

    def register(self, sub: FlowLogSubscription) -> None:
        with self._lock:
            self._by_id[sub.flow_log_id] = sub
        LOG.info(
            "flow log %s registered: %s/%s -> %s (%s)",
            sub.flow_log_id, sub.resource_type, sub.resource_id,
            sub.log_group, sub.destination_type,
        )

    def deregister(self, flow_log_id: str) -> None:
        with self._lock:
            self._by_id.pop(flow_log_id, None)

    def clear(self) -> None:
        """Tests-only: drop every subscription."""
        with self._lock:
            self._by_id.clear()

    # -- read path ----------------------------------------------------

    def all(self) -> list[FlowLogSubscription]:
        with self._lock:
            return list(self._by_id.values())

    def matches_eni(
        self, eni_id: str, action: str,
    ) -> list[FlowLogSubscription]:
        """Return every subscription whose scope contains ``eni_id``
        and whose ``TrafficType`` accepts ``action``.

        ``action`` is the AWS-canonical "ACCEPT" / "REJECT" form the
        recorder already emits. The ``ALL`` traffic type matches both.
        """
        action_norm = (action or "").upper()
        eni_subnet = None  # lazy: only resolve if a Subnet/VPC sub exists
        eni_vpc = None
        out: list[FlowLogSubscription] = []
        for sub in self.all():
            if sub.traffic_type != "ALL" and sub.traffic_type != action_norm:
                continue
            if sub.resource_type == "NetworkInterface":
                if sub.resource_id == eni_id:
                    out.append(sub)
                continue
            if eni_subnet is None and eni_vpc is None:
                eni_subnet, eni_vpc = _resolve_eni_scope(eni_id)
            if sub.resource_type == "Subnet" and sub.resource_id == eni_subnet:
                out.append(sub)
            elif sub.resource_type == "VPC" and sub.resource_id == eni_vpc:
                out.append(sub)
        return out


def _resolve_eni_scope(eni_id: str) -> tuple[str | None, str | None]:
    """Return ``(subnet_id, vpc_id)`` for ``eni_id`` via the
    AddressIndex, or ``(None, None)`` when the ENI is unknown there.

    The AddressIndex carries ENIs for both standalone ``CreateNetworkInterface``
    calls and the primary-ENI synthesis done at ``RunInstances`` time
    (when ``LOCALEMU_VPC_IP_PINNING`` is on), so this covers both the
    explicit and the implicit-ENI cases."""
    try:
        from localemu.services.ec2.docker.address_index import (
            get_address_index,
        )
        entry = get_address_index().get_eni(eni_id)
        if entry is None:
            return None, None
        return entry.subnet_id, entry.vpc_id
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Process-wide singleton + accessors
# ---------------------------------------------------------------------------

_registry: FlowLogSubscriptionRegistry | None = None
_lock = threading.Lock()


def get_flow_log_subscriptions() -> FlowLogSubscriptionRegistry:
    global _registry
    if _registry is None:
        with _lock:
            if _registry is None:
                _registry = FlowLogSubscriptionRegistry()
    return _registry


def reset_for_tests() -> None:
    """Drop the singleton (and any subscriptions in it) so unit tests
    don't leak state between cases."""
    global _registry
    with _lock:
        _registry = None
