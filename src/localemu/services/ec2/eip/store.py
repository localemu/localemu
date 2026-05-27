"""Persistent state for EIP allocations + associations.

The provider's ``AllocateAddress`` handler inserts here on top of
moto so we have a place to hang LocalEmu-specific facts (host
listener ports, container ip resolved at associate time) that don't
fit on the moto record. Survives ``PERSISTENCE=1`` via the standard
state pickler.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EipAssociation:
    """One ``AssociateAddress`` row.

    ``proxies`` maps ``container_port -> host_listener_port`` for the
    userspace-proxy path. Empty on the DNAT path (the kernel needs no
    per-port state). Re-populated on a fresh attach / on persistence
    load; not pickled across restarts because host ports may have
    been claimed by another process in the interim."""
    allocation_id: str
    public_ip: str
    instance_id: str
    network_interface_id: Optional[str] = None
    private_ip: Optional[str] = None
    association_id: Optional[str] = None
    container_ip: Optional[str] = None
    container_name: Optional[str] = None
    proxies: dict[int, int] = field(default_factory=dict)


@dataclass
class EipStore:
    """One per (account_id, region). Holds the LocalEmu view of EIPs."""
    account_id: str
    region: str
    # allocation_id → public_ip (the moto record holds the rest; we
    # only need the IP here so associate() can find it without
    # importing moto).
    allocations: dict[str, str] = field(default_factory=dict)
    # association_id → EipAssociation
    associations: dict[str, EipAssociation] = field(default_factory=dict)
    # public_ip → association_id (reverse lookup for incoming
    # connections on the proxy path)
    _by_ip: dict[str, str] = field(default_factory=dict)

    def register_allocation(self, allocation_id: str, public_ip: str) -> None:
        self.allocations[allocation_id] = public_ip

    def drop_allocation(self, allocation_id: str) -> None:
        self.allocations.pop(allocation_id, None)

    def register_association(self, assoc: EipAssociation) -> None:
        self.associations[assoc.association_id or assoc.allocation_id] = assoc
        self._by_ip[assoc.public_ip] = assoc.association_id or assoc.allocation_id

    def drop_association(self, association_id: str) -> EipAssociation | None:
        assoc = self.associations.pop(association_id, None)
        if assoc and assoc.public_ip in self._by_ip:
            self._by_ip.pop(assoc.public_ip, None)
        return assoc

    def by_ip(self, public_ip: str) -> EipAssociation | None:
        aid = self._by_ip.get(public_ip)
        if aid is None:
            return None
        return self.associations.get(aid)

    def by_allocation(self, allocation_id: str) -> EipAssociation | None:
        for assoc in self.associations.values():
            if assoc.allocation_id == allocation_id:
                return assoc
        return None


# ---------------------------------------------------------------------------
# Process-wide registry keyed by (account_id, region)
# ---------------------------------------------------------------------------

_stores: dict[tuple[str, str], EipStore] = {}
_lock = threading.RLock()


def get_eip_store(account_id: str, region: str) -> EipStore:
    """Return the EipStore for this (account, region), creating it
    lazily. Thread-safe."""
    key = (account_id, region)
    with _lock:
        store = _stores.get(key)
        if store is None:
            store = EipStore(account_id=account_id, region=region)
            _stores[key] = store
        return store


def all_stores() -> list[EipStore]:
    """Snapshot of all stores; used by the dashboard + persistence."""
    with _lock:
        return list(_stores.values())


def reset_for_tests() -> None:
    with _lock:
        _stores.clear()
