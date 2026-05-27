"""Central directory of container network addressing.

For every ENI in every running container, this index records:
  - primary IPv4 + secondary IPv4 list
  - MAC address (deterministic from primary IP — see derive_mac)
  - VPC and subnet membership
  - attached instance + interface name
  - the security groups attached to this ENI

Provides O(1) lookups in both directions:
  - ip -> ENI (used by NACL evaluation, source-IP audit, peering)
  - eni -> { ip, sg_ids, ... } (used by ModifyNetworkInterfaceAttribute)
  - instance -> [ENI, ...] (used by DescribeInstances enrichment)
  - sg_id -> { eni, ... } (used by the SG ipset programmer to compute
              cross-SG-reference membership — fixes the silent-allow bug
              at sg_iptables.py:93-94)

The index is populated from:
  - vm_manager.create_instance (synthesizes an implicit primary ENI per
    instance, mirroring AWS's RunInstances behavior)
  - db_manager.create_db_instance (synthesizes an RDS ENI)
  - ENI lifecycle handlers in services/ec2/provider.py (design 08)

Persisted as JSON under ``~/.localemu/data/address_index.state`` and
reconciled against Docker on startup by ``address_reconciler``.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Iterable, Optional

LOG = logging.getLogger(__name__)

SCHEMA_VERSION = 2  # v2 added source_dest_check / delete_on_termination / device_index


# ---------------------------------------------------------------------------
# MAC derivation
# ---------------------------------------------------------------------------
def derive_mac(ip: str | ipaddress.IPv4Address) -> str:
    """Derive a deterministic MAC from a primary IPv4 address.

    Uses Docker's own bridge MAC scheme: the first two octets are
    ``02:42`` (Docker's locally-administered unicast OUI), the last
    four octets are the IP's four bytes. This matches what Docker
    would have generated if it had picked the IP itself, so handing
    the resulting MAC to ``mac_address=`` on container create produces
    the same MAC the daemon would have produced anyway — but
    reproducible across restarts.

    Example: 10.0.0.5 -> "02:42:0a:00:00:05"
    """
    addr = (
        ip if isinstance(ip, ipaddress.IPv4Address)
        else ipaddress.IPv4Address(ip)
    )
    return "02:42:" + ":".join(f"{b:02x}" for b in addr.packed)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class EniEntry:
    """One entry per ENI. Mirrors AWS's NetworkInterface plus the
    LocalEmu-specific iface_name (the in-container ``eth0``/``eth1``).
    """
    eni_id: str
    vpc_id: str
    subnet_id: str
    primary_ip: ipaddress.IPv4Address
    mac: str  # "02:42:xx:xx:xx:xx"
    secondary_ips: list[ipaddress.IPv4Address] = field(default_factory=list)
    sg_ids: list[str] = field(default_factory=list)  # order matters (AWS contract)
    instance_id: Optional[str] = None  # None when detached
    iface_name: Optional[str] = None  # set on attach
    # v2 fields (default per AWS API defaults)
    source_dest_check: bool = True
    delete_on_termination: bool = True
    device_index: Optional[int] = None  # set on attach; None when detached
    # True when this ENI shares an existing in-container interface with
    # another ENI on the same VPC bridge (Docker rejects two endpoints
    # from one container into the same bridge). In shared mode, the IP
    # is added/removed via ``ip addr add/del`` against the existing
    # iface instead of through ``connect/disconnect_container_from_network``.
    shared_iface: bool = False

    def all_ips(self) -> list[ipaddress.IPv4Address]:
        return [self.primary_ip, *self.secondary_ips]


# ---------------------------------------------------------------------------
# AddressIndex
# ---------------------------------------------------------------------------
class AddressIndex:
    """Process-wide ENI / address index.

    Thread-safe via a single RLock. All operations short.

    Lock ordering when caller also holds other locks:
      vpc_network._lock > subnet_allocator._lock > address_index._lock
    """

    def __init__(self) -> None:
        self._enis: dict[str, EniEntry] = {}
        # ip -> eni_id (primary OR secondary)
        self._ip_to_eni: dict[ipaddress.IPv4Address, str] = {}
        # instance_id -> ordered list of eni_ids (primary first)
        self._instance_to_enis: dict[str, list[str]] = {}
        # sg_id -> set of eni_ids carrying that SG
        self._sg_to_enis: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    # -- ENI lifecycle ------------------------------------------------------

    def register_eni(
        self,
        eni_id: str,
        vpc_id: str,
        subnet_id: str,
        primary_ip: str | ipaddress.IPv4Address,
        mac: Optional[str] = None,
        sg_ids: Optional[Iterable[str]] = None,
        instance_id: Optional[str] = None,
        iface_name: Optional[str] = None,
        secondary_ips: Optional[Iterable[str | ipaddress.IPv4Address]] = None,
    ) -> EniEntry:
        """Create a new ENI entry. If ``mac`` is None, derives one from
        the primary IP. Raises ValueError on duplicate eni_id."""
        primary = (
            primary_ip if isinstance(primary_ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(primary_ip)
        )
        if mac is None:
            mac = derive_mac(primary)
        secondaries = [
            (s if isinstance(s, ipaddress.IPv4Address) else ipaddress.IPv4Address(s))
            for s in (secondary_ips or [])
        ]
        sg_list = list(sg_ids or [])

        with self._lock:
            if eni_id in self._enis:
                raise ValueError(f"ENI {eni_id} already registered")
            entry = EniEntry(
                eni_id=eni_id,
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                primary_ip=primary,
                mac=mac,
                secondary_ips=secondaries,
                sg_ids=sg_list,
                instance_id=instance_id,
                iface_name=iface_name,
            )
            self._enis[eni_id] = entry
            self._ip_to_eni[primary] = eni_id
            for s_ip in secondaries:
                self._ip_to_eni[s_ip] = eni_id
            if instance_id:
                self._instance_to_enis.setdefault(instance_id, []).append(eni_id)
            for sg in sg_list:
                self._sg_to_enis.setdefault(sg, set()).add(eni_id)
            return entry

    def attach_eni(
        self, eni_id: str, instance_id: str, iface_name: str,
    ) -> None:
        """Attach an existing ENI to an instance. Updates indexes."""
        with self._lock:
            entry = self._enis.get(eni_id)
            if entry is None:
                raise KeyError(f"unknown ENI {eni_id}")
            if entry.instance_id == instance_id:
                # Idempotent — update iface_name in case it changed
                entry.iface_name = iface_name
                return
            if entry.instance_id is not None:
                # Detach from previous instance first
                self._remove_eni_from_instance(eni_id, entry.instance_id)
            entry.instance_id = instance_id
            entry.iface_name = iface_name
            self._instance_to_enis.setdefault(instance_id, []).append(eni_id)

    def detach_eni(self, eni_id: str) -> None:
        """Detach an ENI from its instance (does not delete the ENI)."""
        with self._lock:
            entry = self._enis.get(eni_id)
            if entry is None:
                return
            if entry.instance_id is not None:
                self._remove_eni_from_instance(eni_id, entry.instance_id)
            entry.instance_id = None
            entry.iface_name = None

    def delete_eni(self, eni_id: str) -> Optional[EniEntry]:
        """Remove the ENI from every index. Returns the removed entry
        (so the caller can release the IPs in the allocator)."""
        with self._lock:
            entry = self._enis.pop(eni_id, None)
            if entry is None:
                return None
            # Remove from ip -> eni index
            self._ip_to_eni.pop(entry.primary_ip, None)
            for s_ip in entry.secondary_ips:
                self._ip_to_eni.pop(s_ip, None)
            # Remove from instance -> enis index
            if entry.instance_id is not None:
                self._remove_eni_from_instance(eni_id, entry.instance_id)
            # Remove from sg -> enis index
            for sg in entry.sg_ids:
                bucket = self._sg_to_enis.get(sg)
                if bucket is not None:
                    bucket.discard(eni_id)
                    if not bucket:
                        del self._sg_to_enis[sg]
            return entry

    def _remove_eni_from_instance(
        self, eni_id: str, instance_id: str,
    ) -> None:
        """Internal: drop eni_id from _instance_to_enis. Caller holds _lock."""
        enis = self._instance_to_enis.get(instance_id)
        if enis is None:
            return
        try:
            enis.remove(eni_id)
        except ValueError:
            pass
        if not enis:
            del self._instance_to_enis[instance_id]

    # -- secondary IPs ------------------------------------------------------

    def add_secondary_ip(
        self, eni_id: str, ip: str | ipaddress.IPv4Address,
    ) -> None:
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        with self._lock:
            entry = self._enis.get(eni_id)
            if entry is None:
                raise KeyError(f"unknown ENI {eni_id}")
            if addr == entry.primary_ip or addr in entry.secondary_ips:
                return  # idempotent
            entry.secondary_ips.append(addr)
            self._ip_to_eni[addr] = eni_id

    def remove_secondary_ip(
        self, eni_id: str, ip: str | ipaddress.IPv4Address,
    ) -> None:
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        with self._lock:
            entry = self._enis.get(eni_id)
            if entry is None:
                return
            try:
                entry.secondary_ips.remove(addr)
            except ValueError:
                return
            self._ip_to_eni.pop(addr, None)

    # -- SG membership ------------------------------------------------------

    def update_sgs(self, eni_id: str, sg_ids: Iterable[str]) -> None:
        """Replace the SG list on an ENI. Updates the sg -> enis index."""
        new_sgs = list(sg_ids)
        with self._lock:
            entry = self._enis.get(eni_id)
            if entry is None:
                raise KeyError(f"unknown ENI {eni_id}")
            old_sgs = set(entry.sg_ids)
            new_set = set(new_sgs)
            # Remove from buckets we left
            for sg in old_sgs - new_set:
                bucket = self._sg_to_enis.get(sg)
                if bucket is not None:
                    bucket.discard(eni_id)
                    if not bucket:
                        del self._sg_to_enis[sg]
            # Add to buckets we joined
            for sg in new_set - old_sgs:
                self._sg_to_enis.setdefault(sg, set()).add(eni_id)
            entry.sg_ids = new_sgs

    # -- read paths ---------------------------------------------------------

    def get_eni(self, eni_id: str) -> Optional[EniEntry]:
        with self._lock:
            return self._enis.get(eni_id)

    def get_eni_for_ip(
        self, ip: str | ipaddress.IPv4Address,
    ) -> Optional[EniEntry]:
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        with self._lock:
            eni_id = self._ip_to_eni.get(addr)
            if eni_id is None:
                return None
            return self._enis.get(eni_id)

    def get_enis_for_instance(self, instance_id: str) -> list[EniEntry]:
        """Returns ENIs in attach order (primary first)."""
        with self._lock:
            eni_ids = self._instance_to_enis.get(instance_id, [])
            return [self._enis[eid] for eid in eni_ids if eid in self._enis]

    def get_primary_ip_for_instance(
        self, instance_id: str,
    ) -> Optional[ipaddress.IPv4Address]:
        """Return the primary ENI's primary_ip, or None if no ENIs."""
        with self._lock:
            eni_ids = self._instance_to_enis.get(instance_id, [])
            if not eni_ids:
                return None
            entry = self._enis.get(eni_ids[0])
            return entry.primary_ip if entry else None

    def get_ips_for_sg(
        self, sg_id: str,
    ) -> set[ipaddress.IPv4Address]:
        """Return every IP (primary + secondary) on every ENI carrying
        this SG. This is the membership the ipset programmer reads to
        emit `-m set --match-set le-sg-<id>-v4 src` rules."""
        with self._lock:
            eni_ids = self._sg_to_enis.get(sg_id, set())
            ips: set[ipaddress.IPv4Address] = set()
            for eid in eni_ids:
                entry = self._enis.get(eid)
                if entry is not None:
                    ips.add(entry.primary_ip)
                    ips.update(entry.secondary_ips)
            return ips

    def all_enis(self) -> list[EniEntry]:
        with self._lock:
            return list(self._enis.values())

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        with self._lock:
            enis_json = []
            for entry in self._enis.values():
                enis_json.append({
                    "eni_id": entry.eni_id,
                    "vpc_id": entry.vpc_id,
                    "subnet_id": entry.subnet_id,
                    "primary_ip": str(entry.primary_ip),
                    "mac": entry.mac,
                    "secondary_ips": [str(s) for s in entry.secondary_ips],
                    "sg_ids": list(entry.sg_ids),
                    "instance_id": entry.instance_id,
                    "iface_name": entry.iface_name,
                    # v2 fields
                    "source_dest_check": entry.source_dest_check,
                    "delete_on_termination": entry.delete_on_termination,
                    "device_index": entry.device_index,
                })
            return {
                "schema_version": SCHEMA_VERSION,
                "enis": enis_json,
            }

    def from_dict(self, data: dict) -> None:
        """Load state. Accepts v1 (legacy) and v2 (current) snapshots.

        v1 entries lack source_dest_check / delete_on_termination /
        device_index — those default per AWS API defaults (True / True /
        None) which is the safe assumption for an ENI loaded from an
        older snapshot (no source-dest-check override active, default
        delete-on-terminate, no device-index because the entry came from
        the implicit-primary synthesis that never tracked it).
        """
        version = data.get("schema_version")
        if version not in (1, SCHEMA_VERSION):
            LOG.warning(
                "address index: snapshot schema %s not in {1, %s}, ignoring",
                version, SCHEMA_VERSION,
            )
            return
        with self._lock:
            self._enis.clear()
            self._ip_to_eni.clear()
            self._instance_to_enis.clear()
            self._sg_to_enis.clear()
            for entry_data in data.get("enis", []):
                primary = ipaddress.IPv4Address(entry_data["primary_ip"])
                secondaries = [
                    ipaddress.IPv4Address(s)
                    for s in entry_data.get("secondary_ips", [])
                ]
                sg_list = list(entry_data.get("sg_ids", []))
                entry = EniEntry(
                    eni_id=entry_data["eni_id"],
                    vpc_id=entry_data["vpc_id"],
                    subnet_id=entry_data["subnet_id"],
                    primary_ip=primary,
                    mac=entry_data["mac"],
                    secondary_ips=secondaries,
                    sg_ids=sg_list,
                    instance_id=entry_data.get("instance_id"),
                    iface_name=entry_data.get("iface_name"),
                    # v2 fields with AWS-default fallbacks for v1 snapshots
                    source_dest_check=entry_data.get(
                        "source_dest_check", True,
                    ),
                    delete_on_termination=entry_data.get(
                        "delete_on_termination", True,
                    ),
                    device_index=entry_data.get("device_index"),
                )
                self._enis[entry.eni_id] = entry
                self._ip_to_eni[primary] = entry.eni_id
                for s_ip in secondaries:
                    self._ip_to_eni[s_ip] = entry.eni_id
                if entry.instance_id:
                    self._instance_to_enis.setdefault(
                        entry.instance_id, [],
                    ).append(entry.eni_id)
                for sg in sg_list:
                    self._sg_to_enis.setdefault(sg, set()).add(entry.eni_id)
        LOG.info("address index: loaded %d ENIs", len(self._enis))

    def save_to_file(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = self.to_dict()
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(
            prefix=".address_index-", suffix=".tmp", dir=directory,
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load_from_file(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        try:
            with open(path) as f:
                data = json.load(f)
            self.from_dict(data)
            return True
        except Exception as exc:
            LOG.warning(
                "address index: failed to load %s: %s — starting empty",
                path, exc,
            )
            return False


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_singleton: Optional[AddressIndex] = None
_singleton_lock = threading.Lock()


def get_address_index() -> AddressIndex:
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AddressIndex()
        return _singleton


def reset_address_index_for_tests() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None
