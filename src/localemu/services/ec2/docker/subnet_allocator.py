"""Per-(VPC, subnet) IPv4 address allocator.

The allocator is the only place where IP addresses are handed out to
LocalEmu-managed containers. Every container that joins a VPC bridge
gets its IP from here, then the IP is passed as ``ipv4_address=`` on
the Docker connect call. This eliminates the moby/libnetwork#1740 race
(Docker's auto-IPAM can hand the same IP to two concurrent connects)
and lets LocalEmu honor AWS subnet semantics: every container's IP
lies inside its subnet CIDR, the five AWS-reserved addresses are
excluded, and exhaustion raises an explicit fault.

Used by ``vm_manager.create_instance`` (EC2), ``db_manager._do_create_db_instance``
(RDS), ENI ``CreateNetworkInterface`` (design 08), NAT-GW sidecar
create (design 19), and the per-VPC IMDS sidecar create.

State is persisted as JSON under ``~/.localemu/data/subnet_allocator.state``
and reconciled against ``docker network inspect`` on startup by
``address_reconciler.reconcile_on_startup``.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger(__name__)

# Schema version of the persisted file. Bumping this is a forward-only
# migration: a loader seeing a higher version logs a warning and starts
# empty, letting the reconciler rebuild from Docker.
SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class AllocatorError(Exception):
    """Base class for allocator failures."""


class InsufficientFreeAddressesInSubnet(AllocatorError):
    """Subnet pool is exhausted. AWS-API parity error name."""


class InvalidIpForSubnet(AllocatorError):
    """A specific IP was requested that does not lie in the subnet's
    docker_cidr (or it lies in the AWS-reserved set)."""


class IpAddressInUse(AllocatorError):
    """A specific IP was requested that is already allocated."""


class IpClaimConflict(AllocatorError):
    """Reconciler tried to claim an IP that is already allocated to a
    different owner. Signals corruption — operator intervention required."""


class SubnetCidrConflict(AllocatorError):
    """Re-registering a subnet with different CIDRs than the existing
    record. Internal bug, not user-facing."""


class SubnetInUse(AllocatorError):
    """unregister_subnet called on a pool with live allocations."""


class UnknownSubnet(AllocatorError):
    """Operation references a (vpc_id, subnet_id) not registered."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class SubnetPool:
    """One pool per (vpc_id, subnet_id).

    ``aws_cidr`` is what the user / Terraform sees. ``docker_cidr`` is
    what Docker actually carved for the VPC bridge. They are equal in
    the happy path; they diverge only when ``vpc_network._create_docker_bridge``
    fell back to a different tier because the AWS CIDR collided with
    something on the host.
    """
    vpc_id: str
    subnet_id: str
    aws_cidr: ipaddress.IPv4Network
    docker_cidr: ipaddress.IPv4Network
    az: str
    # Reserved address set (AWS .0/.1/.2/.3/broadcast plus Docker gateway
    # if it's not already in the AWS reserved set). Computed on register.
    reserved: set[ipaddress.IPv4Address] = field(default_factory=set)
    # ip -> owner_key. owner_key is "eni-<id>" / "imds-sidecar:<vpc>" /
    # "nat-gw:<vpc>" / "rds:<db-id>" — whatever the caller passes in.
    allocated: dict[ipaddress.IPv4Address, str] = field(default_factory=dict)
    # Iteration cursor for "give me any free IP" requests. Starts at
    # the first non-reserved address in the docker_cidr; advances as IPs
    # are reserved.
    next_hint: Optional[ipaddress.IPv4Address] = None


def _compute_reserved(
    aws_cidr: ipaddress.IPv4Network,
    docker_cidr: ipaddress.IPv4Network,
) -> set[ipaddress.IPv4Address]:
    """Build the reserved-address set for a subnet.

    AWS reserves five per subnet: .0 (network), .1 (VPC router),
    .2 (DNS), .3 (future), and the last (broadcast). Docker reserves
    .0 (network) and .1 (gateway) per bridge — for our model the bridge
    is sized to the whole VPC CIDR so Docker's .1 IS the VPC's .1, which
    is already in the AWS set.

    When docker_cidr != aws_cidr (fallback subnet tier kicked in),
    Docker's gateway lives at docker_cidr[1] which has no AWS meaning
    but must still be excluded — Docker will refuse to assign it.
    """
    reserved: set[ipaddress.IPv4Address] = set()
    # AWS reservations within the AWS-visible subnet.
    if aws_cidr.num_addresses >= 5:
        hosts = list(aws_cidr.hosts())  # excludes .0 and broadcast
        # AWS .0 (network) and broadcast are not in hosts(); add them
        reserved.add(aws_cidr.network_address)
        reserved.add(aws_cidr.broadcast_address)
        # AWS .1, .2, .3 are at positions 0,1,2 of hosts() (since .0 is excluded)
        for i in range(min(3, len(hosts))):
            reserved.add(hosts[i])
    else:
        # Tiny subnets (/30, /31) — just reserve what we can
        reserved.update(aws_cidr.hosts())
        reserved.add(aws_cidr.network_address)
        if aws_cidr.broadcast_address != aws_cidr.network_address:
            reserved.add(aws_cidr.broadcast_address)
    # Docker bridge gateway (if it's outside the AWS reserved set)
    if docker_cidr.num_addresses >= 2:
        docker_gateway = next(docker_cidr.hosts())
        reserved.add(docker_gateway)
    return reserved


def _first_free_after(
    pool: SubnetPool,
    start: ipaddress.IPv4Address,
) -> Optional[ipaddress.IPv4Address]:
    """Walk the pool's docker_cidr from ``start`` looking for the first
    free address. Returns None if exhausted.

    Order: start -> end of docker_cidr -> wrap to first usable -> back to
    start - 1. This gives stable behavior even when next_hint sits late
    in the range after many allocs.
    """
    cidr = pool.docker_cidr
    if start not in cidr:
        # Hint is stale (subnet changed?); reset to start of pool
        start = next(cidr.hosts())
    candidate = start
    end = cidr.broadcast_address
    # Forward sweep from hint to end
    while candidate <= end:
        if candidate not in pool.reserved and candidate not in pool.allocated:
            return candidate
        candidate = candidate + 1
    # Wrap and sweep from start of pool back to hint
    candidate = next(cidr.hosts())
    while candidate < start:
        if candidate not in pool.reserved and candidate not in pool.allocated:
            return candidate
        candidate = candidate + 1
    return None


# ---------------------------------------------------------------------------
# Allocator
# ---------------------------------------------------------------------------
class SubnetAllocator:
    """Process-wide IPv4 allocator for VPC subnets.

    Thread-safe. The single RLock guards all four indexes; operations
    are short (microseconds) so contention is not a concern.

    Do NOT call this with VpcNetworkManager._lock held — there is no
    callback into vpc_network, so it would be safe today, but the
    documented lock ordering (vpc_network -> allocator -> address_index)
    keeps us safe under future change.
    """

    def __init__(self) -> None:
        self._pools: dict[tuple[str, str], SubnetPool] = {}
        # Denormalized reverse index: ip -> (vpc_id, subnet_id) for O(1)
        # "which subnet does this IP live in" lookups (used by NACL and
        # by the reconciler). Rebuilt from _pools on load.
        self._ip_index: dict[
            ipaddress.IPv4Address, tuple[str, str]
        ] = {}
        self._lock = threading.RLock()

    # -- subnet lifecycle ---------------------------------------------------

    def register_subnet(
        self,
        vpc_id: str,
        subnet_id: str,
        aws_cidr: str | ipaddress.IPv4Network,
        docker_cidr: str | ipaddress.IPv4Network,
        az: str,
    ) -> None:
        """Register a subnet pool. Idempotent for same-CIDRs; raises
        SubnetCidrConflict on conflicting re-register."""
        aws_net = (
            aws_cidr if isinstance(aws_cidr, ipaddress.IPv4Network)
            else ipaddress.IPv4Network(aws_cidr, strict=False)
        )
        docker_net = (
            docker_cidr if isinstance(docker_cidr, ipaddress.IPv4Network)
            else ipaddress.IPv4Network(docker_cidr, strict=False)
        )
        key = (vpc_id, subnet_id)
        with self._lock:
            existing = self._pools.get(key)
            if existing is not None:
                if (
                    existing.aws_cidr != aws_net
                    or existing.docker_cidr != docker_net
                ):
                    raise SubnetCidrConflict(
                        f"subnet {subnet_id} re-registered with different CIDR: "
                        f"had (aws={existing.aws_cidr}, docker={existing.docker_cidr}), "
                        f"got (aws={aws_net}, docker={docker_net})"
                    )
                return  # idempotent no-op
            reserved = _compute_reserved(aws_net, docker_net)
            # First-allocable IP: first host of docker_cidr that isn't reserved
            first_free: Optional[ipaddress.IPv4Address] = None
            for host in docker_net.hosts():
                if host not in reserved:
                    first_free = host
                    break
            pool = SubnetPool(
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                aws_cidr=aws_net,
                docker_cidr=docker_net,
                az=az,
                reserved=reserved,
                allocated={},
                next_hint=first_free,
            )
            self._pools[key] = pool
        LOG.info(
            "subnet allocator: registered %s in %s "
            "(aws=%s docker=%s az=%s reserved=%d first_free=%s)",
            subnet_id, vpc_id, aws_net, docker_net, az,
            len(reserved), first_free,
        )

    def unregister_subnet(self, vpc_id: str, subnet_id: str) -> None:
        """Remove a subnet pool. Raises SubnetInUse if any IP is still
        allocated. Use ``force_unregister_subnet`` for cleanup paths
        where we know the subnet is going away regardless."""
        key = (vpc_id, subnet_id)
        with self._lock:
            pool = self._pools.get(key)
            if pool is None:
                return
            if pool.allocated:
                raise SubnetInUse(
                    f"subnet {subnet_id} has {len(pool.allocated)} live allocations"
                )
            del self._pools[key]
            for ip, (vid, sid) in list(self._ip_index.items()):
                if vid == vpc_id and sid == subnet_id:
                    del self._ip_index[ip]
        LOG.info("subnet allocator: unregistered %s in %s", subnet_id, vpc_id)

    def force_unregister_subnet(self, vpc_id: str, subnet_id: str) -> int:
        """Unconditionally remove a subnet pool and release every IP.
        Returns the number of IPs released. Used by VPC delete paths
        where the bridge is going away."""
        key = (vpc_id, subnet_id)
        released = 0
        with self._lock:
            pool = self._pools.pop(key, None)
            if pool is None:
                return 0
            for ip in list(pool.allocated.keys()):
                self._ip_index.pop(ip, None)
                released += 1
        LOG.info(
            "subnet allocator: force-unregistered %s in %s (%d IPs released)",
            subnet_id, vpc_id, released,
        )
        return released

    # -- IP lifecycle -------------------------------------------------------

    def reserve(
        self,
        vpc_id: str,
        subnet_id: str,
        owner_key: str,
        requested: Optional[str | ipaddress.IPv4Address] = None,
    ) -> ipaddress.IPv4Address:
        """Reserve an IP in the subnet's pool.

        If ``requested`` is None, return the first free IP starting from
        the pool's ``next_hint``. If ``requested`` is set, validate and
        reserve that specific IP.

        Raises:
          UnknownSubnet: pool not registered
          InvalidIpForSubnet: requested IP not in docker_cidr or reserved
          IpAddressInUse: requested IP already allocated
          InsufficientFreeAddressesInSubnet: no free IP available
        """
        key = (vpc_id, subnet_id)
        with self._lock:
            pool = self._pools.get(key)
            if pool is None:
                raise UnknownSubnet(
                    f"subnet {subnet_id} in {vpc_id} is not registered"
                )
            if requested is not None:
                ip = (
                    requested if isinstance(requested, ipaddress.IPv4Address)
                    else ipaddress.IPv4Address(requested)
                )
                if ip not in pool.docker_cidr:
                    raise InvalidIpForSubnet(
                        f"{ip} is not in subnet {subnet_id}'s docker_cidr {pool.docker_cidr}"
                    )
                if ip in pool.reserved:
                    raise InvalidIpForSubnet(
                        f"{ip} is reserved (AWS or Docker reservation)"
                    )
                if ip in pool.allocated:
                    raise IpAddressInUse(
                        f"{ip} is already allocated to {pool.allocated[ip]}"
                    )
                pool.allocated[ip] = owner_key
                self._ip_index[ip] = key
                return ip
            # Auto-pick from next_hint
            hint = pool.next_hint or next(pool.docker_cidr.hosts())
            ip = _first_free_after(pool, hint)
            if ip is None:
                raise InsufficientFreeAddressesInSubnet(
                    f"subnet {subnet_id} pool exhausted "
                    f"({len(pool.allocated)} allocated, "
                    f"{len(pool.reserved)} reserved, "
                    f"{pool.docker_cidr.num_addresses} total)"
                )
            pool.allocated[ip] = owner_key
            self._ip_index[ip] = key
            # Advance hint (wrap on last)
            try:
                pool.next_hint = ip + 1
            except (ipaddress.AddressValueError, ValueError):
                pool.next_hint = next(pool.docker_cidr.hosts())
            return ip

    def release(self, ip: str | ipaddress.IPv4Address) -> None:
        """Release an IP. Idempotent: missing IP is a no-op."""
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        with self._lock:
            key = self._ip_index.pop(addr, None)
            if key is None:
                return
            pool = self._pools.get(key)
            if pool is not None:
                pool.allocated.pop(addr, None)

    def claim(
        self,
        vpc_id: str,
        subnet_id: str,
        ip: str | ipaddress.IPv4Address,
        owner_key: str,
    ) -> None:
        """Reconciler-only: mark an IP as taken without iterating.

        Used on startup when ``docker network inspect`` shows a container
        already holds an IP — we want the allocator to remember it so a
        later ``reserve()`` does not hand it out again. Tolerates
        re-claiming the same (ip, owner_key) pair (idempotent). Raises
        ``IpClaimConflict`` if the IP is held by a different owner.
        """
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        key = (vpc_id, subnet_id)
        with self._lock:
            pool = self._pools.get(key)
            if pool is None:
                raise UnknownSubnet(
                    f"subnet {subnet_id} in {vpc_id} is not registered"
                )
            if addr not in pool.docker_cidr:
                # Reconciler observed an IP outside any registered subnet.
                # This happens when adoption races subnet registration; we
                # accept it without raising — the IP just won't be tracked.
                LOG.debug(
                    "subnet allocator: claim %s outside %s docker_cidr %s — skipped",
                    addr, subnet_id, pool.docker_cidr,
                )
                return
            existing = pool.allocated.get(addr)
            if existing is not None and existing != owner_key:
                raise IpClaimConflict(
                    f"{addr} held by {existing!r}, cannot reclaim for {owner_key!r}"
                )
            pool.allocated[addr] = owner_key
            self._ip_index[addr] = key

    # -- read paths ---------------------------------------------------------

    def lookup(
        self, ip: str | ipaddress.IPv4Address,
    ) -> Optional[tuple[str, str, str]]:
        """Return (vpc_id, subnet_id, owner_key) for an IP, or None."""
        addr = (
            ip if isinstance(ip, ipaddress.IPv4Address)
            else ipaddress.IPv4Address(ip)
        )
        with self._lock:
            key = self._ip_index.get(addr)
            if key is None:
                return None
            pool = self._pools.get(key)
            if pool is None:
                return None
            owner = pool.allocated.get(addr)
            if owner is None:
                return None
            return (pool.vpc_id, pool.subnet_id, owner)

    def describe(self, vpc_id: str) -> list[SubnetPool]:
        """Return a snapshot of every pool in a VPC. For diagnostics."""
        with self._lock:
            return [
                pool for (vid, _sid), pool in self._pools.items()
                if vid == vpc_id
            ]

    def all_pools(self) -> list[SubnetPool]:
        """Return every pool. For diagnostics and persistence."""
        with self._lock:
            return list(self._pools.values())

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        with self._lock:
            pools_json = []
            for pool in self._pools.values():
                pools_json.append({
                    "vpc_id": pool.vpc_id,
                    "subnet_id": pool.subnet_id,
                    "aws_cidr": str(pool.aws_cidr),
                    "docker_cidr": str(pool.docker_cidr),
                    "az": pool.az,
                    "reserved": sorted(str(ip) for ip in pool.reserved),
                    "allocated": {
                        str(ip): owner for ip, owner in pool.allocated.items()
                    },
                    "next_hint": (
                        str(pool.next_hint) if pool.next_hint is not None else None
                    ),
                })
            return {
                "schema_version": SCHEMA_VERSION,
                "pools": pools_json,
            }

    def from_dict(self, data: dict) -> None:
        """Load state from a JSON-shaped dict. Wipes existing state.

        Refuses unknown schema versions (logs WARN, leaves state empty —
        the reconciler will rebuild from Docker).
        """
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            LOG.warning(
                "subnet allocator: snapshot schema %s != %s, ignoring file",
                version, SCHEMA_VERSION,
            )
            return
        with self._lock:
            self._pools.clear()
            self._ip_index.clear()
            for entry in data.get("pools", []):
                aws = ipaddress.IPv4Network(entry["aws_cidr"], strict=False)
                docker = ipaddress.IPv4Network(entry["docker_cidr"], strict=False)
                reserved = {
                    ipaddress.IPv4Address(s) for s in entry.get("reserved", [])
                }
                allocated = {
                    ipaddress.IPv4Address(ip): owner
                    for ip, owner in entry.get("allocated", {}).items()
                }
                next_hint_raw = entry.get("next_hint")
                next_hint = (
                    ipaddress.IPv4Address(next_hint_raw)
                    if next_hint_raw else None
                )
                pool = SubnetPool(
                    vpc_id=entry["vpc_id"],
                    subnet_id=entry["subnet_id"],
                    aws_cidr=aws,
                    docker_cidr=docker,
                    az=entry["az"],
                    reserved=reserved,
                    allocated=allocated,
                    next_hint=next_hint,
                )
                key = (pool.vpc_id, pool.subnet_id)
                self._pools[key] = pool
                for ip in allocated.keys():
                    self._ip_index[ip] = key
        LOG.info(
            "subnet allocator: loaded %d pools (%d total allocations)",
            len(self._pools),
            sum(len(p.allocated) for p in self._pools.values()),
        )

    def save_to_file(self, path: str) -> None:
        """Atomic write: temp + rename. Tolerates missing parent dir."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = self.to_dict()
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(
            prefix=".subnet_allocator-", suffix=".tmp", dir=directory,
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
        """Load state from path. Returns True on success, False if file
        is missing or corrupt (always logs corruption)."""
        if not os.path.exists(path):
            return False
        try:
            with open(path) as f:
                data = json.load(f)
            self.from_dict(data)
            return True
        except Exception as exc:
            LOG.warning(
                "subnet allocator: failed to load %s: %s — starting empty",
                path, exc,
            )
            return False


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
_singleton: Optional[SubnetAllocator] = None
_singleton_lock = threading.Lock()


def get_subnet_allocator() -> SubnetAllocator:
    """Process-wide singleton. Thread-safe lazy init."""
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SubnetAllocator()
        return _singleton


def reset_subnet_allocator_for_tests() -> None:
    """Drop the singleton. ONLY for tests; never call from production."""
    global _singleton
    with _singleton_lock:
        _singleton = None
