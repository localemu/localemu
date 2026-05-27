"""Startup reconciliation of allocator + index against Docker reality.

After a LocalEmu restart, the in-memory state from the persisted files
may differ from what Docker actually shows: a user may have manually
``docker network disconnect``ed a container, a daemon restart may have
re-shuffled IPs, the persistence files may be missing entirely.

This module walks ``docker network inspect`` for every LocalEmu-managed
VPC bridge, cross-checks against the SubnetAllocator and AddressIndex,
and converges. Drift is detected, logged, and converged in favor of
Docker (Docker is the source of truth for what is actually running).

Called from ``Ec2Provider.on_after_state_load`` after
``adopt_vpc_networks_from_docker`` and ``rebuild_from_docker`` complete,
but before any provider serves traffic. Also re-runnable mid-session
for the periodic reconciler (TODO: 60-second timer in a follow-up PR).
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

from localemu.services.ec2.docker.address_index import (
    AddressIndex,
    derive_mac,
    get_address_index,
)
from localemu.services.ec2.docker.subnet_allocator import (
    IpClaimConflict,
    SubnetAllocator,
    UnknownSubnet,
    get_subnet_allocator,
)
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# Prefix of LocalEmu-managed VPC bridges, as written by
# vpc_network._docker_network_name.
VPC_NETWORK_PREFIX = "localemu-vpc-"


@dataclass
class ReconcileReport:
    """Summary of what the reconciler did. Logged at INFO and surfaced
    on the dashboard."""
    matched: int = 0
    recreated_index: int = 0  # Docker had it, index missing — created
    dropped_orphan: int = 0   # Index had it, Docker gone — removed
    ip_drift: int = 0         # Same instance, different IP — index updated
    claim_conflicts: int = 0  # IP held by another owner — corruption signal
    skipped_unregistered: int = 0  # subnet not in allocator yet
    enis_after: int = 0

    # Per-class detail for diagnostics
    drifted_instances: list[str] = field(default_factory=list)
    orphan_enis: list[str] = field(default_factory=list)

    def is_clean(self) -> bool:
        return self.ip_drift == 0 and self.claim_conflicts == 0

    def summary(self) -> str:
        return (
            f"ReconcileReport(matched={self.matched}, "
            f"recreated={self.recreated_index}, "
            f"dropped={self.dropped_orphan}, "
            f"drift={self.ip_drift}, "
            f"conflicts={self.claim_conflicts}, "
            f"skipped={self.skipped_unregistered}, "
            f"enis_after={self.enis_after})"
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def reconcile_on_startup(
    allocator: Optional[SubnetAllocator] = None,
    index: Optional[AddressIndex] = None,
) -> ReconcileReport:
    """Walk Docker, converge in-memory state against it.

    Args:
        allocator: override for tests; defaults to the process singleton.
        index: override for tests; defaults to the process singleton.

    Returns:
        ReconcileReport with counts and detail. Always returns; logs
        any internal errors but never raises into the caller.
    """
    allocator = allocator or get_subnet_allocator()
    index = index or get_address_index()
    report = ReconcileReport()

    docker_view = _walk_docker_networks()
    if docker_view is None:
        LOG.warning(
            "address_reconciler: cannot reach Docker — skipping reconciliation; "
            "in-memory state may be stale until next attempt",
        )
        return report

    # Build a quick set of (eni_id, primary_ip) from Docker view
    docker_eni_ids: set[str] = set()
    for net_name, members in docker_view.items():
        for m in members:
            if m.eni_id is not None:
                docker_eni_ids.add(m.eni_id)
                _reconcile_one_member(m, allocator, index, report)

    # Pass 2: find ENIs in the index that Docker no longer has
    for entry in index.all_enis():
        if entry.eni_id in docker_eni_ids:
            continue
        # Index has it, Docker doesn't — orphan. Drop + release.
        index.delete_eni(entry.eni_id)
        allocator.release(entry.primary_ip)
        for s_ip in entry.secondary_ips:
            allocator.release(s_ip)
        report.dropped_orphan += 1
        report.orphan_enis.append(entry.eni_id)
        LOG.info(
            "address_reconciler: dropped orphan ENI %s "
            "(was on %s, Docker no longer reports it)",
            entry.eni_id, entry.primary_ip,
        )

    report.enis_after = len(index.all_enis())
    LOG.info("address_reconciler: %s", report.summary())
    return report


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
@dataclass
class _DockerMember:
    """A container attached to a LocalEmu VPC bridge, as Docker sees it."""
    container_name: str
    network_name: str
    vpc_id: str
    primary_ip: Optional[ipaddress.IPv4Address]
    eni_id: Optional[str]
    subnet_id: Optional[str]
    instance_id: Optional[str]
    sg_ids: list[str]
    mac: Optional[str]
    iface_name: Optional[str] = None


def _walk_docker_networks() -> Optional[dict[str, list[_DockerMember]]]:
    """Build the Docker view: {network_name: [member, ...]}.

    Returns None if Docker is unreachable; logs the failure once.
    """
    try:
        info = DOCKER_CLIENT.get_system_info()
        if not info:
            return None
    except Exception as exc:
        LOG.debug("address_reconciler: Docker unreachable: %s", exc)
        return None

    result: dict[str, list[_DockerMember]] = {}
    try:
        # We need to enumerate every localemu-vpc-* network. There is no
        # filter API to list networks by name prefix; we list all and
        # filter ourselves. The list_networks call accepts no filter for
        # name prefix in either client implementation.
        all_nets = _list_localemu_vpc_networks()
    except Exception as exc:
        LOG.warning(
            "address_reconciler: failed to enumerate networks: %s", exc,
        )
        return None

    for net_name in all_nets:
        vpc_id = net_name[len(VPC_NETWORK_PREFIX):]
        members = _members_of_network(net_name, vpc_id)
        result[net_name] = members
    return result


def _list_localemu_vpc_networks() -> list[str]:
    """Return every network name that starts with localemu-vpc-.

    Implemented by calling DOCKER_CLIENT.inspect_network on candidates
    we discover via list_containers (label filter). This is more
    forgiving than relying on a list_networks API that may not exist on
    every client implementation.
    """
    seen: set[str] = set()
    try:
        containers = DOCKER_CLIENT.list_containers(
            filter=["label=localemu.service=ec2"], all=True,
        )
    except Exception:
        containers = []
    try:
        rds_containers = DOCKER_CLIENT.list_containers(
            filter=["label=localemu.service=rds"], all=True,
        )
    except Exception:
        rds_containers = []
    for c in list(containers) + list(rds_containers):
        name = c.get("name", "")
        if not name:
            continue
        try:
            inspect = DOCKER_CLIENT.inspect_container(name)
        except Exception:
            continue
        nets = (
            (inspect.get("NetworkSettings") or {}).get("Networks") or {}
        )
        for net_name in nets.keys():
            if net_name.startswith(VPC_NETWORK_PREFIX):
                seen.add(net_name)
    return sorted(seen)


def _members_of_network(
    network_name: str, vpc_id: str,
) -> list[_DockerMember]:
    """Walk the network's container list, build _DockerMember per
    attached container.
    """
    members: list[_DockerMember] = []
    try:
        net_attrs = DOCKER_CLIENT.inspect_network(network_name)
    except Exception as exc:
        LOG.debug(
            "address_reconciler: inspect_network %s failed: %s",
            network_name, exc,
        )
        return members

    containers = (net_attrs.get("Containers") or {})
    for _cid, info in containers.items():
        container_name = (info.get("Name") or "").lstrip("/")
        if not container_name:
            continue
        ipv4_cidr = info.get("IPv4Address") or ""
        # IPv4Address has shape "10.0.0.5/24" — strip the mask
        primary_ip: Optional[ipaddress.IPv4Address] = None
        if "/" in ipv4_cidr:
            ip_str = ipv4_cidr.split("/", 1)[0]
            try:
                primary_ip = ipaddress.IPv4Address(ip_str)
            except (ValueError, ipaddress.AddressValueError):
                primary_ip = None
        mac = info.get("MacAddress") or None

        # Pull labels from the container to recover ENI/subnet/SG info
        labels = _container_labels(container_name)
        eni_id = labels.get("localemu.eni-id")
        instance_id = (
            labels.get("localemu.instance-id")
            or labels.get("localemu.db-instance-id")
        )
        subnet_id = labels.get("localemu.subnet-id")
        raw_sgs = labels.get("localemu.sg-ids") or ""
        sg_ids = [s for s in raw_sgs.split(",") if s]

        # Synthesize a stable eni_id when the container predates this
        # design (i.e. has no localemu.eni-id label).
        if eni_id is None and instance_id is not None:
            eni_id = _synth_eni_id(instance_id)

        members.append(_DockerMember(
            container_name=container_name,
            network_name=network_name,
            vpc_id=vpc_id,
            primary_ip=primary_ip,
            eni_id=eni_id,
            subnet_id=subnet_id,
            instance_id=instance_id,
            sg_ids=sg_ids,
            mac=mac,
        ))
    return members


def _container_labels(container_name: str) -> dict[str, str]:
    try:
        inspect = DOCKER_CLIENT.inspect_container(container_name)
    except Exception:
        return {}
    return ((inspect.get("Config") or {}).get("Labels") or {}) or {}


def _synth_eni_id(instance_id: str) -> str:
    """Deterministic synthesized ENI ID for pre-design containers.

    Matches the convention vm_manager will use for new containers:
    ``eni-<instance_id without 'i-' prefix>``.
    """
    suffix = instance_id[2:] if instance_id.startswith("i-") else instance_id
    return f"eni-{suffix}"


def _reconcile_one_member(
    m: _DockerMember,
    allocator: SubnetAllocator,
    index: AddressIndex,
    report: ReconcileReport,
) -> None:
    """Reconcile one Docker member against allocator + index state."""
    if m.eni_id is None or m.primary_ip is None or m.subnet_id is None:
        # Not enough info to reconcile (very old container, or labels
        # got nuked). Skip silently.
        return

    existing = index.get_eni(m.eni_id)
    if existing is None:
        # Docker has it, index missing — recreate entry.
        try:
            allocator.claim(
                m.vpc_id, m.subnet_id, m.primary_ip, f"eni-{m.eni_id}",
            )
        except UnknownSubnet:
            # Subnet not registered yet (subnet allocator hasn't been
            # populated for this subnet — maybe the provider hook ran
            # in a different order on startup). Skip; we'll catch it
            # on a later reconcile cycle if the subnet appears.
            report.skipped_unregistered += 1
            return
        except IpClaimConflict as exc:
            LOG.error(
                "address_reconciler: claim conflict for ENI %s "
                "(ip=%s vpc=%s subnet=%s): %s",
                m.eni_id, m.primary_ip, m.vpc_id, m.subnet_id, exc,
            )
            report.claim_conflicts += 1
            return

        mac = m.mac or derive_mac(m.primary_ip)
        index.register_eni(
            eni_id=m.eni_id,
            vpc_id=m.vpc_id,
            subnet_id=m.subnet_id,
            primary_ip=m.primary_ip,
            mac=mac,
            sg_ids=m.sg_ids,
            instance_id=m.instance_id,
            iface_name=m.iface_name,
        )
        report.recreated_index += 1
        LOG.info(
            "address_reconciler: recreated index for ENI %s on %s "
            "(instance=%s, subnet=%s)",
            m.eni_id, m.primary_ip, m.instance_id, m.subnet_id,
        )
        return

    # Index has it; compare against Docker reality.
    if existing.primary_ip != m.primary_ip:
        # IP drift — Docker wins. Update index, release old IP, claim new.
        LOG.warning(
            "address_reconciler: ENI %s IP drift: was %s, Docker says %s "
            "(instance=%s) — Docker wins; SG iptables re-apply triggered "
            "downstream",
            m.eni_id, existing.primary_ip, m.primary_ip, m.instance_id,
        )
        allocator.release(existing.primary_ip)
        try:
            allocator.claim(
                m.vpc_id, m.subnet_id, m.primary_ip, f"eni-{m.eni_id}",
            )
        except (UnknownSubnet, IpClaimConflict) as exc:
            LOG.error(
                "address_reconciler: drift-fix claim failed for %s: %s",
                m.eni_id, exc,
            )
            report.claim_conflicts += 1
            return
        # Replace the entry by delete+re-register (keeps indexes coherent)
        old_secondary = existing.secondary_ips
        old_iface = existing.iface_name
        index.delete_eni(m.eni_id)
        index.register_eni(
            eni_id=m.eni_id,
            vpc_id=m.vpc_id,
            subnet_id=m.subnet_id,
            primary_ip=m.primary_ip,
            mac=m.mac or derive_mac(m.primary_ip),
            sg_ids=m.sg_ids or existing.sg_ids,
            instance_id=m.instance_id,
            iface_name=old_iface,
            secondary_ips=old_secondary,
        )
        report.ip_drift += 1
        if m.instance_id:
            report.drifted_instances.append(m.instance_id)
        return

    # Same IP, but check for SG drift (labels changed since persistence wrote)
    if m.sg_ids and set(m.sg_ids) != set(existing.sg_ids):
        index.update_sgs(m.eni_id, m.sg_ids)
        LOG.debug(
            "address_reconciler: ENI %s SG set updated from labels: %s -> %s",
            m.eni_id, existing.sg_ids, m.sg_ids,
        )

    report.matched += 1
