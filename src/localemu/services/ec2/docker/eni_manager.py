"""Orchestration layer for AWS ENI lifecycle operations.

The ENI handlers in ``services/ec2/provider.py`` are thin wrappers that
call ``call_moto`` for metadata persistence, then delegate the
Docker-side work to this module. The ``EniManager`` singleton:

- Reserves IPs from the SubnetAllocator with the right owner_key shape.
- Pins the IP to a Docker interface via ``connect_container_to_network``.
- Resolves the in-container interface name via ``iface_resolver``.
- Records the ENI state in the AddressIndex.
- Programs per-interface SG chains and source/dest-check rules.
- Releases resources cleanly on detach/delete.
- Serializes attach/detach per-instance to avoid the race where two
  parallel attaches see each other's new interfaces before either
  has resolved its own.

The orchestration is gated on ``LOCALEMU_ENI_REAL`` (which requires
``LOCALEMU_VPC_IP_PINNING`` as a prerequisite). When the flag is off,
the EniManager singleton is never instantiated and the handlers fall
through to today's pure-moto behavior.

Design contract: ``_deep/DESIGN_eni.md``.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
from typing import Iterable, Optional

from localemu.services.ec2.docker.address_index import (
    AddressIndex,
    derive_mac,
    get_address_index,
)
from localemu.services.ec2.docker.iface_resolver import (
    resolve_iface_for_network,
)
from localemu.services.ec2.docker.subnet_allocator import (
    InsufficientFreeAddressesInSubnet,
    InvalidIpForSubnet,
    IpAddressInUse,
    SubnetAllocator,
    UnknownSubnet,
    get_subnet_allocator,
)
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


def _is_already_on_network_error(exc: BaseException) -> bool:
    """True when Docker rejected ``connect_container_to_network`` because
    the container is already attached to that network. The two clients
    surface this differently (SDK 409 message vs CLI stderr blob), so
    match on the stable error text.

    Triggers the shared-iface fallback in :meth:`EniManager.attach`."""
    msg = str(exc).lower()
    return (
        "endpoint with name" in msg and "already exists in network" in msg
    ) or "endpoint already exists" in msg or "already attached" in msg


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class EniManagerError(Exception):
    """Base class for EniManager failures."""


class EniNotFound(EniManagerError):
    """ENI ID not found in the AddressIndex."""


class EniAlreadyAttached(EniManagerError):
    """AttachNetworkInterface called on an already-attached ENI."""


class EniNotAttached(EniManagerError):
    """DetachNetworkInterface or assign-ip called on a detached ENI."""


class EniInUse(EniManagerError):
    """DeleteNetworkInterface called on an attached ENI (AWS contract:
    InvalidParameterValue)."""


class CannotDetachPrimary(EniManagerError):
    """DetachNetworkInterface called on device-index 0 (AWS contract:
    OperationNotPermitted)."""


class InvalidEniState(EniManagerError):
    """Generic 'state machine violated' error."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _container_name_for_instance(instance_id: str) -> str:
    """Match DockerVmManager._container_name."""
    return f"localemu-ec2-{instance_id}"


def _vpc_network_name(vpc_id: str) -> str:
    """Match VpcNetworkManager._docker_network_name."""
    return f"localemu-vpc-{vpc_id}"


# ---------------------------------------------------------------------------
# EniManager
# ---------------------------------------------------------------------------
class EniManager:
    """Process-wide orchestration of ENI lifecycle operations.

    Thread-safe via per-instance attach locks (one lock per instance_id,
    serializes parallel attach/detach on the same instance to prevent
    the iface-resolution race). Allocator and index have their own
    internal locks; this module never holds them across Docker calls.

    All operations gated on LOCALEMU_VPC_IP_PINNING + LOCALEMU_ENI_REAL
    at the handler layer — by the time we reach EniManager, both are on.
    """

    def __init__(
        self,
        allocator: Optional[SubnetAllocator] = None,
        index: Optional[AddressIndex] = None,
    ):
        self._allocator = allocator or get_subnet_allocator()
        self._index = index or get_address_index()
        self._instance_locks: dict[str, threading.RLock] = {}
        self._dict_lock = threading.Lock()

    def _lock_for(self, instance_id: str) -> threading.RLock:
        """Per-instance attach/detach serialization lock."""
        with self._dict_lock:
            lock = self._instance_locks.get(instance_id)
            if lock is None:
                lock = threading.RLock()
                self._instance_locks[instance_id] = lock
            return lock

    # -- CreateNetworkInterface ---------------------------------------------

    def create(
        self,
        eni_id: str,
        vpc_id: str,
        subnet_id: str,
        sg_ids: Iterable[str],
        requested_ip: Optional[str] = None,
        delete_on_termination: bool = False,  # AWS default for standalone ENIs
    ) -> tuple[ipaddress.IPv4Address, str]:
        """Reserve an IP, derive MAC, register a detached ENI in the index.

        Returns ``(primary_ip, mac)`` so the handler can patch moto's
        record. Raises EniManagerError subclass on failure (caller
        translates to AWS API fault).

        No Docker call here — a freshly created ENI has no container.
        Attach happens separately.
        """
        try:
            ip = self._allocator.reserve(
                vpc_id=vpc_id, subnet_id=subnet_id,
                owner_key=f"eni:{eni_id}",
                requested=requested_ip,
            )
        except (UnknownSubnet, InvalidIpForSubnet, IpAddressInUse,
                InsufficientFreeAddressesInSubnet) as exc:
            raise InvalidEniState(
                f"create_network_interface: {exc}"
            ) from exc

        mac = derive_mac(ip)
        try:
            self._index.register_eni(
                eni_id=eni_id,
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                primary_ip=ip,
                mac=mac,
                sg_ids=list(sg_ids),
                instance_id=None,  # detached at create
                iface_name=None,
            )
            # delete_on_termination is recorded for the future
            # AttachNetworkInterface to honor.
            entry = self._index.get_eni(eni_id)
            if entry is not None:
                entry.delete_on_termination = delete_on_termination
        except Exception:
            # Roll back the allocator reservation
            try:
                self._allocator.release(ip)
            except Exception:
                LOG.debug(
                    "EniManager.create rollback (release) failed",
                    exc_info=True,
                )
            raise

        LOG.info(
            "EniManager.create: %s in %s/%s -> %s (mac=%s)",
            eni_id, vpc_id, subnet_id, ip, mac,
        )
        return ip, mac

    # -- AttachNetworkInterface ---------------------------------------------

    def attach(
        self, eni_id: str, instance_id: str, device_index: int,
    ) -> None:
        """Attach an ENI to an instance's container.

        Sequence (under per-instance lock):
          1. Lookup ENI; refuse if already attached
          2. Pre-register the index entry with instance_id but iface=None
          3. DOCKER_CLIENT.connect_container_to_network(... ipv4_address=...)
             outside the lock
          4. resolve_iface_for_network to find the real iface name
          5. Update index entry's iface_name + device_index
          6. ip-addr-add secondary IPs (best-effort)

        Per-iface SG chains and source/dest-check are programmed by
        separate methods (called by the handler after attach succeeds)
        so this method has a focused responsibility.

        Raises:
          EniNotFound: eni_id not in index
          EniAlreadyAttached: ENI is currently attached to some instance
        """
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")
        if entry.instance_id is not None:
            raise EniAlreadyAttached(
                f"ENI {eni_id} is already attached to {entry.instance_id}"
            )

        container = _container_name_for_instance(instance_id)
        network = _vpc_network_name(entry.vpc_id)

        with self._lock_for(instance_id):
            # 1. Pre-register the attachment in the index (iface=None for now)
            self._index.attach_eni(
                eni_id=eni_id, instance_id=instance_id, iface_name="<pending>",
            )
            shared_iface = False
            try:
                # 2. Pin the IP to a new Docker interface
                DOCKER_CLIENT.connect_container_to_network(
                    network_name=network,
                    container_name_or_id=container,
                    ipv4_address=str(entry.primary_ip),
                    mac_address=entry.mac,  # warned + dropped per moby/moby#48192
                )
            except Exception as exc:
                # Docker rejects a second endpoint from one container into
                # the same bridge. This is the normal case for hot-attach:
                # the instance container is already on its VPC bridge for
                # the primary ENI (eth0). Fall back to shared-iface mode —
                # add the ENI's IP as a secondary on the existing iface
                # via ``ip addr add``. The kernel emits a gratuitous ARP,
                # so other containers on the bridge route to it.
                if _is_already_on_network_error(exc):
                    shared_iface = True
                    LOG.info(
                        "EniManager.attach: container %s already on %s; "
                        "using shared-iface mode for %s",
                        container, network, eni_id,
                    )
                else:
                    try:
                        self._index.detach_eni(eni_id)
                    except Exception:
                        LOG.debug(
                            "EniManager.attach rollback (detach) failed",
                            exc_info=True,
                        )
                    raise InvalidEniState(
                        f"connect_container_to_network failed: {exc}"
                    ) from exc

            # 3. Resolve the actual in-container iface name
            iface = resolve_iface_for_network(container, network) or "eth0"

            # In shared-iface mode, the primary IP isn't pinned via Docker;
            # add it explicitly inside the container so it's routable.
            if shared_iface:
                self._docker_ip_addr_add(container, iface, entry.primary_ip)

            # Update entry with real iface_name + device_index + mode
            updated = self._index.get_eni(eni_id)
            if updated is not None:
                updated.iface_name = iface
                updated.device_index = device_index
                updated.shared_iface = shared_iface

            # 4. ip addr add /32 for each secondary IP (best-effort)
            for secondary_ip in entry.secondary_ips:
                self._docker_ip_addr_add(container, iface, secondary_ip)

        LOG.info(
            "EniManager.attach: %s -> %s (device_index=%d, iface=%s)",
            eni_id, instance_id, device_index, iface,
        )

    # -- DetachNetworkInterface ---------------------------------------------

    def detach(self, eni_id: str) -> None:
        """Detach an ENI from its current instance.

        Raises:
          EniNotFound: eni_id not in index
          EniNotAttached: ENI is detached
          CannotDetachPrimary: device_index == 0
        """
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")
        if entry.instance_id is None:
            raise EniNotAttached(f"ENI {eni_id} is not attached")
        if entry.device_index == 0:
            raise CannotDetachPrimary(
                f"cannot detach primary ENI {eni_id} (device_index=0)"
            )

        container = _container_name_for_instance(entry.instance_id)
        network = _vpc_network_name(entry.vpc_id)
        instance_id = entry.instance_id
        iface = entry.iface_name or "eth0"

        with self._lock_for(instance_id):
            if entry.shared_iface:
                # Shared mode: remove the IPs from the existing iface;
                # don't disconnect the container (the primary ENI and
                # possibly other shared ENIs still use this iface).
                for ip in entry.all_ips():
                    self._docker_ip_addr_del(container, iface, ip)
            else:
                try:
                    DOCKER_CLIENT.disconnect_container_from_network(
                        network_name=network,
                        container_name_or_id=container,
                    )
                except Exception as exc:
                    # Log and continue; AWS contract says detach should not
                    # leave the ENI half-detached just because the data plane
                    # operation failed. The reconciler catches drift.
                    LOG.warning(
                        "EniManager.detach: docker disconnect failed for %s: %s",
                        eni_id, exc,
                    )
            self._index.detach_eni(eni_id)
            # Clear device_index (AWS behavior — re-attach picks a new index)
            updated = self._index.get_eni(eni_id)
            if updated is not None:
                updated.device_index = None
                updated.iface_name = None
                updated.shared_iface = False

        LOG.info("EniManager.detach: %s from %s", eni_id, instance_id)

    # -- DeleteNetworkInterface ---------------------------------------------

    def delete(self, eni_id: str) -> None:
        """Delete an ENI. Refuses if still attached.

        Releases the primary + every secondary IP back to the SubnetAllocator.

        Raises:
          EniNotFound: eni_id not in index
          EniInUse: ENI is currently attached
        """
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")
        if entry.instance_id is not None:
            raise EniInUse(
                f"ENI {eni_id} is currently in use (attached to "
                f"{entry.instance_id})"
            )

        removed = self._index.delete_eni(eni_id)
        if removed is not None:
            try:
                self._allocator.release(removed.primary_ip)
            except Exception:
                LOG.debug(
                    "EniManager.delete: release primary failed",
                    exc_info=True,
                )
            for s_ip in removed.secondary_ips:
                try:
                    self._allocator.release(s_ip)
                except Exception:
                    LOG.debug(
                        "EniManager.delete: release secondary %s failed",
                        s_ip, exc_info=True,
                    )

        LOG.info("EniManager.delete: %s", eni_id)

    # -- Helpers ------------------------------------------------------------

    def _docker_ip_addr_add(
        self, container: str, iface: str, ip: ipaddress.IPv4Address,
    ) -> bool:
        """Run ``ip addr add <ip>/32 dev <iface>`` inside the container.

        Same pattern as container_routing.alias_own_vpc_ip_on_pcx.
        Idempotent (ignores 'File exists'). Returns True on best-effort
        success.
        """
        if not (container and iface and ip):
            return False
        cmd = (
            f"ip addr add {ip}/32 dev {iface} 2>/dev/null || true ; exit 0"
        )
        try:
            DOCKER_CLIENT.exec_in_container(container, ["sh", "-c", cmd])
            return True
        except Exception as exc:
            LOG.warning(
                "EniManager: ip addr add %s/32 dev %s in %s failed: %s",
                ip, iface, container, exc,
            )
            return False

    def _docker_ip_addr_del(
        self, container: str, iface: str, ip: ipaddress.IPv4Address,
    ) -> bool:
        """Run ``ip addr del <ip>/32 dev <iface>`` inside the container."""
        if not (container and iface and ip):
            return False
        cmd = (
            f"ip addr del {ip}/32 dev {iface} 2>/dev/null || true ; exit 0"
        )
        try:
            DOCKER_CLIENT.exec_in_container(container, ["sh", "-c", cmd])
            return True
        except Exception as exc:
            LOG.warning(
                "EniManager: ip addr del %s/32 dev %s in %s failed: %s",
                ip, iface, container, exc,
            )
            return False

    # -- AssignPrivateIpAddresses -------------------------------------------

    def assign_private_ips(
        self,
        eni_id: str,
        explicit_ips: Optional[list[str]] = None,
        count: int = 0,
    ) -> list[ipaddress.IPv4Address]:
        """Reserve secondary IPs, add them to the ENI's index entry, and
        if the ENI is attached, ``ip addr add`` them inside the container.

        Args:
          explicit_ips: caller-specified IPs (each goes through
            allocator.reserve with requested=<ip>).
          count: when explicit_ips is empty, ask the allocator to auto-pick
            this many IPs.

        Returns the list of newly-reserved IPs.
        """
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")

        reserved: list[ipaddress.IPv4Address] = []
        try:
            if explicit_ips:
                for idx, ip_str in enumerate(explicit_ips):
                    ip = self._allocator.reserve(
                        vpc_id=entry.vpc_id, subnet_id=entry.subnet_id,
                        owner_key=f"eni:{eni_id}:sec:{idx}",
                        requested=ip_str,
                    )
                    reserved.append(ip)
            else:
                for i in range(count):
                    ip = self._allocator.reserve(
                        vpc_id=entry.vpc_id, subnet_id=entry.subnet_id,
                        owner_key=f"eni:{eni_id}:sec:auto:{i}",
                    )
                    reserved.append(ip)
        except (UnknownSubnet, InvalidIpForSubnet, IpAddressInUse,
                InsufficientFreeAddressesInSubnet) as exc:
            # Roll back any successful reservations
            for ip in reserved:
                try:
                    self._allocator.release(ip)
                except Exception:
                    pass
            raise InvalidEniState(
                f"assign_private_ips: {exc}"
            ) from exc

        # Record in the index
        for ip in reserved:
            self._index.add_secondary_ip(eni_id, ip)

        # If the ENI is attached, push to the container's kernel
        if entry.instance_id and entry.iface_name:
            container = _container_name_for_instance(entry.instance_id)
            for ip in reserved:
                self._docker_ip_addr_add(container, entry.iface_name, ip)

        LOG.info(
            "EniManager.assign_private_ips: %s +%d IPs",
            eni_id, len(reserved),
        )
        return reserved

    # -- UnassignPrivateIpAddresses -----------------------------------------

    def unassign_private_ips(
        self, eni_id: str, ips: Iterable[str],
    ) -> None:
        """Remove secondary IPs from the ENI: ``ip addr del`` (if attached),
        ``address_index.remove_secondary_ip``, ``allocator.release``."""
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")

        for ip_str in ips:
            try:
                ip = ipaddress.IPv4Address(ip_str)
            except (ValueError, ipaddress.AddressValueError):
                continue
            # Remove from container kernel (if attached)
            if entry.instance_id and entry.iface_name:
                container = _container_name_for_instance(entry.instance_id)
                self._docker_ip_addr_del(container, entry.iface_name, ip)
            # Remove from index
            self._index.remove_secondary_ip(eni_id, ip)
            # Release back to allocator
            try:
                self._allocator.release(ip)
            except Exception:
                LOG.debug(
                    "EniManager.unassign_private_ips: release %s failed",
                    ip, exc_info=True,
                )

        LOG.info(
            "EniManager.unassign_private_ips: %s",
            eni_id,
        )

    # -- ModifyNetworkInterfaceAttribute ------------------------------------

    def modify_attribute(
        self,
        eni_id: str,
        groups: Optional[list[str]] = None,
        source_dest_check: Optional[bool] = None,
        description: Optional[str] = None,
        delete_on_termination: Optional[bool] = None,
    ) -> None:
        """Update one or more ENI attributes.

        Args (any number may be set, the others ignored):
          groups: replace the SG list. Updates AddressIndex._sg_to_enis
            reverse index. If the ENI is attached, per-iface SG chain
            re-apply is triggered (caller's responsibility — left to the
            sg_iptables/sg_reapply integration that lands separately).
          source_dest_check: store on EniEntry.source_dest_check. If
            attached, FORWARD-chain rules are reprogrammed (handled by
            the source_dest_check FORWARD-chain helper that lands in
            the follow-up commit).
          description: stored on moto only; no Docker effect (the EniEntry
            doesn't carry description for v2).
          delete_on_termination: store on EniEntry.delete_on_termination
            so terminate_instance cleanup loop honors it.
        """
        entry = self._index.get_eni(eni_id)
        if entry is None:
            raise EniNotFound(f"unknown ENI {eni_id}")

        if groups is not None:
            self._index.update_sgs(eni_id, list(groups))

        if source_dest_check is not None:
            entry.source_dest_check = bool(source_dest_check)
            # TODO (next commit): apply FORWARD-chain rules to enforce
            # the new value when entry.iface_name is set

        if delete_on_termination is not None:
            entry.delete_on_termination = bool(delete_on_termination)

        # description is moto-only — handler doesn't pass it through

        LOG.info(
            "EniManager.modify_attribute: %s groups=%s sdc=%s dot=%s",
            eni_id, groups, source_dest_check, delete_on_termination,
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_singleton: Optional[EniManager] = None
_singleton_lock = threading.Lock()


def get_eni_manager() -> EniManager:
    """Process-wide singleton. Thread-safe lazy init."""
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = EniManager()
        return _singleton


def reset_eni_manager_for_tests() -> None:
    """Drop the singleton. ONLY for tests."""
    global _singleton
    with _singleton_lock:
        _singleton = None
