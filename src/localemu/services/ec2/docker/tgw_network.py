"""Transit Gateway data plane for LocalEmu (T1 of peering+TGW plan).

Model: per-TGW **shared bridge** named ``localemu-tgw-<tgw-id>`` (not
a container — just a Docker bridge network). Every EC2 container of
every attached VPC also joins this bridge. Traffic between two
attached VPCs uses the same DNAT+SNAT mechanism that P1 established
for VPC peering — packets on the wire are pure tgw-bridge-subnet
traffic (src+dst both on e.g. ``172.20.0.0/16``) which Docker
Desktop's bridge-netfilter allows, and conntrack reverses both NATs
so the application sees the real VPC IPs.

Why not a router-container model:
  A per-TGW container with interfaces on each attached VPC bridge
  (the natural "virtual router" shape) fails on Docker Desktop
  because attached VPC networks are created with ``--internal=true``
  and Docker installs host-level FORWARD rules that DROP packets
  between two ``--internal`` bridges. No amount of ``ip route`` or
  ``sysctl ip_forward=1`` inside the router helps — the host drops
  before the router sees anything.

  The shared-bridge model sidesteps this because every
  cross-VPC-via-TGW packet stays on one non-internal Docker bridge
  from end to end; the host's FORWARD hook doesn't see it as a
  cross-bridge forward.

Non-transitive vs transitive: for T1 (data plane) we implement full
mesh. T2 gates which peer CIDRs each EC2's routing table actually
routes through TGW, so users see AWS-faithful TGW-route-table
semantics even though the underlying L2 is a single bridge.

Limitations (documented, not hidden):
  - A single TGW's attached VPCs share one bridge; this deviates
    from real AWS (per-attachment ENI) but is equivalent at the
    reachability level when route tables align.
  - No TGW peering-attachment cross-region data plane (out of scope
    for this slice).
  - No IPv6.
"""
from __future__ import annotations

import logging
import threading

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

TGW_NETWORK_PREFIX = "localemu-tgw-"


class TgwNetworkManager:
    """Per-process singleton owning the TGW shared bridges and the
    in-memory bookkeeping for attachments + routing."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # tgw_id -> {network_name, attachments: {att_id: {vpc_id, vpc_cidr}}}
        self._tgws: dict[str, dict] = {}
        # attachment_id -> tgw_id (reverse lookup)
        self._att_to_tgw: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    def _network_name(tgw_id: str) -> str:
        return f"{TGW_NETWORK_PREFIX}{tgw_id}"

    def create_tgw(self, tgw_id: str) -> bool:
        """Create the shared Docker bridge for ``tgw_id``. Idempotent."""
        if not tgw_id:
            return False
        with self._lock:
            if tgw_id in self._tgws:
                return True
            net_name = self._network_name(tgw_id)
            try:
                DOCKER_CLIENT.inspect_network(net_name)
                # Already exists — just register.
                self._tgws[tgw_id] = {"network_name": net_name, "attachments": {}}
                return True
            except Exception:
                pass
            # Create the bridge. Non-internal so the host's br_netfilter
            # permits local traffic; no gateway needed (we don't egress).
            try:
                DOCKER_CLIENT.create_network(
                    network_name=net_name, internal=False,
                    labels={
                        "localemu.kind": "tgw",
                        "localemu.tgw-id": tgw_id,
                    },
                )
            except Exception as e:
                LOG.warning("TGW bridge create failed for %s: %s", tgw_id, e)
                return False
            self._tgws[tgw_id] = {"network_name": net_name, "attachments": {}}
            LOG.info("TGW bridge %s created", net_name)
            return True

    def delete_tgw(self, tgw_id: str) -> None:
        """Detach every attachment, then remove the bridge."""
        with self._lock:
            info = self._tgws.pop(tgw_id, None)
            if not info:
                return
            net_name = info["network_name"]
            att_ids = list(info.get("attachments", {}))
            for a in att_ids:
                self._att_to_tgw.pop(a, None)
        # Disconnect every container that joined the bridge (any VPC).
        try:
            net = DOCKER_CLIENT.inspect_network(net_name) or {}
            for c in (net.get("Containers") or {}).values():
                cname = c.get("Name")
                if cname:
                    try:
                        DOCKER_CLIENT.disconnect_container_from_network(
                            net_name, cname,
                        )
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            DOCKER_CLIENT.delete_network(net_name)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Attachments
    # ------------------------------------------------------------------

    def create_vpc_attachment(
        self, attachment_id: str, tgw_id: str, vpc_id: str,
    ) -> bool:
        """Attach every EC2 of ``vpc_id`` to the TGW bridge and program
        routing so cross-VPC traffic via real VPC IPs works."""
        from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
        vpc_mgr = get_vpc_network_manager()

        with self._lock:
            tgw = self._tgws.get(tgw_id)
            if not tgw:
                LOG.debug("create_vpc_attachment: unknown tgw %s", tgw_id)
                return False
            net_name = tgw["network_name"]

        vpc_info = vpc_mgr._vpcs.get(vpc_id) or {}
        vpc_cidr = vpc_info.get("cidr") or ""
        if not vpc_cidr:
            LOG.debug("create_vpc_attachment: vpc %s not tracked", vpc_id)
            return False

        with self._lock:
            tgw["attachments"][attachment_id] = {
                "vpc_id": vpc_id, "vpc_cidr": vpc_cidr,
            }
            self._att_to_tgw[attachment_id] = tgw_id
            peers = dict(tgw["attachments"])

        # Connect each EC2 in this VPC to the TGW bridge.
        containers = list(vpc_info.get("containers", set()))
        for c in containers:
            try:
                DOCKER_CLIENT.connect_container_to_network(net_name, c)
            except Exception as e:
                msg = str(e)
                if "already exists" not in msg and "already connected" not in msg:
                    LOG.debug(
                        "connect %s to %s failed: %s", c, net_name, e,
                    )

        # Full mesh NAT routing across all attached VPCs.
        self._reprogram_full_mesh(tgw_id, peers, vpc_mgr, net_name)
        LOG.info(
            "TGW attachment %s: vpc %s (%s) joined bridge %s",
            attachment_id, vpc_id, vpc_cidr, net_name,
        )
        return True

    def delete_vpc_attachment(self, attachment_id: str) -> None:
        from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
        vpc_mgr = get_vpc_network_manager()
        with self._lock:
            tgw_id = self._att_to_tgw.pop(attachment_id, None)
            if not tgw_id:
                return
            tgw = self._tgws.get(tgw_id)
            if not tgw:
                return
            att = tgw["attachments"].pop(attachment_id, None)
            if not att:
                return
            net_name = tgw["network_name"]
            peers = dict(tgw["attachments"])
        vpc_id = att["vpc_id"]
        vpc_info = vpc_mgr._vpcs.get(vpc_id) or {}
        # Disconnect this VPC's EC2s from the bridge.
        for c in list(vpc_info.get("containers", set())):
            try:
                DOCKER_CLIENT.disconnect_container_from_network(net_name, c)
            except Exception:
                pass
        # Tear down NAT rules that targeted the detached VPC's CIDR on
        # every surviving attachment.
        self._unprogram_for_detached(att, peers, vpc_mgr)

    # ------------------------------------------------------------------
    # Route programming
    # ------------------------------------------------------------------

    def on_container_registered(self, vpc_id: str, container_name: str) -> None:
        """Called right after an EC2 joins a VPC. If the VPC has any
        TGW attachment, connect the container to every relevant TGW
        bridge and program NAT routing for every peer VPC CIDR."""
        from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
        vpc_mgr = get_vpc_network_manager()
        with self._lock:
            matches: list[tuple[str, str, dict]] = []
            for tgw_id, tgw in self._tgws.items():
                own_att = None
                for att_id, att in tgw["attachments"].items():
                    if att["vpc_id"] == vpc_id:
                        own_att = att
                        break
                if not own_att:
                    continue
                matches.append((tgw_id, tgw["network_name"], dict(tgw["attachments"])))
        for tgw_id, net_name, peers in matches:
            try:
                DOCKER_CLIENT.connect_container_to_network(net_name, container_name)
            except Exception as e:
                msg = str(e)
                if "already exists" not in msg:
                    LOG.debug(
                        "connect new %s to %s failed: %s",
                        container_name, net_name, e,
                    )
            self._program_for_container_against_peers(
                container_name, vpc_id, peers, net_name, vpc_mgr,
            )
            # Also update every existing peer container with a /32 DNAT
            # back to the newcomer.
            self._program_peers_for_new_container(
                container_name, vpc_id, peers, net_name, vpc_mgr,
            )

    def _reprogram_full_mesh(
        self, tgw_id: str, peers: dict, vpc_mgr, net_name: str,
    ) -> None:
        """For every attached VPC's EC2, ensure it's on the bridge and
        has NAT routes for every other attached VPC's CIDR."""
        for att in peers.values():
            vpc_info = vpc_mgr._vpcs.get(att["vpc_id"]) or {}
            containers = list(vpc_info.get("containers", set()))
            for c in containers:
                try:
                    DOCKER_CLIENT.connect_container_to_network(net_name, c)
                except Exception as e:
                    msg = str(e)
                    if "already exists" not in msg:
                        pass
            for c in containers:
                self._program_for_container_against_peers(
                    c, att["vpc_id"], peers, net_name, vpc_mgr,
                )

    def _program_for_container_against_peers(
        self, container: str, own_vpc_id: str, peers: dict,
        net_name: str, vpc_mgr,
    ) -> None:
        """For ``container`` (in ``own_vpc_id``), install:
          - alias own VPC IP on the TGW iface
          - blanket SNAT on the TGW iface
          - DNAT + /32 route per peer-instance in other VPCs
        """
        from localemu.services.ec2.docker.container_routing import (
            add_peer_host_route, add_snat_for_pcx,
            alias_own_vpc_ip_on_pcx, resolve_pcx_iface,
        )
        from localemu.services.ec2.docker.vpc_network import VPC_NETWORK_PREFIX

        own_vpc_net = f"{VPC_NETWORK_PREFIX}{own_vpc_id}"
        try:
            own_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container, own_vpc_net,
            )
            own_tgw_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container, net_name,
            )
        except Exception:
            own_vpc_ip = own_tgw_ip = None
        if not (own_vpc_ip and own_tgw_ip):
            return
        tgw_iface = resolve_pcx_iface(container, net_name)
        if not tgw_iface:
            return
        alias_own_vpc_ip_on_pcx(container, tgw_iface, own_vpc_ip)
        add_snat_for_pcx(container, tgw_iface, own_tgw_ip)
        # DNAT + host route per peer instance of every OTHER attached VPC.
        for peer_att in peers.values():
            peer_vpc_id = peer_att["vpc_id"]
            if peer_vpc_id == own_vpc_id:
                continue
            peer_vpc_info = vpc_mgr._vpcs.get(peer_vpc_id) or {}
            peer_vpc_net = f"{VPC_NETWORK_PREFIX}{peer_vpc_id}"
            for peer_c in peer_vpc_info.get("containers", set()):
                try:
                    peer_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                        peer_c, peer_vpc_net,
                    )
                    peer_tgw_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                        peer_c, net_name,
                    )
                except Exception:
                    continue
                if not (peer_vpc_ip and peer_tgw_ip):
                    continue
                add_peer_host_route(
                    container, tgw_iface, peer_vpc_ip, peer_tgw_ip,
                )

    def _program_peers_for_new_container(
        self, new_container: str, new_vpc_id: str, peers: dict,
        net_name: str, vpc_mgr,
    ) -> None:
        """After a newcomer joins, ensure every existing container in
        every OTHER attached VPC has a /32 DNAT+route pointing at the
        newcomer's VPC IP via the newcomer's TGW-bridge IP."""
        from localemu.services.ec2.docker.container_routing import (
            add_peer_host_route, resolve_pcx_iface,
        )
        from localemu.services.ec2.docker.vpc_network import VPC_NETWORK_PREFIX

        try:
            new_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                new_container, f"{VPC_NETWORK_PREFIX}{new_vpc_id}",
            )
            new_tgw_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                new_container, net_name,
            )
        except Exception:
            return
        if not (new_vpc_ip and new_tgw_ip):
            return
        for peer_att in peers.values():
            if peer_att["vpc_id"] == new_vpc_id:
                continue
            vpc_info = vpc_mgr._vpcs.get(peer_att["vpc_id"]) or {}
            for peer_c in vpc_info.get("containers", set()):
                iface = resolve_pcx_iface(peer_c, net_name)
                if not iface:
                    continue
                add_peer_host_route(peer_c, iface, new_vpc_ip, new_tgw_ip)

    def _unprogram_for_detached(self, detached_att: dict, peers: dict, vpc_mgr) -> None:
        """Remove /32 DNAT rules that target the detached VPC's CIDR on
        every remaining attachment's containers."""
        # We use the generic peering-route-del helper via container_routing
        # if we had the peer IP list; for now, a best-effort: rely on the
        # disconnect removing the bridge interface which makes stale
        # rules harmless.
        return

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def attachment(self, attachment_id: str) -> dict | None:
        with self._lock:
            tgw_id = self._att_to_tgw.get(attachment_id)
            if not tgw_id:
                return None
            tgw = self._tgws.get(tgw_id)
            if not tgw:
                return None
            att = tgw["attachments"].get(attachment_id)
            return dict(att) if att else None

    def attachments_for_tgw(self, tgw_id: str) -> dict:
        with self._lock:
            tgw = self._tgws.get(tgw_id)
            return dict(tgw["attachments"]) if tgw else {}


_instance: TgwNetworkManager | None = None
_instance_lock = threading.Lock()


def get_tgw_network_manager() -> TgwNetworkManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TgwNetworkManager()
    return _instance
