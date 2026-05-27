"""In-container routing for VPC peering (fix for real-VPC-IP routing).

Problem: containers in peered VPCs share a Docker bridge
(``localemu-pcx-<id>``), but the kernel doesn't know how to forward
traffic to the peer's own-VPC IP (``10.81.0.3``) — ping / curl to that
address times out. Only the peer's bridge IP (``172.24.0.3``) works,
which is a LocalEmu artifact no real AWS workload ever uses.

Mechanism (after experimentation against Docker Desktop's LinuxKit):
  - Routing via ``<peer-cidr> dev pcx`` alone does not work because
    the host's ``br_netfilter`` rejects frames arriving on the pcx
    bridge whose source IP is from a different network.
  - Sysctls like ``net.ipv4.conf.*.proxy_arp`` and per-interface
    ``accept_local`` cannot be set from inside the container because
    Docker mounts ``/proc/sys`` read-only.
  - So the ONLY configuration we can push is per-container
    ``ip addr``, ``ip route``, and ``iptables`` under ``CAP_NET_ADMIN``
    (which our EC2 containers already have).

Chosen design — SNAT on the sending side + /32 alias on the
receiving side:

  For every peered container C in VPC V with VPC IP ``V_ip`` and pcx
  IP ``V_pcx``, we:
    1. Alias ``V_ip/32`` on the pcx interface (so traffic addressed
       to ``V_ip`` arriving on the pcx bridge is kernel-accepted —
       works even without ``accept_local=1``).
    2. For every peer instance P with VPC IP ``P_ip`` and pcx IP
       ``P_pcx``, install ``ip route replace P_ip/32 via P_pcx
       dev <pcx>``.
    3. For every peer VPC CIDR, install an iptables rule
       ``-t nat -A POSTROUTING -o <pcx> -d <peer-cidr> -j SNAT
       --to-source <V_pcx>`` so outgoing traffic to peer CIDRs
       originates from our pcx IP (otherwise br_netfilter drops it).

  On the way back, conntrack reverses the SNAT. The application
  process sees ``src=<peer-VPC-IP>, dst=<own-VPC-IP>`` — the exact
  addresses a real-AWS workload expects.

  The SOURCE-IP-as-seen-by-peer is the sender's pcx IP, not its
  real VPC IP. This is the one deviation from AWS parity; for
  SG cross-VPC references LocalEmu already uses a custom resolver
  (``sg_evaluator``) and is unaffected.

Non-transitive isolation is preserved because each peering has its
own dedicated bridge with its own SNAT POSTROUTING rule; packets
aren't forwarded between bridges.
"""
from __future__ import annotations

import logging
from typing import Optional

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


def resolve_pcx_iface(container: str, pcx_network: str) -> Optional[str]:
    """Return the interface name (``eth0``/``eth1``/…) inside ``container``
    that is connected to the Docker network ``pcx_network``.

    Backward-compatible thin wrapper. The implementation lives in the
    shared ``iface_resolver`` module (also used by ENI handlers, source-dest
    check programming, and per-iface SG chain installation).
    """
    from localemu.services.ec2.docker.iface_resolver import (
        resolve_iface_for_network,
    )
    return resolve_iface_for_network(container, pcx_network)


def _run(container: str, script: str) -> tuple[int, str, str]:
    """Run a shell script inside ``container``; return (rc, stdout, stderr)."""
    try:
        out, err = DOCKER_CLIENT.exec_in_container(
            container, ["sh", "-c", script],
        )
        stdout = out.decode("utf-8", errors="replace") if isinstance(out, bytes) else str(out)
        stderr = err.decode("utf-8", errors="replace") if isinstance(err, bytes) else str(err or "")
        # exec_in_container raises on non-zero, so rc == 0 when we get here.
        return 0, stdout, stderr
    except Exception as exc:
        return 1, "", str(exc)


def alias_own_vpc_ip_on_pcx(
    container: str, pcx_iface: str, own_vpc_ip: str,
) -> bool:
    """Add ``own_vpc_ip/32`` as an alias on the container's pcx interface
    so inbound traffic addressed to this IP on the peering bridge is
    kernel-accepted without needing per-iface ``accept_local=1``.
    Idempotent."""
    if not (container and pcx_iface and own_vpc_ip):
        return False
    rc, _, err = _run(
        container,
        f"ip addr add {own_vpc_ip}/32 dev {pcx_iface} 2>/dev/null || true ; exit 0",
    )
    if rc != 0:
        LOG.warning("alias_own_vpc_ip_on_pcx failed on %s: %s", container, err)
        return False
    return True


def add_peer_host_route(
    container: str, pcx_iface: str, peer_vpc_ip: str, peer_pcx_ip: str,
) -> bool:
    """Add a host (/32) route on ``container`` so traffic to a specific
    peer instance's VPC IP goes via that peer's pcx-bridge IP. Plus
    install an OUTPUT-chain DNAT rule so the packet's dst is rewritten
    to the peer's pcx IP BEFORE the bridge sees it — that keeps the
    wire traffic pure pcx-to-pcx (which Docker's bridge-netfilter
    doesn't molest) while conntrack reverses the DNAT on the return
    so the application still sees the peer's real VPC IP.

    Idempotent: the DNAT rule is ``-C`` checked before ``-A``.
    """
    if not (container and pcx_iface and peer_vpc_ip and peer_pcx_ip):
        return False
    check = (
        f"iptables -t nat -C OUTPUT -d {peer_vpc_ip}/32 "
        f"-j DNAT --to-destination {peer_pcx_ip} 2>/dev/null"
    )
    add = (
        f"iptables -t nat -A OUTPUT -d {peer_vpc_ip}/32 "
        f"-j DNAT --to-destination {peer_pcx_ip}"
    )
    route = (
        f"ip route replace {peer_vpc_ip}/32 via {peer_pcx_ip} dev {pcx_iface}"
    )
    rc, _, err = _run(container, f"{route} ; {check} || {add} ; exit 0")
    if rc != 0:
        LOG.warning(
            "add_peer_host_route failed on %s (peer=%s via %s): %s",
            container, peer_vpc_ip, peer_pcx_ip, err,
        )
        return False
    return True


def del_peer_host_route(
    container: str, pcx_iface: str, peer_vpc_ip: str, peer_pcx_ip: str,
) -> None:
    """Remove the DNAT rule + host route installed by ``add_peer_host_route``."""
    if not (container and pcx_iface and peer_vpc_ip and peer_pcx_ip):
        return
    _run(
        container,
        f"ip route del {peer_vpc_ip}/32 dev {pcx_iface} 2>/dev/null ; "
        f"iptables -t nat -D OUTPUT -d {peer_vpc_ip}/32 "
        f"-j DNAT --to-destination {peer_pcx_ip} 2>/dev/null ; exit 0",
    )


def add_snat_for_pcx(
    container: str, pcx_iface: str, own_pcx_ip: str,
) -> bool:
    """Install an iptables POSTROUTING SNAT rule so outbound traffic
    leaving ``pcx_iface`` is source-rewritten to ``own_pcx_ip``.

    The wire traffic is therefore pure pcx-to-pcx (src and dst both
    on the peering bridge subnet) which Docker Desktop's
    bridge-netfilter allows. Conntrack reverses on the return.
    """
    if not (container and pcx_iface and own_pcx_ip):
        return False
    check = (
        f"iptables -t nat -C POSTROUTING -o {pcx_iface} "
        f"-j SNAT --to-source {own_pcx_ip} 2>/dev/null"
    )
    add = (
        f"iptables -t nat -A POSTROUTING -o {pcx_iface} "
        f"-j SNAT --to-source {own_pcx_ip}"
    )
    rc, _, err = _run(container, f"{check} || {add} ; exit 0")
    if rc != 0:
        LOG.warning(
            "add_snat_for_pcx failed on %s: %s", container, err,
        )
        return False
    return True


def del_snat_for_pcx(
    container: str, pcx_iface: str, own_pcx_ip: str,
) -> None:
    if not (container and pcx_iface and own_pcx_ip):
        return
    _run(
        container,
        f"iptables -t nat -D POSTROUTING -o {pcx_iface} "
        f"-j SNAT --to-source {own_pcx_ip} 2>/dev/null; exit 0",
    )


def program_peering_routes(
    container: str, pcx_iface: str, own_vpc_ip: str, own_pcx_ip: str,
    peer_instances: list[tuple[str, str]],
) -> bool:
    """One-shot helper: alias own VPC IP on pcx + install full NAT
    (DNAT per peer + blanket SNAT on pcx egress).

    ``peer_instances`` is ``[(peer_vpc_ip, peer_pcx_ip), …]``.
    Returns True iff the base rules (alias + SNAT) landed.
    """
    if not (container and pcx_iface and own_vpc_ip and own_pcx_ip):
        return False
    alias_ok = alias_own_vpc_ip_on_pcx(container, pcx_iface, own_vpc_ip)
    snat_ok = add_snat_for_pcx(container, pcx_iface, own_pcx_ip)
    for peer_vpc_ip, peer_pcx_ip in peer_instances or []:
        add_peer_host_route(container, pcx_iface, peer_vpc_ip, peer_pcx_ip)
    return alias_ok and snat_ok


def unprogram_peering_routes(
    container: str, pcx_iface: str, own_vpc_ip: str,
    peer_vpc_ips: list[str] | None = None,
) -> None:
    """Reverse of ``program_peering_routes``. Best-effort; ignores errors
    because the interface may already have been detached by Docker."""
    if not (container and pcx_iface):
        return
    parts = []
    for ip in peer_vpc_ips or []:
        parts.append(
            f"ip route del {ip}/32 dev {pcx_iface} 2>/dev/null || true"
        )
    if own_vpc_ip:
        parts.append(
            f"ip addr del {own_vpc_ip}/32 dev {pcx_iface} 2>/dev/null || true"
        )
    if not parts:
        return
    _run(container, " ; ".join(parts) + " ; exit 0")
