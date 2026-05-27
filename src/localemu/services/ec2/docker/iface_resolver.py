"""MAC-based interface-name resolution inside a Docker container.

When LocalEmu attaches a container to a Docker network, the kernel
assigns the new interface a name like ``eth1``/``eth2``/... The exact
name depends on attach order, which is NOT stable across container
restart (libnetwork iterates its internal network dict, ordering
varies). The robust way to recover the in-container iface name for a
specific Docker network is:

  1. ``docker inspect`` the container; read the MAC the daemon assigned
     for that network from ``NetworkSettings.Networks[<network>].MacAddress``.
  2. ``ip -o link show`` inside the container; find the line whose
     ``link/ether`` MAC matches; extract the iface name from the
     ``N: <name>@ifX:`` prefix.

The pattern was first implemented for VPC peering at
``container_routing.resolve_pcx_iface`` (used to install per-peer
host routes on the right iface). The ENI design needs the same lookup
for every attached ENI's primary/secondary IP programming, per-iface
SG chain installation, and source/dest-check FORWARD rules.

This module is the factored-out shared helper. ``container_routing``
keeps a thin wrapper for backward compatibility.
"""
from __future__ import annotations

import logging
from typing import Optional

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


def resolve_iface_for_network(
    container_name: str, network_name: str,
) -> Optional[str]:
    """Return the in-container interface name (``eth0``/``eth1``/...)
    for the given Docker network attachment, or ``None`` if it cannot
    be resolved.

    Resolution is MAC-based and tolerant of every known failure mode:
      - Docker inspect failure -> None
      - Network not attached to container -> None
      - Container does not have ``ip`` binary -> None (logged at DEBUG)
      - MAC mismatch (no iface carries the expected MAC) -> None

    Idempotent and side-effect free.
    """
    if not (container_name and network_name):
        return None
    try:
        inspected = DOCKER_CLIENT.inspect_container(container_name)
    except Exception as exc:
        LOG.debug(
            "iface_resolver: inspect_container(%s) failed: %s",
            container_name, exc,
        )
        return None
    nets = (
        (inspected or {}).get("NetworkSettings", {}).get("Networks", {})
        or {}
    )
    net_info = nets.get(network_name) or {}
    mac = (net_info.get("MacAddress") or "").lower()
    if not mac:
        return None
    # Ask the container which iface carries this MAC.
    # ``ip -o link show`` lines look like:
    #   3: eth1@if31: <BROADCAST,...> mtu 1500 ...
    #      link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff
    try:
        out, _ = DOCKER_CLIENT.exec_in_container(
            container_name, ["sh", "-c", "ip -o link show"],
        )
    except Exception as exc:
        LOG.debug(
            "iface_resolver: ip-link exec in %s failed: %s",
            container_name, exc,
        )
        return None
    text = (
        out.decode("utf-8", errors="replace")
        if isinstance(out, bytes) else str(out)
    )
    for line in text.splitlines():
        if mac not in line.lower():
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        # parts[0] = "3:" (ifindex), parts[1] = "eth1@if31:" or "eth1:"
        iface_name = parts[1].rstrip(":")
        # Strip "@ifXX" peer-suffix on veth pairs
        return iface_name.split("@", 1)[0]
    return None
