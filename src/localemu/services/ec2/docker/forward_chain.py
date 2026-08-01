"""Per-ENI iptables FORWARD policy for ``SourceDestCheck``.

EC2 enforces ``SourceDestCheck`` per ENI on AWS: a multi-NIC instance can
have the check enabled on the primary and disabled on a secondary used
for forwarded traffic. LocalEmu approximates the AWS-side drop with
iptables rules on the EC2 container's FORWARD chain.

This module is the per-ENI apply layer. It supersedes the original
``apply_source_dest_check`` semantics, which flipped a single global
``-P FORWARD ACCEPT/DROP`` policy on the whole container and could not
distinguish ENIs. The legacy entry point in
``source_dest_check.py`` is preserved as a thin shim for backward
compatibility with the existing single-NIC quiet-router callers.

Two modes are supported, both observed in real LocalEmu containers:

1. **Separate-iface mode** (``shared_iface=False``): the AWS ENI maps
   to a dedicated container iface, typically ``eth1`` for the primary
   and ``eth2`` for a secondary on a different VPC bridge. The FORWARD
   rule is a plain ``-i <iface_name> -j ACCEPT``.

2. **Shared-iface mode** (``shared_iface=True``): the AWS ENI shares a
   container iface with another ENI on the same VPC bridge (Docker
   rejects two endpoints from one container into the same bridge, so
   ``EniManager`` adds the secondary's IP as an alias on the existing
   iface). A plain ``-i <iface>`` rule would match traffic for both
   ENIs and lose per-ENI semantics. Instead we install TWO rules
   keyed on the ENI's primary IP:

       iptables ... FORWARD -i <iface> -s <eni_ip>/32 -j ACCEPT
       iptables ... FORWARD -i <iface> -d <eni_ip>/32 -j ACCEPT

   so forwarded traffic that either originates from or is destined to
   this specific ENI passes, while traffic for the other shared ENI
   stays under the default-DROP policy unless that ENI also has
   ``SourceDestCheck=false``.

The default container-level policy stays ``-P FORWARD DROP``, set on
every boot by the entrypoint block in ``vm_manager.py``. Per-iface /
per-ENI ACCEPT rules selectively open the gate. Kernel
``net.ipv4.ip_forward`` flips to ``1`` whenever any ENI on the
instance has ``SourceDestCheck=false`` (it is per-instance on real
AWS) and back to ``0`` when every ENI is secure again.

Marker files persist per-ENI state across ``docker restart``. The
entrypoint script walks ``/var/lib/localemu/source-dest-check.d/`` and
re-installs each rule on next boot.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

LOG = logging.getLogger(__name__)


_MARKER_DIR = "/var/lib/localemu/source-dest-check.d"


def container_name_for_instance(instance_id: str) -> str:
    """LocalEmu naming convention for an EC2 instance's container."""
    return f"localemu-ec2-{instance_id}"


def _marker_name_for(iface_name: str, eni_ip: str, shared_iface: bool) -> str:
    """Marker filename for this ENI.

    Separate-iface mode: ``<iface>``. The whole iface is opened/closed.
    Shared-iface mode:   ``<iface>-<eni_ip>``. The two source/dest rules
    are keyed on the IP so two shared ENIs on the same iface get two
    independent markers.

    The entrypoint script distinguishes the two by presence of a hyphen
    in the iface segment of the basename.
    """
    if shared_iface:
        return f"{iface_name}-{eni_ip}"
    return iface_name


def apply_forward_for_eni(
    *,
    instance_id: str,
    iface_name: str,
    eni_ip: str,
    shared_iface: bool,
    source_dest_check: bool,
    container_name: Optional[str] = None,
) -> bool:
    """Install / remove the per-ENI FORWARD rule on the instance's container.

    ``source_dest_check=False`` opens the gate for forwarded traffic
    through this ENI ; ``True`` closes it. The kernel ``ip_forward``
    bit is set to ``1`` if ANY marker remains after this call (i.e. at
    least one ENI on the instance has SDC=false), ``0`` otherwise.

    Returns ``True`` when the container was reachable and the change
    was issued ; ``False`` when the container was missing / stopped
    (the marker file is still updated so the entrypoint script picks
    up the state on next boot, but only if the container exists).

    Never raises. Failure to apply the kernel knob must not fail the
    AWS API call that asked for it. Errors are logged at DEBUG.
    """
    # Sanity-check the IP. A malformed value would corrupt the marker
    # filename and iptables would later reject the rule.
    try:
        ipaddress.ip_address(eni_ip)
    except (TypeError, ValueError):
        LOG.debug(
            "apply_forward_for_eni: bad eni_ip %r ; skipping", eni_ip,
        )
        return False

    cname = container_name or container_name_for_instance(instance_id)
    marker = _marker_name_for(iface_name, eni_ip, shared_iface)

    if not _container_running(cname):
        # Persist the marker if the container exists but is stopped.
        # On next boot the entrypoint script consults the directory and
        # re-installs everything that should be enabled.
        if _container_exists(cname):
            _write_or_remove_marker_offline(cname, marker, source_dest_check)
        return False

    # Live container : apply the iptables rule, then the marker.
    if source_dest_check:
        _remove_rule(cname, iface_name, eni_ip, shared_iface)
    else:
        _install_rule(cname, iface_name, eni_ip, shared_iface)

    _write_or_remove_marker_live(cname, marker, source_dest_check)

    # Kernel ip_forward bit : per-instance, set if ANY marker still
    # exists, cleared otherwise. We let the container's shell decide
    # by globbing the marker directory rather than tracking state on
    # the host.
    _exec(
        cname,
        ["sh", "-c",
         # If at least one marker file exists, ip_forward=1, else 0.
         f"if ls {_MARKER_DIR}/* >/dev/null 2>&1; then "
         f"  v=1 ; "
         f"else "
         f"  v=0 ; "
         f"fi ; "
         f"sysctl -w net.ipv4.ip_forward=$v 2>/dev/null "
         f"|| echo $v > /proc/sys/net/ipv4/ip_forward 2>/dev/null "
         f"|| true"],
    )
    return True


# ---------------------------------------------------------------------------
# Rule installers / removers
# ---------------------------------------------------------------------------


def _install_rule(
    container_name: str, iface_name: str, eni_ip: str, shared_iface: bool,
) -> None:
    """Install the per-ENI ACCEPT rule(s). Idempotent."""
    if shared_iface:
        # Two rules, source-match and dest-match.
        _exec(
            container_name,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             f"  iptables -C FORWARD -i {iface_name} -s {eni_ip}/32 -j ACCEPT 2>/dev/null"
             f"    || iptables -I FORWARD 1 -i {iface_name} -s {eni_ip}/32 -j ACCEPT 2>/dev/null ;"
             f"  iptables -C FORWARD -i {iface_name} -d {eni_ip}/32 -j ACCEPT 2>/dev/null"
             f"    || iptables -I FORWARD 1 -i {iface_name} -d {eni_ip}/32 -j ACCEPT 2>/dev/null ;"
             "} || true"],
        )
    else:
        # One rule, plain iface match.
        _exec(
            container_name,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             f"  iptables -C FORWARD -i {iface_name} -j ACCEPT 2>/dev/null"
             f"    || iptables -I FORWARD 1 -i {iface_name} -j ACCEPT 2>/dev/null ;"
             "} || true"],
        )


def _remove_rule(
    container_name: str, iface_name: str, eni_ip: str, shared_iface: bool,
) -> None:
    """Remove the per-ENI ACCEPT rule(s). Idempotent; loops because the
    same rule may have been inserted more than once across past toggles
    (``iptables -D`` only removes the first match)."""
    if shared_iface:
        _exec(
            container_name,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             f"  while iptables -C FORWARD -i {iface_name} -s {eni_ip}/32 -j ACCEPT 2>/dev/null ; do "
             f"    iptables -D FORWARD -i {iface_name} -s {eni_ip}/32 -j ACCEPT 2>/dev/null || break ; "
             f"  done ;"
             f"  while iptables -C FORWARD -i {iface_name} -d {eni_ip}/32 -j ACCEPT 2>/dev/null ; do "
             f"    iptables -D FORWARD -i {iface_name} -d {eni_ip}/32 -j ACCEPT 2>/dev/null || break ; "
             f"  done ;"
             "} || true"],
        )
    else:
        _exec(
            container_name,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             f"  while iptables -C FORWARD -i {iface_name} -j ACCEPT 2>/dev/null ; do "
             f"    iptables -D FORWARD -i {iface_name} -j ACCEPT 2>/dev/null || break ; "
             f"  done ;"
             "} || true"],
        )


# ---------------------------------------------------------------------------
# Marker file management
# ---------------------------------------------------------------------------


def _write_or_remove_marker_live(
    container_name: str, marker_name: str, source_dest_check: bool,
) -> None:
    """Persist the per-ENI state via a marker file."""
    if source_dest_check:
        _exec(
            container_name,
            ["sh", "-c", f"rm -f {_MARKER_DIR}/{marker_name}"],
        )
    else:
        _exec(
            container_name,
            ["sh", "-c",
             f"mkdir -p {_MARKER_DIR} 2>/dev/null || true ; "
             f"touch {_MARKER_DIR}/{marker_name}"],
        )


def _write_or_remove_marker_offline(
    container_name: str, marker_name: str, source_dest_check: bool,
) -> None:
    """Container is stopped, no exec channel. Log and rely on the
    entrypoint script to apply the persisted state on next boot."""
    LOG.info(
        "forward-chain: container %s is not running ; per-ENI marker "
        "%s (source_dest_check=%s) will take effect at next start "
        "via the entrypoint marker walk",
        container_name, marker_name, source_dest_check,
    )


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def _container_exists(container_name: str) -> bool:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT

        if CONTAINER_CLIENT.is_container_running(container_name):
            return True
        try:
            CONTAINER_CLIENT.inspect_container(container_name)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _container_running(container_name: str) -> bool:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT

        return bool(CONTAINER_CLIENT.is_container_running(container_name))
    except Exception:
        return False


def _exec(container_name: str, argv: list[str]) -> None:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT

        CONTAINER_CLIENT.exec_in_container(container_name, argv)
    except Exception as exc:
        LOG.debug(
            "forward-chain: exec_in_container(%s, %s) failed: %s",
            container_name, argv, exc,
        )
