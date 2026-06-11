"""Host-side iptables helpers for VPC bridge filtering.

Docker creates ``--internal=true`` bridges with a pair of
``DOCKER-INTERNAL`` rules that DROP any L3 traffic whose source or
destination IP lies outside the bridge's subnet. The two rules are
the heart of Docker's internal-network isolation:

    -A DOCKER-INTERNAL ! -s <bridge-cidr> -o <bridge-iface> -j DROP
    -A DOCKER-INTERNAL ! -d <bridge-cidr> -i <bridge-iface> -j DROP

That second rule is what blocks the Quiet Router scenario on a flat
VPC bridge: the victim sends a frame with src=10.86.1.4 dst=10.99.0.50
to the router (dst-MAC=router-MAC); br_netfilter hooks the bridge
forward into iptables; DOCKER-INTERNAL sees dst-IP outside 10.86/16
and DROPs the frame. The router's veth never sees it.

The fix is to insert a single rule in ``DOCKER-USER`` (which Docker
guarantees not to touch) ABOVE ``DOCKER-INTERNAL``:

    -A DOCKER-USER -i <bridge-iface> -o <bridge-iface> -j ACCEPT

This matches only traffic that ARRIVES on the VPC bridge AND LEAVES on
the same VPC bridge — pure intra-VPC L2 forwarding. Internet-bound
egress (which leaves on a different interface like the pubport bridge
or the host NIC) is not affected, so VPC isolation is preserved.

LocalEmu itself runs as an unprivileged host process, so the rule is
applied by spawning a one-shot container in the host network namespace
with NET_ADMIN — same pattern the NAT gateway and flow-log sidecar
already use to drive host-side iptables.

A ``localemu:vpc-intra:<vpc-id>`` comment is attached to every rule
so the shutdown sweep can find and remove every LocalEmu rule
regardless of in-memory state.
"""
from __future__ import annotations

import logging
import subprocess
import threading
from typing import Optional

from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.services.ec2.docker.vpc_network import VPC_NETWORK_PREFIX

LOG = logging.getLogger(__name__)

# Comment tag inserted on every LocalEmu-owned rule so the shutdown
# sweep can find and remove them by string match. Keeping the format
# stable matters — ``cleanup_all_localemu_host_rules`` scans for this
# exact prefix in iptables-save output.
_COMMENT_PREFIX = "localemu:vpc-intra:"

# Image used for the host-netns one-shot. Alpine is tiny (~5 MB) and
# already ships with iptables under the ``iptables`` apk. We keep
# ``alpine`` (not a pinned digest) because the LocalEmu host always
# pulls images on demand; pinning would just trade a "pull every time"
# for a "regression every time we forget to bump the digest".
_HELPER_IMAGE = "alpine:3.19"

_install_lock = threading.Lock()


def _run_host_iptables(script: str, *, what: str) -> tuple[int, str, str]:
    """Run an iptables shell snippet inside a one-shot host-netns
    container. Returns (exit_code, stdout, stderr).

    The container is removed on exit. NET_ADMIN is required for
    iptables; ``--net=host`` is required for the rule to land in the
    host kernel's filter table (the LinuxKit VM on macOS / WSL2;
    the actual host kernel on Linux).

    Errors are logged but never raised — host iptables manipulation is
    best-effort and the calling code path must keep working with or
    without the bridge ACCEPT rule (it just won't unblock cross-subnet
    traffic until LocalEmu can install the rule).
    """
    try:
        # Use the underlying ``docker run`` CLI directly rather than the
        # DOCKER_CLIENT wrapper: the wrapper is tuned for long-lived
        # service containers (label tracking, NetworkMode='') and adds
        # unwanted overhead for a 50-ms one-shot.
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--net=host", "--cap-add", "NET_ADMIN",
                _HELPER_IMAGE,
                "sh", "-c",
                # Install iptables silently and execute the script.
                # We tolerate the "iptables already installed" path
                # (since the image may be pre-warmed).
                "apk add --quiet --no-cache iptables >/dev/null 2>&1; " + script,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        LOG.warning("host iptables: docker CLI not on PATH, cannot %s", what)
        return 127, "", "docker CLI missing"
    except subprocess.TimeoutExpired:
        LOG.warning("host iptables: %s timed out", what)
        return 124, "", "timeout"
    except Exception as exc:
        LOG.warning("host iptables: %s failed: %s", what, exc)
        return 1, "", str(exc)


def _bridge_iface_for_network(network_name: str) -> Optional[str]:
    """Resolve a Docker network NAME to its kernel bridge INTERFACE.

    The bridge interface name is the value of the network's
    ``com.docker.network.bridge.name`` option if the operator set one,
    otherwise Docker auto-generates ``br-<first-12-of-network-id>``.
    We try the option first, fall back to the synthesised name.
    """
    try:
        info = DOCKER_CLIENT.inspect_network(network_name) or {}
    except Exception:
        return None
    options = info.get("Options") or {}
    explicit = options.get("com.docker.network.bridge.name")
    if explicit:
        return explicit
    net_id = info.get("Id") or ""
    if net_id:
        return f"br-{net_id[:12]}"
    return None


def install_vpc_bridge_intra_accept(vpc_id: str) -> bool:
    """Insert the intra-bridge ACCEPT rule for a VPC's Docker bridge.

    Idempotent: the rule is removed first (if present) and re-inserted
    at position 1 of DOCKER-USER. Returns True on success, False if
    the bridge could not be resolved or the iptables call failed —
    callers should log the False outcome but continue (the absence of
    the rule degrades cross-subnet routing, not basic VPC operation).
    """
    network_name = f"{VPC_NETWORK_PREFIX}{vpc_id}"
    iface = _bridge_iface_for_network(network_name)
    if not iface:
        LOG.debug(
            "host iptables: cannot resolve bridge iface for %s — "
            "skipping intra-accept install",
            network_name,
        )
        return False
    comment = f"{_COMMENT_PREFIX}{vpc_id}"
    # ``-D`` may fail if the rule isn't there; we ignore that exit code
    # by guarding the -D with an iptables -C check. ``-I 1`` places the
    # ACCEPT above Docker's chain layout (DOCKER-USER is called BEFORE
    # DOCKER-FORWARD, so this terminates FORWARD with ACCEPT).
    script = (
        f"iptables -C DOCKER-USER -i {iface} -o {iface} "
        f"-m comment --comment '{comment}' -j ACCEPT 2>/dev/null "
        f"&& iptables -D DOCKER-USER -i {iface} -o {iface} "
        f"-m comment --comment '{comment}' -j ACCEPT; "
        f"iptables -I DOCKER-USER 1 -i {iface} -o {iface} "
        f"-m comment --comment '{comment}' -j ACCEPT"
    )
    with _install_lock:
        rc, _out, err = _run_host_iptables(
            script, what=f"install vpc-intra-accept for {vpc_id}",
        )
    if rc != 0:
        LOG.warning(
            "host iptables: install vpc-intra-accept for %s failed (rc=%s): %s",
            vpc_id, rc, err.strip(),
        )
        return False
    LOG.info(
        "host iptables: vpc-intra-accept installed (%s, iface=%s)",
        vpc_id, iface,
    )
    return True


def remove_vpc_bridge_intra_accept(vpc_id: str) -> None:
    """Remove the intra-bridge ACCEPT rule for a VPC's Docker bridge.

    Best-effort: failures are logged at DEBUG. Called on VPC delete
    and on shutdown sweep. Uses the comment tag so the bridge
    interface name doesn't need to be re-resolved (which may already
    be gone if the bridge was deleted before this call).
    """
    comment = f"{_COMMENT_PREFIX}{vpc_id}"
    # Match every DOCKER-USER rule whose comment matches our tag and
    # delete it. We do not need to know the interface name to delete by
    # match-criteria; iptables-save | grep | iptables -D pattern is the
    # standard idiom.
    script = (
        f"iptables-save | grep -F -- '{comment}' | "
        f"sed 's/^-A /-D /' | "
        f"while read -r line; do "
        f"  echo \"$line\" | xargs -r iptables; "
        f"done"
    )
    with _install_lock:
        rc, _out, err = _run_host_iptables(
            script, what=f"remove vpc-intra-accept for {vpc_id}",
        )
    if rc != 0:
        LOG.debug(
            "host iptables: remove vpc-intra-accept for %s rc=%s err=%s",
            vpc_id, rc, err.strip(),
        )
    else:
        LOG.debug("host iptables: vpc-intra-accept removed for %s", vpc_id)


def cleanup_all_localemu_host_rules() -> int:
    """Remove every LocalEmu-installed rule from the host's iptables.

    Called on shutdown (and reconciliation). Walks ``iptables-save``
    for any rule carrying the ``localemu:`` comment prefix and deletes
    it via the equivalent ``-D`` command. Returns the number of rules
    removed.

    Idempotent: a second call is a no-op once the table is clean.
    """
    # Use the wider prefix ``localemu:`` so future LocalEmu-installed
    # rules (different vpc-intra families, future SDC mark rules, etc.)
    # are also caught by the same shutdown sweep.
    script = (
        "removed=0; "
        "iptables-save | grep -F -- 'localemu:' | while read -r line; do "
        "  delete_line=$(echo \"$line\" | sed 's/^-A /-D /'); "
        "  echo \"$delete_line\" | xargs -r iptables && removed=$((removed+1)); "
        "done; "
        "echo \"removed=$removed\""
    )
    with _install_lock:
        rc, out, err = _run_host_iptables(
            script, what="cleanup-all localemu host rules",
        )
    if rc != 0:
        LOG.debug(
            "host iptables: cleanup-all rc=%s out=%s err=%s",
            rc, out.strip(), err.strip(),
        )
        return 0
    # Parse the "removed=N" tail line. The intermediate sub-shell prints
    # the iptables ack lines too; we only care about the final count.
    count = 0
    for line in (out or "").splitlines():
        if line.startswith("removed="):
            try:
                count = int(line.split("=", 1)[1])
            except ValueError:
                count = 0
    if count:
        LOG.info(
            "host iptables: removed %d LocalEmu rule(s) from host filter table",
            count,
        )
    return count
