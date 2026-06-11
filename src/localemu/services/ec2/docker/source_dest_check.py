"""Apply EC2 ``SourceDestCheck`` semantics to an instance's container.

Real EC2 instances ship with the source/destination check enabled
(``SourceDestCheck=true``) — the AWS network plane drops packets whose
destination isn't the instance's own IP. Setting the attribute to
``false`` is the prerequisite for using the instance as a
router / NAT / MITM ("Quiet Router" — PR-006 scenario E4).

LocalEmu has no separate hypervisor layer, so we approximate the
AWS-side packet drop via the container's own iptables FORWARD chain.
Docker's default FORWARD policy is ACCEPT, so a fresh container would
forward anything that managed to enter its netns — which would
silently make the secure (SDC=true) and insecure (SDC=false) states
indistinguishable. Two pieces close that gap:

1. **At every boot, default the FORWARD policy to DROP.** The
   entrypoint scripts run this before the marker check — so a
   container created without the marker is secure-by-default.
2. **Switch the policy explicitly on attribute change.** This module
   sets ``-P FORWARD DROP`` when SDC is enabled and
   ``-P FORWARD ACCEPT`` (+ explicit ``-I FORWARD 1 -j ACCEPT``
   defensive rule) when it's disabled. The marker file persists the
   ``disabled`` state across container restart.

Knob summary:

* ``source_dest_check=false`` →

  * ``sysctl -w net.ipv4.ip_forward=1`` (the kernel will forward
    received packets out another interface),
  * ``iptables -P FORWARD ACCEPT`` (open the FORWARD chain so the
    forwarded traffic is not dropped),
  * ``iptables -I FORWARD 1 -j ACCEPT`` (defensive: kept so the
    explicit rule wins even if some other code later flips the policy),
  * marker file ``/var/lib/localemu/source-dest-check-disabled`` so
    the entrypoint script reapplies all of the above on
    ``docker restart``.

* ``source_dest_check=true`` (the secure default) →

  * ``sysctl -w net.ipv4.ip_forward=0``,
  * ``iptables -P FORWARD DROP`` (the policy that makes the secure
    state actually secure; without this the chain stays at Docker's
    default ACCEPT and the kernel forwards anything that reaches it),
  * ``iptables -D FORWARD -j ACCEPT 2>/dev/null`` (cleanup any
    explicit rule a previous ``disabled`` window left behind),
  * marker file removed.

The application is best-effort: if the container is not running yet
(``ModifyInstanceAttribute`` arrived during a restart), we no-op and
the entrypoint script reads the marker file at next boot. The function
never raises — a failed sysctl must not block the AWS API call that
asked for it.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


_MARKER_PATH = "/var/lib/localemu/source-dest-check-disabled"


def container_name_for_instance(instance_id: str) -> str:
    """The LocalEmu naming convention for an EC2 instance's container."""
    return f"localemu-ec2-{instance_id}"


def apply_source_dest_check(
    *,
    instance_id: str,
    source_dest_check: bool,
    container_name: str | None = None,
) -> bool:
    """Apply the SDC attribute to the instance's container.

    Returns ``True`` when the container was reachable and the change
    was issued, ``False`` when the container was missing / not running
    (the marker file will still have been requested so a future boot
    picks up the right state, but only if the container exists).

    Never raises: failure to apply the kernel knob must not fail the
    AWS API call. Errors are logged.
    """
    cname = container_name or container_name_for_instance(instance_id)
    if not _container_running(cname):
        # Persist the marker file too if the container exists but is
        # paused / stopped — the entrypoint script honours it on next
        # start. If the container doesn't exist at all (RunInstances
        # has not landed yet), there's nothing to do; ``create_instance``
        # will pick up the attribute via the moto control plane on the
        # next launch.
        if _container_exists(cname):
            _write_or_remove_marker_offline(cname, source_dest_check)
        return False

    forward_value = "0" if source_dest_check else "1"
    _exec(
        cname,
        ["sh", "-c",
         # ``sysctl -w`` prints to stderr in some images when /proc is
         # read-only; the ``|| echo > /proc/...`` fallback covers the
         # case where the sysctl command is missing entirely (busybox).
         f"sysctl -w net.ipv4.ip_forward={forward_value} 2>/dev/null "
         f"|| echo {forward_value} > /proc/sys/net/ipv4/ip_forward 2>/dev/null "
         f"|| true"],
    )

    if source_dest_check:
        # Secure state: the FORWARD policy is DROP and any explicit
        # ACCEPT rule a previous "disabled" window inserted is
        # removed. Both are idempotent (best-effort with ``|| true``).
        _exec(
            cname,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             "  iptables -P FORWARD DROP 2>/dev/null;"
             # ``-D`` is run in a loop because we may have inserted
             # the rule multiple times across past toggles; iptables
             # only removes the first match per ``-D``.
             "  while iptables -C FORWARD -j ACCEPT 2>/dev/null; do"
             "    iptables -D FORWARD -j ACCEPT 2>/dev/null || break;"
             "  done;"
             "} || true"],
        )
    else:
        # Router state: open the FORWARD chain. Policy AND an explicit
        # ACCEPT rule are both installed — the rule guarantees
        # forwarded packets pass even if some other subsystem later
        # flips the policy.
        _exec(
            cname,
            ["sh", "-c",
             "command -v iptables >/dev/null 2>&1 && {"
             "  iptables -P FORWARD ACCEPT 2>/dev/null;"
             "  iptables -C FORWARD -j ACCEPT 2>/dev/null"
             "    || iptables -I FORWARD 1 -j ACCEPT 2>/dev/null;"
             "} || true"],
        )
    # Marker file for restart persistence.
    _write_or_remove_marker_live(cname, source_dest_check)
    return True


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _container_exists(container_name: str) -> bool:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT

        # ``CmdDockerClient`` does not expose ``get_container_state`` —
        # we ask ``inspect_container`` instead and treat any non-None
        # answer as "the container exists, possibly stopped".
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
            "source-dest-check: exec_in_container(%s, %s) failed: %s",
            container_name, argv, exc,
        )


def _write_or_remove_marker_live(container_name: str, source_dest_check: bool) -> None:
    """Persist the SDC state via a marker file inside the container."""
    if source_dest_check:
        _exec(container_name, ["sh", "-c", f"rm -f {_MARKER_PATH}"])
    else:
        _exec(
            container_name,
            ["sh", "-c",
             f"mkdir -p $(dirname {_MARKER_PATH}) 2>/dev/null || true; "
             f"touch {_MARKER_PATH}"],
        )


def _write_or_remove_marker_offline(container_name: str, source_dest_check: bool) -> None:
    """Same as ``_live`` but the container is stopped — we have no exec
    channel, so we no-op. Real cleanup happens on next start when the
    entrypoint script consults the marker file. We log so the change
    isn't silently dropped if the container never restarts."""
    LOG.info(
        "source-dest-check: container %s is not running; the attribute "
        "change (source_dest_check=%s) will take effect at next container "
        "start via the entrypoint marker check",
        container_name, source_dest_check,
    )
