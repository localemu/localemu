"""Pin the instance-routes replay block on both container entrypoints.

Both ``SSHD_ENTRYPOINT_SCRIPT`` and ``NO_SSH_ENTRYPOINT_SCRIPT`` must
walk the marker file ``/var/lib/localemu/instance-routes.txt`` at boot
and reinstall every (destination_cidr, gateway_ip) pair via
``ip route replace``. Without that, a ``docker restart`` would silently
drop the routes a prior ``CreateRoute`` / ``AssociateRouteTable``
configured.
"""
from __future__ import annotations

from localemu.services.ec2.docker import vm_manager


def _isolate_routes_block(script: str) -> str:
    marker = "/var/lib/localemu/instance-routes.txt"
    idx = script.find(marker)
    assert idx >= 0
    return "\n".join(script[idx:].splitlines()[:25])


def test_sshd_entrypoint_replays_instance_routes_marker():
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    assert "/var/lib/localemu/instance-routes.txt" in s, (
        "SSHD entrypoint must check the instance-routes marker file at boot."
    )
    block = _isolate_routes_block(s)
    assert "ip route replace" in block
    assert "while read -r" in block


def test_no_ssh_entrypoint_replays_instance_routes_marker():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "/var/lib/localemu/instance-routes.txt" in s, (
        "No-key entrypoint must replay the instance-routes marker too — "
        "without it the AWS-CLI default launch path loses every "
        "CreateRoute-installed route across container restart."
    )
    block = _isolate_routes_block(s)
    assert "ip route replace" in block


def test_entrypoint_route_replay_is_gated_on_ip_command_presence():
    """Minimal images (busybox-only alpine variants) may lack iproute2;
    the replay block must check ``command -v ip`` before iterating."""
    for script in (vm_manager.SSHD_ENTRYPOINT_SCRIPT, vm_manager.NO_SSH_ENTRYPOINT_SCRIPT):
        block = _isolate_routes_block(script)
        assert "command -v ip" in block, (
            "route replay must short-circuit cleanly on images that lack "
            "the ``ip`` command — otherwise every boot would spew a "
            "harmless-but-loud command-not-found error"
        )
