"""Pin the SDC marker-file replay block on both container entrypoints.

Both ``SSHD_ENTRYPOINT_SCRIPT`` and ``NO_SSH_ENTRYPOINT_SCRIPT`` must
re-apply the ``net.ipv4.ip_forward=1`` + ``iptables FORWARD ACCEPT``
configuration when the marker file
``/var/lib/localemu/source-dest-check-disabled`` is present at boot.
Without that, a ``docker restart`` would silently re-enable the
source/dest check and break any router/MITM scenario that the user
configured via ``ec2:ModifyInstanceAttribute --no-source-dest-check``.
"""
from __future__ import annotations

from localemu.services.ec2.docker import vm_manager


def test_sshd_entrypoint_defaults_forward_policy_to_drop_at_boot():
    """Without this, Docker's default ACCEPT policy means a fresh
    instance forwards anything reaching its FORWARD chain — silently
    breaking the AWS SourceDestCheck=true contract."""
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    assert "iptables -P FORWARD DROP" in s, (
        "SSHD entrypoint must default the FORWARD policy to DROP at "
        "boot so SourceDestCheck=true (the AWS default) is actually "
        "enforced. Docker's default is ACCEPT."
    )


def test_no_ssh_entrypoint_defaults_forward_policy_to_drop_at_boot():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "iptables -P FORWARD DROP" in s, (
        "No-key entrypoint must also default-DROP — without it, the "
        "AWS-CLI default launch path silently forwards regardless of "
        "the SourceDestCheck attribute."
    )


def test_sshd_entrypoint_drop_runs_before_marker_check():
    """The DROP default must come BEFORE the marker check so the marker
    can override it; the reverse order would have the marker block
    set ACCEPT, then the unconditional DROP would immediately undo it."""
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    drop_idx = s.find("iptables -P FORWARD DROP")
    marker_idx = s.find("/var/lib/localemu/source-dest-check-disabled")
    assert 0 <= drop_idx < marker_idx, (
        "FORWARD DROP must run before the marker check in the entrypoint"
    )


def test_no_ssh_entrypoint_drop_runs_before_marker_check():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    drop_idx = s.find("iptables -P FORWARD DROP")
    marker_idx = s.find("/var/lib/localemu/source-dest-check-disabled")
    assert 0 <= drop_idx < marker_idx


def test_sshd_entrypoint_replays_sdc_marker():
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    assert "/var/lib/localemu/source-dest-check-disabled" in s, (
        "SSHD entrypoint must check for the SDC marker file at boot."
    )
    assert "net.ipv4.ip_forward=1" in s
    assert "iptables -P FORWARD ACCEPT" in s


def test_no_ssh_entrypoint_replays_sdc_marker():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "/var/lib/localemu/source-dest-check-disabled" in s, (
        "No-key entrypoint must also check the marker — without it, the "
        "AWS-CLI default launch path (no --key-name) would silently lose "
        "SourceDestCheck=false on every container restart."
    )
    assert "net.ipv4.ip_forward=1" in s
    assert "iptables -P FORWARD ACCEPT" in s


def test_entrypoint_uses_idempotent_iptables_check_pattern():
    """``-C`` check before ``-I`` insert prevents duplicate rules across
    restarts. Both scripts must follow the project's idiom."""
    for script in (vm_manager.SSHD_ENTRYPOINT_SCRIPT, vm_manager.NO_SSH_ENTRYPOINT_SCRIPT):
        sdc_section = _isolate_sdc_block(script)
        assert "iptables -C FORWARD -j ACCEPT" in sdc_section
        assert "iptables -I FORWARD 1 -j ACCEPT" in sdc_section


def _isolate_sdc_block(script: str) -> str:
    """Return the chunk of the script that owns the SDC marker handling.

    Used to assert ``-C`` / ``-I`` idempotency live inside the SDC
    block specifically (i.e. so a future regression that drops the
    idempotency guard from the SDC block alone — leaving it intact
    elsewhere — still trips this test).
    """
    marker = "/var/lib/localemu/source-dest-check-disabled"
    idx = script.find(marker)
    assert idx >= 0
    # Take 40 lines following the marker as the SDC block; any reasonable
    # implementation is way shorter than that.
    return "\n".join(script[idx:].splitlines()[:40])
