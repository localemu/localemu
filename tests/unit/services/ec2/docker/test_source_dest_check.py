"""Unit tests for ``localemu.services.ec2.docker.source_dest_check``.

We mock ``CONTAINER_CLIENT`` so we can assert the exact shell commands
that get sent into the container without booting Docker. The
entrypoint scripts that consume the marker file are pinned by
``test_source_dest_check_entrypoint.py``.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.services.ec2.docker import source_dest_check as sdc_mod
from localemu.services.ec2.docker.source_dest_check import (
    apply_source_dest_check,
    container_name_for_instance,
)


@pytest.fixture
def fake_container_client():
    """Replace the singleton DOCKER_CLIENT for the duration of a test."""
    client = MagicMock()
    client.is_container_running.return_value = True
    # ``inspect_container`` returns the inspect dict on a live container,
    # raises ``NoSuchContainer`` when the id is unknown. The default
    # MagicMock return value is truthy, so a stopped-but-existing
    # container looks like "exists" unless a test overrides.
    client.inspect_container.return_value = {"State": {"Running": True}}
    with patch("localemu.utils.docker_utils.DOCKER_CLIENT", client):
        yield client


def _exec_calls_concat(client: MagicMock) -> str:
    """Concatenate all argv strings from ``exec_in_container`` calls."""
    out: list[str] = []
    for call in client.exec_in_container.call_args_list:
        argv = call.args[1]
        if isinstance(argv, (list, tuple)):
            out.append(" ".join(str(a) for a in argv))
        else:
            out.append(str(argv))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


def test_container_name_matches_localemu_convention():
    assert container_name_for_instance("i-abc") == "localemu-ec2-i-abc"


# ---------------------------------------------------------------------------
# SDC = false → enable forwarding + marker file
# ---------------------------------------------------------------------------


def test_disable_source_dest_check_enables_ip_forward(fake_container_client):
    ok = apply_source_dest_check(
        instance_id="i-abc", source_dest_check=False,
    )
    assert ok is True
    text = _exec_calls_concat(fake_container_client)
    assert "net.ipv4.ip_forward=1" in text, (
        "sysctl write to enable ip_forward must be issued when "
        "SourceDestCheck is set to false"
    )
    assert "/proc/sys/net/ipv4/ip_forward" in text, (
        "fallback path via /proc must be present in case the sysctl "
        "command is missing on a minimal base image"
    )


def test_disable_source_dest_check_applies_iptables_forward_accept(fake_container_client):
    apply_source_dest_check(
        instance_id="i-abc", source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -P FORWARD ACCEPT" in text
    # idempotency-guard: ``-C`` before ``-A``/``-I``
    assert "iptables -C FORWARD -j ACCEPT" in text
    assert "iptables -I FORWARD 1 -j ACCEPT" in text


def test_disable_source_dest_check_writes_marker_for_restart(fake_container_client):
    apply_source_dest_check(
        instance_id="i-abc", source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "touch /var/lib/localemu/source-dest-check-disabled" in text


# ---------------------------------------------------------------------------
# SDC = true → disable forwarding + remove marker
# ---------------------------------------------------------------------------


def test_enable_source_dest_check_disables_ip_forward(fake_container_client):
    ok = apply_source_dest_check(
        instance_id="i-abc", source_dest_check=True,
    )
    assert ok is True
    text = _exec_calls_concat(fake_container_client)
    assert "net.ipv4.ip_forward=0" in text


def test_enable_source_dest_check_removes_marker(fake_container_client):
    apply_source_dest_check(
        instance_id="i-abc", source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "rm -f /var/lib/localemu/source-dest-check-disabled" in text


def test_enable_source_dest_check_sets_forward_policy_to_drop(fake_container_client):
    """The secure state must lock the FORWARD chain to DROP.

    Docker's default FORWARD policy is ACCEPT, so without this the
    secure (SDC=true) and insecure (SDC=false) states are
    indistinguishable on the wire — the Quiet Router (E4) attack
    becomes silently always-on. The unit fixed by this assertion is
    the policy switch on every ``ModifyInstanceAttribute SourceDestCheck=true``.
    """
    apply_source_dest_check(
        instance_id="i-abc", source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -P FORWARD DROP" in text, (
        "ec2:ModifyInstanceAttribute --source-dest-check (true) must "
        "set the iptables FORWARD policy to DROP — otherwise the "
        "container silently keeps forwarding packets"
    )
    assert "iptables -P FORWARD ACCEPT" not in text
    assert "iptables -I FORWARD 1 -j ACCEPT" not in text


def test_enable_source_dest_check_removes_explicit_accept_rule(fake_container_client):
    """A previous SDC=false window may have inserted ``-I FORWARD 1 -j ACCEPT``;
    the secure state must cleanup the leftover so the DROP policy is honoured."""
    apply_source_dest_check(
        instance_id="i-abc", source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -D FORWARD -j ACCEPT" in text, (
        "secure state cleanup must remove any explicit FORWARD ACCEPT "
        "rule left behind by an earlier --no-source-dest-check window"
    )


# ---------------------------------------------------------------------------
# Container missing / not running paths
# ---------------------------------------------------------------------------


def test_container_not_running_returns_false_and_does_not_exec(fake_container_client):
    fake_container_client.is_container_running.return_value = False
    fake_container_client.inspect_container.side_effect = Exception("no such container")
    ok = apply_source_dest_check(
        instance_id="i-gone", source_dest_check=False,
    )
    assert ok is False
    # No exec_in_container calls were issued.
    fake_container_client.exec_in_container.assert_not_called()


def test_container_stopped_but_exists_logs_for_next_start(fake_container_client, caplog):
    fake_container_client.is_container_running.return_value = False
    # ``inspect_container`` returning a dict means the container exists
    # but isn't running.
    fake_container_client.inspect_container.return_value = {"State": {"Running": False}}
    ok = apply_source_dest_check(
        instance_id="i-paused", source_dest_check=False,
    )
    assert ok is False
    # No live exec, but a log line so the change is observable in
    # localemu logs.
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "next container start" in msgs.lower() or "source-dest-check" in msgs.lower()


# ---------------------------------------------------------------------------
# Container client raises — never propagates
# ---------------------------------------------------------------------------


def test_exec_failures_are_swallowed(fake_container_client):
    fake_container_client.exec_in_container.side_effect = RuntimeError("docker down")
    # Must not raise.
    result = apply_source_dest_check(
        instance_id="i-x", source_dest_check=False,
    )
    # We still report True (the container WAS running) because the
    # failure is at the kernel-apply boundary, not the contract one.
    assert result is True


# ---------------------------------------------------------------------------
# Explicit container_name override
# ---------------------------------------------------------------------------


def test_explicit_container_name_is_used(fake_container_client):
    apply_source_dest_check(
        instance_id="ignored",
        source_dest_check=False,
        container_name="custom-name",
    )
    for call in fake_container_client.exec_in_container.call_args_list:
        assert call.args[0] == "custom-name"
