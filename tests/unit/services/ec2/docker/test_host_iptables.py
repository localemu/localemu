"""Pin the host-iptables helper for VPC bridge intra-traffic ACCEPT.

The helper installs / removes a single rule in the host's DOCKER-USER
chain so intra-bridge L2 forwarding bypasses Docker's DOCKER-INTERNAL
DROP for ``--internal=true`` networks. The actual iptables effect is
exercised in the E2E suite; here we pin:

  * the script the helper hands to the host-netns container — exact
    chain (DOCKER-USER), insertion at position 1, comment-tag shape,
    delete-before-insert idempotency
  * the bridge-iface resolver — Docker option first, synthesised
    ``br-<12-of-id>`` fallback
  * the cleanup-all sweep — matches the ``localemu:`` comment prefix
    and converts ``-A`` to ``-D`` via sed

These are exactly the points where a regression would silently leave
host iptables in a broken state — either dropping intra-VPC traffic
or leaking rules across LocalEmu restarts.
"""
from __future__ import annotations

from unittest.mock import patch

from localemu.services.ec2.docker import host_iptables


def test_install_script_inserts_at_top_of_docker_user_with_comment():
    """The rule must land at position 1 of DOCKER-USER (so it runs
    BEFORE Docker's DOCKER-FORWARD → DOCKER-INTERNAL chain) AND carry
    the ``localemu:vpc-intra:<vpc-id>`` comment so the shutdown sweep
    can find it."""
    captured = {}

    def fake_run(script, *, what):
        captured["script"] = script
        captured["what"] = what
        return 0, "", ""

    with patch.object(
        host_iptables, "_bridge_iface_for_network",
        return_value="br-abc123",
    ), patch.object(host_iptables, "_run_host_iptables", side_effect=fake_run):
        ok = host_iptables.install_vpc_bridge_intra_accept("vpc-77777")

    assert ok is True
    script = captured["script"]
    # Must target the bridge iface
    assert "-i br-abc123 -o br-abc123" in script
    # Must land in DOCKER-USER, not FORWARD directly
    assert "DOCKER-USER" in script
    # Must insert at position 1 (highest priority)
    assert "-I DOCKER-USER 1" in script
    # Must carry the comment tag for cleanup
    assert "localemu:vpc-intra:vpc-77777" in script
    # The "what" message is what surfaces in logs
    assert "vpc-77777" in captured["what"]


def test_install_script_is_idempotent_via_delete_then_insert():
    """Calling install twice must not stack two ACCEPT rules. The
    helper achieves that by ``-C`` checking, ``-D`` if present, then
    ``-I`` — so the rule is always at position 1 with exactly one
    copy."""
    captured = {}

    def fake_run(script, *, what):
        captured["script"] = script
        return 0, "", ""

    with patch.object(
        host_iptables, "_bridge_iface_for_network",
        return_value="br-deadbeef",
    ), patch.object(host_iptables, "_run_host_iptables", side_effect=fake_run):
        host_iptables.install_vpc_bridge_intra_accept("vpc-idem")

    script = captured["script"]
    # The delete-before-insert pattern: -C check, then -D, then -I
    assert "-C DOCKER-USER" in script
    assert "-D DOCKER-USER" in script
    assert "-I DOCKER-USER 1" in script
    # Order: -C must come before -D must come before -I
    c_pos = script.index("-C DOCKER-USER")
    d_pos = script.index("-D DOCKER-USER")
    i_pos = script.index("-I DOCKER-USER")
    assert c_pos < d_pos < i_pos


def test_install_returns_false_when_bridge_iface_cannot_be_resolved():
    """If ``docker network inspect`` doesn't yield a usable bridge
    interface name, the helper returns False without calling iptables.
    The caller logs and continues — basic VPC operation still works;
    only the Quiet Router path degrades."""
    with patch.object(
        host_iptables, "_bridge_iface_for_network", return_value=None,
    ), patch.object(host_iptables, "_run_host_iptables") as fake_run:
        ok = host_iptables.install_vpc_bridge_intra_accept("vpc-noiface")

    assert ok is False
    fake_run.assert_not_called()


def test_install_returns_false_when_iptables_call_fails():
    """Best-effort: if the host-netns container or iptables call exits
    non-zero, the helper returns False so the caller can log + degrade.
    It must NOT raise — VPC create must keep working even if host
    iptables is unavailable (Docker Desktop bug, hardened kernel, etc.)."""
    with patch.object(
        host_iptables, "_bridge_iface_for_network",
        return_value="br-fail",
    ), patch.object(
        host_iptables, "_run_host_iptables",
        return_value=(2, "", "iptables v1.8.7: can't initialize"),
    ):
        ok = host_iptables.install_vpc_bridge_intra_accept("vpc-fail")

    assert ok is False


def test_remove_uses_iptables_save_grep_sed_delete_by_comment():
    """Removal must work even when the bridge iface is already gone
    (the bridge may have been deleted before the host-iptables removal
    runs). We delete by comment tag, not by iface — extracted from
    iptables-save via grep + sed."""
    captured = {}

    def fake_run(script, *, what):
        captured["script"] = script
        return 0, "", ""

    with patch.object(host_iptables, "_run_host_iptables", side_effect=fake_run):
        host_iptables.remove_vpc_bridge_intra_accept("vpc-r1")

    script = captured["script"]
    assert "iptables-save" in script
    assert "localemu:vpc-intra:vpc-r1" in script
    # The sed converts -A (added) into -D (delete) so the same line
    # piped back to iptables removes the rule.
    assert "sed 's/^-A /-D /'" in script


def test_cleanup_all_sweeps_every_localemu_rule():
    """The shutdown sweep matches the ``localemu:`` comment prefix
    (broader than just vpc-intra:) so future LocalEmu-installed rule
    families are also caught by the same call. Returns the parsed
    ``removed=N`` count."""
    captured = {}

    def fake_run(script, *, what):
        captured["script"] = script
        return 0, "removed=3\n", ""

    with patch.object(host_iptables, "_run_host_iptables", side_effect=fake_run):
        count = host_iptables.cleanup_all_localemu_host_rules()

    assert count == 3
    script = captured["script"]
    # Broader prefix than the per-VPC remove
    assert "'localemu:'" in script
    assert "iptables-save" in script
    assert "sed 's/^-A /-D /'" in script


def test_cleanup_all_tolerates_nonzero_exit():
    """If iptables-save fails (host iptables not available), cleanup
    returns 0, never raises. LocalEmu shutdown must always complete."""
    with patch.object(
        host_iptables, "_run_host_iptables",
        return_value=(1, "", "iptables-save: command not found"),
    ):
        count = host_iptables.cleanup_all_localemu_host_rules()

    assert count == 0


# ---------------------------------------------------------------------------
# Bridge-iface resolver
# ---------------------------------------------------------------------------


def test_bridge_iface_resolver_prefers_explicit_option():
    """When the network was created with
    ``com.docker.network.bridge.name`` set, the resolver returns that
    value verbatim — the operator chose the iface name on purpose."""
    fake_inspect = {
        "Id": "abc123def456789",
        "Options": {"com.docker.network.bridge.name": "vpc-custom-br"},
    }
    with patch(
        "localemu.services.ec2.docker.host_iptables.DOCKER_CLIENT.inspect_network",
        return_value=fake_inspect,
    ):
        iface = host_iptables._bridge_iface_for_network("localemu-vpc-xyz")

    assert iface == "vpc-custom-br"


def test_bridge_iface_resolver_falls_back_to_synthetic_name():
    """Without an explicit option, Docker auto-generates the iface as
    ``br-<first-12-chars-of-network-id>``. We must match that exact
    convention — anything else and our iptables rule references a
    non-existent interface and silently does nothing."""
    fake_inspect = {
        "Id": "67e0eb337394abcdef0123456789",
        "Options": {},
    }
    with patch(
        "localemu.services.ec2.docker.host_iptables.DOCKER_CLIENT.inspect_network",
        return_value=fake_inspect,
    ):
        iface = host_iptables._bridge_iface_for_network("localemu-vpc-xyz")

    assert iface == "br-67e0eb337394"


def test_bridge_iface_resolver_returns_none_on_inspect_failure():
    """If ``docker network inspect`` raises (network gone, daemon
    unreachable), the resolver returns ``None`` cleanly."""
    with patch(
        "localemu.services.ec2.docker.host_iptables.DOCKER_CLIENT.inspect_network",
        side_effect=RuntimeError("daemon down"),
    ):
        iface = host_iptables._bridge_iface_for_network("localemu-vpc-xyz")

    assert iface is None
