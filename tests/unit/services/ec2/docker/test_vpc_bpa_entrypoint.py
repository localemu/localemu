"""Unit tests for the VPC Block Public Access enforcement embedded in the
no-key entrypoint script.

We only check the keyed-string contents (the test runs in-process; the
actual iptables installation happens inside Docker containers and is
exercised by the E2E suite). The shell is asserted to:

* Skip when ``LOCALEMU_VPC_BPA_EXCLUDED=true``.
* Install a dedicated DROP chain (``LOCALEMU_VPC_BPA_IN``) on INPUT when
  mode is ``block-ingress`` or ``block-bidirectional``.
* Also install ``LOCALEMU_VPC_BPA_OUT`` for ``block-bidirectional``.
* Allow ESTABLISHED,RELATED return traffic so an already-open connection
  (e.g. ``docker exec``) survives the new rule.
"""

from __future__ import annotations

from localemu.services.ec2.docker import vm_manager


def test_no_key_entrypoint_has_vpc_bpa_block():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "LOCALEMU_VPC_BPA_MODE" in s
    assert "LOCALEMU_VPC_BPA_EXCLUDED" in s
    assert "LOCALEMU_VPC_BPA_IN" in s
    assert "LOCALEMU_VPC_BPA_OUT" in s
    assert "block-ingress" in s
    assert "block-bidirectional" in s


def test_vpc_bpa_respects_excluded_flag():
    """The DROP chain MUST be inside an ``if`` whose condition includes
    the ``LOCALEMU_VPC_BPA_EXCLUDED != true`` guard. Without this,
    excluded subnets would still get blocked."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    # The conditional and the rule must appear in this order, and the
    # rule must be inside the conditional (not before it).
    guard = "[ \"${LOCALEMU_VPC_BPA_EXCLUDED:-false}\" != \"true\" ]"
    assert guard in s
    rule = "iptables -A LOCALEMU_VPC_BPA_IN -i eth0 -j DROP"
    assert s.index(guard) < s.index(rule)


def test_vpc_bpa_allows_established_return_traffic():
    """A bare DROP on eth0 would break already-open connections like
    docker exec or the IMDS sidecar reply. The chain RETURNs early for
    ESTABLISHED,RELATED so those keep working."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "conntrack --ctstate ESTABLISHED,RELATED -j RETURN" in s


def test_vpc_bpa_chain_is_idempotent_install():
    """Re-running the entrypoint (e.g. after restart) must not pile up
    duplicate jumps in INPUT."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "iptables -C INPUT -j LOCALEMU_VPC_BPA_IN" in s
    assert "iptables -I INPUT 1 -j LOCALEMU_VPC_BPA_IN" in s
