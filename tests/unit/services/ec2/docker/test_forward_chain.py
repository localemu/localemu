"""Per-ENI FORWARD policy : pinning tests for ``apply_forward_for_eni``.

These pin the iptables shape `forward_chain.py` produces for each of
the modes the design supports:

* Separate-iface mode (``shared_iface=False``): plain ``-i <iface>``
  rule, one per ENI, lives on the FORWARD chain. The legacy single-NIC
  quiet-router scenario is a degenerate case.
* Shared-iface mode (``shared_iface=True``): the AWS-side ENI shares a
  container iface with another ENI on the same VPC bridge. Rules are
  keyed on the ENI's IP via ``-s <ip>/32`` and ``-d <ip>/32`` source/
  dest matches, so two co-resident ENIs get independent FORWARD state.

No mock of LocalEmu config flags : the apply layer is pure-Python
state on top of the Docker exec channel, and the tests must catch
regressions in the default mode any user gets out of the box.
Only ``DOCKER_CLIENT`` (the Docker exec channel) is mocked.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.services.ec2.docker.forward_chain import (
    apply_forward_for_eni,
    container_name_for_instance,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_container_client():
    """Replace the Docker client for the duration of a test."""
    client = MagicMock()
    client.is_container_running.return_value = True
    client.inspect_container.return_value = {"State": {"Running": True}}
    with patch("localemu.utils.docker_utils.DOCKER_CLIENT", client):
        yield client


def _exec_calls_concat(client: MagicMock) -> str:
    """Concatenate every shell command that was exec'd into the container."""
    out: list[str] = []
    for call in client.exec_in_container.call_args_list:
        argv = call.args[1]
        if isinstance(argv, (list, tuple)):
            out.append(" ".join(str(a) for a in argv))
        else:
            out.append(str(argv))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Case 1 : separate-iface mode, SDC=false on primary (the AWS-side eth1)
# ---------------------------------------------------------------------------


def test_separate_iface_disable_installs_iface_accept_rule(fake_container_client):
    ok = apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.0.0.5", shared_iface=False,
        source_dest_check=False,
    )
    assert ok is True
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -I FORWARD 1 -i eth1 -j ACCEPT" in text
    assert "iptables -C FORWARD -i eth1 -j ACCEPT" in text
    # No source/dest IP match in separate-iface mode :
    assert "-s 10.0.0.5/32" not in text
    assert "-d 10.0.0.5/32" not in text


# ---------------------------------------------------------------------------
# Case 2 : separate-iface mode, SDC=true on primary removes the rule
# ---------------------------------------------------------------------------


def test_separate_iface_enable_removes_iface_accept_rule(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.0.0.5", shared_iface=False,
        source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -D FORWARD -i eth1 -j ACCEPT" in text
    # Removal uses the while-loop pattern so duplicate inserts get cleaned.
    assert "while iptables -C FORWARD -i eth1 -j ACCEPT" in text


# ---------------------------------------------------------------------------
# Case 3 : separate-iface mode on secondary ENI eth2 keeps eth1 untouched
# ---------------------------------------------------------------------------


def test_separate_iface_secondary_targets_only_eth2(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth2",
        eni_ip="10.0.99.5", shared_iface=False,
        source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -I FORWARD 1 -i eth2 -j ACCEPT" in text
    # The primary's eth1 must not be touched by a secondary-ENI modify :
    assert "-i eth1" not in text


# ---------------------------------------------------------------------------
# Case 4 : kernel ip_forward is per-instance, set when ANY marker exists
# ---------------------------------------------------------------------------


def test_kernel_ip_forward_uses_marker_dir_to_decide_bit(fake_container_client):
    """The sysctl write must read the marker directory and pick 1 if
    anything is there. This way a multi-ENI instance that disables SDC
    on a secondary still flips ``ip_forward`` correctly without the
    Python layer tracking per-instance state."""
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.0.0.5", shared_iface=False,
        source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "/var/lib/localemu/source-dest-check.d/" in text
    assert "sysctl -w net.ipv4.ip_forward=$v" in text


# ---------------------------------------------------------------------------
# Case 5 : marker file path encodes the iface (separate-iface mode)
# ---------------------------------------------------------------------------


def test_marker_path_for_separate_iface_is_iface_only(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth2",
        eni_ip="10.0.99.5", shared_iface=False,
        source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "touch /var/lib/localemu/source-dest-check.d/eth2" in text
    # Make sure the IP did NOT sneak into the filename :
    assert "/var/lib/localemu/source-dest-check.d/eth2-10.0.99.5" not in text


# ---------------------------------------------------------------------------
# Case 6 : enable removes the marker file
# ---------------------------------------------------------------------------


def test_enable_removes_marker_file(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.0.0.5", shared_iface=False,
        source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "rm -f /var/lib/localemu/source-dest-check.d/eth1" in text


# ---------------------------------------------------------------------------
# Case 7 : shared-iface mode installs TWO source/dest IP-match rules
# ---------------------------------------------------------------------------


def test_shared_iface_disable_installs_src_and_dst_match_rules(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.231.1.99", shared_iface=True,
        source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "iptables -I FORWARD 1 -i eth1 -s 10.231.1.99/32 -j ACCEPT" in text
    assert "iptables -I FORWARD 1 -i eth1 -d 10.231.1.99/32 -j ACCEPT" in text
    # Must NOT install the plain ``-i eth1`` rule in shared-iface mode :
    assert "iptables -I FORWARD 1 -i eth1 -j ACCEPT" not in text


# ---------------------------------------------------------------------------
# Case 8 : shared-iface mode marker encodes BOTH iface and IP
# ---------------------------------------------------------------------------


def test_shared_iface_marker_includes_eni_ip(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.231.1.99", shared_iface=True,
        source_dest_check=False,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "touch /var/lib/localemu/source-dest-check.d/eth1-10.231.1.99" in text


# ---------------------------------------------------------------------------
# Case 9 : shared-iface enable removes BOTH IP-match rules; primary's
#         own plain ``-i eth1`` rule is untouched.
# ---------------------------------------------------------------------------


def test_shared_iface_enable_removes_both_ip_rules_only(fake_container_client):
    apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.231.1.99", shared_iface=True,
        source_dest_check=True,
    )
    text = _exec_calls_concat(fake_container_client)
    assert "while iptables -C FORWARD -i eth1 -s 10.231.1.99/32 -j ACCEPT" in text
    assert "while iptables -C FORWARD -i eth1 -d 10.231.1.99/32 -j ACCEPT" in text
    # The plain ``-i eth1`` rule (which would be the primary's) is NOT
    # touched by a shared-iface disable :
    assert "iptables -D FORWARD -i eth1 -j ACCEPT" not in text


# ---------------------------------------------------------------------------
# Defensive : bad IP gracefully no-ops, container not running paths
# ---------------------------------------------------------------------------


def test_invalid_eni_ip_returns_false_without_exec(fake_container_client):
    ok = apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="not-an-ip", shared_iface=False,
        source_dest_check=False,
    )
    assert ok is False
    # We bailed before any exec :
    assert fake_container_client.exec_in_container.call_count == 0


def test_container_not_running_with_existing_container_writes_no_exec_only(
    fake_container_client,
):
    """When the container exists but is stopped, no exec runs (we have
    no channel), the offline marker path logs but does not raise.
    Returns False to tell the caller the live apply did not happen."""
    fake_container_client.is_container_running.return_value = False
    fake_container_client.inspect_container.return_value = {"State": {"Running": False}}
    ok = apply_forward_for_eni(
        instance_id="i-aaa", iface_name="eth1",
        eni_ip="10.0.0.5", shared_iface=False,
        source_dest_check=False,
    )
    assert ok is False
    # No exec because the container is stopped :
    assert fake_container_client.exec_in_container.call_count == 0


# ---------------------------------------------------------------------------
# Helper sanity
# ---------------------------------------------------------------------------


def test_container_name_helper_matches_convention():
    assert container_name_for_instance("i-abcdef") == "localemu-ec2-i-abcdef"
