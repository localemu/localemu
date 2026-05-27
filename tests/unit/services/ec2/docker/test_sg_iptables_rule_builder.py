"""Tests for sg_iptables._build_chain_rules.

Guards two correctness properties found via the SG-cross-reference E2E:

  1. Reads moto's SINGULAR ``ip_range`` / ``source_group`` attributes
     on SecurityGroupRule. The previous code looked up plural
     ``ip_ranges`` / ``source_groups`` which never matched moto, so
     EVERY SG rule silently defaulted its source filter to 0.0.0.0/0.

  2. When LOCALEMU_VPC_IP_PINNING is on and a rule references an SG
     with no current members in the AddressIndex, the rule is SKIPPED
     entirely (the chain's default DROP takes over). This matches the
     AWS contract: an SG reference with no members denies everything,
     not allows everything.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from localemu.services.ec2.docker.address_index import (
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.sg_iptables import _build_chain_rules


@pytest.fixture(autouse=True)
def _reset_index():
    reset_address_index_for_tests()
    yield
    reset_address_index_for_tests()


def _rule(**kw):
    """moto-shaped SecurityGroupRule double. ``ip_range`` / ``source_group``
    are singular dicts per moto's real model."""
    defaults = dict(
        ip_protocol="-1",
        from_port=None, to_port=None,
        ip_range={},
        source_group={},
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestSingularMotoAttributes:
    def test_singular_ip_range_emits_source_filter(self):
        rule = _rule(
            ip_protocol="tcp", from_port=80, to_port=80,
            ip_range={"CidrIp": "10.5.0.0/16"},
        )
        rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        assert any("-s 10.5.0.0/16" in r and "--dport 80" in r and "ACCEPT" in r
                   for r in rules), rules
        # Must NOT silently widen to 0.0.0.0/0 when a CIDR is given
        assert not any("-s 0.0.0.0/0" in r and "--dport 80" in r for r in rules)

    def test_singular_source_group_resolved_via_address_index(self):
        from localemu.services.ec2.docker.address_index import get_address_index
        from localemu.services.ec2.docker.subnet_allocator import (
            get_subnet_allocator, reset_subnet_allocator_for_tests,
        )
        reset_subnet_allocator_for_tests()
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "subnet-a", "10.0.1.0/24", "10.0.1.0/24", "us-east-1a",
        )
        ip = alloc.reserve("vpc-1", "subnet-a", "eni-web")
        get_address_index().register_eni(
            eni_id="eni-web", vpc_id="vpc-1", subnet_id="subnet-a",
            primary_ip=ip, sg_ids=["sg-web"], instance_id="i-web",
        )
        rule = _rule(
            ip_protocol="tcp", from_port=5432, to_port=5432,
            source_group={"GroupId": "sg-web", "UserId": "000000000000"},
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        assert any(f"-s {ip}/32" in r and "--dport 5432" in r and "ACCEPT" in r
                   for r in rules), rules

    def test_source_group_with_no_members_skips_rule(self):
        """AWS contract: SG reference with no current members = deny
        everything for this rule (chain's default DROP wins)."""
        rule = _rule(
            ip_protocol="tcp", from_port=22, to_port=22,
            source_group={"GroupId": "sg-empty"},
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        # No ACCEPT for port 22 — the rule was skipped.
        assert not any("--dport 22" in r and "ACCEPT" in r for r in rules), rules


class TestNoSilentAllowAllRegression:
    def test_pinning_on_with_empty_source_group_skips_rule(self):
        """The regression we just fixed: rule with empty source_group
        (no CIDR, no resolved IPs) used to fall through to a
        0.0.0.0/0 ACCEPT. Now it must emit no ACCEPT line."""
        rule = _rule(
            ip_protocol="tcp", from_port=443, to_port=443,
            source_group={"GroupId": "sg-noone"},
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        assert not any("0.0.0.0/0" in r and "--dport 443" in r for r in rules), rules

    def test_pinning_off_no_cidr_no_sg_falls_back_to_0_0_0_0(self):
        """Off-path keeps today's permissive fallback so existing
        tutorials that do not run with pinning don't break."""
        rule = _rule(
            ip_protocol="tcp", from_port=8080, to_port=8080,
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        assert any("0.0.0.0/0" in r and "--dport 8080" in r and "ACCEPT" in r
                   for r in rules), rules


class TestChainEndsInDefaultDrop:
    def test_drop_at_end_of_chain(self):
        rules = _build_chain_rules([], chain="SG_IN", is_egress=False)
        assert rules[-1] == "-A SG_IN -j DROP"

    def test_drop_at_end_of_chain_with_rules(self):
        rule = _rule(
            ip_protocol="tcp", from_port=22, to_port=22,
            ip_range={"CidrIp": "0.0.0.0/0"},
        )
        rules = _build_chain_rules([rule], chain="SG_IN", is_egress=False)
        assert rules[-1] == "-A SG_IN -j DROP"
