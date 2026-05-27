"""Tests for the SG source_groups enforcement fix.

The bug: sg_iptables._build_chain_rules previously skipped
``rule.source_groups`` entirely and fell back to cidrs=['0.0.0.0/0'],
turning every ``sg-A allows from sg-B`` rule into ``allow from anywhere``.

The fix: when LOCALEMU_VPC_IP_PINNING=1 and source_groups is non-empty,
resolve each referenced SG via AddressIndex.get_ips_for_sg and emit
``-s <ip>/32`` per member. Empty membership produces no ACCEPT (the
chain's terminal DROP takes over), matching AWS deny-by-default.

Off-path (flag off): the old 0.0.0.0/0 fallback is preserved so existing
tutorials don't break before the addressing redesign defaults on.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_iptables
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_address_index_for_tests()
    yield
    reset_address_index_for_tests()


def _rule(**kwargs):
    """Build a fake SG rule object."""
    r = mock.Mock()
    r.ip_protocol = kwargs.get("protocol", "6")
    r.from_port = kwargs.get("from_port", 22)
    r.to_port = kwargs.get("to_port", 22)
    r.ip_ranges = kwargs.get("ip_ranges", [])
    r.source_groups = kwargs.get("source_groups", [])
    # moto's SecurityGroupRule has singular ip_range/source_group too;
    # the builder reads both, so pin them to empty here (these tests
    # exercise the plural form).
    r.ip_range = {}
    r.source_group = {}
    return r


class TestSgCrossReferenceWhenPinningOn:
    def test_resolves_source_group_to_member_ips(self):
        # Populate index with two ENIs in sg-app
        idx = get_address_index()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", sg_ids=["sg-app"],
        )
        idx.register_eni(
            "eni-2", "vpc-1", "sub-a", "10.0.0.6", sg_ids=["sg-app"],
        )
        rule = _rule(source_groups=[{"GroupId": "sg-app"}])

        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )

        # Two -s <ip>/32 ACCEPT lines, no 0.0.0.0/0
        body = "\n".join(rules)
        assert "-s 10.0.0.5/32" in body
        assert "-s 10.0.0.6/32" in body
        assert "0.0.0.0/0" not in body

    def test_empty_membership_emits_no_accept(self):
        # source_groups references sg-empty which has zero members
        rule = _rule(source_groups=[{"GroupId": "sg-empty"}])
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        # No -s 10.x or 0.0.0.0/0 ACCEPT for this rule; chain ends in DROP
        accept_lines = [r for r in rules if "-j ACCEPT" in r and "-s 0.0.0.0/0" in r]
        assert accept_lines == []
        # Chain still ends in DROP (preserved)
        assert rules[-1] == "-A SG_IN -j DROP"

    def test_mixed_cidr_and_source_group(self):
        idx = get_address_index()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", sg_ids=["sg-app"],
        )
        rule = _rule(
            ip_ranges=[{"CidrIp": "192.168.0.0/16"}],
            source_groups=[{"GroupId": "sg-app"}],
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        body = "\n".join(rules)
        assert "-s 192.168.0.0/16" in body
        assert "-s 10.0.0.5/32" in body

    def test_index_lookup_failure_falls_back_silently(self):
        rule = _rule(source_groups=[{"GroupId": "sg-app"}])
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch(
                 "localemu.services.ec2.docker.address_index"
                 ".get_address_index",
                 side_effect=RuntimeError("index broken"),
             ):
            # No raise; the rule emits no -s line (empty cidrs +
            # source_groups present + pinning on -> continue)
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        # Chain still ends in DROP — no silent allow-all
        assert rules[-1] == "-A SG_IN -j DROP"
        # No 0.0.0.0/0 leaked
        assert not any("0.0.0.0/0" in r and "ACCEPT" in r for r in rules)


class TestBackwardCompatWhenPinningOff:
    def test_source_group_with_pinning_off_uses_legacy_fallback(self):
        """Off-path tutorial preservation: keep the 0.0.0.0/0 fallback
        so existing tutorials that depend on sg-ref => allow-all keep
        working until the flag defaults on."""
        rule = _rule(source_groups=[{"GroupId": "sg-app"}])
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        # Legacy: 0.0.0.0/0 ACCEPT (this is the historical bug, retained
        # as opt-in until the redesign defaults on)
        body = "\n".join(rules)
        assert "-s 0.0.0.0/0" in body

    def test_cidr_only_rule_unchanged_when_pinning_off(self):
        rule = _rule(ip_ranges=[{"CidrIp": "10.0.0.0/8"}], source_groups=[])
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        body = "\n".join(rules)
        assert "-s 10.0.0.0/8" in body
        assert "0.0.0.0/0" not in body

    def test_cidr_only_rule_unchanged_when_pinning_on(self):
        rule = _rule(ip_ranges=[{"CidrIp": "10.0.0.0/8"}], source_groups=[])
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            rules = sg_iptables._build_chain_rules(
                [rule], chain="SG_IN", is_egress=False,
            )
        body = "\n".join(rules)
        assert "-s 10.0.0.0/8" in body
