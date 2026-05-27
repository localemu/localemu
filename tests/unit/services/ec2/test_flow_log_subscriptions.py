"""Tests for the VPC Flow Log subscription registry.

Closes audit bug #11 (recorder hard-coded to one CWL group regardless
of CreateFlowLogs input). The registry must:

  * round-trip a subscription registered from CreateFlowLogs
  * match ENI-scoped subscriptions by exact ENI id
  * match Subnet/VPC-scoped subscriptions via the AddressIndex
  * filter by TrafficType (ACCEPT / REJECT / ALL)
  * drop subscriptions on deregister so DeleteFlowLogs is honored
"""
from __future__ import annotations

import pytest

from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.flow_logs import (
    FlowLogSubscription,
    FlowLogSubscriptionRegistry,
    get_flow_log_subscriptions,
    reset_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_for_tests()
    reset_address_index_for_tests()
    yield
    reset_for_tests()
    reset_address_index_for_tests()


def _sub(
    fl_id="fl-1", rtype="NetworkInterface", rid="eni-1",
    traffic="ALL", group="/aws/my-flow-logs", account="000000000000",
    region="us-east-1",
):
    return FlowLogSubscription(
        flow_log_id=fl_id, account_id=account, region=region,
        resource_type=rtype, resource_id=rid,
        traffic_type=traffic, destination_type="cloud-watch-logs",
        log_group=group,
    )


class TestRegistryBasics:
    def test_register_then_lookup_by_eni(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-abc"))
        matches = reg.matches_eni("eni-abc", "ACCEPT")
        assert len(matches) == 1
        assert matches[0].flow_log_id == "fl-1"

    def test_deregister_drops_subscription(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-abc"))
        reg.deregister("fl-1")
        assert reg.matches_eni("eni-abc", "ACCEPT") == []

    def test_unknown_eni_returns_empty(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-abc"))
        assert reg.matches_eni("eni-other", "ACCEPT") == []

    def test_singleton_is_stable(self):
        a = get_flow_log_subscriptions()
        b = get_flow_log_subscriptions()
        assert a is b


class TestTrafficTypeFilter:
    def test_accept_only_blocks_reject(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-x", traffic="ACCEPT"))
        assert reg.matches_eni("eni-x", "ACCEPT")
        assert reg.matches_eni("eni-x", "REJECT") == []

    def test_reject_only_blocks_accept(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-x", traffic="REJECT"))
        assert reg.matches_eni("eni-x", "REJECT")
        assert reg.matches_eni("eni-x", "ACCEPT") == []

    def test_all_matches_both(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-x", traffic="ALL"))
        assert reg.matches_eni("eni-x", "ACCEPT")
        assert reg.matches_eni("eni-x", "REJECT")

    def test_action_case_insensitive(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rid="eni-x", traffic="ACCEPT"))
        assert reg.matches_eni("eni-x", "accept")


class TestScopeResolution:
    def _seed_eni(self, eni_id="eni-1", subnet="subnet-a", vpc="vpc-1"):
        get_address_index().register_eni(
            eni_id=eni_id, vpc_id=vpc, subnet_id=subnet,
            primary_ip="10.0.1.5", sg_ids=[],
        )

    def test_subnet_scope_matches_via_address_index(self):
        self._seed_eni()
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rtype="Subnet", rid="subnet-a"))
        assert reg.matches_eni("eni-1", "ACCEPT")

    def test_vpc_scope_matches_via_address_index(self):
        self._seed_eni()
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rtype="VPC", rid="vpc-1"))
        assert reg.matches_eni("eni-1", "ACCEPT")

    def test_subnet_scope_does_not_match_wrong_subnet(self):
        self._seed_eni(subnet="subnet-a")
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rtype="Subnet", rid="subnet-OTHER"))
        assert reg.matches_eni("eni-1", "ACCEPT") == []

    def test_eni_without_address_index_entry_falls_through(self):
        """A FlowLog scoped to a Subnet but the entry's ENI isn't in
        the AddressIndex (legacy or external) → no match. Avoids
        widening the route silently."""
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(rtype="Subnet", rid="subnet-a"))
        assert reg.matches_eni("eni-stranger", "ACCEPT") == []


class TestMultipleSubscriptions:
    def test_fan_out_to_multiple_destinations(self):
        """A user can create two FlowLogs scoped to the same ENI with
        different destinations — every match must be returned."""
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(fl_id="fl-1", rid="eni-x", group="/aws/g1"))
        reg.register(_sub(fl_id="fl-2", rid="eni-x", group="/aws/g2"))
        matches = reg.matches_eni("eni-x", "ACCEPT")
        groups = sorted(m.log_group for m in matches)
        assert groups == ["/aws/g1", "/aws/g2"]

    def test_clear_drops_all(self):
        reg = FlowLogSubscriptionRegistry()
        reg.register(_sub(fl_id="fl-1"))
        reg.register(_sub(fl_id="fl-2"))
        reg.clear()
        assert reg.all() == []
