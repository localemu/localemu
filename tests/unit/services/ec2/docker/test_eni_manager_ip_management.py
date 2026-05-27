"""Tests for the ENI IP-management ops added to EniManager:

  - assign_private_ips: explicit + auto-pick paths, attached + detached
  - unassign_private_ips: kernel removal + index + allocator release
  - modify_attribute: groups, source_dest_check, delete_on_termination
"""
from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from localemu.services.ec2.docker import eni_manager
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.eni_manager import (
    EniManager,
    EniNotFound,
    InvalidEniState,
    reset_eni_manager_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()


def _create_eni(attached: bool = False):
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
    )
    mgr = EniManager()
    mgr.create(
        eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=["sg-web"],
    )
    if attached:
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"), \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth1",
             ):
            mgr.attach("eni-1", "i-abc", device_index=1)
    return mgr


class TestAssignPrivateIps:
    def test_explicit_ips_reserved_and_indexed_when_detached(self):
        mgr = _create_eni(attached=False)
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            assigned = mgr.assign_private_ips(
                "eni-1", explicit_ips=["10.0.7.10", "10.0.7.11"],
            )
            # No exec since detached
            assert dc.exec_in_container.call_count == 0
        assert [str(a) for a in assigned] == ["10.0.7.10", "10.0.7.11"]
        # Both in index
        e = get_address_index().get_eni("eni-1")
        assert ipaddress.IPv4Address("10.0.7.10") in e.secondary_ips
        assert ipaddress.IPv4Address("10.0.7.11") in e.secondary_ips
        # Both in allocator
        assert get_subnet_allocator().lookup("10.0.7.10") is not None
        assert get_subnet_allocator().lookup("10.0.7.11") is not None

    def test_attached_eni_runs_ip_addr_add(self):
        mgr = _create_eni(attached=True)
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            mgr.assign_private_ips("eni-1", explicit_ips=["10.0.8.1"])
            # exec_in_container called with the ip addr add command
            assert any(
                "ip addr add 10.0.8.1/32" in str(c)
                for c in dc.exec_in_container.call_args_list
            )

    def test_auto_pick_count(self):
        mgr = _create_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"):
            assigned = mgr.assign_private_ips("eni-1", count=3)
        assert len(assigned) == 3
        e = get_address_index().get_eni("eni-1")
        assert len(e.secondary_ips) == 3

    def test_collision_rolls_back_partial_reservations(self):
        mgr = _create_eni()
        # 10.0.7.10 already reserved by someone else
        get_subnet_allocator().reserve(
            "vpc-1", "sub-a", "other", requested="10.0.7.10",
        )
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"):
            with pytest.raises(InvalidEniState):
                mgr.assign_private_ips(
                    "eni-1", explicit_ips=["10.0.7.11", "10.0.7.10"],
                )
        # 10.0.7.11 was rolled back (only "other" owns 10.0.7.10)
        assert get_subnet_allocator().lookup("10.0.7.11") is None
        e = get_address_index().get_eni("eni-1")
        assert ipaddress.IPv4Address("10.0.7.11") not in e.secondary_ips

    def test_unknown_eni_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.assign_private_ips("eni-nope", explicit_ips=["10.0.0.5"])


class TestUnassignPrivateIps:
    def test_releases_from_index_and_allocator(self):
        mgr = _create_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"):
            mgr.assign_private_ips("eni-1", explicit_ips=["10.0.5.5"])
            mgr.unassign_private_ips("eni-1", ips=["10.0.5.5"])
        e = get_address_index().get_eni("eni-1")
        assert ipaddress.IPv4Address("10.0.5.5") not in e.secondary_ips
        assert get_subnet_allocator().lookup("10.0.5.5") is None

    def test_attached_runs_ip_addr_del(self):
        mgr = _create_eni(attached=True)
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            mgr.assign_private_ips("eni-1", explicit_ips=["10.0.5.5"])
            dc.reset_mock()
            mgr.unassign_private_ips("eni-1", ips=["10.0.5.5"])
            assert any(
                "ip addr del 10.0.5.5/32" in str(c)
                for c in dc.exec_in_container.call_args_list
            )

    def test_unknown_eni_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.unassign_private_ips("eni-nope", ips=["10.0.0.5"])

    def test_malformed_ip_silently_skipped(self):
        mgr = _create_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"):
            # Not raising on bad input — best-effort cleanup
            mgr.unassign_private_ips("eni-1", ips=["not-an-ip"])


class TestModifyAttribute:
    def test_groups_updates_index(self):
        mgr = _create_eni()
        mgr.modify_attribute("eni-1", groups=["sg-app", "sg-db"])
        e = get_address_index().get_eni("eni-1")
        assert e.sg_ids == ["sg-app", "sg-db"]
        # Reverse index updated
        idx = get_address_index()
        assert "eni-1" in idx._sg_to_enis.get("sg-app", set())
        assert "eni-1" in idx._sg_to_enis.get("sg-db", set())
        # Old SG bucket no longer contains the ENI
        assert "eni-1" not in idx._sg_to_enis.get("sg-web", set())

    def test_source_dest_check(self):
        mgr = _create_eni()
        mgr.modify_attribute("eni-1", source_dest_check=False)
        assert get_address_index().get_eni("eni-1").source_dest_check is False
        mgr.modify_attribute("eni-1", source_dest_check=True)
        assert get_address_index().get_eni("eni-1").source_dest_check is True

    def test_delete_on_termination(self):
        mgr = _create_eni()
        # Default for standalone is False (set by create with default)
        assert get_address_index().get_eni("eni-1").delete_on_termination is False
        mgr.modify_attribute("eni-1", delete_on_termination=True)
        assert get_address_index().get_eni("eni-1").delete_on_termination is True

    def test_unknown_eni_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.modify_attribute("eni-nope", source_dest_check=False)

    def test_no_op_when_no_attributes(self):
        mgr = _create_eni()
        # All-None call — no-op, no raise
        mgr.modify_attribute("eni-1")
