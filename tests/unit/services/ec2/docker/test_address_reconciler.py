"""Unit tests for AddressReconciler.

All tests mock DOCKER_CLIENT so no real Docker is required. We exercise
the four reconciliation cases:
  - Match: Docker has it, index has it, same IP -> matched++
  - Recreate: Docker has it, index missing -> recreate, claim allocator
  - Drop orphan: Index has it, Docker doesn't -> remove, release IP
  - IP drift: Same instance, different IP -> Docker wins, log + counters
"""
from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from localemu.services.ec2.docker import address_reconciler
from localemu.services.ec2.docker.address_index import (
    AddressIndex,
)
from localemu.services.ec2.docker.address_reconciler import (
    VPC_NETWORK_PREFIX,
    _DockerMember,
    _reconcile_one_member,
    reconcile_on_startup,
)
from localemu.services.ec2.docker.subnet_allocator import SubnetAllocator


# ---------------------------------------------------------------------------
# Per-member reconciliation logic (no Docker)
# ---------------------------------------------------------------------------
class TestReconcileOne:
    def _setup(self):
        alloc = SubnetAllocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        idx = AddressIndex()
        report = address_reconciler.ReconcileReport()
        return alloc, idx, report

    def test_recreate_when_index_missing(self):
        alloc, idx, report = self._setup()
        m = _DockerMember(
            container_name="localemu-ec2-i-abc",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.0.5"),
            eni_id="eni-abc",
            subnet_id="sub-a",
            instance_id="i-abc",
            sg_ids=["sg-web"],
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.recreated_index == 1
        # ENI is now in the index
        e = idx.get_eni("eni-abc")
        assert e is not None
        assert e.primary_ip == ipaddress.IPv4Address("10.0.0.5")
        assert e.sg_ids == ["sg-web"]
        assert e.mac == "02:42:0a:00:00:05"  # derived
        # IP is claimed in the allocator
        assert alloc.lookup("10.0.0.5") == ("vpc-1", "sub-a", "eni-eni-abc")

    def test_matched_when_index_agrees(self):
        alloc, idx, report = self._setup()
        # Pre-populate index with the matching entry
        alloc.claim("vpc-1", "sub-a", "10.0.0.5", "eni-eni-abc")
        idx.register_eni(
            "eni-abc", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web"], instance_id="i-abc",
        )
        m = _DockerMember(
            container_name="localemu-ec2-i-abc",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.0.5"),
            eni_id="eni-abc",
            subnet_id="sub-a",
            instance_id="i-abc",
            sg_ids=["sg-web"],
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.matched == 1
        assert report.recreated_index == 0
        assert report.ip_drift == 0

    def test_drift_docker_wins(self):
        alloc, idx, report = self._setup()
        # Index thinks ENI is at 10.0.0.5, Docker says 10.0.0.7
        alloc.claim("vpc-1", "sub-a", "10.0.0.5", "eni-eni-abc")
        idx.register_eni(
            "eni-abc", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web"], instance_id="i-abc",
        )
        m = _DockerMember(
            container_name="localemu-ec2-i-abc",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.0.7"),  # different
            eni_id="eni-abc",
            subnet_id="sub-a",
            instance_id="i-abc",
            sg_ids=["sg-web"],
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.ip_drift == 1
        assert "i-abc" in report.drifted_instances
        # Index now has the new IP
        e = idx.get_eni("eni-abc")
        assert e.primary_ip == ipaddress.IPv4Address("10.0.0.7")
        # Old IP is released, new IP is claimed
        assert alloc.lookup("10.0.0.5") is None
        assert alloc.lookup("10.0.0.7") == ("vpc-1", "sub-a", "eni-eni-abc")

    def test_skipped_when_subnet_not_registered(self):
        alloc = SubnetAllocator()  # nothing registered
        idx = AddressIndex()
        report = address_reconciler.ReconcileReport()
        m = _DockerMember(
            container_name="localemu-ec2-i-orphan",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-99",
            vpc_id="vpc-99",
            primary_ip=ipaddress.IPv4Address("10.99.0.5"),
            eni_id="eni-orphan",
            subnet_id="sub-zz",  # not in allocator
            instance_id="i-orphan",
            sg_ids=[],
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.skipped_unregistered == 1
        assert idx.get_eni("eni-orphan") is None

    def test_sg_drift_updates_membership(self):
        alloc, idx, report = self._setup()
        alloc.claim("vpc-1", "sub-a", "10.0.0.5", "eni-eni-abc")
        idx.register_eni(
            "eni-abc", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-old"], instance_id="i-abc",
        )
        m = _DockerMember(
            container_name="localemu-ec2-i-abc",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.0.5"),
            eni_id="eni-abc",
            subnet_id="sub-a",
            instance_id="i-abc",
            sg_ids=["sg-new"],  # changed
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.matched == 1
        assert idx.get_eni("eni-abc").sg_ids == ["sg-new"]

    def test_missing_eni_id_silently_skips(self):
        """Container without a localemu.eni-id label and no instance_id
        (legacy / corrupted) is not enough to reconcile — skip silently."""
        alloc, idx, report = self._setup()
        m = _DockerMember(
            container_name="some-random-container",
            network_name=f"{VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.0.5"),
            eni_id=None,
            subnet_id="sub-a",
            instance_id=None,
            sg_ids=[],
            mac=None,
        )
        _reconcile_one_member(m, alloc, idx, report)
        assert report.recreated_index == 0
        assert report.matched == 0


# ---------------------------------------------------------------------------
# Whole-flow with mocked Docker
# ---------------------------------------------------------------------------
class TestReconcileOnStartup:
    def test_orphan_dropped(self):
        alloc = SubnetAllocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        idx = AddressIndex()
        # Pre-populate an ENI that Docker won't report
        alloc.claim("vpc-1", "sub-a", "10.0.0.5", "eni-eni-ghost")
        idx.register_eni(
            "eni-ghost", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-w"], instance_id="i-ghost",
        )
        with mock.patch(
            "localemu.services.ec2.docker.address_reconciler.DOCKER_CLIENT",
        ) as dc:
            dc.get_system_info.return_value = {"ID": "x"}
            dc.list_containers.return_value = []  # no containers
            report = reconcile_on_startup(allocator=alloc, index=idx)
        assert report.dropped_orphan == 1
        assert "eni-ghost" in report.orphan_enis
        assert idx.get_eni("eni-ghost") is None
        assert alloc.lookup("10.0.0.5") is None

    def test_docker_unreachable_returns_empty_report(self):
        alloc = SubnetAllocator()
        idx = AddressIndex()
        with mock.patch(
            "localemu.services.ec2.docker.address_reconciler.DOCKER_CLIENT",
        ) as dc:
            dc.get_system_info.side_effect = Exception("docker down")
            report = reconcile_on_startup(allocator=alloc, index=idx)
        # No raise; empty report
        assert report.matched == 0
        assert report.recreated_index == 0
        assert report.dropped_orphan == 0

    def test_full_recreate_path_via_docker_mocks(self):
        """End-to-end: empty index, Docker reports one container — index
        is recreated and IP is claimed in allocator."""
        alloc = SubnetAllocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        idx = AddressIndex()
        with mock.patch(
            "localemu.services.ec2.docker.address_reconciler.DOCKER_CLIENT",
        ) as dc:
            dc.get_system_info.return_value = {"ID": "x"}
            # One EC2 container exists
            dc.list_containers.side_effect = lambda filter=None, all=False: (
                [{"name": "localemu-ec2-i-abc"}]
                if filter and "label=localemu.service=ec2" in filter
                else []
            )
            # That container is on the vpc-1 network
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {
                        "localemu-vpc-vpc-1": {
                            "IPAddress": "10.0.0.5",
                        },
                    },
                },
                "Config": {
                    "Labels": {
                        "localemu.instance-id": "i-abc",
                        "localemu.eni-id": "eni-abc",
                        "localemu.subnet-id": "sub-a",
                        "localemu.sg-ids": "sg-web",
                    },
                },
            }
            # Network inspect: one container attached
            dc.inspect_network.return_value = {
                "Containers": {
                    "cid-abc": {
                        "Name": "localemu-ec2-i-abc",
                        "IPv4Address": "10.0.0.5/16",
                        "MacAddress": "02:42:0a:00:00:05",
                    },
                },
            }
            report = reconcile_on_startup(allocator=alloc, index=idx)
        assert report.recreated_index == 1
        assert idx.get_eni("eni-abc").primary_ip == ipaddress.IPv4Address(
            "10.0.0.5",
        )
        assert alloc.lookup("10.0.0.5") == ("vpc-1", "sub-a", "eni-eni-abc")
