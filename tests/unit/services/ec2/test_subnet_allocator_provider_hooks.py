"""Tests for the CreateSubnet/DeleteSubnet allocator integration hooks.

Verifies that _register_subnet_with_allocator and
_unregister_subnet_from_allocator wire moto's subnet response into the
SubnetAllocator when LOCALEMU_VPC_IP_PINNING=1, and are no-ops when the
flag is off (the default).
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2 import provider as ec2_provider
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_allocator():
    reset_subnet_allocator_for_tests()
    yield
    reset_subnet_allocator_for_tests()


class TestRegisterSubnetHook:
    def test_no_op_when_flag_off(self):
        # Default: LOCALEMU_VPC_IP_PINNING is False
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            ec2_provider._register_subnet_with_allocator({
                "SubnetId": "subnet-aaa",
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
            })
            # Nothing registered
            assert get_subnet_allocator().all_pools() == []

    def test_registers_when_flag_on_using_aws_cidr_fallback(self):
        # No live bridge yet -> docker_cidr defaults to aws_cidr
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            ec2_provider._register_subnet_with_allocator({
                "SubnetId": "subnet-aaa",
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
            })
            pools = get_subnet_allocator().describe("vpc-1")
            assert len(pools) == 1
            assert pools[0].subnet_id == "subnet-aaa"
            assert str(pools[0].aws_cidr) == "10.0.1.0/24"
            # docker_cidr matches aws_cidr in the no-bridge case
            assert str(pools[0].docker_cidr) == "10.0.1.0/24"

    def test_pool_cidr_equals_subnet_cidr_not_vpc_bridge_cidr(self):
        """AWS contract: an ENI's primary IP must lie inside its subnet's
        CidrBlock. The pool's docker_cidr must therefore equal the
        SUBNET's CIDR, not the VPC bridge's wider CIDR. Found via E2E
        when an ENI in subnet 10.99.1.0/24 was getting IP 10.99.0.2
        (inside VPC /16 but outside subnet /24) — invalid per AWS.
        """
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            ec2_provider._register_subnet_with_allocator({
                "SubnetId": "subnet-aaa",
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
            })
            pools = get_subnet_allocator().describe("vpc-1")
            assert str(pools[0].docker_cidr) == "10.0.1.0/24"
            assert str(pools[0].aws_cidr) == "10.0.1.0/24"
            # Reserve an IP and verify it's in the subnet CIDR, NOT
            # somewhere else in the VPC's wider CIDR
            ip = get_subnet_allocator().reserve(
                "vpc-1", "subnet-aaa", "test-owner",
            )
            assert str(ip).startswith("10.0.1."), (
                f"IP {ip} should be in subnet 10.0.1.0/24"
            )

    def test_missing_fields_skipped(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            # No SubnetId — skip
            ec2_provider._register_subnet_with_allocator({
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
            })
            assert get_subnet_allocator().all_pools() == []

    def test_swallows_register_exceptions(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 get_subnet_allocator(), "register_subnet",
                 side_effect=RuntimeError("boom"),
             ):
            # No raise — error is logged and swallowed
            ec2_provider._register_subnet_with_allocator({
                "SubnetId": "subnet-aaa",
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
            })


class TestUnregisterSubnetHook:
    def test_no_op_when_flag_off(self):
        # Even if a pool exists, the flag-off path is a no-op
        get_subnet_allocator().register_subnet(
            "vpc-1", "subnet-aaa", "10.0.1.0/24", "10.0.1.0/24", "us-east-1a",
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            ec2_provider._unregister_subnet_from_allocator(
                "000000000000", "us-east-1", "subnet-aaa",
            )
            assert get_subnet_allocator().describe("vpc-1") != []

    def test_removes_when_flag_on(self):
        get_subnet_allocator().register_subnet(
            "vpc-1", "subnet-aaa", "10.0.1.0/24", "10.0.1.0/24", "us-east-1a",
        )
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            ec2_provider._unregister_subnet_from_allocator(
                "000000000000", "us-east-1", "subnet-aaa",
            )
            assert get_subnet_allocator().describe("vpc-1") == []

    def test_force_unregister_releases_allocations(self):
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "subnet-aaa", "10.0.1.0/24", "10.0.1.0/24", "us-east-1a",
        )
        ip = alloc.reserve("vpc-1", "subnet-aaa", "eni-1")
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            ec2_provider._unregister_subnet_from_allocator(
                "000000000000", "us-east-1", "subnet-aaa",
            )
            # IP released
            assert alloc.lookup(ip) is None

    def test_missing_subnet_id_skipped(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            ec2_provider._unregister_subnet_from_allocator(
                "000000000000", "us-east-1", None,
            )  # no raise
