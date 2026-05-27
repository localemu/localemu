"""Tests for the EIP pool + ElasticAddress patch.

Pin the contract:
  - Allocated EIPs land in 198.51.100.0/24 (not 127/8)
  - No two EIPs share an IP within the same account-region
  - Explicit BYOIP path (caller passes ``address=``) is preserved
  - Pool exhaustion falls back to upstream random_ip without raising
"""
from __future__ import annotations

import ipaddress

import boto3
import pytest
from moto import mock_aws
from moto.ec2.models.elastic_ip_addresses import ElasticAddress

# Triggers the patch
import localemu.services.ec2.eip_patches  # noqa: F401
from localemu.services.ec2.eip_pool import (
    EIP_POOL_CIDR, next_free_ip, usable_pool,
)


class TestPool:
    def test_pool_has_254_usable_ips(self):
        ips = usable_pool()
        assert len(ips) == 254
        assert str(ips[0]) == "198.51.100.1"
        assert str(ips[-1]) == "198.51.100.254"

    def test_next_free_skips_used(self):
        used = {f"198.51.100.{i}" for i in range(1, 10)}
        assert next_free_ip(used) == "198.51.100.10"

    def test_next_free_returns_none_when_exhausted(self):
        used = {f"198.51.100.{i}" for i in range(1, 255)}
        assert next_free_ip(used) is None

    def test_pool_is_in_documented_test_net_2(self):
        net = ipaddress.IPv4Network(EIP_POOL_CIDR)
        # RFC 5737 TEST-NET-2 is 198.51.100.0/24
        assert str(net) == "198.51.100.0/24"


class TestPatchedAllocate:
    @mock_aws
    def test_allocate_address_returns_real_pool_ip(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        r = ec2.allocate_address(Domain="vpc")
        ip = ipaddress.IPv4Address(r["PublicIp"])
        assert ip in ipaddress.IPv4Network("198.51.100.0/24"), (
            f"EIP {ip} should be in 198.51.100.0/24, not 127/8"
        )

    @mock_aws
    def test_two_allocations_get_distinct_pool_ips(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        a = ec2.allocate_address(Domain="vpc")["PublicIp"]
        b = ec2.allocate_address(Domain="vpc")["PublicIp"]
        assert a != b
        for ip in (a, b):
            assert ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(
                "198.51.100.0/24",
            )

    @mock_aws
    def test_explicit_address_byoip_preserved(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        # AWS supports allocating a specific public IP via Address=...
        # The patch must NOT override an explicit IP.
        r = ec2.allocate_address(Domain="vpc", Address="203.0.113.42")
        assert r["PublicIp"] == "203.0.113.42"


class TestPatchHonorsPoolExhaustion:
    def test_init_falls_back_when_pool_exhausted(self):
        """Direct unit test on ElasticAddress: when the backend already
        owns all 254 pool IPs, the patched init must still produce an
        address (the upstream random_ip path), not raise."""
        class FakeBackend:
            addresses = [
                type("E", (), {"public_ip": f"198.51.100.{i}"})()
                for i in range(1, 255)
            ]
        ea = ElasticAddress(FakeBackend(), domain="vpc")
        # The fallback IP is from the upstream random_ip (127/8).
        # The contract is "it produced an IP without raising".
        assert ea.public_ip is not None
        assert "." in ea.public_ip
