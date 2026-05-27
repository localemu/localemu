"""Tests for the IMDS public-ipv4 dynamic lookup.

Closes the EIP loop: when a user calls ``associate-address`` AFTER
container boot, the next ``curl http://169.254.169.254/latest/meta-data/public-ipv4``
must reflect the new EIP — not the stale "127.0.0.1" baked into the
metadata snapshot at register-time.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

# Triggers the EIP-pool patch so allocate_address returns 198.51.100.X
import localemu.services.ec2.eip_patches  # noqa: F401
from localemu.services.ec2.docker.imds import _lookup_public_ipv4


@mock_aws
class TestLookupPublicIpv4:
    def _launch(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
        )["Subnet"]
        r = ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
        )
        return ec2, r["Instances"][0]["InstanceId"]

    def test_no_eip_falls_back_to_localhost(self):
        ec2, iid = self._launch()
        meta = {
            "instance_id": iid,
            "account_id": "123456789012",
            "region": "us-east-1",
        }
        assert _lookup_public_ipv4(meta) == "127.0.0.1"

    def test_associated_eip_is_returned(self):
        ec2, iid = self._launch()
        eip = ec2.allocate_address(Domain="vpc")
        ec2.associate_address(
            InstanceId=iid, AllocationId=eip["AllocationId"],
        )
        meta = {
            "instance_id": iid,
            "account_id": "123456789012",
            "region": "us-east-1",
        }
        assert _lookup_public_ipv4(meta) == eip["PublicIp"]

    def test_disassociated_eip_falls_back_again(self):
        ec2, iid = self._launch()
        eip = ec2.allocate_address(Domain="vpc")
        assoc = ec2.associate_address(
            InstanceId=iid, AllocationId=eip["AllocationId"],
        )
        # Confirm association reflected
        meta = {
            "instance_id": iid,
            "account_id": "123456789012",
            "region": "us-east-1",
        }
        assert _lookup_public_ipv4(meta) == eip["PublicIp"]

        # Now detach — IMDS must revert to localhost
        ec2.disassociate_address(AssociationId=assoc["AssociationId"])
        assert _lookup_public_ipv4(meta) == "127.0.0.1"

    def test_missing_instance_id_returns_fallback_without_raising(self):
        # No instance_id key at all
        assert _lookup_public_ipv4({}) == "127.0.0.1"
        # Empty string
        assert _lookup_public_ipv4({"instance_id": ""}) == "127.0.0.1"

    def test_eip_lookup_is_per_instance(self):
        """Two instances; only one gets an EIP. Each instance's IMDS
        must see its own state, not the other's."""
        ec2, iid_a = self._launch()
        ec2_b = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2_b.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]
        sub = ec2_b.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.99.1.0/24",
        )["Subnet"]
        r = ec2_b.run_instances(
            ImageId="ami-12345678", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
        )
        iid_b = r["Instances"][0]["InstanceId"]

        eip = ec2.allocate_address(Domain="vpc")
        ec2.associate_address(
            InstanceId=iid_a, AllocationId=eip["AllocationId"],
        )

        meta_a = {"instance_id": iid_a, "account_id": "123456789012", "region": "us-east-1"}
        meta_b = {"instance_id": iid_b, "account_id": "123456789012", "region": "us-east-1"}
        assert _lookup_public_ipv4(meta_a) == eip["PublicIp"]
        assert _lookup_public_ipv4(meta_b) == "127.0.0.1"
