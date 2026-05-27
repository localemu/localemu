"""E2E: ENI lifecycle via boto3 against a running LocalEmu.

Exercises the full user-visible workflow:

    aws ec2 create-vpc
    aws ec2 create-subnet
    aws ec2 create-network-interface  --subnet-id ...
    aws ec2 describe-network-interfaces --network-interface-ids ...
    aws ec2 assign-private-ip-addresses --network-interface-id ...
    aws ec2 modify-network-interface-attribute --no-source-dest-check
    aws ec2 unassign-private-ip-addresses
    aws ec2 delete-network-interface

Requires LocalEmu running with
``LOCALEMU_VPC_IP_PINNING=1 LOCALEMU_ENI_REAL=1 EC2_VM_MANAGER=docker``.

Validates the AWS contract that LocalEmu's ENI emulation must honor:
  - PrivateIpAddress lies inside SubnetId's CidrBlock
  - MacAddress is stable across describe calls
  - Secondary IPs added via AssignPrivateIpAddresses appear in
    DescribeNetworkInterfaces.PrivateIpAddresses
  - SourceDestCheck round-trips through ModifyNetworkInterfaceAttribute
  - DeleteNetworkInterface releases the IPs for re-use
"""
from __future__ import annotations

import ipaddress
import uuid

import boto3
import pytest
from botocore.config import Config

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"


def _client():
    return boto3.client(
        "ec2",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0}),
    )


@pytest.fixture
def vpc_subnet():
    """Per-test isolated VPC + subnet. Cleaned up after."""
    ec2 = _client()
    tag = uuid.uuid4().hex[:8]
    vpc_cidr = f"10.{200 + (hash(tag) % 50)}.0.0/16"
    subnet_cidr = vpc_cidr.replace("0.0/16", "1.0/24")
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]
    subnet = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=subnet_cidr,
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]
    yield {"vpc": vpc, "subnet": subnet, "ec2": ec2}
    # Best-effort cleanup; some calls may already have removed objects
    try:
        for eni in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}],
        ).get("NetworkInterfaces", []):
            try:
                ec2.delete_network_interface(
                    NetworkInterfaceId=eni["NetworkInterfaceId"],
                )
            except Exception:
                pass
    except Exception:
        pass
    try:
        ec2.delete_subnet(SubnetId=subnet["SubnetId"])
    except Exception:
        pass
    try:
        ec2.delete_vpc(VpcId=vpc["VpcId"])
    except Exception:
        pass


class TestEniStandaloneLifecycle:
    """ENI without an attached instance — covers Create / Describe /
    AssignPrivateIpAddresses / Unassign / ModifyAttribute / Delete."""

    def test_create_eni_assigns_ip_inside_subnet_cidr(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        subnet_cidr = ipaddress.IPv4Network(subnet["CidrBlock"])
        assigned = ipaddress.IPv4Address(eni["PrivateIpAddress"])
        assert assigned in subnet_cidr, (
            f"AWS contract: ENI IP {assigned} must lie inside subnet "
            f"CIDR {subnet_cidr}"
        )

    def test_mac_is_stable_across_describes(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        first_mac = eni["MacAddress"]
        # Describe twice — MAC must be the same
        d1 = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        d2 = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        assert d1["MacAddress"] == first_mac
        assert d2["MacAddress"] == first_mac

    def test_assign_secondary_ip_appears_in_describe(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        primary = eni["PrivateIpAddress"]
        # Pick a secondary IP inside the subnet that isn't the primary
        subnet_cidr = ipaddress.IPv4Network(subnet["CidrBlock"])
        candidates = [
            str(h) for h in subnet_cidr.hosts()
            if str(h) != primary and int(h.packed[-1]) >= 10
        ]
        secondary = candidates[0]
        ec2.assign_private_ip_addresses(
            NetworkInterfaceId=eni_id,
            PrivateIpAddresses=[secondary],
        )
        # Describe — both IPs in PrivateIpAddresses[]
        result = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        ips = {p["PrivateIpAddress"] for p in result["PrivateIpAddresses"]}
        assert primary in ips
        assert secondary in ips

    def test_unassign_removes_secondary(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        primary = eni["PrivateIpAddress"]
        subnet_cidr = ipaddress.IPv4Network(subnet["CidrBlock"])
        secondary = next(
            str(h) for h in subnet_cidr.hosts()
            if str(h) != primary and int(h.packed[-1]) >= 10
        )
        ec2.assign_private_ip_addresses(
            NetworkInterfaceId=eni_id,
            PrivateIpAddresses=[secondary],
        )
        ec2.unassign_private_ip_addresses(
            NetworkInterfaceId=eni_id,
            PrivateIpAddresses=[secondary],
        )
        result = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        ips = {p["PrivateIpAddress"] for p in result["PrivateIpAddresses"]}
        assert primary in ips
        assert secondary not in ips

    def test_source_dest_check_round_trips(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        # Default: True
        described = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        assert described["SourceDestCheck"] is True
        # Flip to False
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            SourceDestCheck={"Value": False},
        )
        described = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        assert described["SourceDestCheck"] is False

    def test_delete_releases_ip_for_reuse(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni1 = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        ip = eni1["PrivateIpAddress"]
        ec2.delete_network_interface(
            NetworkInterfaceId=eni1["NetworkInterfaceId"],
        )
        # Create another ENI with the SAME IP — should succeed because
        # the previous one freed the allocator slot
        eni2 = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
            PrivateIpAddress=ip,
        )["NetworkInterface"]
        assert eni2["PrivateIpAddress"] == ip

    def test_create_with_explicit_ip(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        subnet_cidr = ipaddress.IPv4Network(subnet["CidrBlock"])
        pinned = next(
            str(h) for h in subnet_cidr.hosts()
            if int(h.packed[-1]) >= 100
        )
        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
            PrivateIpAddress=pinned,
        )["NetworkInterface"]
        assert eni["PrivateIpAddress"] == pinned

    def test_two_enis_get_different_ips(self, vpc_subnet):
        ec2 = vpc_subnet["ec2"]
        subnet = vpc_subnet["subnet"]
        eni1 = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni2 = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        assert eni1["PrivateIpAddress"] != eni2["PrivateIpAddress"]
        assert eni1["MacAddress"] != eni2["MacAddress"]
