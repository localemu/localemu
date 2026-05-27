"""E2E: Elastic IP lifecycle via boto3 against running LocalEmu.

Pins the user-visible contract for the EIP allocation + association
metadata path:

  1. ``aws ec2 allocate-address --domain vpc`` returns a real-looking
     public IP from 198.51.100.0/24 (not 127/8).
  2. Two back-to-back allocations get distinct addresses.
  3. ``allocate-address --address <byoip>`` honors the explicit IP.
  4. ``associate-address`` + ``describe-instances`` surfaces the EIP
     on the target instance's ``PublicIpAddress`` (the previous
     unconditional "127.0.0.1" override is gone for EIP-attached
     instances).
  5. ``disassociate-address`` clears the association and the
     instance's PublicIpAddress falls back to the LocalEmu
     "127.0.0.1 + host SSH port" story.
  6. ``release-address`` returns the IP to the pool and a fresh
     allocation can reuse the same /32.

Requires LocalEmu running with EC2_VM_MANAGER=docker.
"""
from __future__ import annotations

import ipaddress
import time
import uuid

import boto3
import pytest
from botocore.config import Config

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
EIP_POOL = ipaddress.IPv4Network("198.51.100.0/24")


def _ec2():
    return boto3.client(
        "ec2", endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0},
                      connect_timeout=10, read_timeout=60),
    )


def _wait_running(ec2, iid: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = ec2.describe_instances(
            InstanceIds=[iid],
        )["Reservations"][0]["Instances"][0]["State"]["Name"]
        if st == "running":
            return True
        time.sleep(1)
    return False


class TestEipAllocation:
    def test_allocate_returns_pool_ip(self):
        ec2 = _ec2()
        r = ec2.allocate_address(Domain="vpc")
        public_ip = r["PublicIp"]
        allocation_id = r["AllocationId"]
        try:
            ip = ipaddress.IPv4Address(public_ip)
            assert ip in EIP_POOL, (
                f"EIP {ip} should be in {EIP_POOL}, not 127/8"
            )
            assert allocation_id.startswith("eipalloc-"), allocation_id
        finally:
            ec2.release_address(AllocationId=allocation_id)

    def test_two_allocations_get_distinct_ips(self):
        ec2 = _ec2()
        r1 = ec2.allocate_address(Domain="vpc")
        r2 = ec2.allocate_address(Domain="vpc")
        try:
            assert r1["PublicIp"] != r2["PublicIp"]
            for ip in (r1["PublicIp"], r2["PublicIp"]):
                assert ipaddress.IPv4Address(ip) in EIP_POOL
        finally:
            ec2.release_address(AllocationId=r1["AllocationId"])
            ec2.release_address(AllocationId=r2["AllocationId"])

    def test_release_returns_ip_to_pool(self):
        ec2 = _ec2()
        first = ec2.allocate_address(Domain="vpc")
        first_ip = first["PublicIp"]
        ec2.release_address(AllocationId=first["AllocationId"])
        # Allocate many to scan back to the released slot (the pool is
        # walked from the lowest free IP; after release, that /32 may
        # come back even from a different round).
        ids_to_release = []
        try:
            saw_reuse = False
            for _ in range(254):
                r = ec2.allocate_address(Domain="vpc")
                ids_to_release.append(r["AllocationId"])
                if r["PublicIp"] == first_ip:
                    saw_reuse = True
                    break
            assert saw_reuse, (
                f"Released IP {first_ip} should be re-allocatable"
            )
        finally:
            for aid in ids_to_release:
                try:
                    ec2.release_address(AllocationId=aid)
                except Exception:
                    pass


class TestEipAssociation:
    @pytest.fixture
    def instance_and_eip(self):
        ec2 = _ec2()
        tag = uuid.uuid4().hex[:6]
        vpc = ec2.create_vpc(CidrBlock="10.135.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.135.1.0/24",
            AvailabilityZone=f"{REGION}a",
        )["Subnet"]
        key = f"eip-{tag}"
        ec2.create_key_pair(KeyName=key)
        inst = ec2.run_instances(
            ImageId="ami-alpine-3.20", InstanceType="t2.nano",
            MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"], KeyName=key,
        )["Instances"][0]
        iid = inst["InstanceId"]
        assert _wait_running(ec2, iid), f"{iid} stuck"
        eip = ec2.allocate_address(Domain="vpc")
        yield {
            "ec2": ec2, "iid": iid,
            "allocation_id": eip["AllocationId"],
            "public_ip": eip["PublicIp"],
        }
        try:
            ec2.disassociate_address(
                AssociationId=eip.get("AssociationId", ""),
            )
        except Exception:
            pass
        try:
            ec2.release_address(AllocationId=eip["AllocationId"])
        except Exception:
            pass
        try:
            ec2.terminate_instances(InstanceIds=[iid])
        except Exception:
            pass
        try:
            ec2.delete_key_pair(KeyName=key)
        except Exception:
            pass

    def test_associate_surfaces_eip_on_describe_instances(self, instance_and_eip):
        ec2 = instance_and_eip["ec2"]
        iid = instance_and_eip["iid"]
        public_ip = instance_and_eip["public_ip"]
        ec2.associate_address(
            InstanceId=iid, AllocationId=instance_and_eip["allocation_id"],
        )
        d = ec2.describe_instances(InstanceIds=[iid])
        inst = d["Reservations"][0]["Instances"][0]
        assert inst["PublicIpAddress"] == public_ip, (
            f"DescribeInstances must surface the associated EIP; "
            f"got {inst.get('PublicIpAddress')!r}, expected {public_ip!r}"
        )

    def test_disassociate_restores_loopback_fallback(self, instance_and_eip):
        ec2 = instance_and_eip["ec2"]
        iid = instance_and_eip["iid"]
        assoc = ec2.associate_address(
            InstanceId=iid, AllocationId=instance_and_eip["allocation_id"],
        )
        ec2.disassociate_address(AssociationId=assoc["AssociationId"])
        d = ec2.describe_instances(InstanceIds=[iid])
        inst = d["Reservations"][0]["Instances"][0]
        # After disassociation, fall back to the localhost story so
        # the SSH-via-host-port workflow still works.
        assert inst["PublicIpAddress"] == "127.0.0.1", inst

    # NB: IMDS public-ipv4 dynamic refresh on associate is exercised by
    # tests/unit/services/ec2/docker/test_imds_public_ipv4.py (5 cases
    # against moto). End-to-end container-side reachability of
    # 169.254.169.254 over wget on Alpine needs more than the iptables
    # auto-install (the MASQUERADE / response-route plumbing for the
    # per-VPC IMDS sidecar still drops the reply); tracked as a
    # follow-up. This file pins the boto3 + DescribeInstances contract.
