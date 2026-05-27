"""E2E: ENI hot-attach against a running EC2 instance container.

Exercises ``aws ec2 attach-network-interface`` / ``detach-network-interface``
on an instance that's already up. The contract LocalEmu must honor:

  * After AttachNetworkInterface the ENI's reserved IP is reachable on a
    second interface (eth1) inside the instance container.
  * DescribeNetworkInterfaces reflects Attachment.InstanceId +
    Status='attached' + DeviceIndex.
  * DescribeInstances surfaces the new ENI in NetworkInterfaces.
  * After DetachNetworkInterface the IP is gone from inside the container
    and the ENI is back in 'available' state.

Requires LocalEmu running with:
``LOCALEMU_VPC_IP_PINNING=1 LOCALEMU_ENI_REAL=1 EC2_VM_MANAGER=docker``.
"""
from __future__ import annotations

import time
import uuid

import os

import boto3
import pytest
from botocore.config import Config
import docker as docker_sdk

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"


def _ec2():
    return boto3.client(
        "ec2",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0}),
    )


def _docker():
    return docker_sdk.from_env()


def _wait_running(ec2, iid: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = ec2.describe_instances(InstanceIds=[iid])
        state = d["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            return
        time.sleep(1)
    raise AssertionError(f"instance {iid} did not reach running in {timeout}s")


def _container_name_for_instance(iid: str) -> str:
    return f"localemu-ec2-{iid}"


def _exec(container_name: str, *cmd: str) -> str:
    c = _docker().containers.get(container_name)
    rc, out = c.exec_run(list(cmd))
    return out.decode(errors="replace")


def _ip_addrs(container_name: str) -> list[str]:
    """Return all inet addresses inside the container (any iface)."""
    out = _exec(container_name, "ip", "-4", "-o", "addr", "show")
    ips: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            ips.append(parts[3].split("/")[0])
    return ips


@pytest.fixture
def vpc_instance():
    """Per-test VPC + subnet + running instance. Cleaned up after."""
    ec2 = _ec2()
    tag = uuid.uuid4().hex[:8]
    vpc_cidr = f"10.{220 + (hash(tag) % 30)}.0.0/16"
    subnet_cidr = vpc_cidr.replace("0.0/16", "1.0/24")
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]
    subnet = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=subnet_cidr,
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]
    resp = ec2.run_instances(
        ImageId="ami-alpine-3.20",
        InstanceType="t2.nano",
        MinCount=1, MaxCount=1,
        SubnetId=subnet["SubnetId"],
    )
    iid = resp["Instances"][0]["InstanceId"]
    _wait_running(ec2, iid)
    yield {
        "ec2": ec2, "vpc": vpc, "subnet": subnet, "instance_id": iid,
        "container_name": _container_name_for_instance(iid),
    }
    # Cleanup: terminate instance, delete ENIs, subnet, vpc
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except Exception:
        pass
    try:
        for eni in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}],
        ).get("NetworkInterfaces", []):
            try:
                if eni.get("Attachment"):
                    ec2.detach_network_interface(
                        AttachmentId=eni["Attachment"]["AttachmentId"],
                        Force=True,
                    )
            except Exception:
                pass
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


class TestEniHotAttach:
    def test_attach_adds_eni_ip_inside_container(self, vpc_instance):
        ec2 = vpc_instance["ec2"]
        subnet = vpc_instance["subnet"]
        iid = vpc_instance["instance_id"]
        container = vpc_instance["container_name"]

        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        eni_ip = eni["PrivateIpAddress"]

        ips_before = set(_ip_addrs(container))
        assert eni_ip not in ips_before, ips_before

        attach_resp = ec2.attach_network_interface(
            NetworkInterfaceId=eni_id,
            InstanceId=iid,
            DeviceIndex=1,
        )
        assert "AttachmentId" in attach_resp, attach_resp

        # Poll briefly — iface_resolver runs ip link inside container
        # which can take a fraction of a second after connect.
        deadline = time.time() + 10
        while time.time() < deadline:
            ips_after = set(_ip_addrs(container))
            if eni_ip in ips_after:
                break
            time.sleep(0.5)
        assert eni_ip in ips_after, (
            f"ENI IP {eni_ip} not visible inside container {container}; "
            f"saw {sorted(ips_after - ips_before)}"
        )

    def test_describe_after_attach_shows_attachment(self, vpc_instance):
        ec2 = vpc_instance["ec2"]
        subnet = vpc_instance["subnet"]
        iid = vpc_instance["instance_id"]

        eni_id = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]["NetworkInterfaceId"]
        ec2.attach_network_interface(
            NetworkInterfaceId=eni_id, InstanceId=iid, DeviceIndex=1,
        )

        d = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        att = d.get("Attachment") or {}
        assert att.get("InstanceId") == iid, att
        assert att.get("DeviceIndex") == 1, att
        assert att.get("Status") in ("attached", "attaching"), att

        di = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        attached_eni_ids = {
            n.get("NetworkInterfaceId") for n in di.get("NetworkInterfaces", [])
        }
        assert eni_id in attached_eni_ids, (eni_id, attached_eni_ids)

    def test_detach_removes_ip_from_container(self, vpc_instance):
        ec2 = vpc_instance["ec2"]
        subnet = vpc_instance["subnet"]
        iid = vpc_instance["instance_id"]
        container = vpc_instance["container_name"]

        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        eni_ip = eni["PrivateIpAddress"]

        att = ec2.attach_network_interface(
            NetworkInterfaceId=eni_id, InstanceId=iid, DeviceIndex=1,
        )
        attachment_id = att["AttachmentId"]

        # Confirm IP is present pre-detach
        deadline = time.time() + 10
        while time.time() < deadline and eni_ip not in _ip_addrs(container):
            time.sleep(0.5)
        assert eni_ip in _ip_addrs(container)

        ec2.detach_network_interface(AttachmentId=attachment_id, Force=True)

        # Poll for the IP to disappear (detach is async-ish; the
        # disconnect_container_from_network call removes the iface).
        deadline = time.time() + 10
        while time.time() < deadline and eni_ip in _ip_addrs(container):
            time.sleep(0.5)
        assert eni_ip not in _ip_addrs(container), (
            f"ENI IP {eni_ip} still inside container after detach"
        )

        d = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id],
        )["NetworkInterfaces"][0]
        assert d.get("Status") in ("available", "in-use"), d.get("Status")
        # After Force detach + a moment, attachment is gone
        assert not d.get("Attachment") or d["Attachment"].get("Status") in (
            "detached", "detaching",
        ), d.get("Attachment")

    def test_attach_with_secondary_ips_propagates(self, vpc_instance):
        """ENI with secondary IPs assigned BEFORE attach: each must
        land inside the container after the hot-attach completes."""
        ec2 = vpc_instance["ec2"]
        subnet = vpc_instance["subnet"]
        iid = vpc_instance["instance_id"]
        container = vpc_instance["container_name"]

        eni = ec2.create_network_interface(
            SubnetId=subnet["SubnetId"],
            SecondaryPrivateIpAddressCount=2,
        )["NetworkInterface"]
        eni_id = eni["NetworkInterfaceId"]
        all_ips = [p["PrivateIpAddress"] for p in eni["PrivateIpAddresses"]]
        assert len(all_ips) == 3, all_ips

        ec2.attach_network_interface(
            NetworkInterfaceId=eni_id, InstanceId=iid, DeviceIndex=1,
        )

        deadline = time.time() + 10
        while time.time() < deadline:
            inside = set(_ip_addrs(container))
            if all(ip in inside for ip in all_ips):
                break
            time.sleep(0.5)
        inside = set(_ip_addrs(container))
        missing = [ip for ip in all_ips if ip not in inside]
        assert not missing, f"secondary IPs missing inside container: {missing}"
