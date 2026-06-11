"""End-to-end tests for VPC DHCP DNS forwarding (PR-006 subsystem A).

Each test exercises the full chain:
  1. Create VPC + subnet.
  2. Build a DHCP options set with a chosen ``domain-name-servers``.
  3. Associate it with the VPC.
  4. ``RunInstances`` into the subnet.
  5. ``docker exec`` into the container and assert
     ``/etc/resolv.conf`` advertises the chosen DNS servers.

Skips cleanly on hosts without Docker.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host; VPC DHCP DNS E2E cannot run",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_container_running(cname: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", cname],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip() == "true":
            return
        time.sleep(0.5)
    raise AssertionError(
        f"container {cname} did not reach Running within {timeout}s"
    )


def _run_instance(ec2, *, subnet_id: str) -> tuple[str, str]:
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=subnet_id,
    )
    iid = r["Instances"][0]["InstanceId"]
    cname = f"localemu-ec2-{iid}"
    _wait_container_running(cname)
    return iid, cname


def _terminate(ec2, iid: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except Exception:
        pass


def _resolv_conf(cname: str) -> str:
    r = subprocess.run(
        ["docker", "exec", cname, "cat", "/etc/resolv.conf"],
        capture_output=True, text=True, timeout=15,
    )
    return r.stdout


def _build_vpc_with_dhcp(
    ec2_client, *, domain_name_servers: list[str],
) -> tuple[str, str, str]:
    """Returns (vpc_id, subnet_id, dhcp_options_id)."""
    vpc_id = ec2_client.create_vpc(CidrBlock="10.234.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.234.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    dhcp_options_id = ec2_client.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name-servers", "Values": domain_name_servers},
        ],
    )["DhcpOptions"]["DhcpOptionsId"]
    ec2_client.associate_dhcp_options(
        DhcpOptionsId=dhcp_options_id, VpcId=vpc_id,
    )
    return vpc_id, subnet_id, dhcp_options_id


def _cleanup_vpc(ec2_client, vpc_id: str, subnet_id: str,
                 dhcp_options_id: str) -> None:
    for fn in (
        lambda: ec2_client.associate_dhcp_options(
            DhcpOptionsId="default", VpcId=vpc_id,
        ),
        lambda: ec2_client.delete_dhcp_options(DhcpOptionsId=dhcp_options_id),
        lambda: ec2_client.delete_subnet(SubnetId=subnet_id),
        lambda: ec2_client.delete_vpc(VpcId=vpc_id),
    ):
        try:
            fn()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_instance_resolv_conf_advertises_dhcp_dns_server(ec2_client):
    """Single custom DNS → /etc/resolv.conf carries it."""
    vpc, subnet, dopt = _build_vpc_with_dhcp(
        ec2_client, domain_name_servers=["6.6.6.6"],
    )
    try:
        iid, cname = _run_instance(ec2_client, subnet_id=subnet)
        try:
            resolv = _resolv_conf(cname)
            assert "6.6.6.6" in resolv, (
                f"/etc/resolv.conf did not pick up the DHCP DNS:\n{resolv}"
            )
        finally:
            _terminate(ec2_client, iid)
    finally:
        _cleanup_vpc(ec2_client, vpc, subnet, dopt)


def test_instance_resolv_conf_carries_multiple_dns_servers(ec2_client):
    vpc, subnet, dopt = _build_vpc_with_dhcp(
        ec2_client,
        domain_name_servers=["10.10.10.10", "8.8.8.8", "1.1.1.1"],
    )
    try:
        iid, cname = _run_instance(ec2_client, subnet_id=subnet)
        try:
            resolv = _resolv_conf(cname)
            for srv in ("10.10.10.10", "8.8.8.8", "1.1.1.1"):
                assert srv in resolv, (
                    f"DHCP DNS {srv!r} missing from /etc/resolv.conf:\n{resolv}"
                )
        finally:
            _terminate(ec2_client, iid)
    finally:
        _cleanup_vpc(ec2_client, vpc, subnet, dopt)


def test_no_dhcp_options_leaves_docker_default_dns(ec2_client):
    """When the VPC has no associated DHCP options, the instance keeps
    Docker's default DNS — the regression guard."""
    vpc_id = ec2_client.create_vpc(CidrBlock="10.235.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.235.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    try:
        iid, cname = _run_instance(ec2_client, subnet_id=subnet_id)
        try:
            resolv = _resolv_conf(cname)
            # Should NOT contain the hijack value used in other tests.
            assert "6.6.6.6" not in resolv
            # And it must contain SOMETHING valid (Docker's default DNS).
            assert "nameserver" in resolv.lower()
        finally:
            _terminate(ec2_client, iid)
    finally:
        try:
            ec2_client.delete_subnet(SubnetId=subnet_id)
        except Exception:
            pass
        try:
            ec2_client.delete_vpc(VpcId=vpc_id)
        except Exception:
            pass


def test_vpc_dns_hijack_scenario_end_to_end(ec2_client):
    """PR-006 E3 reproduction: attacker sets DHCP DNS, every new
    instance launched in the VPC resolves through the malicious DNS."""
    attacker_dns = "6.6.6.6"
    vpc, subnet, dopt = _build_vpc_with_dhcp(
        ec2_client, domain_name_servers=[attacker_dns],
    )
    try:
        iid, cname = _run_instance(ec2_client, subnet_id=subnet)
        try:
            resolv = _resolv_conf(cname)
            assert attacker_dns in resolv, (
                "DNS hijack scenario E3 still blocked: instance launched "
                f"into a VPC with malicious DHCP DNS does not use it.\n"
                f"resolv.conf:\n{resolv}"
            )
        finally:
            _terminate(ec2_client, iid)
    finally:
        _cleanup_vpc(ec2_client, vpc, subnet, dopt)
