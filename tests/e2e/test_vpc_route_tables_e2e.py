"""End-to-end tests for VPC route-table data plane.

These tests run against a live LocalEmu + Docker. The decisive
evidence is the direct ``ip route`` table dump inside each container:

* After ``CreateRoute`` to an instance target, every OTHER container
  in the subnet has the route installed via ``ip route``.
* The router instance itself does NOT receive a self-loop route.
* ``DeleteRoute`` cleans the route out of every container.
* A newly-launched instance picks up routes that were configured
  BEFORE it joined the subnet.
* The route survives ``docker restart`` via the marker file.
"""
from __future__ import annotations

import shutil
import subprocess
import time
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host; VPC route-table E2E cannot run",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_running(cname: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", cname],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip() == "true":
            return
        time.sleep(0.5)
    raise AssertionError(f"container {cname} did not reach Running within {timeout}s")


def _ip_routes(cname: str) -> str:
    """``ip route show`` inside the container - the decisive evidence."""
    r = subprocess.run(
        ["docker", "exec", cname, "ip", "route"],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout or ""


def _has_marker_line(cname: str, dest: str) -> bool:
    r = subprocess.run(
        ["docker", "exec", cname, "cat", "/var/lib/localemu/instance-routes.txt"],
        capture_output=True, text=True, timeout=10,
    )
    return any(line.split() and line.split()[0] == dest for line in (r.stdout or "").splitlines())


def _make_vpc_subnet_rt(ec2):
    vpc = ec2.create_vpc(CidrBlock="10.240.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.240.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    assoc = ec2.associate_route_table(SubnetId=sub, RouteTableId=rt)["AssociationId"]
    return vpc, sub, rt, assoc


def _cleanup_vpc(ec2, vpc, sub, rt, assoc):
    for fn in (
        lambda: ec2.disassociate_route_table(AssociationId=assoc),
        lambda: ec2.delete_route_table(RouteTableId=rt),
        lambda: ec2.delete_subnet(SubnetId=sub),
        lambda: ec2.delete_vpc(VpcId=vpc),
    ):
        try:
            fn()
        except Exception:
            pass


def _run_instance(ec2, sub):
    iid = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sub,
    )["Instances"][0]["InstanceId"]
    cname = f"localemu-ec2-{iid}"
    _wait_running(cname)
    return iid, cname


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_route_to_instance_target_installs_route_in_other_containers(ec2_client):
    """The reproduction: Quiet Router data plane.

    Two instances in the same subnet: ``victim`` and ``router``.
    ``CreateRoute --instance-id router --destination 10.99.0.0/16``
    must install ``ip route ... via <router's private IP>`` inside
    the victim's container.
    """
    vpc, sub, rt, assoc = _make_vpc_subnet_rt(ec2_client)
    try:
        v_iid, v_cname = _run_instance(ec2_client, sub)
        r_iid, r_cname = _run_instance(ec2_client, sub)
        try:
            router_desc = ec2_client.describe_instances(
                InstanceIds=[r_iid],
            )["Reservations"][0]["Instances"][0]
            router_ip = router_desc["PrivateIpAddress"]

            ec2_client.create_route(
                RouteTableId=rt,
                DestinationCidrBlock="10.99.0.0/16",
                InstanceId=r_iid,
            )
            time.sleep(2)

            victim_routes = _ip_routes(v_cname)
            assert f"10.99.0.0/16 via {router_ip}" in victim_routes, (
                f"CreateRoute to {r_iid} did not install ip route in {v_iid}'s "
                f"container.\n``ip route`` dump:\n{victim_routes}"
            )
            assert _has_marker_line(v_cname, "10.99.0.0/16"), (
                "marker file must capture the route so it survives restart"
            )
            # Router itself must not have a self-loop route.
            router_routes = _ip_routes(r_cname)
            assert f"10.99.0.0/16 via {router_ip}" not in router_routes, (
                "router instance must NOT receive a self-loop route"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[v_iid, r_iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub, rt, assoc)


def test_delete_route_removes_from_all_containers(ec2_client):
    vpc, sub, rt, assoc = _make_vpc_subnet_rt(ec2_client)
    try:
        v_iid, v_cname = _run_instance(ec2_client, sub)
        r_iid, r_cname = _run_instance(ec2_client, sub)
        try:
            ec2_client.create_route(
                RouteTableId=rt,
                DestinationCidrBlock="10.98.0.0/16",
                InstanceId=r_iid,
            )
            time.sleep(2)
            assert "10.98.0.0/16" in _ip_routes(v_cname)

            ec2_client.delete_route(
                RouteTableId=rt,
                DestinationCidrBlock="10.98.0.0/16",
            )
            time.sleep(2)
            assert "10.98.0.0/16" not in _ip_routes(v_cname), (
                "DeleteRoute must remove the ip route entry from every "
                "container in the subnet"
            )
            assert not _has_marker_line(v_cname, "10.98.0.0/16"), (
                "marker file must drop the deleted route"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[v_iid, r_iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub, rt, assoc)


def test_route_survives_container_restart(ec2_client):
    """``docker restart`` must replay the marker file at boot."""
    vpc, sub, rt, assoc = _make_vpc_subnet_rt(ec2_client)
    try:
        v_iid, v_cname = _run_instance(ec2_client, sub)
        r_iid, _r_cname = _run_instance(ec2_client, sub)
        try:
            ec2_client.create_route(
                RouteTableId=rt,
                DestinationCidrBlock="10.97.0.0/16",
                InstanceId=r_iid,
            )
            time.sleep(2)
            assert "10.97.0.0/16" in _ip_routes(v_cname)

            subprocess.run(["docker", "restart", v_cname], check=True, timeout=30)
            _wait_running(v_cname)
            time.sleep(2)
            assert "10.97.0.0/16" in _ip_routes(v_cname), (
                "route did not survive ``docker restart`` - marker file "
                "replay block in the entrypoint is broken"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[v_iid, r_iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub, rt, assoc)


def test_newly_launched_instance_picks_up_existing_routes(ec2_client):
    """A route configured BEFORE an instance joins the subnet must
    still apply to that instance after it launches."""
    vpc, sub, rt, assoc = _make_vpc_subnet_rt(ec2_client)
    try:
        # Step 1: only the router exists; configure the route.
        r_iid, _r_cname = _run_instance(ec2_client, sub)
        ec2_client.create_route(
            RouteTableId=rt,
            DestinationCidrBlock="10.96.0.0/16",
            InstanceId=r_iid,
        )
        # Step 2: now launch the victim - it must inherit the route.
        v_iid, v_cname = _run_instance(ec2_client, sub)
        try:
            time.sleep(2)
            assert "10.96.0.0/16" in _ip_routes(v_cname), (
                "newly-launched instance did not pick up the existing "
                "instance-target route - RunInstances -> on_instance_launch "
                "hook is broken"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[v_iid, r_iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub, rt, assoc)
