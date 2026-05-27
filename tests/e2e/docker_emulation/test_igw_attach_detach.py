#!/usr/bin/env python3
"""End-to-end Internet Gateway attach / detach test (fix #81).

Proves the architectural promise with REAL network behaviour, not
just API calls:

  - Without IGW: the VPC's Docker network is ``--internal=true``. A
    curl bound to the VPC interface (``curl --interface <vpc-ip>``)
    cannot reach the host gateway. Intra-VPC traffic between two
    EC2s on the same subnet DOES work.

  - AttachInternetGateway: LocalEmu performs a live recreate of the
    Docker network without ``--internal``. Running EC2 containers
    stay up across the recreation. Now the VPC interface CAN reach
    the host gateway.

  - DetachInternetGateway: live recreate back to ``--internal``.
    Containers still up. VPC-interface path blocked again. Intra-VPC
    still works.

All of this is exercised against live LocalEmu + live Docker with
real EC2 Docker containers and the LocalEmu ``vpc_network`` manager
driving the actual network-recreate migration.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

ec2 = boto3.client("ec2", **KW)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []
state: dict = {}


def step(name: str):
    def deco(fn):
        def wrap():
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn()
                dt = time.time() - t0
                print(f"  PASS [{dt:.1f}s]", flush=True)
                PASS.append((name, dt))
            except AssertionError as e:
                dt = time.time() - t0
                print(f"  FAIL [{dt:.1f}s] {e}", flush=True)
                FAIL.append((name, str(e)))
            except Exception as e:
                dt = time.time() - t0
                print(f"  ERROR [{dt:.1f}s] {type(e).__name__}: {e}", flush=True)
                FAIL.append((name, f"{type(e).__name__}: {e}"))
        return wrap
    return deco


def dexec(container: str, *cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def docker_running(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


def wait_running(name: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if docker_running(name):
            return True
        time.sleep(2)
    return False


def network_internal_flag(network_name: str) -> bool | None:
    """Return the Internal flag of a Docker network, or None if unknown."""
    r = subprocess.run(
        ["docker", "network", "inspect", "--format", "{{.Internal}}", network_name],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return None
    return r.stdout.strip().lower() == "true"


def container_vpc_ip(container: str, network_name: str) -> str | None:
    """Return the container's IPv4 on the given Docker network, or None."""
    r = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}"
         "{{if eq $k \"" + network_name + "\"}}{{$v.IPAddress}}{{end}}{{end}}",
         container],
        capture_output=True, text=True, timeout=10,
    )
    ip = r.stdout.strip()
    return ip if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) else None


@step("01-setup-vpc-and-two-ec2s")
def setup_vpc():
    vpc = ec2.create_vpc(CidrBlock="10.210.0.0/16")["Vpc"]["VpcId"]
    state["vpc"] = vpc
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.210.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    state["subnet"] = sub
    state["key"] = f"igw-{TAG}"
    ec2.create_key_pair(KeyName=state["key"])
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sub, KeyName=state["key"],
    )
    state["i1"] = r["Instances"][0]["InstanceId"]
    state["c1"] = f"localemu-ec2-{state['i1']}"
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sub, KeyName=state["key"],
    )
    state["i2"] = r["Instances"][0]["InstanceId"]
    state["c2"] = f"localemu-ec2-{state['i2']}"
    assert wait_running(state["c1"], timeout=60)
    assert wait_running(state["c2"], timeout=60)
    state["vpc_network"] = f"localemu-vpc-{state['vpc']}"


@step("02-baseline-vpc-network-is-internal")
def baseline_internal():
    flag = network_internal_flag(state["vpc_network"])
    assert flag is True, f"VPC network {state['vpc_network']} must be internal, got {flag}"


@step("03-baseline-intra-vpc-ping-works")
def intra_vpc_ping():
    ip2 = container_vpc_ip(state["c2"], state["vpc_network"])
    assert ip2, f"EC2 #2 has no VPC IP on {state['vpc_network']}"
    state["i2_vpc_ip"] = ip2
    r = dexec(state["c1"], "ping", "-c", "2", "-W", "2", ip2, timeout=10)
    assert r.returncode == 0, f"intra-VPC ping failed: {r.stdout!r} {r.stderr!r}"


@step("04-baseline-vpc-iface-cannot-reach-host")
def vpc_iface_blocked_baseline():
    ip1 = container_vpc_ip(state["c1"], state["vpc_network"])
    assert ip1, f"EC2 #1 has no VPC IP on {state['vpc_network']}"
    state["i1_vpc_ip_before"] = ip1
    # curl binds the source IP to the VPC interface. The VPC network
    # is --internal=true at this point, so the packet cannot leave.
    r = dexec(
        state["c1"], "sh", "-c",
        f"curl -sf -o /dev/null -w '%{{http_code}}' "
        f"--interface {ip1} --max-time 5 --connect-timeout 3 "
        f"http://host.docker.internal:4566/_localemu/health || echo BLOCKED:$?",
    )
    assert "BLOCKED" in r.stdout, \
        f"VPC interface must not reach host without IGW, got: {r.stdout!r}"


@step("05-create-and-attach-internet-gateway")
def attach_igw():
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    state["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=state["vpc"])
    # Let the Docker network recreation settle.
    time.sleep(3)


@step("06-network-now-non-internal-post-recreate")
def network_non_internal():
    deadline = time.time() + 15
    flag = None
    while time.time() < deadline:
        flag = network_internal_flag(state["vpc_network"])
        if flag is False:
            break
        time.sleep(1)
    assert flag is False, \
        f"VPC network must be non-internal after IGW attach, got {flag}"


@step("07-both-ec2s-still-running-after-network-recreate")
def containers_survived_attach():
    assert docker_running(state["c1"]), f"{state['c1']} stopped during IGW attach"
    assert docker_running(state["c2"]), f"{state['c2']} stopped during IGW attach"


@step("08-intra-vpc-ping-still-works-after-recreate")
def intra_vpc_post_attach():
    # IPs may have changed after network recreate — re-resolve.
    ip2 = container_vpc_ip(state["c2"], state["vpc_network"])
    assert ip2, "EC2 #2 has no VPC IP after recreate"
    r = dexec(state["c1"], "ping", "-c", "2", "-W", "2", ip2, timeout=10)
    assert r.returncode == 0, f"intra-VPC ping failed post-attach: {r.stderr!r}"


@step("09-vpc-iface-can-now-reach-host")
def vpc_iface_reaches_host():
    ip1 = container_vpc_ip(state["c1"], state["vpc_network"])
    assert ip1, "EC2 #1 has no VPC IP after recreate"
    state["i1_vpc_ip_after"] = ip1
    r = dexec(
        state["c1"], "sh", "-c",
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f"--interface {ip1} --max-time 5 --connect-timeout 3 "
        f"http://host.docker.internal:4566/_localemu/health",
    )
    assert r.stdout.strip() == "200", \
        f"VPC interface should reach host after IGW attach, got: {r.stdout!r}"


@step("10-detach-internet-gateway")
def detach_igw():
    ec2.detach_internet_gateway(
        InternetGatewayId=state["igw"], VpcId=state["vpc"],
    )
    time.sleep(3)


@step("11-network-internal-again-post-detach")
def network_internal_again():
    deadline = time.time() + 15
    flag = None
    while time.time() < deadline:
        flag = network_internal_flag(state["vpc_network"])
        if flag is True:
            break
        time.sleep(1)
    assert flag is True, \
        f"VPC network must be internal after IGW detach, got {flag}"


@step("12-both-ec2s-still-running-after-detach-recreate")
def containers_survived_detach():
    assert docker_running(state["c1"]), f"{state['c1']} stopped during IGW detach"
    assert docker_running(state["c2"]), f"{state['c2']} stopped during IGW detach"


@step("13-vpc-iface-blocked-again-after-detach")
def vpc_iface_blocked_again():
    ip1 = container_vpc_ip(state["c1"], state["vpc_network"])
    assert ip1, "EC2 #1 has no VPC IP after second recreate"
    r = dexec(
        state["c1"], "sh", "-c",
        f"curl -sf -o /dev/null -w '%{{http_code}}' "
        f"--interface {ip1} --max-time 5 --connect-timeout 3 "
        f"http://host.docker.internal:4566/_localemu/health || echo BLOCKED:$?",
    )
    assert "BLOCKED" in r.stdout, \
        f"VPC interface must be blocked again after detach, got: {r.stdout!r}"


@step("14-intra-vpc-ping-still-works-after-detach")
def intra_vpc_post_detach():
    ip2 = container_vpc_ip(state["c2"], state["vpc_network"])
    assert ip2, "EC2 #2 has no VPC IP after detach recreate"
    r = dexec(state["c1"], "ping", "-c", "2", "-W", "2", ip2, timeout=10)
    assert r.returncode == 0, \
        f"intra-VPC ping broken post-detach: {r.stderr!r}"


def cleanup():
    print("\n=== CLEANUP ===")
    if state.get("igw") and state.get("vpc"):
        try:
            ec2.detach_internet_gateway(
                InternetGatewayId=state["igw"], VpcId=state["vpc"],
            )
        except Exception:
            pass
        try:
            ec2.delete_internet_gateway(InternetGatewayId=state["igw"])
        except Exception:
            pass
    for ikey in ("i1", "i2"):
        iid = state.get(ikey)
        if iid:
            try:
                ec2.terminate_instances(InstanceIds=[iid])
            except Exception:
                pass
    time.sleep(2)
    if state.get("subnet"):
        try:
            ec2.delete_subnet(SubnetId=state["subnet"])
        except Exception:
            pass
    if state.get("vpc"):
        try:
            ec2.delete_vpc(VpcId=state["vpc"])
        except Exception:
            pass
    if state.get("key"):
        try:
            ec2.delete_key_pair(KeyName=state["key"])
        except Exception:
            pass


def main() -> int:
    steps = [
        setup_vpc,
        baseline_internal,
        intra_vpc_ping,
        vpc_iface_blocked_baseline,
        attach_igw,
        network_non_internal,
        containers_survived_attach,
        intra_vpc_post_attach,
        vpc_iface_reaches_host,
        detach_igw,
        network_internal_again,
        containers_survived_detach,
        vpc_iface_blocked_again,
        intra_vpc_post_detach,
    ]
    for s in steps:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS:
        print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL:
        print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
