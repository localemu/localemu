#!/usr/bin/env python3
"""E2E — VPC peering routes via real VPC IPs (P1).

Proves that after ``AcceptVpcPeeringConnection`` cross-VPC traffic
flows using each side's own VPC IP (e.g. ``10.81.0.3``), not the
Docker-bridge artefact IP. Uses ``aws ssm send-command`` to run the
ping/curl from inside the instances — no ``docker exec`` in the
verification path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=60)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

ec2 = boto3.client("ec2", **KW)
ssm = boto3.client("ssm", **KW)

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


def wait_running(instance_id: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = ec2.describe_instances(InstanceIds=[instance_id])
        st = r["Reservations"][0]["Instances"][0]["State"]["Name"]
        if st == "running":
            return True
        time.sleep(1)
    return False


def ssm_run(instance_id: str, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """Run ``cmd`` on ``instance_id`` via aws ssm send-command.

    Returns (response_code, stdout, stderr). response_code is the
    exit code of the shell command; 0 on success.
    """
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[instance_id],
        Parameters={"commands": [cmd]},
    )
    command_id = r["Command"]["CommandId"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            inv = ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id,
            )
        except Exception:
            time.sleep(1); continue
        if inv.get("Status") in ("Success", "Failed", "TimedOut", "Cancelled"):
            return (
                int(inv.get("ResponseCode", -1)),
                inv.get("StandardOutputContent", "") or "",
                inv.get("StandardErrorContent", "") or "",
            )
        time.sleep(1)
    return -1, "", "ssm timeout"


@step("01-create-2-vpcs-and-peer-them")
def create_pair():
    vA = ec2.create_vpc(CidrBlock="10.80.0.0/16")["Vpc"]["VpcId"]
    vB = ec2.create_vpc(CidrBlock="10.81.0.0/16")["Vpc"]["VpcId"]
    sA = ec2.create_subnet(
        VpcId=vA, CidrBlock="10.80.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    sB = ec2.create_subnet(
        VpcId=vB, CidrBlock="10.81.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    pcx = ec2.create_vpc_peering_connection(
        VpcId=vA, PeerVpcId=vB,
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    r = ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    assert r["VpcPeeringConnection"]["Status"]["Code"] == "active"
    state.update(dict(vA=vA, vB=vB, sA=sA, sB=sB, pcx=pcx))


@step("02-launch-one-ec2-per-vpc")
def launch_ec2s():
    key = f"peer-rt-{TAG}"
    ec2.create_key_pair(KeyName=key)
    state["key"] = key
    rA = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro", MinCount=1,
        MaxCount=1, SubnetId=state["sA"], KeyName=key,
    )["Instances"][0]
    rB = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro", MinCount=1,
        MaxCount=1, SubnetId=state["sB"], KeyName=key,
    )["Instances"][0]
    state["iA"] = rA["InstanceId"]
    state["iB"] = rB["InstanceId"]
    assert wait_running(state["iA"])
    assert wait_running(state["iB"])
    # Re-describe to pick up the private IPs assigned by the VPC Docker net.
    dA = ec2.describe_instances(InstanceIds=[state["iA"]])["Reservations"][0]["Instances"][0]
    dB = ec2.describe_instances(InstanceIds=[state["iB"]])["Reservations"][0]["Instances"][0]
    state["ipA"] = dA["PrivateIpAddress"]
    state["ipB"] = dB["PrivateIpAddress"]
    print(f"  A private IP: {state['ipA']}  /  B private IP: {state['ipB']}")
    assert state["ipA"].startswith("10.80."), f"A VPC IP unexpected: {state['ipA']}"
    assert state["ipB"].startswith("10.81."), f"B VPC IP unexpected: {state['ipB']}"


@step("03-ping-A-to-B-via-real-VPC-IP")
def ping_a_to_b():
    rc, out, err = ssm_run(
        state["iA"],
        f"ping -c 3 -W 2 {state['ipB']} >/tmp/p.out 2>&1; echo RC=$?; cat /tmp/p.out",
    )
    print(out)
    assert rc == 0, f"ssm exit={rc}, stderr={err!r}"
    assert "RC=0" in out, f"ping to {state['ipB']} failed: {out!r}"


@step("04-ping-B-to-A-via-real-VPC-IP")
def ping_b_to_a():
    rc, out, err = ssm_run(
        state["iB"],
        f"ping -c 3 -W 2 {state['ipA']} >/tmp/p.out 2>&1; echo RC=$?; cat /tmp/p.out",
    )
    print(out)
    assert rc == 0
    assert "RC=0" in out, f"ping to {state['ipA']} failed: {out!r}"


@step("05-tcp-connectivity-via-VPC-IP")
def tcp_ab():
    # Start a tiny http listener on B using python3 -m http.server.
    ssm_run(
        state["iB"],
        "mkdir -p /srv/peer && echo hello-from-B > /srv/peer/probe.txt "
        "&& (pkill -f 'http.server 18080' 2>/dev/null; true) "
        "&& nohup sh -c 'cd /srv/peer && python3 -m http.server 18080' "
        "> /var/log/peer.log 2>&1 &",
    )
    time.sleep(2)
    rc, out, err = ssm_run(
        state["iA"],
        f"curl -sf --max-time 4 http://{state['ipB']}:18080/probe.txt || echo FAIL",
    )
    print(out)
    assert "hello-from-B" in out, f"TCP probe failed: rc={rc} out={out!r}"


@step("06-late-join-new-ec2-reaches-peer")
def late_join():
    # Launch a 2nd EC2 in A AFTER the peering is already active —
    # verifies the register_container late-join programmer works.
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=state["sA"], KeyName=state["key"],
    )["Instances"][0]
    iA2 = r["InstanceId"]
    state["iA2"] = iA2
    assert wait_running(iA2)
    rc, out, _ = ssm_run(
        iA2,
        f"ping -c 3 -W 2 {state['ipB']} >/tmp/p.out 2>&1; echo RC=$?",
    )
    assert "RC=0" in out, f"late-join A2 can't reach B: {out!r}"


@step("07-non-transitive-peering-holds")
def non_transitive():
    # Add VPC C peered with A only. B must NOT be able to reach C's VPC IP.
    vC = ec2.create_vpc(CidrBlock="10.82.0.0/16")["Vpc"]["VpcId"]
    sC = ec2.create_subnet(
        VpcId=vC, CidrBlock="10.82.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    pcx2 = ec2.create_vpc_peering_connection(
        VpcId=state["vA"], PeerVpcId=vC,
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx2)
    rC = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sC, KeyName=state["key"],
    )["Instances"][0]
    iC = rC["InstanceId"]
    state.update(dict(vC=vC, sC=sC, pcx2=pcx2, iC=iC))
    assert wait_running(iC)
    ipC = ec2.describe_instances(InstanceIds=[iC])["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    state["ipC"] = ipC
    rc, out, _ = ssm_run(
        state["iB"],
        f"ping -c 2 -W 2 {ipC} >/tmp/p.out 2>&1; echo RC=$?",
    )
    assert "RC=0" not in out, (
        f"B must NOT reach C's VPC IP {ipC} (non-transitive); got: {out!r}"
    )


@step("08-delete-peering-breaks-reachability")
def delete_breaks():
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=state["pcx"])
    time.sleep(2)
    rc, out, _ = ssm_run(
        state["iA"],
        f"ping -c 2 -W 2 {state['ipB']} >/tmp/p.out 2>&1; echo RC=$?",
    )
    assert "RC=0" not in out, \
        f"after delete, A still reaches B: {out!r}"


def cleanup():
    print("\n=== CLEANUP ===")
    for iid in (state.get("iA"), state.get("iA2"), state.get("iB"), state.get("iC")):
        if iid:
            try: ec2.terminate_instances(InstanceIds=[iid])
            except Exception: pass
    time.sleep(2)
    for p in (state.get("pcx"), state.get("pcx2")):
        if p:
            try: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=p)
            except Exception: pass
    for s in (state.get("sA"), state.get("sB"), state.get("sC")):
        if s:
            try: ec2.delete_subnet(SubnetId=s)
            except Exception: pass
    for v in (state.get("vA"), state.get("vB"), state.get("vC")):
        if v:
            try: ec2.delete_vpc(VpcId=v)
            except Exception: pass
    if state.get("key"):
        try: ec2.delete_key_pair(KeyName=state["key"])
        except Exception: pass


def main() -> int:
    steps = [
        create_pair, launch_ec2s, ping_a_to_b, ping_b_to_a,
        tcp_ab, late_join, non_transitive, delete_breaks,
    ]
    for s in steps:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
