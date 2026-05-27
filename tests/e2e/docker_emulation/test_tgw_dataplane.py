#!/usr/bin/env python3
"""E2E — Transit Gateway data plane (T1).

Proves LocalEmu now routes cross-VPC traffic via real VPC IPs through
a per-TGW router container.
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
state: dict = {"instances": []}


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


def wait_running(iid: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = ec2.describe_instances(InstanceIds=[iid])
        if r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running":
            return True
        time.sleep(1)
    return False


def ssm_run(iid: str, cmd: str, timeout: int = 30) -> tuple[int, str]:
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[iid], Parameters={"commands": [cmd]},
    )
    cid = r["Command"]["CommandId"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except Exception:
            time.sleep(1); continue
        if inv.get("Status") in ("Success", "Failed", "TimedOut", "Cancelled"):
            return (int(inv.get("ResponseCode", -1)),
                    (inv.get("StandardOutputContent") or ""))
        time.sleep(1)
    return -1, ""


@step("01-create-tgw-creates-shared-bridge")
def create_tgw():
    r = ec2.create_transit_gateway(
        Description=f"tgw-test-{TAG}",
        Options={
            "AmazonSideAsn": 64512,
            "AutoAcceptSharedAttachments": "enable",
            "DefaultRouteTableAssociation": "enable",
            "DefaultRouteTablePropagation": "enable",
        },
    )
    tgw_id = r["TransitGateway"]["TransitGatewayId"]
    state["tgw_id"] = tgw_id
    net_name = f"localemu-tgw-{tgw_id}"
    state["tgw_net"] = net_name
    # Give Docker a beat to commit the bridge.
    deadline = time.time() + 15
    while time.time() < deadline:
        out = subprocess.run(
            ["docker", "network", "inspect", net_name],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return
        time.sleep(1)
    raise AssertionError(f"TGW bridge {net_name} was not created")


@step("02-attach-two-vpcs-via-TGW")
def attach_two_vpcs():
    # VPC A (10.130.0.0/16), VPC B (10.131.0.0/16)
    va = ec2.create_vpc(CidrBlock="10.130.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.131.0.0/16")["Vpc"]["VpcId"]
    sa = ec2.create_subnet(VpcId=va, CidrBlock="10.130.1.0/24",
                           AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    sb = ec2.create_subnet(VpcId=vb, CidrBlock="10.131.1.0/24",
                           AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    state.update(dict(va=va, vb=vb, sa=sa, sb=sb))
    # Launch one EC2 per VPC FIRST so the VPC's Docker network exists
    # and ``VpcNetworkManager._vpcs[vpc_id]`` is populated before
    # ``create_vpc_attachment`` tries to reserve the ``.254``.
    key = f"tgw-test-{TAG}"
    ec2.create_key_pair(KeyName=key); state["key"] = key
    ia = ec2.run_instances(ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
                           MinCount=1, MaxCount=1, SubnetId=sa,
                           KeyName=key)["Instances"][0]["InstanceId"]
    ib = ec2.run_instances(ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
                           MinCount=1, MaxCount=1, SubnetId=sb,
                           KeyName=key)["Instances"][0]["InstanceId"]
    state["ia"] = ia; state["ib"] = ib
    state["instances"].extend([ia, ib])
    assert wait_running(ia); assert wait_running(ib)
    # Attachments
    atta = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=state["tgw_id"], VpcId=va, SubnetIds=[sa],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    attb = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=state["tgw_id"], VpcId=vb, SubnetIds=[sb],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    state["atta"] = atta; state["attb"] = attb
    # Give data-plane a beat.
    time.sleep(2)


@step("03-ping-A-to-B-via-VPC-IP-through-TGW")
def ping_a_to_b():
    ip_b = ec2.describe_instances(InstanceIds=[state["ib"]])[
        "Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    state["ip_b"] = ip_b
    rc, out = ssm_run(
        state["ia"],
        f"ping -c 3 -W 2 {ip_b} >/tmp/p.out 2>&1; echo RC=$?",
    )
    print(out)
    assert "RC=0" in out, f"A→B ping via VPC IP failed: {out!r}"


@step("04-ping-B-to-A-via-VPC-IP-through-TGW")
def ping_b_to_a():
    ip_a = ec2.describe_instances(InstanceIds=[state["ia"]])[
        "Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    state["ip_a"] = ip_a
    rc, out = ssm_run(
        state["ib"],
        f"ping -c 3 -W 2 {ip_a} >/tmp/p.out 2>&1; echo RC=$?",
    )
    print(out)
    assert "RC=0" in out, f"B→A ping via VPC IP failed: {out!r}"


@step("05-late-join-EC2-reaches-peer-via-TGW")
def late_join():
    # Launch an extra EC2 in VPC A AFTER TGW attachments exist.
    ia2 = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=state["sa"], KeyName=state["key"],
    )["Instances"][0]["InstanceId"]
    state["ia2"] = ia2
    state["instances"].append(ia2)
    assert wait_running(ia2)
    rc, out = ssm_run(
        ia2, f"ping -c 3 -W 2 {state['ip_b']} >/tmp/p.out 2>&1; echo RC=$?",
    )
    assert "RC=0" in out, f"late-join A2→B via TGW failed: {out!r}"


@step("06-detach-removes-reachability")
def detach_breaks():
    ec2.delete_transit_gateway_vpc_attachment(
        TransitGatewayAttachmentId=state["attb"],
    )
    time.sleep(2)
    rc, out = ssm_run(
        state["ia"], f"ping -c 2 -W 2 {state['ip_b']} >/tmp/p.out 2>&1; echo RC=$?",
    )
    assert "RC=0" not in out, \
        f"after detach, A still reaches B: {out!r}"


def cleanup():
    print("\n=== CLEANUP ===")
    for att in ("atta", "attb"):
        aid = state.get(att)
        if aid:
            try: ec2.delete_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=aid)
            except Exception: pass
    if state.get("tgw_id"):
        try: ec2.delete_transit_gateway(TransitGatewayId=state["tgw_id"])
        except Exception: pass
    for iid in state.get("instances", []):
        try: ec2.terminate_instances(InstanceIds=[iid])
        except Exception: pass
    time.sleep(2)
    for s in (state.get("sa"), state.get("sb")):
        if s:
            try: ec2.delete_subnet(SubnetId=s)
            except Exception: pass
    for v in (state.get("va"), state.get("vb")):
        if v:
            try: ec2.delete_vpc(VpcId=v)
            except Exception: pass
    if state.get("key"):
        try: ec2.delete_key_pair(KeyName=state["key"])
        except Exception: pass


def main() -> int:
    for s in [create_tgw, attach_two_vpcs, ping_a_to_b, ping_b_to_a,
              late_join, detach_breaks]:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:300]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
