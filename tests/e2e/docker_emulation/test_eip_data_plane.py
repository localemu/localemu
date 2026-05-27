#!/usr/bin/env python3
"""End-to-end test for the EIP data plane (v2: host-side asyncio proxy).

User flow this validates (the foundation gap that triggered all the
addressing / ENI / Aurora work): a user running ANY TCP service on
ANY port inside a LocalEmu EC2 container can reach it from their host
machine through the allocated EIP, with **per-CIDR SG enforcement**
against the real source IP.

Validates:

  1. ``0.0.0.0/0`` rule on :80 -> host port opens, curl returns body
  2. ``203.0.113.0/24`` rule on :8080 -> no host port (caller is
     127.0.0.1, not in 203.0.113.0/24) -> proves per-CIDR DENY works
  3. ``127.0.0.0/8`` rule on :12345 -> host port opens, curl returns
     body -> proves per-CIDR ALLOW works AND that ANY port works
  4. Revoke :80 rule -> host port disappears within seconds
  5. Re-authorize :80 -> host port reappears + curl works again

The v2 architecture is the only way (1)-(3) can all be true at once:
the LocalEmu process accepts the TCP connection itself and reads the
real caller IP from the socket peer, then evaluates the SG before
tunneling into the container's netns via ``docker exec ... socat``.

Requires LocalEmu running with the EC2 Docker backend.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid

import boto3
from botocore.config import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 0})
KW = dict(
    endpoint_url=ENDPOINT, region_name=REGION,
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    config=CFG,
)
ec2 = boto3.client("ec2", **KW)


PASS: list[str] = []
FAIL: list[tuple[str, str]] = []


def step(name: str):
    def deco(fn):
        def wrap(*a, **kw):
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn(*a, **kw)
                print(f"  PASS [{time.time()-t0:.1f}s]", flush=True)
                PASS.append(name)
            except AssertionError as e:
                print(f"  FAIL [{time.time()-t0:.1f}s] {e}", flush=True)
                FAIL.append((name, str(e)))
            except Exception as e:
                print(
                    f"  ERROR [{time.time()-t0:.1f}s] {type(e).__name__}: {e}",
                    flush=True,
                )
                FAIL.append((name, f"{type(e).__name__}: {e}"))
        return wrap
    return deco


def docker(*args, timeout=15) -> tuple[int, str, str]:
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def host_port_for(eip: str, container_port: int) -> int | None:
    desc = ec2.describe_addresses(PublicIps=[eip])["Addresses"][0]
    for t in desc.get("Tags") or []:
        if t["Key"] == f"localemu:HostPort:{container_port}":
            return int(t["Value"].split(":")[-1])
    return None


def wait_for_host_port(eip: str, container_port: int, timeout: int = 20) -> int | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        hp = host_port_for(eip, container_port)
        if hp:
            return hp
        time.sleep(1)
    return None


def wait_for_host_port_gone(eip: str, container_port: int, timeout: int = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if host_port_for(eip, container_port) is None:
            return True
        time.sleep(1)
    return False


def curl(host_port: int) -> tuple[int, str]:
    r = subprocess.run(
        ["curl", "-sS", "-m", "5", "-w", "\n__rc__%{http_code}",
         f"http://127.0.0.1:{host_port}/"],
        capture_output=True, text=True,
    )
    body = (r.stdout or "").rsplit("\n__rc__", 1)
    return r.returncode, body[0]


STATE: dict = {}


@step("setup: sg with three per-CIDR rules, instance, three http servers")
def setup():
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}],
    )["Vpcs"]
    STATE["vpc_id"] = vpcs[0]["VpcId"]
    STATE["sg_id"] = ec2.create_security_group(
        GroupName=f"eip-{TAG}", Description="eip e2e", VpcId=STATE["vpc_id"],
    )["GroupId"]
    # Three distinct CIDRs on three distinct ports. Mac is 127.0.0.1.
    #   :80    open to the world         -> ALLOW (catches 127.0.0.1)
    #   :8080  open only to a remote /24 -> DENY  (127.0.0.1 not in /24)
    #   :12345 open only to loopback /8  -> ALLOW (127.0.0.1 in /8)
    ec2.authorize_security_group_ingress(
        GroupId=STATE["sg_id"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
             "IpRanges": [{"CidrIp": "203.0.113.0/24"}]},
            {"IpProtocol": "tcp", "FromPort": 12345, "ToPort": 12345,
             "IpRanges": [{"CidrIp": "127.0.0.0/8"}]},
        ],
    )
    r = ec2.run_instances(
        ImageId="ami-alpine-3.20", InstanceType="t2.nano",
        MinCount=1, MaxCount=1, SecurityGroupIds=[STATE["sg_id"]],
    )
    STATE["iid"] = r["Instances"][0]["InstanceId"]
    deadline = time.time() + 60
    while time.time() < deadline:
        d = ec2.describe_instances(
            InstanceIds=[STATE["iid"]],
        )["Reservations"][0]["Instances"][0]
        if d["State"]["Name"] == "running":
            break
        time.sleep(1)
    assert d["State"]["Name"] == "running", d["State"]

    container = f"localemu-ec2-{STATE['iid']}"
    STATE["container"] = container
    docker("exec", container, "sh", "-c",
           "apk add --no-cache python3 >/dev/null 2>&1", timeout=120)
    docker("exec", "-d", container, "sh", "-c",
           "mkdir -p /srv80 && cd /srv80 && "
           "echo '<h1>EIP-OK-80</h1>' > index.html && "
           "exec python3 -m http.server 80")
    docker("exec", "-d", container, "sh", "-c",
           "mkdir -p /srv8080 && cd /srv8080 && "
           "echo '<h1>EIP-OK-8080</h1>' > index.html && "
           "exec python3 -m http.server 8080")
    docker("exec", "-d", container, "sh", "-c",
           "mkdir -p /srv12345 && cd /srv12345 && "
           "echo '<h1>EIP-OK-12345</h1>' > index.html && "
           "exec python3 -m http.server 12345")
    deadline = time.time() + 15
    while time.time() < deadline:
        _, out, _ = docker("exec", container, "netstat", "-tln")
        if ":80 " in out and ":8080 " in out and ":12345 " in out:
            break
        time.sleep(1)
    assert (
        ":80 " in out and ":8080 " in out and ":12345 " in out
    ), f"servers not all listening: {out!r}"


@step("associate EIP")
def associate_eip():
    a = ec2.allocate_address(Domain="vpc")
    STATE["eip"] = a["PublicIp"]
    STATE["alloc_id"] = a["AllocationId"]
    ec2.associate_address(
        AllocationId=STATE["alloc_id"], InstanceId=STATE["iid"],
    )
    time.sleep(2)


@step("curl :80 (cidr 0.0.0.0/0) -> ALLOW + body returned")
def curl_80_allow():
    hp = wait_for_host_port(STATE["eip"], 80, timeout=20)
    assert hp is not None, "no host port for :80 — 0.0.0.0/0 rule must open it"
    STATE["hp80"] = hp
    rc, body = curl(hp)
    assert "EIP-OK-80" in body, f"unexpected body: {body!r}"


@step("curl :8080 (cidr 203.0.113.0/24) -> DENY + no host port")
def curl_8080_deny():
    # 8080 is open ONLY to 203.0.113.0/24. The host is 127.0.0.1, so the
    # data plane must refuse to publish ANY host port for :8080 (no probe
    # IP matches the rule).  This is the per-CIDR DENY proof.
    hp = host_port_for(STATE["eip"], 8080)
    # Allow a brief settle window — port watcher polls every ~3s
    if hp is not None:
        time.sleep(4)
        hp = host_port_for(STATE["eip"], 8080)
    assert hp is None, (
        f"host port {hp} appeared for :8080 even though the only SG rule "
        f"is 203.0.113.0/24 — per-CIDR enforcement is broken"
    )


@step("curl :12345 (cidr 127.0.0.0/8) -> ALLOW + body returned")
def curl_12345_allow():
    hp = wait_for_host_port(STATE["eip"], 12345, timeout=20)
    assert hp is not None, (
        "no host port for :12345 — 127.0.0.0/8 rule must open it"
    )
    STATE["hp12345"] = hp
    rc, body = curl(hp)
    assert "EIP-OK-12345" in body, f"unexpected body: {body!r}"


@step("revoke SG :80 -> host port disappears + curl fails")
def revoke_80_blocks():
    ec2.revoke_security_group_ingress(
        GroupId=STATE["sg_id"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    gone = wait_for_host_port_gone(STATE["eip"], 80, timeout=10)
    assert gone, "host port for :80 didn't disappear after revoke"
    rc, _ = curl(STATE["hp80"])
    assert rc != 0, "curl unexpectedly succeeded after revoke"


@step("re-authorize SG :80 -> host port comes back + curl works")
def reauth_80_works():
    ec2.authorize_security_group_ingress(
        GroupId=STATE["sg_id"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )
    hp = wait_for_host_port(STATE["eip"], 80, timeout=15)
    assert hp is not None, "host port for :80 didn't reappear after re-auth"
    rc, body = curl(hp)
    assert "EIP-OK-80" in body, f"unexpected body after re-auth: {body!r}"


@step("teardown")
def teardown():
    for fn in (
        lambda: ec2.disassociate_address(PublicIp=STATE["eip"]),
        lambda: ec2.release_address(AllocationId=STATE["alloc_id"]),
        lambda: ec2.terminate_instances(InstanceIds=[STATE["iid"]]),
        lambda: ec2.delete_security_group(GroupId=STATE["sg_id"]),
    ):
        try:
            fn()
        except Exception:
            pass


def main() -> int:
    setup()
    associate_eip()
    curl_80_allow()
    curl_8080_deny()
    curl_12345_allow()
    revoke_80_blocks()
    reauth_80_works()
    teardown()
    print(f"\n=== summary === PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
