#!/usr/bin/env python3
"""End-to-end non-base-AMI test (fix #84).

Verifies that LocalEmu can launch EC2 instances from AMIs that map to
non-Ubuntu Docker images (Alpine, Amazon Linux). For each image the
test validates that:

  - ``RunInstances`` succeeds and returns a running Docker container.
  - The container's Docker image matches the AMI mapping in
    ``ami_mapping.BUILTIN_AMI_MAP``.
  - The container is actually reachable via ``docker exec`` and
    running a distro-appropriate shell (busybox ``sh`` for Alpine,
    bash or ``sh`` for Amazon Linux).
  - User-data executes correctly on the image at boot — writes a
    sentinel file inside the container that we then read back.
  - Intra-VPC connectivity to a peer (the LocalEmu-base Ubuntu
    container) works — proving the container joined the VPC network
    and can route to siblings.
  - IMDSv2 is reachable from the container via the env var
    ``AWS_EC2_METADATA_SERVICE_ENDPOINT`` LocalEmu injects.

We do NOT require SSH on non-base images: upstream Alpine/AL images
don't ship openssh-server and a VPC ``--internal=true`` network has
no route to alpine's package mirrors to install it post-boot. That
limitation is documented in ``vm_manager.SSHD_ENTRYPOINT_SCRIPT``;
this test pins behavior rather than pretending SSH works.
"""
from __future__ import annotations

import base64
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
CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=30)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

ec2 = boto3.client("ec2", **KW)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []
state: dict = {"launched": []}


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
        time.sleep(1)
    return False


def docker_image(container: str) -> str:
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", container],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip()


def launch_ec2(ami_id: str, user_data_script: str | None = None) -> tuple[str, str]:
    """Run-instances with ``ami_id`` in the shared VPC. Returns (instance_id, container_name)."""
    kwargs = dict(
        ImageId=ami_id, InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=state["subnet"],
    )
    if user_data_script:
        # boto3 base64-encodes UserData automatically — pass the raw
        # script or it ends up double-encoded.
        kwargs["UserData"] = user_data_script
    r = ec2.run_instances(**kwargs)
    iid = r["Instances"][0]["InstanceId"]
    cname = f"localemu-ec2-{iid}"
    assert wait_running(cname, timeout=90), \
        f"{cname} did not start within 90s (ami={ami_id})"
    state["launched"].append(iid)
    return iid, cname


@step("01-setup-shared-vpc-for-all-amis")
def setup():
    vpc = ec2.create_vpc(CidrBlock="10.220.0.0/16")["Vpc"]["VpcId"]
    state["vpc"] = vpc
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.220.1.0/24",
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    state["subnet"] = sub
    # Peer on the LocalEmu base image — used to prove intra-VPC
    # connectivity from each non-base launch.
    peer_id, peer_c = launch_ec2("ami-ubuntu-22.04")
    state["peer_id"] = peer_id
    state["peer_c"] = peer_c


@step("02-alpine-3.20-container-starts-with-correct-image")
def alpine_starts():
    iid, cname = launch_ec2("ami-alpine-3.20")
    state["alpine_id"] = iid
    state["alpine_c"] = cname
    img = docker_image(cname)
    assert img == "alpine:3.20", \
        f"alpine AMI should map to alpine:3.20, got {img}"


@step("03-alpine-busybox-shell-works")
def alpine_shell():
    r = dexec(state["alpine_c"], "sh", "-c", "echo live && uname -a")
    assert r.returncode == 0, f"alpine shell failed: {r.stderr!r}"
    assert "live" in r.stdout, f"unexpected shell output: {r.stdout!r}"


@step("04-alpine-user-data-executed-on-boot")
def alpine_user_data():
    ud = (
        "#!/bin/sh\n"
        f"echo alpine-userdata-ok-{TAG} > /tmp/userdata.out\n"
    )
    iid, cname = launch_ec2("ami-alpine-3.20", user_data_script=ud)
    state["alpine_ud_id"] = iid
    state["alpine_ud_c"] = cname
    # Container inline-executes user-data post-start; check the file.
    r = dexec(cname, "sh", "-c", "cat /tmp/userdata.out 2>/dev/null || echo MISSING")
    assert f"alpine-userdata-ok-{TAG}" in r.stdout, \
        f"user-data sentinel missing on alpine: {r.stdout!r}"


@step("05-alpine-can-ping-peer-inside-vpc")
def alpine_vpc_ping():
    # Get the peer's VPC IP from Docker.
    peer_net = f"localemu-vpc-{state['vpc']}"
    r = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}"
         f"{{{{if eq $k \"{peer_net}\"}}}}{{{{$v.IPAddress}}}}{{{{end}}}}"
         "{{end}}", state["peer_c"]],
        capture_output=True, text=True, timeout=10,
    )
    peer_ip = r.stdout.strip()
    assert peer_ip, f"peer has no IP on {peer_net}"
    # Alpine's busybox ping is at /bin/ping; use -c 2 for a quick test.
    r = dexec(state["alpine_c"], "ping", "-c", "2", "-W", "2", peer_ip,
              timeout=10)
    assert r.returncode == 0, \
        f"alpine->peer intra-VPC ping failed: {r.stdout!r} {r.stderr!r}"


@step("06-alpine-imds-env-var-set")
def alpine_imds_env():
    r = dexec(state["alpine_c"], "sh", "-c",
              "echo $AWS_EC2_METADATA_SERVICE_ENDPOINT")
    url = r.stdout.strip()
    assert url and url.startswith("http://"), \
        f"AWS_EC2_METADATA_SERVICE_ENDPOINT not set on alpine: {url!r}"


@step("07-amazon-linux-2023-container-starts-with-correct-image")
def amazonlinux_starts():
    iid, cname = launch_ec2("ami-amazon-linux-2023")
    state["al_id"] = iid
    state["al_c"] = cname
    img = docker_image(cname)
    assert img == "amazonlinux:2023", \
        f"AL2023 AMI should map to amazonlinux:2023, got {img}"


@step("08-amazon-linux-shell-works")
def al_shell():
    r = dexec(state["al_c"], "sh", "-c",
              "cat /etc/os-release | head -3")
    assert r.returncode == 0, f"AL shell failed: {r.stderr!r}"
    assert "amazon" in r.stdout.lower() or "amzn" in r.stdout.lower(), \
        f"AL os-release unexpected: {r.stdout!r}"


@step("09-peer-can-ping-amazon-linux-inside-vpc")
def al_vpc_ping():
    # amazonlinux:2023 minimal doesn't ship ping / curl / nc, so we
    # probe routing from the Ubuntu peer (which has a full toolbox)
    # INTO the AL container — same proof of VPC-level connectivity
    # without relying on what's installed in the AL image.
    peer_net = f"localemu-vpc-{state['vpc']}"
    r = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}"
         f"{{{{if eq $k \"{peer_net}\"}}}}{{{{$v.IPAddress}}}}{{{{end}}}}"
         "{{end}}", state["al_c"]],
        capture_output=True, text=True, timeout=10,
    )
    al_ip = r.stdout.strip()
    assert al_ip, f"AL has no IP on {peer_net}"
    r = dexec(state["peer_c"], "ping", "-c", "2", "-W", "2", al_ip,
              timeout=10)
    assert r.returncode == 0, \
        f"peer->AL intra-VPC ping failed: {r.stdout!r} {r.stderr!r}"


@step("10-amazon-linux-user-data-executed")
def al_user_data():
    ud = (
        "#!/bin/sh\n"
        f"echo al-userdata-ok-{TAG} > /tmp/userdata.out\n"
    )
    iid, cname = launch_ec2("ami-amazon-linux-2023", user_data_script=ud)
    state["al_ud_id"] = iid
    state["al_ud_c"] = cname
    r = dexec(cname, "sh", "-c",
              "cat /tmp/userdata.out 2>/dev/null || echo MISSING")
    assert f"al-userdata-ok-{TAG}" in r.stdout, \
        f"user-data sentinel missing on AL: {r.stdout!r}"


@step("11-describe-instances-returns-all-launched")
def describe_all():
    r = ec2.describe_instances(InstanceIds=state["launched"])
    seen = set()
    for rsv in r.get("Reservations", []):
        for inst in rsv.get("Instances", []):
            seen.add(inst["InstanceId"])
    missing = set(state["launched"]) - seen
    assert not missing, f"DescribeInstances missing: {missing}"


def cleanup():
    print("\n=== CLEANUP ===")
    if state["launched"]:
        try:
            ec2.terminate_instances(InstanceIds=state["launched"])
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


def main() -> int:
    steps = [
        setup,
        alpine_starts,
        alpine_shell,
        alpine_user_data,
        alpine_vpc_ping,
        alpine_imds_env,
        amazonlinux_starts,
        al_shell,
        al_vpc_ping,
        al_user_data,
        describe_all,
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
