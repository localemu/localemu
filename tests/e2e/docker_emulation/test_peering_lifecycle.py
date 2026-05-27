#!/usr/bin/env python3
"""E2E — VPC peering lifecycle + orphan reconciliation (P3).

Scenarios:
  01 Fresh peering bridge carries labels (``localemu.kind=vpc-peering``,
     ``localemu.pcx-id``, ``localemu.vpc1``, ``localemu.vpc2``).
  02 Under PERSISTENCE=1, seed an orphan ``localemu-pcx-*`` Docker
     network (as if from a previous LocalEmu session where the moto
     peering was deleted but the Docker side leaked). Restart
     LocalEmu. Reconciler fires on ``on_after_state_load`` →
     orphan removed, active peering survives.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import boto3
from botocore.client import Config

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=30)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

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


def _docker_inspect_labels(net: str) -> dict:
    r = subprocess.run(
        ["docker", "network", "inspect", net, "--format", "{{json .Labels}}"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout.strip()) or {}
    except Exception:
        return {}


def _network_exists(net: str) -> bool:
    r = subprocess.run(
        ["docker", "network", "inspect", net],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0


def _find_pid() -> int | None:
    r = subprocess.run(
        ["lsof", "-iTCP:4566", "-sTCP:LISTEN", "-P"],
        capture_output=True, text=True, timeout=10,
    )
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except ValueError:
                continue
    return None


def _stop_localemu(pid: int | None, timeout: int = 25) -> None:
    pid = pid or _find_pid()
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.5)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _wait_healthy(timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["curl", "-sf", "-o", "/dev/null",
             f"{ENDPOINT}/_localemu/health"],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            return True
        time.sleep(2)
    return False


def _start_localemu(data_dir: str, log_path: str) -> subprocess.Popen:
    env = os.environ.copy()
    env.update({
        "PERSISTENCE": "1",
        "FILESYSTEM_ROOT": data_dir,
        "EC2_VM_MANAGER": "docker",
        "RDS_DOCKER_BACKEND": "1",
        "ECS_DOCKER_BACKEND": "1",
        "OPENSEARCH_DOCKER_BACKEND": "1",
        "EKS_K8S_PROVIDER": "k3d",
        "IMDS_SINGLE_INSTANCE_FALLBACK": "1",
    })
    log_fh = open(log_path, "wb")
    return subprocess.Popen(
        [os.path.expanduser(
            "~/.virtualenvs/localemu-dev/bin/localemu"), "start"],
        env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True,
    )


@step("00-stop-existing-localemu-and-boot-with-PERSISTENCE")
def boot_persist():
    _stop_localemu(None)
    time.sleep(2)
    state["data_dir"] = tempfile.mkdtemp(prefix="localemu-p3-")
    state["log_a"] = f"/tmp/le-p3-a-{TAG}.log"
    p = _start_localemu(state["data_dir"], state["log_a"])
    state["pid_a"] = p.pid
    assert _wait_healthy(), f"LocalEmu did not become healthy; log: {state['log_a']}"


@step("01-peering-bridge-carries-labels")
def labels_present():
    ec2 = boto3.client("ec2", **KW)
    va = ec2.create_vpc(CidrBlock="10.240.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.241.0.0/16")["Vpc"]["VpcId"]
    p = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)[
        "VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=p)
    state.update(dict(va=va, vb=vb, p=p))
    net = f"localemu-pcx-{p}"
    state["net"] = net
    labels = _docker_inspect_labels(net)
    assert labels.get("localemu.kind") == "vpc-peering", labels
    assert labels.get("localemu.pcx-id") == p, labels
    assert labels.get("localemu.vpc1") == va, labels
    assert labels.get("localemu.vpc2") == vb, labels


@step("02-stop-localemu-and-seed-orphan-pcx")
def seed_orphan():
    _stop_localemu(state["pid_a"])
    time.sleep(2)
    assert _find_pid() is None, "LocalEmu still listening after shutdown"
    zombie = f"localemu-pcx-pcx-zombie-{TAG}"
    r = subprocess.run(
        ["docker", "network", "create", "--internal",
         "--label", "localemu.kind=vpc-peering",
         "--label", f"localemu.pcx-id=pcx-zombie-{TAG}",
         zombie],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, f"failed to seed orphan: {r.stderr}"
    state["zombie"] = zombie
    assert _network_exists(zombie)
    # Real peering survives too (LocalEmu doesn't wipe pcx on graceful stop).
    assert _network_exists(state["net"]), \
        "active peering Docker bridge already gone before restart"


@step("03-restart-localemu-reconciler-sweeps-orphan")
def restart_and_reconcile():
    state["log_b"] = f"/tmp/le-p3-b-{TAG}.log"
    p = _start_localemu(state["data_dir"], state["log_b"])
    state["pid_b"] = p.pid
    assert _wait_healthy(), f"restart failed; log: {state['log_b']}"
    # Give the reconciler a beat.
    time.sleep(2)
    # Orphan must be gone.
    assert not _network_exists(state["zombie"]), \
        f"zombie {state['zombie']} still present after restart"
    # Real peering must survive — moto restored the pcx and the
    # reconciler either kept the network or re-created it.
    assert _network_exists(state["net"]), \
        f"active peering network {state['net']} disappeared"


def cleanup():
    print("\n=== CLEANUP ===")
    ec2 = boto3.client("ec2", **KW)
    if state.get("p"):
        try: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=state["p"])
        except Exception: pass
    for key in ("va", "vb"):
        v = state.get(key)
        if v:
            try: ec2.delete_vpc(VpcId=v)
            except Exception: pass
    if state.get("zombie"):
        subprocess.run(["docker", "network", "rm", state["zombie"]],
                       capture_output=True, text=True, timeout=10)
    _stop_localemu(state.get("pid_b"))
    if state.get("data_dir") and os.path.exists(state["data_dir"]):
        subprocess.run(["rm", "-rf", state["data_dir"]], timeout=10)


def main() -> int:
    for s in [boot_persist, labels_present, seed_orphan, restart_and_reconcile]:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
