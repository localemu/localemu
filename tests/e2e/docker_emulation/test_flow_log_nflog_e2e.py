"""End-to-end integration test for the NFLOG-based VPC Flow Logs path.

Proves the full pipeline:

    iptables NFLOG (inside EC2 container netns)
       → ulogd2 in the flow-log sidecar (same netns)
       → /var/log/localemu-flow/flow.log (inside sidecar)
       → SidecarFlowLogPoller (LocalEmu host process)
       → FlowLogRecorder.record(...)

Why this test exists
--------------------
The ``LOG`` → dmesg path fires on all platforms (counters tick) but
produces no readable dmesg output on macOS Docker Desktop because the
LinuxKit VM shares one kernel ring buffer across every container. That
broke ``FlowLogPoller.poll_once`` even though the underlying iptables
rules were doing the right thing. The NFLOG path is per-netns and
therefore works on both macOS Docker Desktop AND Linux Docker hosts.

How the test runs
-----------------
* Preconditions: LocalEmu must be running with ``EC2_VM_MANAGER=docker``
  and ``FLOW_LOGS_FULL=1`` (the sidecar + poller are gated on this env
  var so vanilla LocalEmu is unchanged by the feature).
* The test uses ``boto3`` to create a VPC, subnet, SG, and EC2
  instance, then sends a denied TCP/443 packet to a second EC2 in the
  same VPC. It asserts:
    1. The flow-log sidecar container is running.
    2. The sidecar's ``/var/log/localemu-flow/flow.log`` contains a
       ``LE-FL:*:I:D:`` line matching the packet.
    3. ``FlowLogRecorder.get_recent()`` — the in-process singleton on
       the LocalEmu host — carries a REJECT entry with the expected
       ports / addresses within 20s.
* Final assertion (3) runs over HTTP against the LocalEmu-side
  dashboard endpoint (``/_localemu/vpc-flow-logs``) because the
  singleton lives in the server process, not the test process.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
TAG = uuid.uuid4().hex[:8]

CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=60)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="test", aws_secret_access_key="test", config=CFG)

ec2 = boto3.client("ec2", **KW)
logs = boto3.client("logs", **KW)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []


def _log(msg: str) -> None:
    print(msg, flush=True)


def _docker(*args: str, timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(["docker", *args], capture_output=True,
                       text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def _docker_running(name: str) -> bool:
    rc, out, _ = _docker("inspect", "--format", "{{.State.Running}}", name, timeout=10)
    return rc == 0 and out.strip() == "true"


def _wait_running(name: str, timeout: int = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _docker_running(name):
            return True
        time.sleep(2)
    return False


def _describe_private_ip(instance_id: str) -> str:
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    return desc["Reservations"][0]["Instances"][0]["PrivateIpAddress"]


def _recent_flow_logs_from_host() -> list[str]:
    """Fetch the LocalEmu-host FlowLogRecorder buffer via the dashboard
    HTTP endpoint. Returns an empty list if the endpoint is absent
    (older LocalEmu builds fall back to dashboard-only access).

    Accepts 404 — the test then falls back to reading the sidecar file
    directly, which at minimum proves the NFLOG → ulogd2 stage works.
    """
    url = f"{ENDPOINT}/_localemu/vpc-flow-logs?limit=200"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    except Exception:
        return []
    # Either plain-text (one line per entry) or JSON array. Be tolerant.
    body = body.strip()
    if not body:
        return []
    if body.startswith("["):
        import json
        try:
            data = json.loads(body)
        except Exception:
            return []
        return [str(line) for line in data if isinstance(line, str)]
    return [line for line in body.splitlines() if line.strip()]


def _cloudwatch_flow_log_hits(iid_suffix: str) -> list[str]:
    """Scan ``/localemu/vpc-flow-logs`` streams for entries referencing
    ``eni-<iid_suffix>`` and port 443 with REJECT action.

    Returns the matching message strings. Empty list on any failure or
    when the log group / stream doesn't exist yet (recorder hasn't
    flushed — caller retries).
    """
    group = "/localemu/vpc-flow-logs"
    try:
        streams = logs.describe_log_streams(logGroupName=group)
    except Exception:
        return []
    hits: list[str] = []
    eni_needle = f"eni-{iid_suffix}"
    for s in streams.get("logStreams", []):
        try:
            events = logs.get_log_events(
                logGroupName=group, logStreamName=s["logStreamName"],
                limit=500,
            )
        except Exception:
            continue
        for e in events.get("events", []):
            msg = e.get("message", "")
            if eni_needle in msg and " 443 " in msg and "REJECT" in msg:
                hits.append(msg)
    return hits


def _sidecar_flow_log_contents(instance_id: str) -> str:
    """Read /var/log/localemu-flow/flow.log out of the sidecar."""
    sidecar = f"localemu-flowlog-{instance_id}"
    rc, out, _err = _docker(
        "exec", sidecar, "sh", "-c",
        "cat /var/log/localemu-flow/flow.log 2>/dev/null || true",
        timeout=10,
    )
    if rc != 0:
        return ""
    return out


def _wait_for_sidecar(instance_id: str, timeout: int = 30) -> bool:
    """Wait until the flow-log sidecar for this instance is running AND
    its ulogd2 log file exists. Returns True on ready, False on timeout.
    """
    sidecar = f"localemu-flowlog-{instance_id}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _docker_running(sidecar):
            rc, out, _ = _docker(
                "exec", sidecar, "sh", "-c",
                "test -f /var/log/localemu-flow/flow.log && echo OK || echo NO",
                timeout=5,
            )
            if rc == 0 and "OK" in out:
                return True
        time.sleep(1)
    return False


def _run() -> int:
    t0 = time.time()
    state: dict = {}
    _log(f"=== NFLOG flow-log e2e ({TAG}) ===")

    # --- 1. Build topology -------------------------------------------------
    r = ec2.create_vpc(CidrBlock="10.77.0.0/16")
    state["vpc"] = r["Vpc"]["VpcId"]
    _log(f"  vpc={state['vpc']}")

    state["subnet"] = ec2.create_subnet(
        VpcId=state["vpc"], CidrBlock="10.77.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]

    state["sg"] = ec2.create_security_group(
        GroupName=f"nflog-{TAG}", Description="nflog e2e",
        VpcId=state["vpc"],
    )["GroupId"]
    # Allow ping + SSH so baseline connectivity still works; TCP 443
    # is intentionally NOT allowed so our probe packet gets DROPPED
    # and therefore logged.
    ec2.authorize_security_group_ingress(
        GroupId=state["sg"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
             "IpRanges": [{"CidrIp": "10.77.0.0/16"}]},
        ],
    )

    # Key pair so the entrypoint starts sshd (not the sleep loop) —
    # matches how real EC2 runs and gives ``nc`` a live target port.
    kp = ec2.create_key_pair(KeyName=f"nflog-{TAG}")
    state["key"] = kp["KeyName"]

    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key"],
        SecurityGroupIds=[state["sg"]], SubnetId=state["subnet"],
    )
    i1 = r["Instances"][0]["InstanceId"]
    state["i1"] = i1
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key"],
        SecurityGroupIds=[state["sg"]], SubnetId=state["subnet"],
    )
    i2 = r["Instances"][0]["InstanceId"]
    state["i2"] = i2

    for iid in (i1, i2):
        assert _wait_running(f"localemu-ec2-{iid}", timeout=180), \
            f"EC2 container localemu-ec2-{iid} never came up"

    # --- 2. Flow-log sidecar up and ready ---------------------------------
    _log(f"  waiting for flow-log sidecar for {i2}…")
    assert _wait_for_sidecar(i2, timeout=45), \
        ("flow-log sidecar localemu-flowlog-" + i2 +
         " did not become ready — is FLOW_LOGS_FULL=1 set on LocalEmu?")
    _log(f"  sidecar localemu-flowlog-{i2} READY")

    # --- 3. Fire a denied TCP/443 packet from i1 → i2 ---------------------
    ip2 = _describe_private_ip(i2)
    _log(f"  sending denied TCP/443 packet i1 → {ip2}")
    # Fire the probe packet a few times: NFLOG may drop the very first
    # packet on some kernels before the socket is fully up. Retries add
    # robustness with negligible runtime cost.
    for attempt in range(6):
        _docker(
            "exec", f"localemu-ec2-{i1}", "sh", "-c",
            f"timeout 2 nc -z {ip2} 443 2>&1 || true",
            timeout=10,
        )
        time.sleep(1)

    # --- 4. Sidecar flow.log must carry an LE-FL line for this packet ----
    contents = ""
    deadline = time.time() + 30
    while time.time() < deadline:
        contents = _sidecar_flow_log_contents(i2)
        if "LE-FL:" in contents and f"DPT=443" in contents:
            break
        time.sleep(2)

    assert "LE-FL:" in contents, (
        "sidecar flow.log has no LE-FL entries — NFLOG → ulogd2 stage "
        f"BROKEN. Full contents:\n{contents[:2000]}"
    )
    assert "DPT=443" in contents, (
        "sidecar flow.log has no DPT=443 entry for the denied probe "
        f"packet. Contents:\n{contents[:2000]}"
    )
    drop_lines = [
        l for l in contents.splitlines()
        if "LE-FL:" in l and ":I:D:" in l and "DPT=443" in l
    ]
    assert drop_lines, (
        "sidecar flow.log has no INGRESS-DROP (LE-FL:*:I:D:) line for "
        f"DPT=443. Contents:\n{contents[:2000]}"
    )
    _log(f"  sidecar flow.log OK ({len(drop_lines)} matching DROP lines):")
    _log(f"    {drop_lines[0][:300]}")

    # --- 5. LocalEmu-host FlowLogRecorder has a parsed REJECT entry ------
    # The recorder flushes buffered entries to CloudWatch Logs group
    # ``/localemu/vpc-flow-logs`` every 60s (see flow_log_recorder.py).
    # We also expose a dashboard endpoint; either surface is acceptable
    # end-of-pipeline proof.
    iid_suffix = i2[-8:]
    host_lines: list[str] = []
    cw_hits: list[str] = []
    deadline = time.time() + 90  # recorder flush interval is 60s
    while time.time() < deadline:
        host_lines = _recent_flow_logs_from_host()
        cw_hits = _cloudwatch_flow_log_hits(iid_suffix)
        if cw_hits:
            _log(
                f"  CloudWatch /localemu/vpc-flow-logs OK: {cw_hits[0][:220]}",
            )
            break
        hits = [l for l in host_lines if "REJECT" in l and " 443 " in l]
        if hits:
            _log(f"  LocalEmu dashboard /_localemu/vpc-flow-logs OK: {hits[0][:200]}")
            break
        time.sleep(3)
    else:
        raise AssertionError(
            "LocalEmu FlowLogRecorder never surfaced a REJECT entry for "
            f"eni-{iid_suffix}/DPT=443. Sidecar had {len(drop_lines)} DROP "
            f"lines but they never reached the recorder within 90s. "
            f"host_lines_tail={host_lines[-3:] if host_lines else []}"
        )

    # --- Cleanup (best effort) --------------------------------------------
    _log("  cleanup …")
    for iid in (i1, i2):
        try:
            ec2.terminate_instances(InstanceIds=[iid])
        except Exception:
            pass
    time.sleep(3)
    try:
        ec2.delete_security_group(GroupId=state["sg"])
    except Exception:
        pass
    try:
        ec2.delete_subnet(SubnetId=state["subnet"])
    except Exception:
        pass
    try:
        ec2.delete_vpc(VpcId=state["vpc"])
    except Exception:
        pass
    try:
        ec2.delete_key_pair(KeyName=state["key"])
    except Exception:
        pass

    dt = time.time() - t0
    _log(f"\n  PASS [{dt:.1f}s]  NFLOG flow-log e2e")
    return 0


def main() -> int:
    try:
        return _run()
    except AssertionError as exc:
        print(f"\n  FAIL  {exc}", flush=True)
        return 1
    except Exception as exc:
        print(f"\n  ERROR  {type(exc).__name__}: {exc}", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
