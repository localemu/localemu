#!/usr/bin/env python3
"""End-to-end SSM test against live LocalEmu (fix #76).

Exercises:
  - aws ssm send-command --document-name AWS-RunShellScript
  - aws ssm get-command-invocation
  - Non-zero exit still captures stdout+stderr (beats LocalStack Pro gap)
  - {{ssm:/path}} parameter resolution
  - Instance unreachable path
  - aws ssm describe-instance-information includes the running EC2
  - aws ssm start-session returns UnsupportedOperation with SSH hint
  - Non-shell document (AWS-RunPatchBaseline) returns synthetic success
"""
from __future__ import annotations

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
CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=60)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="t", aws_secret_access_key="t", config=CFG)

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


def wait_command(command_id: str, instance_id: str, timeout: int = 45) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id,
            )
            last = r
            if r.get("Status") in ("Success", "Failed", "TimedOut", "Cancelled"):
                return r
        except ssm.exceptions.InvocationDoesNotExist:
            pass
        except Exception as e:
            last = {"Status": "ERROR", "error": str(e)}
        time.sleep(1)
    return last or {}


def docker_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", name],
                       capture_output=True, text=True, timeout=10)
    return r.returncode == 0 and r.stdout.strip() == "true"


def wait_running(name: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if docker_running(name):
            return True
        time.sleep(2)
    return False


@step("01-launch-ec2-for-ssm")
def launch_ec2():
    state["key_name"] = f"ssm-{TAG}"
    ec2.create_key_pair(KeyName=state["key_name"])
    vpc = ec2.describe_vpcs(
        Filters=[{"Name": "is-default", "Values": ["true"]}],
    )["Vpcs"][0]["VpcId"]
    subnet = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}],
    )["Subnets"][0]["SubnetId"]
    sg = ec2.create_security_group(
        GroupName=f"ssm-{TAG}", Description="ssm", VpcId=vpc,
    )["GroupId"]
    state["sg"] = sg
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key_name"],
        SecurityGroupIds=[sg], SubnetId=subnet,
    )
    state["i1"] = r["Instances"][0]["InstanceId"]
    assert wait_running(f"localemu-ec2-{state['i1']}", timeout=60), \
        "EC2 container did not start"


@step("02-send-command-hello")
def send_hello():
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[state["i1"]],
        Parameters={"commands": ["uname -s", "echo hello-from-ssm"]},
    )
    cid = r["Command"]["CommandId"]
    state["cmd_hello"] = cid
    inv = wait_command(cid, state["i1"])
    print(f"  status={inv.get('Status')}")
    print(f"  stdout={inv.get('StandardOutputContent','')!r}")
    assert inv.get("Status") == "Success", inv
    assert inv.get("ResponseCode") == 0
    assert "Linux" in inv.get("StandardOutputContent", "")
    assert "hello-from-ssm" in inv.get("StandardOutputContent", "")


@step("03-send-command-nonzero-exit-still-captures-output")
def send_nonzero():
    # beats LocalStack Pro: stdout+stderr captured even when exit != 0
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[state["i1"]],
        Parameters={"commands": [
            "echo partial-stdout",
            "echo error-msg 1>&2",
            "exit 7",
        ]},
    )
    cid = r["Command"]["CommandId"]
    inv = wait_command(cid, state["i1"])
    print(f"  status={inv.get('Status')}, rc={inv.get('ResponseCode')}")
    print(f"  stdout={inv.get('StandardOutputContent','')!r}")
    print(f"  stderr={inv.get('StandardErrorContent','')!r}")
    assert inv.get("Status") == "Failed"
    assert inv.get("ResponseCode") == 7
    assert "partial-stdout" in inv.get("StandardOutputContent", "")
    assert "error-msg" in inv.get("StandardErrorContent", "")


@step("04-shell-constructs-work-and-pipes")
def send_pipes():
    # beats LocalStack Pro: &&, |, > all work via bash-script execution
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[state["i1"]],
        Parameters={"commands": [
            "echo one && echo two | wc -l > /tmp/counted",
            "cat /tmp/counted",
        ]},
    )
    cid = r["Command"]["CommandId"]
    inv = wait_command(cid, state["i1"])
    assert inv.get("Status") == "Success", inv
    # wc -l on a 1-line stream prints "1"
    assert "1" in inv.get("StandardOutputContent", "").strip().split("\n")[-1]


@step("05-ssm-placeholder-resolution")
def send_placeholder():
    # PutParameter then {{ssm:/my/key}} in a command
    ssm.put_parameter(
        Name=f"/e2e/{TAG}/greeting", Value="bonjour-from-param",
        Type="String", Overwrite=True,
    )
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[state["i1"]],
        Parameters={"commands": [
            f"echo '{{{{ssm:/e2e/{TAG}/greeting}}}}'",
        ]},
    )
    cid = r["Command"]["CommandId"]
    inv = wait_command(cid, state["i1"])
    print(f"  stdout={inv.get('StandardOutputContent','')!r}")
    assert inv.get("Status") == "Success"
    assert "bonjour-from-param" in inv.get("StandardOutputContent", "")


@step("06-instance-unreachable")
def send_ghost():
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=["i-does-not-exist-" + TAG],
        Parameters={"commands": ["echo shouldnt-run"]},
    )
    cid = r["Command"]["CommandId"]
    inv = wait_command(cid, "i-does-not-exist-" + TAG, timeout=15)
    print(f"  status={inv.get('Status')}, details={inv.get('StatusDetails')}")
    assert inv.get("Status") == "Failed"
    assert inv.get("StatusDetails") == "InstanceUnreachable"


@step("07-non-shell-document-stubbed-success")
def send_patch_baseline():
    r = ssm.send_command(
        DocumentName="AWS-RunPatchBaseline",
        InstanceIds=[state["i1"]],
        Parameters={"Operation": ["Scan"]},
    )
    cid = r["Command"]["CommandId"]
    inv = wait_command(cid, state["i1"], timeout=15)
    assert inv.get("Status") == "Success"
    assert "stubbed" in (inv.get("StatusDetails") or "").lower()


@step("08-describe-instance-information-lists-our-instance")
def describe_info():
    r = ssm.describe_instance_information()
    ids = [info["InstanceId"] for info in r.get("InstanceInformationList", [])]
    print(f"  instances visible: {ids}")
    assert state["i1"] in ids
    # The PingStatus for our instance must be Online
    for info in r["InstanceInformationList"]:
        if info["InstanceId"] == state["i1"]:
            assert info.get("PingStatus") == "Online"
            break


@step("09-start-session-returns-unsupported-with-ssh-hint")
def start_session_unsupported():
    try:
        ssm.start_session(Target=state["i1"])
    except Exception as e:
        msg = str(e)
        print(f"  exception: {type(e).__name__}: {msg[:200]}")
        assert "UnsupportedOperation" in msg or "ssh" in msg.lower()
        return
    raise AssertionError("StartSession should have raised")


def cleanup():
    print("\n=== CLEANUP ===")
    if "i1" in state:
        try:
            ec2.terminate_instances(InstanceIds=[state["i1"]])
        except Exception:
            pass
    time.sleep(3)
    if "sg" in state:
        try:
            ec2.delete_security_group(GroupId=state["sg"])
        except Exception:
            pass
    if "key_name" in state:
        try:
            ec2.delete_key_pair(KeyName=state["key_name"])
        except Exception:
            pass


def main() -> int:
    steps = [
        launch_ec2,
        send_hello,
        send_nonzero,
        send_pipes,
        send_placeholder,
        send_ghost,
        send_patch_baseline,
        describe_info,
        start_session_unsupported,
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
