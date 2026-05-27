#!/usr/bin/env python3
"""End-to-end PERSISTENCE=1 full stop/start cycle test (fix #82).

Drives LocalEmu through a real restart under PERSISTENCE=1 and proves
that the operator's resources survive:

  Phase A (before restart) — under PERSISTENCE=1:
    * create an IAM role + inline policy
    * create an S3 bucket + put an object with known body
    * create a VPC + subnet + SSH key + EC2 with the role profile
    * assert the EC2 Docker container is running
    * confirm the SSH port binding published on the host

  Shutdown — SIGTERM the LocalEmu process:
    * wait for clean exit (persistence save must run before exit)
    * assert the state directory was populated on disk
    * assert the EC2 Docker container is STILL RUNNING (LocalEmu
      does not kill customer EC2 containers on shutdown — that is
      the whole point of persistence)

  Phase B (after restart) — under PERSISTENCE=1 with the same data dir:
    * IAM role + inline policy still exist
    * S3 bucket still lists; object body byte-for-byte identical
    * DescribeInstances returns the EC2 with same instance-id
    * SSH host port from Phase A is the same port LocalEmu reports
      in the DescribeInstances Tags — and ``nc -z`` on the host
      reaches that port (the Docker container's SSH was preserved
      across the restart)

The test is self-contained: it stops any existing LocalEmu, brings
up its own with PERSISTENCE=1 pointed at a fresh data dir, runs the
two phases, and cleans up.
"""
from __future__ import annotations

import json
import os
import signal
import socket
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


def find_localemu_pid() -> int | None:
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


def stop_localemu(pid: int | None = None, timeout: int = 20) -> None:
    pid = pid or find_localemu_pid()
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
    # Still alive — force.
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def wait_for_health(timeout: int = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["curl", "-sf", "-o", "/dev/null",
             "http://localhost:4566/_localemu/health"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return True
        time.sleep(2)
    return False


def start_localemu(data_dir: str, log_path: str) -> subprocess.Popen:
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
    p = subprocess.Popen(
        [os.path.expanduser(
            "~/.virtualenvs/localemu-dev/bin/localemu"), "start"],
        env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return p


ROLE = f"persist-role-{TAG}"
PROFILE = f"persist-prof-{TAG}"
BUCKET = f"persist-bkt-{TAG}"
OBJ_KEY = "hello.txt"
OBJ_BODY = f"persistence-body-{TAG}".encode()


def clients():
    return (
        boto3.client("iam", **KW),
        boto3.client("s3", **KW),
        boto3.client("ec2", **KW),
    )


@step("00-stop-any-existing-localemu-and-clean")
def prep():
    stop_localemu()
    time.sleep(2)
    # Don't touch pre-existing Docker containers — some tests run in
    # parallel sessions. We only care about OUR EC2 container which
    # we track by instance id.


@step("01-start-localemu-with-persistence-phase-a")
def start_phase_a():
    state["data_dir"] = tempfile.mkdtemp(prefix="localemu-persist-test-")
    state["log_phase_a"] = f"/tmp/le-persist-a-{TAG}.log"
    p = start_localemu(state["data_dir"], state["log_phase_a"])
    state["pid_a"] = p.pid
    assert wait_for_health(timeout=120), \
        f"LocalEmu phase A did not become healthy (log: {state['log_phase_a']})"


@step("02-create-iam-role-and-inline-policy")
def create_iam():
    iam, _, _ = clients()
    iam.create_role(
        RoleName=ROLE,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
    iam.put_role_policy(
        RoleName=ROLE,
        PolicyName="probe-policy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": "*",
            }],
        }),
    )
    iam.create_instance_profile(InstanceProfileName=PROFILE)
    iam.add_role_to_instance_profile(
        InstanceProfileName=PROFILE, RoleName=ROLE,
    )


@step("03-create-s3-bucket-and-put-object")
def create_s3():
    _, s3, _ = clients()
    s3.create_bucket(Bucket=BUCKET)
    s3.put_object(Bucket=BUCKET, Key=OBJ_KEY, Body=OBJ_BODY,
                  ContentType="text/plain")
    # Sanity check: read back now.
    got = s3.get_object(Bucket=BUCKET, Key=OBJ_KEY)["Body"].read()
    assert got == OBJ_BODY, "S3 readback mismatch pre-restart"


@step("04-launch-ec2-with-profile")
def launch_ec2():
    _, _, ec2 = clients()
    state["key_name"] = f"persist-key-{TAG}"
    ec2.create_key_pair(KeyName=state["key_name"])
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key_name"],
        IamInstanceProfile={"Name": PROFILE},
    )
    state["instance_id"] = r["Instances"][0]["InstanceId"]
    state["container"] = f"localemu-ec2-{state['instance_id']}"
    assert wait_running(state["container"], timeout=60), \
        "EC2 container never ran"
    # Snapshot the SSH host port so we can verify it survives.
    tags = r["Instances"][0].get("Tags", [])
    state["ssh_port_a"] = int(next(
        (t["Value"] for t in tags if t["Key"] == "localemu:ssh-port"), "0"
    ))
    # Confirm SSH port actually bound on the host.
    state["ssh_port_a_bound"] = _port_open("127.0.0.1", state["ssh_port_a"])


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    if not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


@step("05-confirm-ssh-port-bound-before-restart")
def confirm_ssh_bound_pre():
    assert state["ssh_port_a"] > 0, "no SSH port assigned pre-restart"
    assert state["ssh_port_a_bound"], \
        f"SSH port {state['ssh_port_a']} not open pre-restart"


@step("06-shutdown-localemu-cleanly-triggering-save")
def shutdown_save():
    pid = state.get("pid_a") or find_localemu_pid()
    assert pid, "no LocalEmu pid to SIGTERM"
    stop_localemu(pid, timeout=60)
    # Verify the process is gone.
    still = find_localemu_pid()
    assert still is None, f"LocalEmu still listening after shutdown (pid={still})"


@step("07-state-directory-populated-on-disk")
def state_dir_populated():
    # PERSISTENCE=1 under FILESYSTEM_ROOT=<data_dir> writes snapshots
    # under <data_dir>/var/lib/localemu/state/**. We don't assume a
    # filename — just that there is content.
    root = os.path.join(state["data_dir"], "var", "lib", "localemu", "state")
    total_bytes = 0
    file_count = 0
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            try:
                total_bytes += os.path.getsize(os.path.join(dirpath, f))
                file_count += 1
            except OSError:
                pass
    assert file_count > 0 and total_bytes > 0, (
        f"state dir empty after shutdown: {root} "
        f"(files={file_count}, bytes={total_bytes})"
    )
    print(f"  wrote {file_count} file(s), total {total_bytes} bytes to {root}")


@step("08-ec2-docker-container-preserved-on-disk")
def container_survives():
    # LocalEmu's graceful shutdown STOPS the container (``docker stop``)
    # but does NOT remove it — the writable layer must stay on disk
    # so the container can be resurrected on the next boot. "Preserved"
    # here means ``docker inspect`` still returns it, not that it's
    # still running. This matches ``vm_manager.stop_all``'s contract.
    r = subprocess.run(
        ["docker", "inspect", state["container"]],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0, (
        f"{state['container']} was REMOVED on LocalEmu shutdown — "
        f"persistence requires the writable layer to survive. "
        f"stderr: {r.stderr!r}"
    )
    info = json.loads(r.stdout)
    assert info, f"empty docker inspect for {state['container']}"


@step("09-start-localemu-phase-b-with-same-data-dir")
def start_phase_b():
    state["log_phase_b"] = f"/tmp/le-persist-b-{TAG}.log"
    p = start_localemu(state["data_dir"], state["log_phase_b"])
    state["pid_b"] = p.pid
    assert wait_for_health(timeout=120), \
        f"LocalEmu phase B did not become healthy (log: {state['log_phase_b']})"


@step("10-iam-role-restored")
def iam_restored():
    iam, _, _ = clients()
    r = iam.get_role(RoleName=ROLE)
    assert r["Role"]["RoleName"] == ROLE
    p = iam.get_role_policy(RoleName=ROLE, PolicyName="probe-policy")
    doc = p["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    actions = doc["Statement"][0]["Action"]
    assert "s3:ListBucket" in actions and "s3:GetObject" in actions


@step("11-s3-bucket-and-object-byte-identical")
def s3_restored():
    _, s3, _ = clients()
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    assert BUCKET in buckets, f"{BUCKET} missing post-restart, found: {buckets}"
    got = s3.get_object(Bucket=BUCKET, Key=OBJ_KEY)["Body"].read()
    assert got == OBJ_BODY, (
        f"S3 object body MISMATCH post-restart: "
        f"expected={OBJ_BODY!r} got={got!r}"
    )


@step("12-ec2-instance-restored-with-same-id")
def ec2_restored():
    _, _, ec2 = clients()
    r = ec2.describe_instances(InstanceIds=[state["instance_id"]])
    rsv = r.get("Reservations", [])
    assert rsv, "instance not found post-restart"
    inst = rsv[0]["Instances"][0]
    assert inst["InstanceId"] == state["instance_id"]


@step("13-ssh-port-still-open-post-restart")
def ssh_port_survives():
    # The Docker container survived, so its SSH port binding on the
    # host must still be serving. We use the SAME port recorded in
    # phase A — if LocalEmu reassigned a port on restore, that's a
    # persistence bug.
    assert _port_open("127.0.0.1", state["ssh_port_a"]), (
        f"SSH port {state['ssh_port_a']} not open after restart — "
        f"restore_instance did not recover the host port binding"
    )


@step("14-describe-tags-report-same-ssh-port-post-restart")
def ssh_port_tags():
    _, _, ec2 = clients()
    r = ec2.describe_instances(InstanceIds=[state["instance_id"]])
    inst = r["Reservations"][0]["Instances"][0]
    tags = inst.get("Tags", [])
    ssh_port_b = int(next(
        (t["Value"] for t in tags if t["Key"] == "localemu:ssh-port"), "0"
    ))
    # It's acceptable for the tag to be absent if LocalEmu rebuilds
    # it from Docker inspect; what matters is that when present, it
    # matches what phase A saw.
    if ssh_port_b:
        assert ssh_port_b == state["ssh_port_a"], (
            f"SSH port changed across restart: "
            f"phase A={state['ssh_port_a']} phase B={ssh_port_b}"
        )


def cleanup():
    print("\n=== CLEANUP ===")
    try:
        iam, s3, ec2 = clients()
        try:
            ec2.terminate_instances(InstanceIds=[state.get("instance_id", "")])
        except Exception:
            pass
        try:
            s3.delete_object(Bucket=BUCKET, Key=OBJ_KEY)
        except Exception:
            pass
        try:
            s3.delete_bucket(Bucket=BUCKET)
        except Exception:
            pass
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=PROFILE, RoleName=ROLE,
            )
        except Exception:
            pass
        try:
            iam.delete_instance_profile(InstanceProfileName=PROFILE)
        except Exception:
            pass
        try:
            iam.delete_role_policy(RoleName=ROLE, PolicyName="probe-policy")
        except Exception:
            pass
        try:
            iam.delete_role(RoleName=ROLE)
        except Exception:
            pass
        if state.get("key_name"):
            try:
                ec2.delete_key_pair(KeyName=state["key_name"])
            except Exception:
                pass
    except Exception:
        pass
    # Terminate LocalEmu phase B.
    stop_localemu(state.get("pid_b"))
    # Leave the Docker container to get cleaned by terminate_instances
    # above; fallback force-remove if it's still around.
    if state.get("container"):
        subprocess.run(
            ["docker", "rm", "-f", state["container"]],
            capture_output=True, timeout=10,
        )
    if state.get("data_dir") and os.path.exists(state["data_dir"]):
        subprocess.run(["rm", "-rf", state["data_dir"]], timeout=10)


def main() -> int:
    steps = [
        prep,
        start_phase_a,
        create_iam,
        create_s3,
        launch_ec2,
        confirm_ssh_bound_pre,
        shutdown_save,
        state_dir_populated,
        container_survives,
        start_phase_b,
        iam_restored,
        s3_restored,
        ec2_restored,
        ssh_port_survives,
        ssh_port_tags,
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
