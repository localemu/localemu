#!/usr/bin/env python3
"""End-to-end ECS task-role credentials test (fix #79).

Exercises the full chain:
  aws iam create-role (trust: ecs-tasks.amazonaws.com) →
  put-role-policy (s3:ListAllMyBuckets) →
  aws ecs register-task-definition --task-role-arn <role> →
  aws ecs run-task →
  docker exec <task-container> aws sts get-caller-identity
      → Arn contains assumed-role/<role>/ecs-task-...

Under IAM_ENFORCEMENT=1:
  - role-allowed call succeeds
  - role-denied call returns AccessDenied
  - task without task role → NoCredentialsError (local to SDK)
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
CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=60)
# Use the default LocalEmu root key so this suite works under IAM_ENFORCEMENT=1.
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

iam = boto3.client("iam", **KW)
ecs = boto3.client("ecs", **KW)
s3 = boto3.client("s3", **KW)

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


def find_task_container(task_arn: str, timeout: int = 30) -> str | None:
    """Locate the Docker container whose ``localemu.task-arn`` label matches."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}",
             "--filter", f"label=localemu.task-arn={task_arn}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[0]
        time.sleep(1)
    return None


ROLE_NAME = f"ecs-role-{TAG}"
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
ALLOW_S3_LIST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        # Cover both AWS's canonical action and LocalEmu's derived name.
        "Action": ["s3:ListAllMyBuckets", "s3:ListBuckets",
                   "s3:ListBucket", "s3:GetObject",
                   "sts:GetCallerIdentity"],
        "Resource": "*",
    }],
}


@step("01-setup-role-policy")
def setup_role():
    iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
    )
    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="allow-s3-list",
        PolicyDocument=json.dumps(ALLOW_S3_LIST),
    )
    state["role_name"] = ROLE_NAME
    # Ensure the default cluster exists so run_task doesn't fail upfront.
    try:
        ecs.create_cluster(clusterName="default")
    except Exception:
        pass


@step("02-register-task-def-with-role")
def register_td_with_role():
    # Use the LocalEmu EC2 base image so awscli is available for test assertions
    r = ecs.register_task_definition(
        family=f"td-with-role-{TAG}",
        taskRoleArn=f"arn:aws:iam::000000000000:role/{ROLE_NAME}",
        containerDefinitions=[{
            "name": "app",
            "image": "localemu/ec2-base:v3",
            "essential": True,
            "command": ["sh", "-c", "sleep 600"],
            "memory": 256,
        }],
    )
    state["td_with_role"] = r["taskDefinition"]["taskDefinitionArn"]


@step("03-run-task-with-role")
def run_task_with_role():
    r = ecs.run_task(
        cluster="default",
        taskDefinition=state["td_with_role"],
        count=1,
    )
    assert r.get("tasks"), r
    t = r["tasks"][0]
    state["task_arn_with_role"] = t["taskArn"]
    cname = find_task_container(t["taskArn"], timeout=45)
    assert cname, f"could not find task container for {t['taskArn']}"
    state["c_with_role"] = cname
    assert wait_running(cname, timeout=45), f"task container {cname} never ran"


@step("04-credentials-endpoint-reachable-from-container")
def creds_endpoint():
    # The SDK flow uses AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, which
    # is always resolved against 169.254.170.2. Our DNAT rule inside
    # the container redirects 169.254.170.2:80 → host creds server.
    probe = (
        'test -n "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" '
        '&& curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
    )
    r = dexec(state["c_with_role"], "sh", "-c", probe)
    assert r.returncode == 0 and r.stdout.strip(), \
        f"creds fetch failed: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    doc = json.loads(r.stdout)
    assert doc.get("AccessKeyId", "")[:4] in ("ASIA", "LSIA"), doc
    assert ROLE_NAME in doc.get("RoleArn", ""), doc
    assert doc.get("Token"), doc
    assert doc.get("Expiration"), doc


@step("05-sts-get-caller-identity-from-inside-container")
def sts_identity():
    r = dexec(state["c_with_role"], "aws", "sts", "get-caller-identity",
              "--output", "json")
    assert r.returncode == 0, f"rc={r.returncode} err={r.stderr!r}"
    data = json.loads(r.stdout)
    arn = data.get("Arn", "")
    assert f":assumed-role/{ROLE_NAME}/" in arn, arn


@step("06-allowed-action-succeeds")
def allowed_action():
    # Pre-create a bucket from the host so the list has something to show.
    bucket = f"ecs-bkt-{TAG}"
    s3.create_bucket(Bucket=bucket)
    state["bucket"] = bucket
    r = dexec(state["c_with_role"], "aws", "s3api", "list-buckets",
              "--query", "Buckets[].Name", "--output", "json")
    assert r.returncode == 0, f"rc={r.returncode} err={r.stderr!r}"
    names = json.loads(r.stdout)
    assert bucket in names, f"{bucket} not in {names}"


@step("07-denied-action-returns-access-denied")
def denied_action():
    if os.environ.get("IAM_ENFORCEMENT", "").lower() not in ("1", "true", "yes"):
        print("  SKIP (IAM_ENFORCEMENT not set)")
        return
    # Our policy allows s3:ListBuckets but NOT s3:DeleteBucket. Use a
    # same-service action so endpoint resolution is identical to the
    # allowed scenario above — isolates the IAM decision from any
    # service-specific endpoint quirks.
    target = state.get("bucket") or f"ecs-bkt-{TAG}"
    r = dexec(state["c_with_role"], "aws", "s3", "rb", f"s3://{target}")
    assert r.returncode != 0, \
        f"s3 rb should have been denied: {r.stdout!r}"
    combined = (r.stdout + r.stderr).lower()
    assert "accessdenied" in combined or "not authorized" in combined, \
        f"expected AccessDenied, got stderr={r.stderr!r}"


@step("08-no-task-role-means-no-credentials")
def no_task_role():
    r = ecs.register_task_definition(
        family=f"td-no-role-{TAG}",
        containerDefinitions=[{
            "name": "app",
            "image": "localemu/ec2-base:v3",
            "essential": True,
            "command": ["sh", "-c", "sleep 600"],
            "memory": 256,
        }],
    )
    td = r["taskDefinition"]["taskDefinitionArn"]
    state["td_no_role"] = td
    t = ecs.run_task(cluster="default", taskDefinition=td, count=1)["tasks"][0]
    state["task_arn_no_role"] = t["taskArn"]
    cname = find_task_container(t["taskArn"], timeout=45)
    assert cname
    state["c_no_role"] = cname
    assert wait_running(cname, timeout=45)
    # Verify neither FULL_URI nor RELATIVE_URI was injected
    env = dexec(cname, "sh", "-c", "env | grep AWS_CONTAINER_CREDENTIALS || true").stdout
    assert "FULL_URI" not in env and "RELATIVE_URI" not in env, \
        f"credentials env must be absent for no-task-role: {env!r}"
    # The SDK must fail at credential discovery
    r = dexec(cname, "aws", "sts", "get-caller-identity")
    assert r.returncode != 0, f"expected NoCredentials, got {r.stdout!r}"
    low = (r.stdout + r.stderr).lower()
    assert ("unable to locate credentials" in low
            or "nocredentials" in low), \
        f"expected NoCredentials error, got stderr={r.stderr!r}"


def cleanup():
    print("\n=== CLEANUP ===")
    for arn_key in ("task_arn_with_role", "task_arn_no_role"):
        arn = state.get(arn_key)
        if not arn:
            continue
        try:
            ecs.stop_task(cluster="default", task=arn, reason="test-cleanup")
        except Exception:
            pass
    time.sleep(2)
    for td_key in ("td_with_role", "td_no_role"):
        td = state.get(td_key)
        if not td:
            continue
        try:
            ecs.deregister_task_definition(taskDefinition=td)
        except Exception:
            pass
    if state.get("bucket"):
        try:
            s3.delete_bucket(Bucket=state["bucket"])
        except Exception:
            pass
    if state.get("role_name"):
        try:
            iam.delete_role_policy(
                RoleName=state["role_name"], PolicyName="allow-s3-list",
            )
        except Exception:
            pass
        try:
            iam.delete_role(RoleName=state["role_name"])
        except Exception:
            pass


def main() -> int:
    steps = [
        setup_role,
        register_td_with_role,
        run_task_with_role,
        creds_endpoint,
        sts_identity,
        allowed_action,
        denied_action,
        no_task_role,
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
