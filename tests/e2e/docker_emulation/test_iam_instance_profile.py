#!/usr/bin/env python3
"""End-to-end IAM instance profile test (fix #78).

Exercises the full chain from the HOST:
  aws iam create-role → put-role-policy → create-instance-profile →
  add-role-to-instance-profile → aws ec2 run-instances
                                    --iam-instance-profile Name=<p>
  → docker exec <container> aws s3 ls
        SDK discovers IMDSv2 creds → SigV4-signs with ASIA+SessionToken
        → LocalEmu edge → resolve_caller → PolicyEvaluator

Scenarios:
  01 setup role + policy + instance-profile
  02 launch ec2 with profile, wait container running
  03 IMDSv2 token dance from inside → security-credentials/<role> has ASIA*
  04 docker exec aws sts get-caller-identity → assumed-role/<role>/...
  05 allow-path: policy permits s3:ListAllMyBuckets → aws s3 ls succeeds
  06 deny-path: aws s3 mb s3://foo → AccessDenied under IAM_ENFORCEMENT=1
  07 no-profile: second instance without profile, `aws s3 ls` fails with
     NoCredentialsError (IMDS returns 404 for security-credentials/)
  08 /iam/info returns InstanceProfileArn + Code=Success
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
# Use the well-known LocalEmu root key so this suite works whether
# IAM_ENFORCEMENT is on or off (the default root set includes
# AKIAIOSFODNN7EXAMPLE). Role-assumed creds are still minted by moto
# at run-instances time for the in-container calls.
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

ec2 = boto3.client("ec2", **KW)
iam = boto3.client("iam", **KW)
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


ROLE_NAME = f"ip-role-{TAG}"
PROFILE_NAME = f"ip-prof-{TAG}"
TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
ALLOW_LIST_BUCKETS = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        # Real AWS maps the ListBuckets API call to s3:ListAllMyBuckets;
        # LocalEmu's IAM enforcer currently derives the action name from
        # the service:operation pair, which yields s3:ListBuckets. Accept
        # both so the policy is valid against real AWS *and* LocalEmu.
        "Action": [
            "s3:ListAllMyBuckets", "s3:ListBuckets",
            "s3:ListBucket", "s3:GetObject",
        ],
        "Resource": "*",
    }],
}


@step("01-setup-role-policy-profile")
def setup_role():
    iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
    )
    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="allow-list-buckets",
        PolicyDocument=json.dumps(ALLOW_LIST_BUCKETS),
    )
    iam.create_instance_profile(InstanceProfileName=PROFILE_NAME)
    iam.add_role_to_instance_profile(
        InstanceProfileName=PROFILE_NAME, RoleName=ROLE_NAME,
    )
    state["role_name"] = ROLE_NAME
    state["profile_name"] = PROFILE_NAME


@step("02-launch-ec2-with-profile")
def launch_with_profile():
    state["key_name"] = f"ip-{TAG}"
    ec2.create_key_pair(KeyName=state["key_name"])
    r = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key_name"],
        IamInstanceProfile={"Name": PROFILE_NAME},
    )
    state["i1"] = r["Instances"][0]["InstanceId"]
    state["c1"] = f"localemu-ec2-{state['i1']}"
    assert wait_running(state["c1"], timeout=60), "EC2 container did not start"
    # Also launch a second instance WITHOUT a profile for scenario 07.
    r2 = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, KeyName=state["key_name"],
    )
    state["i2"] = r2["Instances"][0]["InstanceId"]
    state["c2"] = f"localemu-ec2-{state['i2']}"
    assert wait_running(state["c2"], timeout=60)


@step("03-imdsv2-serves-asia-session-creds")
def imdsv2_serves_creds():
    # IMDSv2: PUT to /latest/api/token, then GET with that token.
    # We use the container's configured IMDS endpoint (the env var that
    # every AWS SDK honours) rather than the link-local 169.254.169.254
    # literal so the test works on both VPC-attached (sidecar) and
    # default-bridge (per-instance proxy) instances.
    base = '"$AWS_EC2_METADATA_SERVICE_ENDPOINT"'
    token_cmd = (
        f'curl -s -X PUT {base}latest/api/token '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300"'
    )
    r = dexec(state["c1"], "sh", "-c", token_cmd)
    assert r.returncode == 0 and r.stdout.strip(), \
        f"token fetch failed: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    token = r.stdout.strip()
    list_cmd = (
        f'curl -s -H "X-aws-ec2-metadata-token: {token}" '
        f'{base}latest/meta-data/iam/security-credentials/'
    )
    r = dexec(state["c1"], "sh", "-c", list_cmd)
    assert r.returncode == 0 and ROLE_NAME in r.stdout, \
        f"IMDS role listing: rc={r.returncode} out={r.stdout!r}"
    doc_cmd = (
        f'curl -s -H "X-aws-ec2-metadata-token: {token}" '
        f'{base}latest/meta-data/iam/security-credentials/{ROLE_NAME}'
    )
    r = dexec(state["c1"], "sh", "-c", doc_cmd)
    assert r.returncode == 0, f"IMDS creds fetch rc={r.returncode}"
    doc = json.loads(r.stdout)
    assert doc.get("Code") == "Success", doc
    # LocalEmu rewrites temp-key prefixes to LSIA (via iam_patches) unless
    # PARITY_AWS_ACCESS_KEY_ID=1 is set, in which case moto's native ASIA
    # prefix is kept. Either is a valid AWS temporary-credential prefix.
    assert doc.get("AccessKeyId", "")[:4] in ("ASIA", "LSIA"), doc
    assert doc.get("Token"), doc
    assert doc.get("Expiration"), doc


@step("04-sts-get-caller-identity-from-inside-container")
def sts_identity_from_inside():
    r = dexec(state["c1"], "aws", "sts", "get-caller-identity",
              "--output", "json")
    assert r.returncode == 0, f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    data = json.loads(r.stdout)
    arn = data.get("Arn", "")
    # Must be an assumed-role ARN pointing at OUR role — never a static key.
    assert f":assumed-role/{ROLE_NAME}/" in arn, arn


@step("05-aws-s3-ls-from-inside-container-succeeds")
def s3_ls_allowed():
    # Pre-create a bucket from the host so the list has something to show.
    bucket = f"ip-bkt-{TAG}"
    s3.create_bucket(Bucket=bucket)
    state["bucket"] = bucket
    # From inside the container — SDK auto-discovers IMDS creds and
    # signs with the assumed-role session token. Endpoint URL comes
    # from the AWS_ENDPOINT_URL env var set at container create time.
    r = dexec(state["c1"], "aws", "s3api", "list-buckets",
              "--query", "Buckets[].Name", "--output", "json")
    assert r.returncode == 0, f"rc={r.returncode} out={r.stdout!r} err={r.stderr!r}"
    names = json.loads(r.stdout)
    assert bucket in names, f"{bucket} not in listed {names}"


@step("06-denied-action-returns-access-denied")
def denied_action():
    # Role policy allows ListBuckets/GetObject but NOT CreateBucket.
    # With IAM_ENFORCEMENT=1 the enforcer must reject this.
    if os.environ.get("IAM_ENFORCEMENT", "").lower() not in ("1", "true", "yes"):
        print("  SKIP (IAM_ENFORCEMENT not set)")
        return
    r = dexec(state["c1"], "aws", "s3", "mb", f"s3://denied-{TAG}")
    # Must NOT succeed. AWS CLI returns non-zero + 'AccessDenied' in stderr
    assert r.returncode != 0, \
        f"mb should have been denied but succeeded: {r.stdout!r}"
    combined = (r.stdout + r.stderr).lower()
    assert "accessdenied" in combined or "not authorized" in combined, \
        f"expected AccessDenied, got stdout={r.stdout!r} stderr={r.stderr!r}"


@step("07-no-profile-means-no-creds")
def no_profile_no_creds():
    # The second instance has no IamInstanceProfile — IMDS must return
    # 404 for security-credentials/, and `aws s3 ls` must fail at the
    # credential-discovery stage (NoCredentialsError), NOT at the
    # request stage.
    base = '"$AWS_EC2_METADATA_SERVICE_ENDPOINT"'
    token_cmd = (
        f'curl -s -X PUT {base}latest/api/token '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300"'
    )
    tk = dexec(state["c2"], "sh", "-c", token_cmd).stdout.strip()
    probe = (
        f'curl -s -o /dev/null -w "%{{http_code}}" '
        f'-H "X-aws-ec2-metadata-token: {tk}" '
        f'{base}latest/meta-data/iam/security-credentials/'
    )
    r = dexec(state["c2"], "sh", "-c", probe)
    code = r.stdout.strip()
    assert code in ("404", "200"), f"probe code={code!r}"
    if code == "200":
        body_cmd = (
            f'curl -s -H "X-aws-ec2-metadata-token: {tk}" '
            f'{base}latest/meta-data/iam/security-credentials/'
        )
        body = dexec(state["c2"], "sh", "-c", body_cmd).stdout.strip()
        assert not body, f"expected empty role list, got: {body!r}"

    # Now a real SDK call — must fail locally (no creds), not reach LocalEmu.
    r = dexec(state["c2"], "aws", "s3", "ls")
    assert r.returncode != 0, f"s3 ls must fail: {r.stdout!r}"
    # AWS CLI phrasing varies; look for either NoCredentials or
    # "Unable to locate credentials".
    low = (r.stdout + r.stderr).lower()
    assert ("unable to locate credentials" in low
            or "nocredentials" in low), \
        f"expected NoCredentials-like error, got stderr={r.stderr!r}"


@step("08-imds-iam-info-serves-profile-arn")
def imds_iam_info():
    base = '"$AWS_EC2_METADATA_SERVICE_ENDPOINT"'
    token_cmd = (
        f'curl -s -X PUT {base}latest/api/token '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300"'
    )
    tk = dexec(state["c1"], "sh", "-c", token_cmd).stdout.strip()
    info_cmd = (
        f'curl -s -H "X-aws-ec2-metadata-token: {tk}" '
        f'{base}latest/meta-data/iam/info'
    )
    r = dexec(state["c1"], "sh", "-c", info_cmd)
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    assert info.get("Code") == "Success", info
    arn = info.get("InstanceProfileArn", "")
    assert PROFILE_NAME in arn, arn


def cleanup():
    print("\n=== CLEANUP ===")
    if "i1" in state:
        try:
            ec2.terminate_instances(InstanceIds=[state["i1"]])
        except Exception:
            pass
    if "i2" in state:
        try:
            ec2.terminate_instances(InstanceIds=[state["i2"]])
        except Exception:
            pass
    time.sleep(3)
    if "bucket" in state:
        try:
            s3.delete_bucket(Bucket=state["bucket"])
        except Exception:
            pass
    if "profile_name" in state:
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=state["profile_name"],
                RoleName=state["role_name"],
            )
        except Exception:
            pass
        try:
            iam.delete_instance_profile(
                InstanceProfileName=state["profile_name"],
            )
        except Exception:
            pass
    if "role_name" in state:
        try:
            iam.delete_role_policy(
                RoleName=state["role_name"],
                PolicyName="allow-list-buckets",
            )
        except Exception:
            pass
        try:
            iam.delete_role(RoleName=state["role_name"])
        except Exception:
            pass
    if "key_name" in state:
        try:
            ec2.delete_key_pair(KeyName=state["key_name"])
        except Exception:
            pass


def main() -> int:
    steps = [
        setup_role,
        launch_with_profile,
        imdsv2_serves_creds,
        sts_identity_from_inside,
        s3_ls_allowed,
        denied_action,
        no_profile_no_creds,
        imds_iam_info,
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
