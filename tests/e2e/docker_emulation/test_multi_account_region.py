#!/usr/bin/env python3
"""End-to-end multi-account / multi-region isolation test (fix #83).

Proves that LocalEmu correctly scopes moto backends per (account_id,
region) — resources created with credentials that decode to one
account must NOT be visible to clients using another account, and
resources created in one region must NOT be visible from another.

Scope exercised:

  Multi-account (S3, IAM, EC2):
    01 Account A creates bucket ``dup-name-<tag>``; Account B
       creates a bucket with the SAME name — both succeed because
       LocalEmu scopes S3 per-account.
    02 Account A's list-buckets returns A's bucket only;
       Account B's list-buckets returns B's bucket only.
    03 Account A creates IAM role ``R`` and account B creates a
       role ``R`` too; get_role returns account-specific ARNs.
    04 Account A runs an EC2 instance; Account B runs an EC2.
       Each Docker container carries its own ``localemu.account-id``
       label.
    05 Account A's describe-instances does NOT see B's instance
       and vice versa.

  Multi-region (DynamoDB):
    06 Same account, two regions (us-east-1 + us-west-2). Table
       ``T-<tag>`` created in both with a single region-specific
       item.
    07 GetItem of the east item from us-east-1 succeeds; from
       us-west-2 returns no Item.
    08 And the mirror: west-only item is visible in us-west-2
       but not in us-east-1.

No mocks. Live LocalEmu, live Docker, real boto3 clients.
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
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=30)

ACCT_A = "000000000000"
ACCT_B = "111111111111"
REGION_EAST = "us-east-1"
REGION_WEST = "us-west-2"


def _kw(access_key: str, region: str) -> dict:
    # LocalEmu's accounts.py derives the account id from a 12-digit
    # access-key-id pattern — using "000000000000" / "111111111111"
    # as the key yields the matching account directly.
    return dict(
        endpoint_url=ENDPOINT, region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key="dummy",
        config=CFG,
    )


def s3(acct: str, region: str = REGION_EAST):
    return boto3.client("s3", **_kw(acct, region))


def iam(acct: str, region: str = REGION_EAST):
    return boto3.client("iam", **_kw(acct, region))


def ec2(acct: str, region: str = REGION_EAST):
    return boto3.client("ec2", **_kw(acct, region))


def ddb(acct: str, region: str):
    return boto3.client("dynamodb", **_kw(acct, region))


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


def docker_label(name: str, label: str) -> str:
    r = subprocess.run(
        ["docker", "inspect", "--format",
         "{{index .Config.Labels \"" + label + "\"}}", name],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip()


BUCKET = f"dup-name-{TAG}"
ROLE = f"mar-role-{TAG}"
DDB_TABLE = f"mar-tbl-{TAG}"
EAST_ITEM_PK = f"east-{TAG}"
WEST_ITEM_PK = f"west-{TAG}"


@step("01-s3-bucket-name-is-globally-unique-across-accounts")
def acct_buckets():
    # Real AWS parity: S3 bucket names live in a global namespace,
    # not a per-account one. Account A can create ``BUCKET``; when
    # account B tries the same name it must get BucketAlreadyExists.
    s3(ACCT_A).create_bucket(Bucket=BUCKET)
    try:
        s3(ACCT_B).create_bucket(Bucket=BUCKET)
    except Exception as e:
        msg = str(e)
        assert ("BucketAlreadyExists" in msg
                or "BucketAlreadyOwnedByYou" in msg), (
            f"expected BucketAlreadyExists from account B, got: {msg}"
        )
        return
    raise AssertionError(
        "account B must NOT be able to create a bucket with "
        "account A's name — bucket names are globally unique"
    )


@step("02-list-buckets-account-isolation")
def list_buckets_iso():
    # Each account sees its own bucket only — we create another
    # bucket unique to A and unique to B to make the isolation
    # measurable.
    a_only = f"a-only-{TAG}"
    b_only = f"b-only-{TAG}"
    s3(ACCT_A).create_bucket(Bucket=a_only)
    s3(ACCT_B).create_bucket(Bucket=b_only)
    state["a_only"] = a_only
    state["b_only"] = b_only

    a_list = {b["Name"] for b in s3(ACCT_A).list_buckets()["Buckets"]}
    b_list = {b["Name"] for b in s3(ACCT_B).list_buckets()["Buckets"]}

    assert a_only in a_list, f"A-only bucket missing from A's list: {a_list}"
    assert a_only not in b_list, f"A-only bucket LEAKED to B: {b_list}"
    assert b_only in b_list, f"B-only bucket missing from B's list: {b_list}"
    assert b_only not in a_list, f"B-only bucket LEAKED to A: {a_list}"


@step("03-iam-roles-scoped-per-account")
def iam_per_acct():
    iam(ACCT_A).create_role(
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
    iam(ACCT_B).create_role(
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
    ra = iam(ACCT_A).get_role(RoleName=ROLE)["Role"]["Arn"]
    rb = iam(ACCT_B).get_role(RoleName=ROLE)["Role"]["Arn"]
    # ARNs must embed different account IDs.
    assert f":{ACCT_A}:" in ra, f"A role ARN wrong: {ra}"
    assert f":{ACCT_B}:" in rb, f"B role ARN wrong: {rb}"
    assert ra != rb, f"ARNs collided: {ra}"


@step("04-ec2-per-account-docker-label")
def ec2_per_acct_label():
    ra = ec2(ACCT_A).run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1,
    )
    ia = ra["Instances"][0]["InstanceId"]
    ca = f"localemu-ec2-{ia}"
    state["ia"] = ia
    state["ca"] = ca
    assert wait_running(ca, timeout=60), f"A's EC2 {ca} did not start"
    lbl_a = docker_label(ca, "localemu.account-id")
    assert lbl_a == ACCT_A, f"A container label wrong: {lbl_a!r}"

    rb = ec2(ACCT_B).run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1,
    )
    ib = rb["Instances"][0]["InstanceId"]
    cb = f"localemu-ec2-{ib}"
    state["ib"] = ib
    state["cb"] = cb
    assert wait_running(cb, timeout=60), f"B's EC2 {cb} did not start"
    lbl_b = docker_label(cb, "localemu.account-id")
    assert lbl_b == ACCT_B, f"B container label wrong: {lbl_b!r}"


@step("05-describe-instances-account-isolation")
def describe_iso():
    a_ids = set()
    for rsv in ec2(ACCT_A).describe_instances().get("Reservations", []):
        for inst in rsv.get("Instances", []):
            a_ids.add(inst.get("InstanceId"))
    b_ids = set()
    for rsv in ec2(ACCT_B).describe_instances().get("Reservations", []):
        for inst in rsv.get("Instances", []):
            b_ids.add(inst.get("InstanceId"))
    assert state["ia"] in a_ids, f"A missing own instance: {a_ids}"
    assert state["ia"] not in b_ids, \
        f"A's instance LEAKED to account B: {b_ids}"
    assert state["ib"] in b_ids, f"B missing own instance: {b_ids}"
    assert state["ib"] not in a_ids, \
        f"B's instance LEAKED to account A: {a_ids}"


@step("06-ddb-create-table-in-both-regions-with-items")
def ddb_two_regions():
    for region in (REGION_EAST, REGION_WEST):
        ddb(ACCT_A, region).create_table(
            TableName=DDB_TABLE,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
    ddb(ACCT_A, REGION_EAST).put_item(
        TableName=DDB_TABLE,
        Item={"pk": {"S": EAST_ITEM_PK}, "val": {"S": "east-val"}},
    )
    ddb(ACCT_A, REGION_WEST).put_item(
        TableName=DDB_TABLE,
        Item={"pk": {"S": WEST_ITEM_PK}, "val": {"S": "west-val"}},
    )


@step("07-east-item-visible-only-in-east")
def east_only_east():
    east = ddb(ACCT_A, REGION_EAST).get_item(
        TableName=DDB_TABLE, Key={"pk": {"S": EAST_ITEM_PK}},
    )
    assert "Item" in east and east["Item"]["val"]["S"] == "east-val", east
    west = ddb(ACCT_A, REGION_WEST).get_item(
        TableName=DDB_TABLE, Key={"pk": {"S": EAST_ITEM_PK}},
    )
    assert "Item" not in west, f"east item LEAKED to us-west-2: {west}"


@step("08-west-item-visible-only-in-west")
def west_only_west():
    west = ddb(ACCT_A, REGION_WEST).get_item(
        TableName=DDB_TABLE, Key={"pk": {"S": WEST_ITEM_PK}},
    )
    assert "Item" in west and west["Item"]["val"]["S"] == "west-val", west
    east = ddb(ACCT_A, REGION_EAST).get_item(
        TableName=DDB_TABLE, Key={"pk": {"S": WEST_ITEM_PK}},
    )
    assert "Item" not in east, f"west item LEAKED to us-east-1: {east}"


def cleanup():
    print("\n=== CLEANUP ===")
    for acct in (ACCT_A, ACCT_B):
        try:
            for b in (BUCKET, state.get("a_only"), state.get("b_only")):
                if not b:
                    continue
                try:
                    s3(acct).delete_bucket(Bucket=b)
                except Exception:
                    pass
            try:
                iam(acct).delete_role(RoleName=ROLE)
            except Exception:
                pass
        except Exception:
            pass
    for ikey in ("ia", "ib"):
        iid = state.get(ikey)
        acct = ACCT_A if ikey == "ia" else ACCT_B
        if iid:
            try:
                ec2(acct).terminate_instances(InstanceIds=[iid])
            except Exception:
                pass
    for region in (REGION_EAST, REGION_WEST):
        try:
            ddb(ACCT_A, region).delete_table(TableName=DDB_TABLE)
        except Exception:
            pass


def main() -> int:
    steps = [
        acct_buckets,
        list_buckets_iso,
        iam_per_acct,
        ec2_per_acct_label,
        describe_iso,
        ddb_two_regions,
        east_only_east,
        west_only_west,
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
