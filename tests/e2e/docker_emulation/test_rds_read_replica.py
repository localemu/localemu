#!/usr/bin/env python3
"""End-to-end CreateDBInstanceReadReplica against live LocalEmu.

Closes audit bug #8 (read replica spawned a fresh empty container
with no data from the source). This test:

  1. Creates a Postgres source, inserts rows.
  2. CreateDBInstanceReadReplica — must seed the replica from source.
  3. Verifies the replica has the rows from step 1.
  4. (Honest scope) does NOT assert ongoing streaming replication;
     the MVP is a one-shot dump+load. Continuous replication is a
     follow-up that needs the source restarted with
     ``wal_level=replica``.

Requires LocalEmu with ``RDS_DOCKER_BACKEND=1``.
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
CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=120)
KW = dict(
    endpoint_url=ENDPOINT, region_name=REGION,
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    config=CFG,
)
rds = boto3.client("rds", **KW)

SRC_ID = f"rr-src-{TAG}"
REPLICA_ID = f"rr-replica-{TAG}"
MASTER_USER = "rradmin"
MASTER_PASS = "RR-Secret-12345!"
DB_NAME = "rrdb"

PASS: list[str] = []
FAIL: list[tuple[str, str]] = []


def step(name: str):
    def deco(fn):
        def wrap():
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn()
                print(f"  PASS [{time.time()-t0:.1f}s]", flush=True)
                PASS.append(name)
            except AssertionError as e:
                print(f"  FAIL [{time.time()-t0:.1f}s] {e}", flush=True)
                FAIL.append((name, str(e)))
            except Exception as e:
                print(f"  ERROR [{time.time()-t0:.1f}s] {type(e).__name__}: {e}", flush=True)
                FAIL.append((name, f"{type(e).__name__}: {e}"))
        return wrap
    return deco


def docker(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def wait_instance_available(db_id: str, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            d = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
            if d.get("DBInstanceStatus") == "available":
                return
        except Exception:
            pass
        time.sleep(3)
    raise AssertionError(f"{db_id} not available in {timeout}s")


def psql_in_container(db_id: str, sql: str, retries: int = 30) -> str:
    container = f"localemu-rds-{db_id}"
    last_err = ""
    for _ in range(retries):
        rc, out, err = docker(
            "exec", container,
            "env", f"PGPASSWORD={MASTER_PASS}",
            "psql", "-U", MASTER_USER, "-h", "127.0.0.1",
            "-d", DB_NAME, "-tAc", sql,
        )
        if rc == 0:
            return out.strip()
        last_err = err
        time.sleep(1)
    raise AssertionError(f"psql failed in {container}: {last_err}")


@step("create source + seed rows")
def test_seed_source():
    rds.create_db_instance(
        DBInstanceIdentifier=SRC_ID,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername=MASTER_USER,
        MasterUserPassword=MASTER_PASS,
        DBName=DB_NAME,
        AllocatedStorage=20,
    )
    wait_instance_available(SRC_ID)
    psql_in_container(
        SRC_ID,
        "CREATE TABLE orders (id int PRIMARY KEY, item text); "
        f"INSERT INTO orders VALUES (1, 'widget-{TAG}'), (2, 'gadget-{TAG}');",
    )
    rows = psql_in_container(SRC_ID, "SELECT count(*) FROM orders;")
    assert rows == "2", rows


@step("CreateDBInstanceReadReplica copies source data")
def test_create_replica():
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=REPLICA_ID,
        SourceDBInstanceIdentifier=SRC_ID,
        DBInstanceClass="db.t3.micro",
    )
    wait_instance_available(REPLICA_ID)
    rows = psql_in_container(REPLICA_ID, "SELECT count(*) FROM orders;")
    assert rows == "2", f"replica has {rows} rows, expected 2"
    widget = psql_in_container(
        REPLICA_ID, "SELECT item FROM orders WHERE id=1;",
    )
    assert widget == f"widget-{TAG}", widget


@step("describe replica surfaces source link")
def test_describe_replica():
    d = rds.describe_db_instances(DBInstanceIdentifier=REPLICA_ID)["DBInstances"][0]
    src = d.get("ReadReplicaSourceDBInstanceIdentifier")
    assert src == SRC_ID, src


@step("teardown")
def test_teardown():
    for db_id in (REPLICA_ID, SRC_ID):
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True,
            )
        except Exception:
            pass


def main() -> int:
    test_seed_source()
    test_create_replica()
    test_describe_replica()
    test_teardown()
    print(f"\n=== summary === PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
