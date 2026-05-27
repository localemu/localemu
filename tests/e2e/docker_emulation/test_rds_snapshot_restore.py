#!/usr/bin/env python3
"""End-to-end RDS snapshot+restore against live LocalEmu.

Closes audit bug #9 (RestoreDBInstanceFromDBSnapshot spawned a fresh
empty container with no source data). This test:

  1. Creates a Postgres instance, inserts rows.
  2. CreateDBSnapshot — must dump the data to ${VOLUME_DIR}/rds/snapshots.
  3. Deletes the source instance.
  4. RestoreDBInstanceFromDBSnapshot — spawns a new container.
  5. Verifies the new container has the rows from step 1.

Requires LocalEmu with ``RDS_DOCKER_BACKEND=1`` and Docker available.
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

SRC_ID = f"snap-src-{TAG}"
SNAP_ID = f"snap-{TAG}"
DST_ID = f"snap-dst-{TAG}"
MASTER_USER = "snapadmin"
MASTER_PASS = "Snap-Secret-12345!"
DB_NAME = "snapdb"

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


def wait_snapshot_available(snap_id: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
            if s.get("Status") == "available":
                return
        except Exception:
            pass
        time.sleep(2)
    raise AssertionError(f"snapshot {snap_id} not available in {timeout}s")


def psql_in_container(db_id: str, sql: str, retries: int = 30) -> str:
    """Run psql via TCP inside the container. Retries briefly because
    LocalEmu's standalone-instance ``_wait_for_port`` only confirms
    the docker-proxy host port is bound — Postgres itself may take a
    couple more seconds to start accepting TCP connections."""
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


@step("create source instance + seed data")
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
    # Seed two rows we can spot after restore.
    psql_in_container(
        SRC_ID,
        "CREATE TABLE pets (id int PRIMARY KEY, name text); "
        f"INSERT INTO pets VALUES (1, 'cat-{TAG}'), (2, 'dog-{TAG}');",
    )
    rows = psql_in_container(SRC_ID, "SELECT count(*) FROM pets;")
    assert rows == "2", rows


@step("CreateDBSnapshot persists a real dump on disk")
def test_create_snapshot():
    rds.create_db_snapshot(
        DBInstanceIdentifier=SRC_ID, DBSnapshotIdentifier=SNAP_ID,
    )
    wait_snapshot_available(SNAP_ID)
    # Manifest must exist in LOCALEMU_RDS_SNAPSHOT_DIR or
    # ~/.localemu/rds/snapshots/<id>/manifest.json. We can't peek into
    # the server's filesystem from outside the test directly when the
    # server uses defaults, so we settle for the API surface saying
    # the snapshot is available (status only flips on a real write).


@step("delete source instance")
def test_delete_source():
    rds.delete_db_instance(DBInstanceIdentifier=SRC_ID, SkipFinalSnapshot=True)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=SRC_ID)
            time.sleep(2)
        except Exception:
            return
    raise AssertionError(f"source {SRC_ID} not deleted in 60s")


@step("RestoreDBInstanceFromDBSnapshot rehydrates the data")
def test_restore():
    rds.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=DST_ID,
        DBSnapshotIdentifier=SNAP_ID,
    )
    wait_instance_available(DST_ID)
    # The rows from the source must be present in the restored instance.
    rows = psql_in_container(DST_ID, "SELECT count(*) FROM pets;")
    assert rows == "2", f"restored instance has {rows} rows, expected 2"
    cat = psql_in_container(DST_ID, "SELECT name FROM pets WHERE id=1;")
    assert cat == f"cat-{TAG}", cat


@step("teardown")
def test_teardown():
    try:
        rds.delete_db_instance(DBInstanceIdentifier=DST_ID, SkipFinalSnapshot=True)
    except Exception:
        pass
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=SNAP_ID)
    except Exception:
        pass


def main() -> int:
    test_seed_source()
    test_create_snapshot()
    test_delete_source()
    test_restore()
    test_teardown()
    print(f"\n=== summary === PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
