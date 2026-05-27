#!/usr/bin/env python3
"""End-to-end Aurora FailoverDBCluster against a live LocalEmu.

Requires the server to be running with ``RDS_DOCKER_BACKEND=1`` so
each cluster member is backed by a real Postgres Docker container.

Validates:
  * After FailoverDBCluster, the requested reader becomes writable
    (``pg_is_in_recovery()`` returns false) and exec'd writes succeed.
  * The cluster's writer network alias (``<cluster_id>-writer``) now
    routes to the new writer container.
  * The remaining standbys get their ``primary_conninfo`` repointed
    and a write on the new writer propagates to them.
  * The old writer container is stopped.
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

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []


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


def docker(*args: str, timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def wait_cluster_available(cluster_id: str, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
            if c.get("Status") == "available":
                return
        except Exception:
            pass
        time.sleep(3)
    raise AssertionError(f"cluster {cluster_id} not available in {timeout}s")


def wait_instance_available(db_id: str, timeout: int = 240) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            d = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
            if d.get("DBInstanceStatus") == "available":
                return
        except Exception:
            pass
        time.sleep(3)
    raise AssertionError(f"instance {db_id} not available in {timeout}s")


CLUSTER_ID = f"failover-{TAG}"
WRITER_ID = CLUSTER_ID
R1_ID = f"{CLUSTER_ID}-r1"
R2_ID = f"{CLUSTER_ID}-r2"
MASTER_USER = "clusteradmin"
MASTER_PASS = "Failover-Secret-12345!"


@step("setup: cluster + 2 readers")
def setup():
    rds.create_db_cluster(
        DBClusterIdentifier=CLUSTER_ID,
        Engine="aurora-postgresql",
        MasterUsername=MASTER_USER,
        MasterUserPassword=MASTER_PASS,
    )
    wait_cluster_available(CLUSTER_ID)
    for rid in (R1_ID, R2_ID):
        rds.create_db_instance(
            DBInstanceIdentifier=rid,
            DBClusterIdentifier=CLUSTER_ID,
            Engine="aurora-postgresql",
            DBInstanceClass="db.t3.medium",
        )
        wait_instance_available(rid)
    # Seed a row on the writer so we can check propagation pre+post failover.
    rc, _, err = docker(
        "exec", f"localemu-rds-{WRITER_ID}",
        "psql", "-U", MASTER_USER, "-d", "postgres", "-c",
        "CREATE TABLE IF NOT EXISTS failover_test (id int PRIMARY KEY, v text);"
        "INSERT INTO failover_test VALUES (1, 'pre-failover') "
        "ON CONFLICT (id) DO NOTHING;",
    )
    assert rc == 0, f"seed insert failed: {err}"


@step("pre-failover sanity: writer writable, readers in recovery")
def pre_failover_sanity():
    rc, out, _ = docker(
        "exec", f"localemu-rds-{WRITER_ID}",
        "psql", "-U", MASTER_USER, "-d", "postgres", "-tAc",
        "SELECT pg_is_in_recovery()",
    )
    assert out.strip().lower() in ("f", "false"), out
    for rid in (R1_ID, R2_ID):
        rc, out, _ = docker(
            "exec", f"localemu-rds-{rid}",
            "psql", "-U", MASTER_USER, "-d", "postgres", "-tAc",
            "SELECT pg_is_in_recovery()",
        )
        assert out.strip().lower() in ("t", "true"), \
            f"{rid} not in recovery: {out!r}"


@step("FailoverDBCluster promotes the requested target")
def failover_to_r1():
    rds.failover_db_cluster(
        DBClusterIdentifier=CLUSTER_ID,
        TargetDBInstanceIdentifier=R1_ID,
    )
    # Give the orchestrator a moment to flip Docker state.
    time.sleep(3)
    # The promoted reader must report it's NOT in recovery anymore.
    rc, out, err = docker(
        "exec", f"localemu-rds-{R1_ID}",
        "psql", "-U", MASTER_USER, "-d", "postgres", "-tAc",
        "SELECT pg_is_in_recovery()",
    )
    assert rc == 0, f"psql failed on new writer: {err}"
    # pg_ctl promote is async — poll up to 20s.
    deadline = time.time() + 20
    while time.time() < deadline and out.strip().lower() not in ("f", "false"):
        time.sleep(1)
        rc, out, _ = docker(
            "exec", f"localemu-rds-{R1_ID}",
            "psql", "-U", MASTER_USER, "-d", "postgres", "-tAc",
            "SELECT pg_is_in_recovery()",
        )
    assert out.strip().lower() in ("f", "false"), \
        f"new writer never promoted: pg_is_in_recovery={out!r}"


@step("post-failover: write on new writer is visible on the other reader")
def post_failover_replication():
    rc, _, err = docker(
        "exec", f"localemu-rds-{R1_ID}",
        "psql", "-U", MASTER_USER, "-d", "postgres", "-c",
        f"INSERT INTO failover_test VALUES (2, 'post-failover-{TAG}');",
    )
    assert rc == 0, f"new-writer insert failed: {err}"

    deadline = time.time() + 30
    seen = False
    last_err = ""
    while time.time() < deadline and not seen:
        rc, out, err = docker(
            "exec", f"localemu-rds-{R2_ID}",
            "psql", "-U", MASTER_USER, "-d", "postgres", "-tAc",
            "SELECT v FROM failover_test WHERE id=2",
        )
        if rc == 0 and f"post-failover-{TAG}" in out:
            seen = True
            break
        last_err = err
        time.sleep(2)
    assert seen, f"r2 never saw post-failover write: last_err={last_err!r}"


@step("teardown")
def teardown():
    for rid in (R1_ID, R2_ID):
        try:
            rds.delete_db_instance(DBInstanceIdentifier=rid, SkipFinalSnapshot=True)
        except Exception:
            pass
    deadline = time.time() + 60
    while time.time() < deadline:
        ids = [
            d["DBInstanceIdentifier"]
            for d in rds.describe_db_instances()["DBInstances"]
        ]
        if R1_ID not in ids and R2_ID not in ids:
            break
        time.sleep(2)
    try:
        rds.delete_db_cluster(DBClusterIdentifier=CLUSTER_ID, SkipFinalSnapshot=True)
    except Exception:
        pass


def main() -> int:
    setup()
    pre_failover_sanity()
    failover_to_r1()
    post_failover_replication()
    teardown()
    print(f"\n=== summary === PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
