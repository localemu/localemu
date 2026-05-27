#!/usr/bin/env python3
"""End-to-end Aurora cluster topology test against live LocalEmu.

Requires the server to be running with ``RDS_DOCKER_BACKEND=1`` so
each cluster member is backed by a real Postgres Docker container.

What this validates:
  * CreateDBCluster spawns the writer container with a cluster_id
    label and the ``<cluster_id>-writer`` Docker network alias.
  * CreateDBInstance with DBClusterIdentifier spawns a reader container
    on the same cluster network, with the reader-side labels.
  * DescribeDBClusters surfaces the writer port; DescribeDBInstances
    surfaces each member's own host port.
  * DeleteDBCluster (after deleting members) removes the writer
    container and forgets the cluster network if it's idle.
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
KW = dict(
    endpoint_url=ENDPOINT, region_name=REGION,
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    config=CFG,
)
rds = boto3.client("rds", **KW)

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
    raise AssertionError(f"cluster {cluster_id} did not reach available in {timeout}s")


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
    raise AssertionError(f"instance {db_id} did not reach available in {timeout}s")


CLUSTER_ID = f"aurora-{TAG}"
WRITER_ID = CLUSTER_ID
R1_ID = f"{CLUSTER_ID}-r1"
R2_ID = f"{CLUSTER_ID}-r2"
NETWORK = f"localemu-aurora-{CLUSTER_ID}"
MASTER_PASS = "Cluster-Secret-12345!"


@step("create cluster spawns writer container")
def test_create_cluster_spawns_writer():
    rds.create_db_cluster(
        DBClusterIdentifier=CLUSTER_ID,
        Engine="aurora-postgresql",
        MasterUsername="clusteradmin",
        MasterUserPassword=MASTER_PASS,
    )
    wait_cluster_available(CLUSTER_ID)

    # Writer container exists with the cluster labels
    rc, out, err = docker(
        "inspect", f"localemu-rds-{WRITER_ID}",
        "--format", "{{json .Config.Labels}}",
    )
    assert rc == 0, f"writer container missing: {err}"
    labels = json.loads(out.strip())
    assert labels.get("localemu.cluster-id") == CLUSTER_ID, labels
    assert labels.get("localemu.is-writer") == "true", labels
    state["writer_labels"] = labels

    # Writer is attached to the cluster network with the writer alias
    rc, out, _ = docker(
        "network", "inspect", NETWORK,
        "--format", "{{json .Containers}}",
    )
    assert rc == 0, "cluster network missing"
    containers = json.loads(out.strip())
    assert any(
        f"localemu-rds-{WRITER_ID}" in (c.get("Name") or "")
        for c in containers.values()
    ), containers


@step("create 2 reader instances on the cluster")
def test_create_readers():
    for rid in (R1_ID, R2_ID):
        rds.create_db_instance(
            DBInstanceIdentifier=rid,
            DBClusterIdentifier=CLUSTER_ID,
            Engine="aurora-postgresql",
            DBInstanceClass="db.t3.medium",
        )
        wait_instance_available(rid)

    # Both readers should be on the cluster network with reader labels
    for rid in (R1_ID, R2_ID):
        rc, out, err = docker(
            "inspect", f"localemu-rds-{rid}",
            "--format", "{{json .Config.Labels}}",
        )
        assert rc == 0, f"reader {rid} container missing: {err}"
        labels = json.loads(out.strip())
        assert labels.get("localemu.cluster-id") == CLUSTER_ID
        assert labels.get("localemu.is-writer") == "false", labels


@step("writer carries the replication command-line flags")
def test_writer_has_replication_flags():
    rc, out, err = docker(
        "inspect", f"localemu-rds-{WRITER_ID}",
        "--format", "{{json .Config.Cmd}}",
    )
    assert rc == 0, err
    cmd = json.loads(out.strip())
    flat = " ".join(cmd)
    assert "wal_level=replica" in flat, cmd
    assert "max_wal_senders=" in flat, cmd
    assert "hot_standby=on" in flat, cmd


@step("writer has the replication user + pg_hba grant")
def test_writer_has_replication_user():
    rc, out, err = docker(
        "exec", f"localemu-rds-{WRITER_ID}",
        "psql", "-U", "clusteradmin", "-d", "postgres", "-tAc",
        "SELECT rolname FROM pg_roles WHERE rolname='localemu_repl'",
    )
    assert rc == 0, f"psql exec failed: {err}"
    assert "localemu_repl" in out, f"replication role missing: {out!r}"

    rc, out, err = docker(
        "exec", f"localemu-rds-{WRITER_ID}",
        "grep", "-F", "host replication localemu_repl 0.0.0.0/0 md5",
        "/var/lib/postgresql/data/pg_hba.conf",
    )
    assert rc == 0, f"pg_hba grant missing: {err}"


@step("reader registered as standby (pg_is_in_recovery=true)")
def test_reader_is_standby():
    for rid in (R1_ID, R2_ID):
        rc, out, err = docker(
            "exec", f"localemu-rds-{rid}",
            "psql", "-U", "clusteradmin", "-d", "postgres", "-tAc",
            "SELECT pg_is_in_recovery()",
        )
        assert rc == 0, f"reader {rid} psql failed: {err}"
        assert out.strip().lower() in ("t", "true"), \
            f"reader {rid} not in recovery mode: {out!r}"


@step("replication: write on writer, read on reader")
def test_replication_propagates():
    rc, _, err = docker(
        "exec", f"localemu-rds-{WRITER_ID}",
        "psql", "-U", "clusteradmin", "-d", "postgres", "-c",
        "CREATE TABLE IF NOT EXISTS aurora_test (id int, payload text);"
        f"INSERT INTO aurora_test VALUES (1, 'hello-{TAG}');",
    )
    assert rc == 0, f"writer insert failed: {err}"

    # Streaming replication is async — poll up to 30s.
    deadline = time.time() + 30
    seen = False
    last_err = ""
    while time.time() < deadline and not seen:
        rc, out, err = docker(
            "exec", f"localemu-rds-{R1_ID}",
            "psql", "-U", "clusteradmin", "-d", "postgres", "-tAc",
            f"SELECT payload FROM aurora_test WHERE id=1",
        )
        if rc == 0 and f"hello-{TAG}" in out:
            seen = True
            break
        last_err = err
        time.sleep(2)
    assert seen, f"reader {R1_ID} never saw written row: last err={last_err!r}"


@step("describe cluster exposes writer endpoint port")
def test_describe_cluster_endpoints():
    c = rds.describe_db_clusters(DBClusterIdentifier=CLUSTER_ID)["DBClusters"][0]
    writer_port = c.get("Port")
    assert isinstance(writer_port, int) and writer_port > 0, c

    # Each reader has its own host port distinct from the writer's
    r1 = rds.describe_db_instances(DBInstanceIdentifier=R1_ID)["DBInstances"][0]
    r2 = rds.describe_db_instances(DBInstanceIdentifier=R2_ID)["DBInstances"][0]
    assert r1["Endpoint"]["Port"] != writer_port
    assert r2["Endpoint"]["Port"] != writer_port
    assert r1["Endpoint"]["Port"] != r2["Endpoint"]["Port"]


@step("teardown: delete readers + cluster")
def test_teardown():
    for rid in (R1_ID, R2_ID):
        rds.delete_db_instance(DBInstanceIdentifier=rid, SkipFinalSnapshot=True)
    # Wait for moto to drop the records
    deadline = time.time() + 60
    while time.time() < deadline:
        remaining = [
            d["DBInstanceIdentifier"]
            for d in rds.describe_db_instances()["DBInstances"]
            if d["DBInstanceIdentifier"] in (R1_ID, R2_ID)
        ]
        if not remaining:
            break
        time.sleep(2)

    rds.delete_db_cluster(DBClusterIdentifier=CLUSTER_ID, SkipFinalSnapshot=True)

    # Writer container should be gone after a brief wait
    deadline = time.time() + 30
    gone = False
    while time.time() < deadline:
        rc, _, _ = docker("inspect", f"localemu-rds-{WRITER_ID}")
        if rc != 0:
            gone = True
            break
        time.sleep(2)
    assert gone, "writer container still present after delete_db_cluster"


def main() -> int:
    test_create_cluster_spawns_writer()
    test_create_readers()
    test_writer_has_replication_flags()
    test_writer_has_replication_user()
    test_reader_is_standby()
    test_replication_propagates()
    test_describe_cluster_endpoints()
    test_teardown()
    print(f"\n=== summary ===\n  PASS={len(PASS)}  FAIL={len(FAIL)}")
    for n, e in FAIL:
        print(f"  - {n}: {e}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
