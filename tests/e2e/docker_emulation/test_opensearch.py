#!/usr/bin/env python3
"""Deep end-to-end test for the LocalEmu OpenSearch Docker backend.

This test does not rely on any mock.  It drives a live LocalEmu instance
(`OPENSEARCH_DOCKER_BACKEND=1`) through the full user journey: domain
creation, indexing, search, aggregation, update, delete, multi-index
queries, settings changes, container-restart persistence, config update
and finally domain deletion with volume removal.

Every step prints ``PASS``/``FAIL`` with a duration so the output is
readable at a glance.  The summary at the end reports pass/fail counts
and the answer to the key question: "did data survive a container
restart?".

Usage::

    OPENSEARCH_DOCKER_BACKEND=1 localemu start           # shell 1
    python tests/e2e/docker_emulation/test_opensearch.py # shell 2

The domain, container and named data volume are always cleaned up on
exit, even if a step fails part-way.
"""
from __future__ import annotations

import json
import os
import random
import string
import subprocess
import sys
import time
import uuid

import boto3
import requests
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

RAND = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
DOMAIN_NAME = f"e2e-os-{RAND}"
CONTAINER_NAME = f"localemu-opensearch-{DOMAIN_NAME}"
VOLUME_NAME = f"localemu-opensearch-{DOMAIN_NAME}-data"

CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=120)
KW = dict(
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    config=CFG,
)

opensearch = boto3.client("opensearch", **KW)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []
DATA_PERSISTED: bool | None = None

# Shared state between steps (host port, counts, doc versions...)
STATE: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def step(name: str):
    """Decorator: turns a function into a tracked test step with timings."""
    def deco(fn):
        def wrap(*a, **k):
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn(*a, **k)
                dt = time.time() - t0
                print(f"  PASS [{dt:.1f}s]", flush=True)
                PASS.append((name, dt))
            except AssertionError as exc:
                dt = time.time() - t0
                print(f"  FAIL [{dt:.1f}s] {exc}", flush=True)
                FAIL.append((name, str(exc)))
            except Exception as exc:  # noqa: BLE001
                dt = time.time() - t0
                print(f"  ERROR [{dt:.1f}s] {type(exc).__name__}: {exc}",
                      flush=True)
                FAIL.append((name, f"{type(exc).__name__}: {exc}"))
        return wrap
    return deco


def docker(*args: str, timeout: int = 30) -> tuple[int, str, str]:
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def os_url() -> str:
    port = STATE.get("host_port")
    assert port, "host_port is unknown — did step 03 run?"
    return f"http://localhost:{port}"


def wait_green_or_yellow(deadline_s: float = 120.0) -> str:
    """Poll the cluster health until it reports green/yellow, or timeout."""
    url = f"{os_url()}/_cluster/health"
    deadline = time.time() + deadline_s
    last = ""
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                last = resp.json().get("status", "")
                if last in ("green", "yellow"):
                    return last
        except Exception as exc:  # noqa: BLE001
            last = f"error: {exc}"
        time.sleep(2)
    raise AssertionError(f"cluster never reached green/yellow (last={last!r})")


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
@step("01-CreateDomain")
def s01_create_domain():
    resp = opensearch.create_domain(
        DomainName=DOMAIN_NAME,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
    )
    status = resp["DomainStatus"]
    assert status["DomainName"] == DOMAIN_NAME
    assert status.get("Created") is True
    print(f"  domain created: {status['DomainName']} engine={status.get('EngineVersion')}")


@step("02-WaitDomainActive")
def s02_wait_active():
    """Wait for (a) DescribeDomain Processing=False and (b) cluster health."""
    deadline = time.time() + 240
    processing = True
    while time.time() < deadline:
        rc, out, _ = docker(
            "inspect", "--format", "{{.State.Running}}", CONTAINER_NAME,
            timeout=10,
        )
        if rc == 0 and out.strip() == "true":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"container {CONTAINER_NAME} never started")

    # DescribeDomain should eventually say Processing=False
    while time.time() < deadline:
        info = opensearch.describe_domain(DomainName=DOMAIN_NAME)["DomainStatus"]
        processing = bool(info.get("Processing", True))
        if not processing:
            break
        time.sleep(3)
    assert not processing, "DescribeDomain still reports Processing=True"

    endpoint = info.get("Endpoint") or ""
    assert endpoint, f"no Endpoint in DescribeDomain: {info}"
    # Endpoint is "localhost:<port>" — remember the port for later steps
    if ":" in endpoint:
        STATE["host_port"] = int(endpoint.rsplit(":", 1)[-1])
    print(f"  Processing=False, Endpoint={endpoint}")


@step("03-DockerPort9200")
def s03_docker_port():
    rc, out, err = docker("port", CONTAINER_NAME, "9200/tcp", timeout=10)
    assert rc == 0, f"docker port failed rc={rc}: {err}"
    line = next((ln for ln in out.splitlines() if ln.strip()), "")
    assert ":" in line, f"unexpected docker port output: {out!r}"
    host_port = int(line.rsplit(":", 1)[-1])
    # sanity: matches Endpoint from DescribeDomain
    assert STATE["host_port"] == host_port, (
        f"docker port {host_port} disagrees with DescribeDomain Endpoint "
        f"port {STATE['host_port']}"
    )
    status = wait_green_or_yellow(deadline_s=180)
    print(f"  host port {host_port}, cluster status: {status}")


@step("04-IndexSingleDoc")
def s04_index_one():
    resp = requests.put(
        f"{os_url()}/test-index/_doc/1",
        json={"name": "alice", "age": 30},
        timeout=15,
    )
    assert resp.status_code in (200, 201), (
        f"PUT _doc/1 returned {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    assert body.get("result") == "created", f"expected created, got {body}"
    # refresh so the doc is visible immediately
    requests.post(f"{os_url()}/test-index/_refresh", timeout=10)
    print(f"  indexed id=1, result={body.get('result')}, version={body.get('_version')}")


@step("05-BulkIndex100")
def s05_bulk_index():
    lines = []
    for i in range(2, 102):  # ids 2..101 -> 100 docs
        lines.append(json.dumps({"index": {"_index": "test-index", "_id": str(i)}}))
        lines.append(json.dumps({
            "name": random.choice(["bob", "carol", "dave", "erin"]),
            "age": 20 + (i % 40),
        }))
    payload = "\n".join(lines) + "\n"
    resp = requests.post(
        f"{os_url()}/_bulk",
        data=payload,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=60,
    )
    assert resp.status_code == 200, f"bulk failed {resp.status_code}: {resp.text[:300]}"
    body = resp.json()
    assert body.get("errors") is False, (
        f"bulk had errors: {json.dumps(body, indent=2)[:800]}"
    )
    assert len(body.get("items", [])) == 100
    requests.post(f"{os_url()}/test-index/_refresh", timeout=10)
    print(f"  bulk inserted {len(body['items'])} docs, took={body.get('took')}ms")


@step("06-MatchAllSearch")
def s06_search_all():
    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"query": {"match_all": {}}, "size": 0},
        timeout=15,
    )
    assert resp.status_code == 200, f"search failed {resp.status_code}: {resp.text}"
    body = resp.json()
    total = body["hits"]["total"]
    total_val = total["value"] if isinstance(total, dict) else total
    assert total_val == 101, f"expected 101 docs, got {total_val}"
    print(f"  match_all -> hits.total={total_val}")


@step("07-TermQueryAlice")
def s07_term_alice():
    # "name" defaults to text; use match to hit the analyzer consistently
    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"query": {"match": {"name": "alice"}}, "size": 10},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    total = body["hits"]["total"]
    total_val = total["value"] if isinstance(total, dict) else total
    assert total_val == 1, f"expected exactly 1 alice, got {total_val}"
    src = body["hits"]["hits"][0]["_source"]
    assert src == {"name": "alice", "age": 30}, f"returned doc mismatch: {src}"
    print(f"  match name=alice -> total=1, source={src}")


@step("08-AvgAgeAggregation")
def s08_agg_avg():
    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"size": 0, "aggs": {"avg_age": {"avg": {"field": "age"}}}},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    val = body["aggregations"]["avg_age"]["value"]
    assert isinstance(val, (int, float)), f"avg_age.value not numeric: {val!r}"
    assert val > 0, f"avg_age should be > 0, got {val}"
    STATE["avg_age"] = val
    print(f"  avg(age) = {val:.2f}")


@step("09-UpdateDocument")
def s09_update_doc():
    # fetch current version
    resp = requests.get(f"{os_url()}/test-index/_doc/1", timeout=10)
    assert resp.status_code == 200, resp.text
    before = resp.json()
    before_ver = before["_version"]

    resp = requests.post(
        f"{os_url()}/test-index/_update/1",
        json={"doc": {"age": 31}},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("result") == "updated", body
    after_ver = body["_version"]
    assert after_ver > before_ver, (
        f"version did not increment: {before_ver} -> {after_ver}"
    )
    # confirm new field value
    resp = requests.get(f"{os_url()}/test-index/_doc/1", timeout=10)
    src = resp.json()["_source"]
    assert src["age"] == 31, f"expected age=31 post-update, got {src}"
    print(f"  version {before_ver} -> {after_ver}, age=31")


@step("10-DeleteDocConfirmCount")
def s10_delete_doc():
    resp = requests.delete(f"{os_url()}/test-index/_doc/2", timeout=10)
    assert resp.status_code == 200, resp.text
    assert resp.json().get("result") == "deleted", resp.json()
    requests.post(f"{os_url()}/test-index/_refresh", timeout=10)

    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"query": {"match_all": {}}, "size": 0},
        timeout=15,
    )
    total = resp.json()["hits"]["total"]
    total_val = total["value"] if isinstance(total, dict) else total
    assert total_val == 100, f"expected 100 docs after delete, got {total_val}"
    STATE["test_index_count"] = total_val
    print(f"  deleted id=2, remaining={total_val}")


@step("11-SecondIndexCrossSearch")
def s11_second_index():
    # index one nested doc
    doc = {
        "sku": "p1",
        "name": "widget",
        "price": 9.99,
        "specs": {"color": "red", "size": "M", "tags": ["new", "sale"]},
    }
    resp = requests.put(f"{os_url()}/products/_doc/p1", json=doc, timeout=15)
    assert resp.status_code in (200, 201), resp.text
    requests.post(f"{os_url()}/products/_refresh", timeout=10)

    # cross-index search
    resp = requests.post(
        f"{os_url()}/test-index,products/_search",
        json={"query": {"match_all": {}}, "size": 0},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    total = resp.json()["hits"]["total"]
    total_val = total["value"] if isinstance(total, dict) else total
    expected = STATE["test_index_count"] + 1
    assert total_val == expected, (
        f"cross-index total={total_val}, expected {expected}"
    )
    print(f"  cross-index hits={total_val}")


@step("12-UpdateIndexReplicas")
def s12_update_settings():
    resp = requests.put(
        f"{os_url()}/test-index/_settings",
        json={"index": {"number_of_replicas": 0}},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("acknowledged") is True, body
    # confirm read-back
    resp = requests.get(f"{os_url()}/test-index/_settings", timeout=10)
    settings = list(resp.json().values())[0]["settings"]["index"]
    assert settings["number_of_replicas"] == "0", settings
    print(f"  number_of_replicas=0, acknowledged=True")


@step("13-ClusterStatsDocs")
def s13_cluster_stats():
    resp = requests.get(f"{os_url()}/_cluster/stats", timeout=15)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    docs = body.get("indices", {}).get("docs", {})
    count = docs.get("count", 0)
    assert count >= 100, f"cluster docs.count={count}, expected >=100"
    print(f"  indices.docs.count={count}")


@step("14-RestartContainerPersistData")
def s14_restart_persist():
    global DATA_PERSISTED
    # snapshot count pre-restart
    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"query": {"match_all": {}}, "size": 0},
        timeout=15,
    )
    pre_total = resp.json()["hits"]["total"]
    pre_val = pre_total["value"] if isinstance(pre_total, dict) else pre_total

    # confirm volume exists
    rc, out, _ = docker("volume", "inspect", VOLUME_NAME, timeout=10)
    assert rc == 0, f"volume {VOLUME_NAME} not found before restart"

    rc, out, err = docker("restart", CONTAINER_NAME, timeout=60)
    assert rc == 0, f"docker restart failed: {err}"

    # Wait for cluster to come back
    wait_green_or_yellow(deadline_s=180)

    # re-query
    resp = requests.post(
        f"{os_url()}/test-index/_search",
        json={"query": {"match_all": {}}, "size": 0},
        timeout=15,
    )
    assert resp.status_code == 200, resp.text
    post_total = resp.json()["hits"]["total"]
    post_val = post_total["value"] if isinstance(post_total, dict) else post_total
    DATA_PERSISTED = post_val == pre_val and pre_val > 0
    assert DATA_PERSISTED, (
        f"data NOT persisted across restart: pre={pre_val}, post={post_val}"
    )
    # also re-check id=1 content
    resp = requests.get(f"{os_url()}/test-index/_doc/1", timeout=10)
    assert resp.status_code == 200, resp.text
    assert resp.json()["_source"]["age"] == 31, (
        f"id=1 lost updates after restart: {resp.json()}"
    )
    print(f"  pre={pre_val}, post={post_val}, data survived restart")


@step("15-UpdateDomainConfig")
def s15_update_domain_config():
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{REGION}:000000000000:domain/{DOMAIN_NAME}/*",
        }],
    })
    resp = opensearch.update_domain_config(
        DomainName=DOMAIN_NAME,
        AccessPolicies=policy,
    )
    cfg = resp["DomainConfig"]
    returned = cfg.get("AccessPolicies", {}).get("Options", "")
    assert returned == policy, f"AccessPolicies round-trip mismatch: {returned!r}"
    # confirm describe_domain_config reflects the change
    info = opensearch.describe_domain_config(DomainName=DOMAIN_NAME)
    stored = info["DomainConfig"]["AccessPolicies"]["Options"]
    assert stored == policy, f"DescribeDomainConfig did not persist policy: {stored!r}"
    print(f"  AccessPolicies updated ({len(policy)} chars) and read back intact")


@step("16-DeleteDomainAndVolume")
def s16_delete_domain():
    opensearch.delete_domain(DomainName=DOMAIN_NAME)

    # Wait for container to be gone
    deadline = time.time() + 60
    while time.time() < deadline:
        rc, _, _ = docker("inspect", CONTAINER_NAME, timeout=10)
        if rc != 0:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"container {CONTAINER_NAME} still exists after DeleteDomain"
        )

    # Wait for volume to be gone
    deadline = time.time() + 30
    while time.time() < deadline:
        rc, _, _ = docker("volume", "inspect", VOLUME_NAME, timeout=10)
        if rc != 0:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"volume {VOLUME_NAME} still exists after DeleteDomain"
        )
    print(f"  container and volume removed")


# ---------------------------------------------------------------------------
# Cleanup (runs on every exit, including failures)
# ---------------------------------------------------------------------------
def cleanup():
    """Always destroy the domain + container + volume, even on failure."""
    print("\n=== CLEANUP ===", flush=True)
    try:
        opensearch.delete_domain(DomainName=DOMAIN_NAME)
        print(f"  DeleteDomain OK")
    except opensearch.exceptions.ResourceNotFoundException:
        # already deleted by step 16 — happy path
        print(f"  DeleteDomain: already gone (expected after step 16)")
    except Exception as exc:  # noqa: BLE001
        print(f"  DeleteDomain: {type(exc).__name__}: {exc}")

    # Best-effort direct docker cleanup in case the API call failed
    rc, _, _ = docker("inspect", CONTAINER_NAME, timeout=10)
    if rc == 0:
        docker("rm", "-f", CONTAINER_NAME, timeout=30)
        print(f"  force-removed container {CONTAINER_NAME}")
    rc, _, _ = docker("volume", "inspect", VOLUME_NAME, timeout=10)
    if rc == 0:
        docker("volume", "rm", "-f", VOLUME_NAME, timeout=30)
        print(f"  force-removed volume {VOLUME_NAME}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    print(
        f"LocalEmu OpenSearch Docker E2E\n"
        f"  endpoint : {ENDPOINT}\n"
        f"  region   : {REGION}\n"
        f"  domain   : {DOMAIN_NAME}\n"
        f"  container: {CONTAINER_NAME}\n"
        f"  volume   : {VOLUME_NAME}\n",
        flush=True,
    )
    fns = [
        s01_create_domain,
        s02_wait_active,
        s03_docker_port,
        s04_index_one,
        s05_bulk_index,
        s06_search_all,
        s07_term_alice,
        s08_agg_avg,
        s09_update_doc,
        s10_delete_doc,
        s11_second_index,
        s12_update_settings,
        s13_cluster_stats,
        s14_restart_persist,
        s15_update_domain_config,
        s16_delete_domain,
    ]
    try:
        for fn in fns:
            fn()
    finally:
        # never skip cleanup — even on SIGINT we want the volume gone
        try:
            cleanup()
        except Exception as exc:  # noqa: BLE001
            print(f"  cleanup error: {exc}", flush=True)

    print("\n=== SUMMARY ===", flush=True)
    print(f"  PASS: {len(PASS)}")
    for name, dt in PASS:
        print(f"    {name:<40s} {dt:6.1f}s")
    print(f"  FAIL: {len(FAIL)}")
    for name, reason in FAIL:
        print(f"    {name:<40s} {reason}")
    if DATA_PERSISTED is None:
        print("  data-persisted-across-restart: NOT REACHED")
    else:
        print(f"  data-persisted-across-restart: {DATA_PERSISTED}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
