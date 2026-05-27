#!/usr/bin/env python3
"""Real-infra E2E test for the LocalEmu EKS provider.

Exercises every meaningful EKS feature end-to-end against a live LocalEmu
instance with ``EKS_K8S_PROVIDER=k3d``. No mocks. Each step prints PASS or
FAIL with a duration and a one-line reason; the final summary lists all
results and exits non-zero iff any step failed.

Prerequisites (the test will NOT install these for you):
  * LocalEmu running on LOCALEMU_ENDPOINT (default http://localhost:4566)
    with ``EKS_K8S_PROVIDER=k3d`` in its environment.
  * ``k3d`` and ``kubectl`` on PATH. The test checks for k3d first and,
    if missing on macOS, attempts ``brew install k3d`` as a one-time
    setup step — the result is reported in the summary.
  * Docker daemon up (k3d uses docker under the hood).

Usage::

    EKS_K8S_PROVIDER=k3d localemu start   # in one shell
    python tests/e2e/docker_emulation/test_eks.py   # in another

Cleanup: the k3d cluster is force-destroyed even on test failure (via a
try/finally around the main run).
"""
from __future__ import annotations

import os
import random
import shutil
import string
import subprocess
import sys
import time
import uuid

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
ACCOUNT = "000000000000"

RAND = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
CLUSTER_NAME = f"e2e-eks-{RAND}"
K3D_NAME = f"localemu-eks-{CLUSTER_NAME}"  # must match cluster_manager._k3d_cluster_name
NAMESPACE = "e2e-test"
NODEGROUP_NAME = f"ng-{RAND}"
KUBECONFIG_PATH = f"/tmp/e2e-eks-kubeconfig-{RAND}.yaml"

CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=120)
KW = dict(
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    config=CFG,
)

eks = boto3.client("eks", **KW)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []
NOTES: list[str] = []


# ---------------------------------------------------------------------------
# Step framework
# ---------------------------------------------------------------------------
def step(name: str):
    """Decorator: runs ``fn`` in a tracked step; records PASS / FAIL."""

    def deco(fn):
        def wrap(*a, **k):
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn(*a, **k)
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


def run(
    cmd: list[str],
    timeout: int = 30,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Thin wrapper around ``subprocess.run`` with default capture + text."""
    print(f"  $ {' '.join(cmd)}", flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.stdout:
        out = r.stdout if len(r.stdout) < 2000 else r.stdout[:2000] + "...<truncated>"
        print(f"    stdout: {out.rstrip()}", flush=True)
    if r.stderr and r.returncode != 0:
        err = r.stderr if len(r.stderr) < 2000 else r.stderr[:2000] + "...<truncated>"
        print(f"    stderr: {err.rstrip()}", flush=True)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} exited {r.returncode}: {r.stderr or r.stdout}"
        )
    return r


def kubectl(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Invoke kubectl with the test's kubeconfig."""
    return run(
        ["kubectl", "--kubeconfig", KUBECONFIG_PATH, *args],
        timeout=timeout,
    )


state: dict = {}


# ---------------------------------------------------------------------------
# 1. Provider prerequisite: k3d (and kubectl) binaries
# ---------------------------------------------------------------------------
@step("01-k3d-binary-available")
def check_k3d() -> None:
    """Verify k3d is installed; on macOS, attempt ``brew install k3d`` once."""
    if shutil.which("k3d") is None:
        # One-time setup on macOS only
        if sys.platform == "darwin" and shutil.which("brew"):
            print("  k3d missing; running `brew install k3d` (one-time setup)")
            r = run(["brew", "install", "k3d"], timeout=300)
            NOTES.append(
                f"Performed one-time setup: `brew install k3d` "
                f"(exit={r.returncode})"
            )
            assert r.returncode == 0, f"brew install k3d failed: {r.stderr}"
        else:
            raise AssertionError(
                "k3d not on PATH and brew not available. "
                "Install from https://k3d.io/"
            )
    r = run(["k3d", "version"], timeout=10)
    assert r.returncode == 0, f"k3d version returned {r.returncode}"
    assert shutil.which("kubectl") is not None, "kubectl not on PATH"
    r = run(["kubectl", "version", "--client", "-o", "yaml"], timeout=10)
    assert r.returncode == 0, "kubectl --client failed"


# ---------------------------------------------------------------------------
# 2. CreateCluster
# ---------------------------------------------------------------------------
@step("02-create-cluster")
def create_cluster() -> None:
    """CreateCluster via boto3; name e2e-eks-<rand>, version 1.30, fake role."""
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/fake-eks-service-role"
    resp = eks.create_cluster(
        name=CLUSTER_NAME,
        version="1.30",
        roleArn=role_arn,
        resourcesVpcConfig={
            "subnetIds": ["subnet-fake1", "subnet-fake2"],
            "securityGroupIds": ["sg-fake"],
        },
    )
    cluster = resp.get("cluster") or {}
    print(f"  CreateCluster returned status={cluster.get('status')}")
    assert cluster.get("name") == CLUSTER_NAME, (
        f"CreateCluster returned wrong name: {cluster.get('name')}"
    )
    # PARITY-09: provider returns CREATING immediately, ACTIVE comes later
    assert cluster.get("status") in ("CREATING", "ACTIVE"), (
        f"Unexpected initial status: {cluster.get('status')}"
    )
    state["created"] = True


# ---------------------------------------------------------------------------
# 3. Wait for ACTIVE
# ---------------------------------------------------------------------------
@step("03-wait-cluster-active")
def wait_active() -> None:
    """Poll DescribeCluster until status ACTIVE (k3d cluster create ~60-120s)."""
    deadline = time.time() + 300  # 5 min for slow first pull of k3s image
    last_status = "unknown"
    while time.time() < deadline:
        try:
            r = eks.describe_cluster(name=CLUSTER_NAME)
            last_status = r["cluster"].get("status")
            print(f"  status={last_status} ({int(deadline - time.time())}s left)")
            if last_status == "ACTIVE":
                return
            if last_status == "CREATE_FAILED":
                raise AssertionError(
                    "Cluster creation failed (see LocalEmu logs for k3d error)"
                )
        except ClientError as e:
            print(f"  DescribeCluster error: {e}")
        time.sleep(5)
    raise AssertionError(
        f"Cluster never became ACTIVE within 300s (last status={last_status})"
    )


# ---------------------------------------------------------------------------
# 4. DescribeCluster: endpoint + CA populated
# ---------------------------------------------------------------------------
@step("04-describe-cluster-returns-endpoint-and-ca")
def describe_cluster() -> None:
    """Endpoint URL and certificateAuthority.data must be populated."""
    r = eks.describe_cluster(name=CLUSTER_NAME)
    cluster = r["cluster"]
    endpoint = cluster.get("endpoint") or ""
    ca = (cluster.get("certificateAuthority") or {}).get("data") or ""
    print(f"  endpoint={endpoint}")
    print(f"  ca len={len(ca)} (first 40 chars: {ca[:40]}...)")
    assert endpoint.startswith("https://"), (
        f"Endpoint not populated or not https://: {endpoint!r}"
    )
    assert len(ca) > 100, (
        f"certificateAuthority.data looks empty/truncated (len={len(ca)})"
    )
    state["endpoint"] = endpoint
    state["ca"] = ca
    # Extra: AWS-parity fields added by provider.py _handle_describe_cluster
    assert cluster.get("platformVersion"), "platformVersion missing"
    assert (cluster.get("kubernetesNetworkConfig") or {}).get("serviceIpv4Cidr"), (
        "kubernetesNetworkConfig.serviceIpv4Cidr missing"
    )
    oidc = ((cluster.get("identity") or {}).get("oidc") or {}).get("issuer") or ""
    assert oidc.startswith("https://oidc.eks."), f"identity.oidc.issuer missing: {oidc!r}"


# ---------------------------------------------------------------------------
# 5. Get kubeconfig via `k3d kubeconfig get`
# ---------------------------------------------------------------------------
@step("05-get-kubeconfig-from-k3d")
def get_kubeconfig() -> None:
    """Shell out to ``k3d kubeconfig get <k3d_name>`` and write to /tmp."""
    r = run(["k3d", "kubeconfig", "get", K3D_NAME], timeout=30)
    assert r.returncode == 0, (
        f"k3d kubeconfig get failed: {r.stderr or r.stdout}"
    )
    kubeconfig = r.stdout
    assert "apiVersion" in kubeconfig and "clusters:" in kubeconfig, (
        "kubeconfig YAML looks malformed"
    )
    with open(KUBECONFIG_PATH, "w") as f:
        f.write(kubeconfig)
    os.chmod(KUBECONFIG_PATH, 0o600)
    print(f"  wrote kubeconfig to {KUBECONFIG_PATH} ({len(kubeconfig)} bytes)")


# ---------------------------------------------------------------------------
# 6. kubectl get nodes
# ---------------------------------------------------------------------------
@step("06-kubectl-get-nodes-ready")
def kubectl_get_nodes() -> None:
    """At least one node must be Ready."""
    # Small grace window — k3d `--wait` should already have returned, but
    # the node controller may still be marking the node Ready.
    deadline = time.time() + 60
    last_out = ""
    while time.time() < deadline:
        r = kubectl("get", "nodes", "--no-headers")
        last_out = r.stdout
        if r.returncode == 0:
            ready = [
                ln for ln in r.stdout.strip().splitlines()
                if " Ready" in f" {ln} "
            ]
            if ready:
                state["initial_node_count"] = len(
                    r.stdout.strip().splitlines()
                )
                print(f"  initial_node_count={state['initial_node_count']}")
                return
        time.sleep(3)
    raise AssertionError(f"No Ready node after 60s; last output:\n{last_out}")


# ---------------------------------------------------------------------------
# 7. Create namespace
# ---------------------------------------------------------------------------
@step("07-kubectl-create-namespace")
def create_namespace() -> None:
    r = kubectl("create", "namespace", NAMESPACE)
    assert r.returncode == 0, f"create ns failed: {r.stderr}"


# ---------------------------------------------------------------------------
# 8. Run nginx pod
# ---------------------------------------------------------------------------
@step("08-kubectl-run-nginx")
def run_nginx() -> None:
    # k3s provisions the `default` service account a few seconds after
    # the namespace is created. `kubectl run` fails fast if it isn't
    # there yet — retry until it exists, then run the pod.
    deadline = time.time() + 30
    while time.time() < deadline:
        r = kubectl("get", "serviceaccount", "default", "-n", NAMESPACE)
        if r.returncode == 0:
            break
        time.sleep(2)
    r = kubectl(
        "run", "nginx",
        "--image=nginx:alpine",
        "--port=80",
        "-n", NAMESPACE,
    )
    assert r.returncode == 0, f"kubectl run nginx failed: {r.stderr}"


# ---------------------------------------------------------------------------
# 9. Wait for nginx Ready
# ---------------------------------------------------------------------------
@step("09-kubectl-wait-nginx-ready")
def wait_nginx() -> None:
    r = kubectl(
        "wait", "--for=condition=Ready",
        "pod/nginx", "-n", NAMESPACE,
        "--timeout=120s",
        timeout=180,
    )
    assert r.returncode == 0, (
        f"pod/nginx never reached Ready condition: {r.stderr}"
    )


# ---------------------------------------------------------------------------
# 10. kubectl exec nginx -- wget → nginx welcome page
# ---------------------------------------------------------------------------
@step("10-kubectl-exec-nginx-welcome")
def exec_nginx() -> None:
    r = kubectl(
        "exec", "nginx", "-n", NAMESPACE,
        "--",
        "wget", "-qO-", "http://localhost:80",
        timeout=30,
    )
    state["nginx_exec_output"] = r.stdout
    assert r.returncode == 0, (
        f"kubectl exec returned {r.returncode}: {r.stderr}"
    )
    assert "<title>" in r.stdout, (
        f"nginx welcome page not returned; got: {r.stdout[:500]!r}"
    )


# ---------------------------------------------------------------------------
# 11. CreateNodegroup → second node joins (agent)
# ---------------------------------------------------------------------------
@step("11-create-nodegroup-second-node-joins")
def create_nodegroup() -> None:
    """CreateNodegroup with desiredSize=1 should add one k3d agent node."""
    try:
        eks.create_nodegroup(
            clusterName=CLUSTER_NAME,
            nodegroupName=NODEGROUP_NAME,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            subnets=["subnet-fake1", "subnet-fake2"],
            nodeRole=f"arn:aws:iam::{ACCOUNT}:role/fake-nodegroup-role",
        )
        state["nodegroup_created"] = True
    except ClientError as e:
        # Some moto versions require instanceTypes/amiType — try fallback
        print(f"  first attempt failed ({e}); retrying with more fields")
        eks.create_nodegroup(
            clusterName=CLUSTER_NAME,
            nodegroupName=NODEGROUP_NAME,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            subnets=["subnet-fake1", "subnet-fake2"],
            nodeRole=f"arn:aws:iam::{ACCOUNT}:role/fake-nodegroup-role",
            instanceTypes=["t3.small"],
            amiType="AL2_x86_64",
            diskSize=20,
        )
        state["nodegroup_created"] = True

    initial = state.get("initial_node_count", 1)
    deadline = time.time() + 180
    last_count = initial
    while time.time() < deadline:
        r = kubectl("get", "nodes", "--no-headers")
        last_count = len([
            ln for ln in r.stdout.strip().splitlines() if ln.strip()
        ])
        print(f"  node count now={last_count} (initial={initial})")
        if last_count > initial:
            return
        time.sleep(5)
    raise AssertionError(
        f"Second node never joined: initial={initial}, final={last_count}"
    )


# ---------------------------------------------------------------------------
# 12. DeleteCluster → k3d cluster gone
# ---------------------------------------------------------------------------
@step("12-delete-cluster-k3d-gone")
def delete_cluster() -> None:
    """DeleteCluster via boto3; then verify k3d cluster is absent."""
    # Nodegroup must be deleted first per EKS rules, best-effort here.
    if state.get("nodegroup_created"):
        try:
            eks.delete_nodegroup(
                clusterName=CLUSTER_NAME, nodegroupName=NODEGROUP_NAME,
            )
            # Short wait for moto to drop the record
            for _ in range(20):
                try:
                    eks.describe_nodegroup(
                        clusterName=CLUSTER_NAME,
                        nodegroupName=NODEGROUP_NAME,
                    )
                    time.sleep(2)
                except ClientError:
                    break
        except ClientError as e:
            print(f"  delete_nodegroup best-effort failed: {e}")

    eks.delete_cluster(name=CLUSTER_NAME)

    # The provider deletes k3d in a background thread → poll k3d.
    deadline = time.time() + 120
    while time.time() < deadline:
        r = run(["k3d", "cluster", "list", "-o", "json"], timeout=15)
        if r.returncode != 0:
            time.sleep(2)
            continue
        import json as _json
        try:
            clusters = _json.loads(r.stdout or "[]")
        except ValueError:
            clusters = []
        names = [c.get("name") for c in clusters]
        print(f"  k3d clusters now: {names}")
        if K3D_NAME not in names:
            state["cluster_deleted"] = True
            return
        time.sleep(3)
    raise AssertionError(
        f"k3d cluster {K3D_NAME} still present 120s after DeleteCluster"
    )


# ---------------------------------------------------------------------------
# Cleanup: force-delete k3d cluster even on earlier failure
# ---------------------------------------------------------------------------
def cleanup() -> None:
    print("\n=== CLEANUP ===", flush=True)
    # If step 12 already cleaned up we're done.
    if state.get("cluster_deleted"):
        return
    # Best-effort EKS DeleteCluster (provider will background-delete k3d).
    if state.get("created"):
        try:
            eks.delete_cluster(name=CLUSTER_NAME)
        except ClientError as e:
            print(f"  cleanup: DeleteCluster: {e}")
    # Force: `k3d cluster delete` directly, always.
    try:
        r = subprocess.run(
            ["k3d", "cluster", "delete", K3D_NAME],
            capture_output=True, text=True, timeout=120,
        )
        print(
            f"  k3d cluster delete {K3D_NAME}: rc={r.returncode}\n"
            f"    stdout={r.stdout.strip()}\n"
            f"    stderr={r.stderr.strip()}"
        )
    except Exception as e:
        print(f"  cleanup: k3d delete failed: {e}")
    # Remove the temp kubeconfig.
    try:
        if os.path.exists(KUBECONFIG_PATH):
            os.remove(KUBECONFIG_PATH)
    except OSError:
        pass


def main() -> int:
    fns = [
        check_k3d,
        create_cluster,
        wait_active,
        describe_cluster,
        get_kubeconfig,
        kubectl_get_nodes,
        create_namespace,
        run_nginx,
        wait_nginx,
        exec_nginx,
        create_nodegroup,
        delete_cluster,
    ]
    try:
        for fn in fns:
            fn()
    finally:
        cleanup()

    total = len(PASS) + len(FAIL)
    print("\n" + "=" * 60)
    print(f"EKS E2E SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)} of {total}")
    print("=" * 60)
    for n, dt in PASS:
        print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, e in FAIL:
        print(f"  FAIL  {n}  -- {e[:300]}")

    if NOTES:
        print("\nNOTES:")
        for note in NOTES:
            print(f"  * {note}")

    if "nginx_exec_output" in state:
        print(
            "\nRaw nginx exec output (first 300 chars):\n"
            f"  {state['nginx_exec_output'][:300]!r}"
        )

    return 0 if not FAIL else 1


if __name__ == "__main__":
    # Basic environment sanity print.
    print(
        f"LocalEmu endpoint: {ENDPOINT}\n"
        f"Region: {REGION}\n"
        f"EKS cluster name: {CLUSTER_NAME}\n"
        f"k3d cluster name: {K3D_NAME}\n"
    )
    sys.exit(main())
