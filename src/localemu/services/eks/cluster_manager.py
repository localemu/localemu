"""k3d-backed Kubernetes cluster manager for EKS emulation.

Manages real k3s Kubernetes clusters via k3d for EKS CreateCluster calls.
Each EKS cluster maps to a k3d cluster running a real Kubernetes control plane.

BUG-09: TOCTOU port race is a known limitation. Between get_free_tcp_port()
and k3d's actual bind, another process could claim the port. This is an
accepted trade-off for local emulation.
"""

import base64
import json
import logging
import subprocess
import threading
from dataclasses import dataclass

import yaml

from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

K3D_CLUSTER_PREFIX = "localemu-eks"
K3D_CREATE_TIMEOUT = 180  # seconds

# PARITY-06: Map EKS Kubernetes versions to k3s image tags.
# Not all EKS versions have direct k3s equivalents. When an exact match
# is not available, we use the closest available k3s image.
# The k3s image tags follow the format: rancher/k3s:v<version>-k3s1
_EKS_TO_K3S_IMAGE: dict[str, str] = {
    "1.24": "rancher/k3s:v1.24.17-k3s1",
    "1.25": "rancher/k3s:v1.25.16-k3s4",
    "1.26": "rancher/k3s:v1.26.15-k3s1",
    "1.27": "rancher/k3s:v1.27.16-k3s1",
    "1.28": "rancher/k3s:v1.28.13-k3s1",
    "1.29": "rancher/k3s:v1.29.8-k3s1",
    "1.30": "rancher/k3s:v1.30.4-k3s1",
    "1.31": "rancher/k3s:v1.31.1-k3s1",
}


def _list_k3d_clusters() -> dict[str, dict]:
    """Return ``{k3d_cluster_name: info_dict}`` for every k3d cluster on
    this host. ``info_dict`` carries at least ``serverStatus`` (``"running"``,
    ``"stopped"``, or similar). Swallows errors and returns ``{}`` if k3d
    is missing, not installed, or returns malformed JSON."""
    try:
        result = subprocess.run(
            ["k3d", "cluster", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return {}
        clusters = json.loads(result.stdout or "[]")
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for entry in clusters:
        name = entry.get("name") or ""
        if not name:
            continue
        nodes = entry.get("nodes") or []
        running = any(
            (n.get("State") or {}).get("Running") for n in nodes if isinstance(n, dict)
        )
        out[name] = {
            "serverStatus": "running" if running else "stopped",
            "nodes": nodes,
        }
    return out


def _parse_kubeconfig(kubeconfig_yaml: str) -> tuple[str, str]:
    """Extract ``(server_url, base64_ca_cert)`` from a kubeconfig YAML
    blob. Returns ``("", "")`` on parse errors."""
    try:
        doc = yaml.safe_load(kubeconfig_yaml)
        clusters = (doc or {}).get("clusters") or []
        if not clusters:
            return "", ""
        first = clusters[0].get("cluster") or {}
        return first.get("server", ""), first.get("certificate-authority-data", "")
    except Exception:
        return "", ""


def _update_moto_cluster(
    account_id: str, region: str, cluster_name: str, info: "ClusterInfo",
) -> None:
    """Patch the moto EKS cluster record so DescribeCluster returns the
    post-restart endpoint + CA. Best-effort; moto's attribute shape has
    drifted across versions."""
    try:
        import moto.backends as mb

        backend = mb.get_backend("eks")
        region_map = backend.get(account_id) or {}
        region_backend = region_map.get(region) if isinstance(region_map, dict) else None
        if region_backend is None:
            return
        clusters = getattr(region_backend, "clusters", {}) or {}
        cluster = clusters.get(cluster_name)
        if cluster is None:
            return
        for attr, value in (
            ("endpoint", info.endpoint),
            ("certificate_authority", {"data": info.ca_cert_data}),
            ("status", "ACTIVE"),
        ):
            if hasattr(cluster, attr):
                try:
                    setattr(cluster, attr, value)
                except Exception:
                    pass
    except Exception:
        LOG.debug("Failed to patch moto EKS cluster %s", cluster_name, exc_info=True)


@dataclass
class ClusterInfo:
    """Tracks a running k3d cluster backing an EKS cluster."""

    name: str
    k3d_name: str
    endpoint: str
    ca_cert_data: str  # base64-encoded CA certificate
    api_port: int
    status: str = "CREATING"
    kubeconfig: str = ""


class K3dClusterManager:
    """Manages k3d clusters that back EKS API clusters.

    Each EKS cluster name maps to one k3d cluster running a real k3s
    Kubernetes control plane.

    BUG-03: Clusters are keyed by (account_id, region, name) tuple to support
    multi-account and multi-region isolation.
    """

    def __init__(self):
        # BUG-03: Key by (account, region, name) instead of just name
        self._clusters: dict[tuple[str, str, str], ClusterInfo] = {}
        self._lock = threading.Lock()
        self._k3d_verified = False

    def _cluster_key(self, name: str, account_id: str = "", region: str = "") -> tuple[str, str, str]:
        """Build a composite key for multi-account/region support (BUG-03)."""
        return (account_id or "default", region or "us-east-1", name)

    def _k3d_cluster_name(self, eks_name: str, account_id: str = "", region: str = "") -> str:
        """Map EKS cluster name to k3d cluster name.

        BUG-03: Include account/region in k3d name for uniqueness.
        """
        # Keep it short but unique
        suffix = ""
        if account_id and account_id != "000000000000":
            suffix += f"-{account_id[-4:]}"
        if region and region != "us-east-1":
            suffix += f"-{region.replace('-', '')[:8]}"
        return f"{K3D_CLUSTER_PREFIX}-{eks_name}{suffix}"

    def _verify_k3d(self) -> None:
        """Check that k3d is installed and reachable. Raises RuntimeError if not.

        ISSUE-04: the lock is held for the full probe (including subprocess.run)
        so that two concurrent callers cannot both shell out to ``k3d version``
        when _k3d_verified is still False. The probe is cheap (10s timeout,
        executed at most once per process) so holding the lock is acceptable.
        """
        with self._lock:  # BUG-07 fix: protect _k3d_verified read/write
            if self._k3d_verified:
                return
            try:
                result = subprocess.run(
                    ["k3d", "version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"k3d returned non-zero exit code: {result.returncode}\n"
                        f"stderr: {result.stderr}"
                    )
                self._k3d_verified = True
                LOG.info("k3d detected: %s", result.stdout.strip().split("\n")[0])
            except FileNotFoundError:
                raise RuntimeError(
                    "k3d is not installed. Install it with:\n"
                    "  curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash\n"
                    "Or via Homebrew:\n"
                    "  brew install k3d"
                )

    def create_cluster(
        self,
        name: str,
        kubernetes_version: str | None = None,
        account_id: str = "",
        region: str = "",
    ) -> ClusterInfo:
        """Create a k3d cluster backing an EKS cluster.

        :param name: the EKS cluster name
        :param kubernetes_version: optional Kubernetes version (e.g. "1.29")
        :param account_id: AWS account ID for multi-account support (BUG-03)
        :param region: AWS region for multi-region support (BUG-03)
        :returns: ClusterInfo with endpoint, CA cert, and kubeconfig
        :raises RuntimeError: if k3d is not installed or cluster creation fails
        """
        self._verify_k3d()

        key = self._cluster_key(name, account_id, region)

        # BUG-02 fix: duplicate guard
        with self._lock:
            if key in self._clusters:
                return self._clusters[key]

        k3d_name = self._k3d_cluster_name(name, account_id, region)
        api_port = get_free_tcp_port()

        LOG.info(
            "Creating k3d cluster %s (api_port=%s, k8s_version=%s)",
            k3d_name,
            api_port,
            kubernetes_version or "default",
        )

        # Build k3d cluster create command
        cmd = [
            "k3d",
            "cluster",
            "create",
            k3d_name,
            "--api-port",
            f"127.0.0.1:{api_port}",
            "--wait",
            "--timeout",
            "120s",
            "--no-lb",
            "--k3s-arg",
            "--disable=traefik@server:0",
        ]

        # PARITY-02/PARITY-06: Pass Kubernetes version via --image flag
        # Map EKS version to k3s image tag when available
        if kubernetes_version:
            # Normalize version (strip "v" prefix if present, handle "1.29.x" -> "1.29")
            ver = kubernetes_version.lstrip("v")
            major_minor = ".".join(ver.split(".")[:2])
            k3s_image = _EKS_TO_K3S_IMAGE.get(major_minor)
            if k3s_image:
                cmd.extend(["--image", k3s_image])
                LOG.info("Using k3s image %s for EKS version %s", k3s_image, kubernetes_version)
            else:
                LOG.info(
                    "No k3s image mapping for EKS version %s, using k3d default",
                    kubernetes_version,
                )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=K3D_CREATE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            # BUG-08 fix: clean up partial cluster on timeout
            LOG.warning("k3d cluster create timed out after %ds, cleaning up...", K3D_CREATE_TIMEOUT)
            try:
                subprocess.run(["k3d", "cluster", "delete", k3d_name], capture_output=True, timeout=30)
            except Exception:
                pass
            raise RuntimeError(f"k3d cluster create timed out after {K3D_CREATE_TIMEOUT}s")

        if result.returncode != 0:
            raise RuntimeError(
                f"k3d cluster create failed (exit {result.returncode}):\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )

        LOG.info("k3d cluster %s created, extracting kubeconfig...", k3d_name)

        # Extract kubeconfig
        kc_result = subprocess.run(
            ["k3d", "kubeconfig", "get", k3d_name],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if kc_result.returncode != 0:
            raise RuntimeError(
                f"Failed to get kubeconfig for {k3d_name}:\n"
                f"stderr: {kc_result.stderr}"
            )

        kubeconfig_raw = kc_result.stdout
        endpoint, ca_cert_data = self._parse_kubeconfig(kubeconfig_raw)

        # Override endpoint to use the allocated port on localhost
        endpoint = f"https://127.0.0.1:{api_port}"

        info = ClusterInfo(
            name=name,
            k3d_name=k3d_name,
            endpoint=endpoint,
            ca_cert_data=ca_cert_data,
            api_port=api_port,
            status="ACTIVE",
            kubeconfig=kubeconfig_raw,
        )

        with self._lock:
            self._clusters[key] = info

        LOG.info(
            "k3d cluster %s ready at %s",
            k3d_name,
            endpoint,
        )
        return info

    def _parse_kubeconfig(self, kubeconfig_raw: str) -> tuple[str, str]:
        """Parse kubeconfig YAML to extract server endpoint and CA cert.

        :returns: (endpoint, ca_cert_data_base64)
        """
        try:
            kc = yaml.safe_load(kubeconfig_raw)
        except yaml.YAMLError as e:
            raise RuntimeError(f"Failed to parse kubeconfig YAML: {e}")

        clusters = kc.get("clusters", [])
        if not clusters:
            raise RuntimeError("No clusters found in kubeconfig")

        cluster_data = clusters[0].get("cluster", {})
        endpoint = cluster_data.get("server", "")
        ca_cert_data = cluster_data.get("certificate-authority-data", "")

        if not ca_cert_data:
            # Some k3d versions write the CA cert to a file path instead
            ca_cert_file = cluster_data.get("certificate-authority")
            if ca_cert_file:
                try:
                    with open(ca_cert_file, "rb") as f:
                        ca_cert_data = base64.b64encode(f.read()).decode("ascii")
                except OSError:
                    LOG.warning(
                        "Could not read CA cert file %s; "
                        "DescribeCluster will return empty certificateAuthority",
                        ca_cert_file,
                    )
                    ca_cert_data = ""

        return endpoint, ca_cert_data

    def add_agent_nodes(
        self,
        cluster_name: str,
        nodegroup_name: str,
        count: int = 1,
        account_id: str = "",
        region: str = "",
    ) -> None:
        """PARITY-04: Add k3d agent nodes for an EKS nodegroup.

        Creates real k3d agent nodes that join the cluster, providing
        actual compute capacity instead of metadata-only nodegroups.
        """
        key = self._cluster_key(cluster_name, account_id, region)
        with self._lock:
            info = self._clusters.get(key)

        if not info:
            LOG.warning("Cannot add agent nodes: cluster %s not found", cluster_name)
            return

        k3d_name = info.k3d_name

        for i in range(count):
            node_name = f"{k3d_name}-{nodegroup_name}-agent-{i}"
            try:
                result = subprocess.run(
                    [
                        "k3d", "node", "create", node_name,
                        "--cluster", k3d_name,
                        "--role", "agent",
                        "--wait",
                        "--timeout", "60s",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    LOG.warning(
                        "Failed to add agent node %s to cluster %s: %s",
                        node_name, k3d_name, result.stderr,
                    )
                else:
                    LOG.info("Added k3d agent node %s to cluster %s", node_name, k3d_name)
            except Exception as e:
                LOG.warning("Error adding agent node %s: %s", node_name, e)

    def delete_cluster(self, name: str, account_id: str = "", region: str = "") -> None:
        """Delete a k3d cluster backing an EKS cluster."""
        key = self._cluster_key(name, account_id, region)

        with self._lock:
            info = self._clusters.get(key)

        k3d_name = info.k3d_name if info else self._k3d_cluster_name(name, account_id, region)

        LOG.info("Deleting k3d cluster %s", k3d_name)

        try:
            result = subprocess.run(
                ["k3d", "cluster", "delete", k3d_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                LOG.warning(
                    "k3d cluster delete returned %d for %s: %s",
                    result.returncode,
                    k3d_name,
                    result.stderr,
                )
        except Exception as e:
            LOG.warning("Failed to delete k3d cluster %s: %s", k3d_name, e)

        with self._lock:
            self._clusters.pop(key, None)

        LOG.info("k3d cluster %s deleted", k3d_name)

    def get_cluster_info(self, name: str, account_id: str = "", region: str = "") -> ClusterInfo | None:
        """Return ClusterInfo for the given EKS cluster name, or None."""
        key = self._cluster_key(name, account_id, region)
        with self._lock:  # BUG-06 fix: thread safety
            return self._clusters.get(key)

    def stop_cluster(
        self, name: str, account_id: str = "", region: str = "",
    ) -> None:
        """Stop (but do NOT delete) a k3d cluster. Containers remain on
        disk with k3s state (etcd / SQLite) intact. ``start_cluster`` — or
        in the persistence path, ``reattach_from_disk`` — resumes them.
        """
        key = self._cluster_key(name, account_id, region)
        with self._lock:
            info = self._clusters.get(key)
        k3d_name = info.k3d_name if info else self._k3d_cluster_name(
            name, account_id, region,
        )
        try:
            subprocess.run(
                ["k3d", "cluster", "stop", k3d_name],
                capture_output=True, text=True, timeout=60,
            )
            if info:
                info.status = "STOPPED"
            LOG.info("k3d cluster %s stopped (data preserved)", k3d_name)
        except Exception as exc:
            LOG.warning("Failed to stop k3d cluster %s: %s", k3d_name, exc)

    def shutdown_all(self) -> None:
        """Persistence-path counterpart to ``cleanup_all``: stop every
        managed k3d cluster WITHOUT deleting it. The cluster's server
        container holds k3s's etcd/SQLite state, PVC bind-mounts, and
        CA keys in its writable layer; ``docker stop`` preserves all of
        them."""
        LOG.info("Stopping k3d EKS clusters (clusters preserved)...")
        with self._lock:
            entries = list(self._clusters.items())
        for _key, info in entries:
            try:
                subprocess.run(
                    ["k3d", "cluster", "stop", info.k3d_name],
                    capture_output=True, text=True, timeout=60,
                )
                info.status = "STOPPED"
            except Exception as exc:
                LOG.warning(
                    "k3d cluster stop failed for %s: %s", info.k3d_name, exc,
                )

    def reattach_from_disk(
        self, moto_clusters: list[tuple[str, str, str]],
    ) -> None:
        """Reconcile a set of persisted EKS clusters with the live k3d
        daemon. ``moto_clusters`` is ``[(account_id, region, name), ...]``.

        Three branches:
            - k3d has cluster, moto also has it → ``k3d cluster start``
              (idempotent if already running) and rehydrate ``ClusterInfo``.
            - moto has cluster, k3d does not → re-create from scratch
              (user may have ``k3d cluster delete``'d out of band).
            - k3d has a ``localemu-eks-*`` cluster moto does not know
              about → delete as an orphan.
        """
        try:
            self._verify_k3d()
        except Exception:
            LOG.warning(
                "k3d not available — EKS reconcile skipped; clusters will appear "
                "in DescribeCluster but kubectl will fail until k3d is fixed",
                exc_info=True,
            )
            return

        existing = _list_k3d_clusters()
        wanted: dict[str, tuple[str, str, str]] = {}
        for acct, rgn, name in moto_clusters:
            k3d_name = self._k3d_cluster_name(name, acct, rgn)
            wanted[k3d_name] = (name, acct, rgn)

        # Orphans: clusters k3d has but moto does not.
        for k3d_name in set(existing) - set(wanted):
            if not k3d_name.startswith(K3D_CLUSTER_PREFIX):
                continue
            try:
                subprocess.run(
                    ["k3d", "cluster", "delete", k3d_name],
                    capture_output=True, timeout=30,
                )
                LOG.info("Deleted orphan k3d cluster %s", k3d_name)
            except Exception:
                pass

        # Reattach or recreate.
        for k3d_name, (name, acct, rgn) in wanted.items():
            if k3d_name in existing:
                status = (existing[k3d_name].get("serverStatus") or "").lower()
                if status != "running":
                    try:
                        subprocess.run(
                            [
                                "k3d", "cluster", "start", k3d_name,
                                "--wait", "--timeout", "120s",
                            ],
                            capture_output=True, text=True, timeout=180,
                        )
                    except Exception as exc:
                        LOG.warning(
                            "k3d cluster start %s failed: %s", k3d_name, exc,
                        )
                        continue
                info = self._rehydrate_info(name, k3d_name, acct, rgn)
                if info is not None:
                    with self._lock:
                        self._clusters[self._cluster_key(name, acct, rgn)] = info
                    _update_moto_cluster(acct, rgn, name, info)
                    LOG.info("Resumed k3d cluster %s (EKS %s)", k3d_name, name)
            else:
                LOG.warning(
                    "EKS cluster %s present in moto but no k3d cluster %s — "
                    "recreating (this may take 60-90s)",
                    name, k3d_name,
                )
                # Recreate in background so the load orchestrator doesn't
                # block LocalEmu startup on a 60-90s cluster build.
                threading.Thread(
                    target=self._recreate_background,
                    args=(name, acct, rgn),
                    daemon=True,
                    name=f"eks-recreate-{name}",
                ).start()

    def _recreate_background(self, name: str, acct: str, rgn: str) -> None:
        try:
            self.create_cluster(name, account_id=acct, region=rgn)
        except Exception:
            LOG.warning(
                "Background recreate of EKS cluster %s failed", name, exc_info=True,
            )

    def _rehydrate_info(
        self, name: str, k3d_name: str, acct: str, rgn: str,
    ) -> ClusterInfo | None:
        """Pull the kubeconfig for a running k3d cluster and pack it into
        ``ClusterInfo`` so the moto record can be updated."""
        try:
            result = subprocess.run(
                ["k3d", "kubeconfig", "get", k3d_name],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                LOG.warning("k3d kubeconfig get failed: %s", result.stderr)
                return None
        except Exception:
            LOG.warning("k3d kubeconfig get threw", exc_info=True)
            return None

        kubeconfig = result.stdout
        endpoint, ca = _parse_kubeconfig(kubeconfig)
        try:
            api_port = int(endpoint.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            api_port = 0
        return ClusterInfo(
            name=name,
            k3d_name=k3d_name,
            endpoint=endpoint,
            ca_cert_data=ca,
            api_port=api_port,
            status="ACTIVE",
            kubeconfig=kubeconfig,
        )

    def cleanup_all(self) -> None:
        """Delete all localemu-eks-* k3d clusters. Called on shutdown when
        persistence is OFF. Destructive — for the persistence path, see
        ``shutdown_all``.

        Also scans for orphaned k3d clusters from previous crashes (BUG-10 fix).
        """
        LOG.info("Cleaning up k3d EKS clusters...")
        with self._lock:
            entries = list(self._clusters.items())
            self._clusters.clear()
        for key, info in entries:
            try:
                subprocess.run(
                    ["k3d", "cluster", "delete", info.k3d_name],
                    capture_output=True, text=True, timeout=30,
                )
            except Exception as e:
                LOG.debug("Failed to clean up k3d cluster %s: %s", info.k3d_name, e)

        # BUG-10 fix: scan for any orphaned localemu-eks-* k3d clusters
        try:
            result = subprocess.run(
                ["k3d", "cluster", "list", "-o", "json"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                clusters = json.loads(result.stdout or "[]")
                for cluster in clusters:
                    c_name = cluster.get("name", "")
                    if c_name.startswith(K3D_CLUSTER_PREFIX):
                        try:
                            subprocess.run(
                                ["k3d", "cluster", "delete", c_name],
                                capture_output=True, timeout=30,
                            )
                            LOG.info("Cleaned up orphaned k3d cluster: %s", c_name)
                        except Exception:
                            pass
        except Exception:
            pass
