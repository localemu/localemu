"""Docker-backed OpenSearch/Elasticsearch cluster manager.

Manages real OpenSearch and Elasticsearch clusters running in Docker containers.
Each CreateDomain call starts a real search engine container that supports
full-text indexing, queries, and aggregations.
"""

import logging
import os
import threading
import time

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

# Image pull locks (same pattern as Lambda, EC2, RDS)
# PERF-R2-01: bounded with LRU eviction to prevent unbounded growth
_IMAGE_PULL_LOCKS_MAXSIZE = 64
_image_pull_locks: dict[str, threading.Lock] = {}
_image_pull_locks_lock = threading.Lock()

# Default images
OPENSEARCH_IMAGES = {
    "OpenSearch_2.11": "opensearchproject/opensearch:2.11.1",
    "OpenSearch_2.9": "opensearchproject/opensearch:2.9.0",
    "OpenSearch_2.7": "opensearchproject/opensearch:2.7.0",
    "OpenSearch_2.5": "opensearchproject/opensearch:2.5.0",
    "OpenSearch_1.3": "opensearchproject/opensearch:1.3.14",
    "default": "opensearchproject/opensearch:2.11.1",
}

ELASTICSEARCH_IMAGES = {
    "Elasticsearch_7.10": "docker.elastic.co/elasticsearch/elasticsearch-oss:7.10.2",
    "Elasticsearch_7.9": "docker.elastic.co/elasticsearch/elasticsearch-oss:7.9.3",
    "Elasticsearch_7.7": "docker.elastic.co/elasticsearch/elasticsearch-oss:7.7.1",
    "default": "docker.elastic.co/elasticsearch/elasticsearch-oss:7.10.2",
}

CONTAINER_LABEL = "localemu.service=opensearch"


class ClusterInfo:
    """Tracks a running OpenSearch/Elasticsearch Docker container."""

    def __init__(
        self,
        domain_name: str,
        container_name: str,
        engine: str,
        image: str,
        host_port: int,
        endpoint: str,
    ):
        self.domain_name = domain_name
        self.container_name = container_name
        self.engine = engine
        self.image = image
        self.host_port = host_port
        self.endpoint = endpoint
        self.status = "creating"


class DockerClusterManager:
    """Manages OpenSearch/Elasticsearch Docker containers.

    Each domain maps to one Docker container running a real search engine.
    """

    def __init__(self):
        self._clusters: dict[str, ClusterInfo] = {}
        self._lock = threading.Lock()
        self._recover_orphaned_containers()

    def _recover_orphaned_containers(self) -> None:
        """Scan for labeled OpenSearch containers from a previous run.

        ``All=True`` so stopped-and-preserved containers (the
        ``PERSISTENCE=1`` case) are picked up too. Previously the
        recovery used ``all=False``, silently skipping every domain
        whose container had been stopped — DescribeDomain kept
        reporting them but the container was never started back up.

        Running containers are recorded as ``active``. Stopped
        containers are started and then recorded — matching RDS's
        recovery semantics.
        """
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=[f"label={CONTAINER_LABEL}"],
                all=True,
            )
            for container in containers:
                labels = container.get("labels", {})
                domain_name = labels.get("localemu.domain-name")
                if not domain_name or domain_name in self._clusters:
                    continue
                try:
                    name = container.get("name", "")
                    inspect_info = DOCKER_CLIENT.inspect_container(
                        name or container.get("id"),
                    )
                    port_bindings = (
                        inspect_info.get("HostConfig", {}).get("PortBindings", {})
                        or inspect_info.get("NetworkSettings", {}).get("Ports", {})
                    )
                    host_port = None
                    for bindings in port_bindings.values():
                        if bindings:
                            try:
                                host_port = int(bindings[0].get("HostPort", 0))
                            except (TypeError, ValueError):
                                host_port = None
                            break
                    if not host_port:
                        continue

                    state = inspect_info.get("State") or {}
                    running = bool(state.get("Running"))
                    if not running:
                        # Stopped container from a PERSISTENCE=1 shutdown —
                        # start it so the domain actually serves traffic
                        # again instead of being listed but unreachable.
                        try:
                            DOCKER_CLIENT.start_container(name)
                            LOG.info(
                                "Started stopped OpenSearch container %s "
                                "from previous run", name,
                            )
                        except Exception as exc:
                            LOG.warning(
                                "Could not start stopped OpenSearch container %s: %s",
                                name, exc,
                            )
                            # Continue anyway — recording the domain as
                            # "creating" is better than hiding it.

                    engine = labels.get("localemu.engine", "OpenSearch_2.11")
                    image = inspect_info.get("Config", {}).get("Image", "")
                    info = ClusterInfo(
                        domain_name=domain_name,
                        container_name=name,
                        engine=engine,
                        image=image,
                        host_port=host_port,
                        endpoint=f"localhost:{host_port}",
                    )
                    info.status = "active"
                    self._clusters[domain_name] = info
                    LOG.info(
                        "Recovered OpenSearch container: %s (port %s)",
                        domain_name, host_port,
                    )
                except Exception as e:
                    LOG.debug("Failed to recover container for %s: %s", domain_name, e)
        except Exception as e:
            LOG.debug("Failed to scan for orphaned OpenSearch containers: %s", e)

    def _container_name(self, domain_name: str, account_id: str = "") -> str:
        # LOW-02: Include account_id to avoid container name collisions
        # across multiple emulated AWS accounts.
        if account_id:
            return f"localemu-opensearch-{account_id}-{domain_name}"
        return f"localemu-opensearch-{domain_name}"

    def _resolve_image(self, engine_version: str | None) -> str:
        """Resolve engine version to Docker image.

        MEDIUM-01: Find the closest matching version instead of returning the
        first prefix match.  For example, ``OpenSearch_2.7`` should match
        ``OpenSearch_2.7`` exactly, not ``OpenSearch_2.11`` (which would win
        with a naive iteration because dicts are insertion-ordered).

        Strategy: exact match first, then find the closest version whose
        major.minor prefix matches the requested version.
        """
        if engine_version:
            # Exact match in either image map
            if engine_version in OPENSEARCH_IMAGES:
                return OPENSEARCH_IMAGES[engine_version]
            if engine_version in ELASTICSEARCH_IMAGES:
                return ELASTICSEARCH_IMAGES[engine_version]

            # Determine which image map to search
            if engine_version.startswith("Elasticsearch"):
                image_map = ELASTICSEARCH_IMAGES
            else:
                image_map = OPENSEARCH_IMAGES

            # Extract the requested version number (e.g. "2.7" from "OpenSearch_2.7")
            req_ver = engine_version.rsplit("_", 1)[-1] if "_" in engine_version else engine_version

            def _parse_version(ver_str: str) -> tuple[int, ...]:
                """Parse a dotted version string into a comparable tuple."""
                try:
                    return tuple(int(p) for p in ver_str.split("."))
                except (ValueError, AttributeError):
                    return (0,)

            req_tuple = _parse_version(req_ver)

            # Find the closest version that does not exceed the requested version
            best_key = None
            best_tuple: tuple[int, ...] = (0,)
            for key in image_map:
                if key == "default":
                    continue
                key_ver = key.rsplit("_", 1)[-1] if "_" in key else key
                key_tuple = _parse_version(key_ver)
                # Must not exceed requested version, and must be the largest such version
                if key_tuple <= req_tuple and key_tuple > best_tuple:
                    best_tuple = key_tuple
                    best_key = key

            if best_key:
                return image_map[best_key]

        return OPENSEARCH_IMAGES["default"]

    def _ensure_image(self, image: str) -> None:
        """Pull Docker image if not available. Thread-safe."""
        with _image_pull_locks_lock:
            if image not in _image_pull_locks:
                # PERF-R2-01: evict oldest entry when maxsize reached
                if len(_image_pull_locks) >= _IMAGE_PULL_LOCKS_MAXSIZE:
                    oldest_key = next(iter(_image_pull_locks))
                    del _image_pull_locks[oldest_key]
                _image_pull_locks[image] = threading.Lock()
            lock = _image_pull_locks[image]

        with lock:
            try:
                DOCKER_CLIENT.inspect_image(image)
            except Exception:
                LOG.info("Pulling OpenSearch image %s...", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                    LOG.info("Image %s pulled successfully", image)
                except Exception as e:
                    raise RuntimeError(f"Failed to pull OpenSearch image {image}: {e}") from e

    def create_cluster(
        self,
        domain_name: str,
        engine_version: str | None = None,
    ) -> ClusterInfo:
        """Create and start a Docker container with a real OpenSearch/ES instance."""
        container_name = self._container_name(domain_name)
        image = self._resolve_image(engine_version)
        host_port = get_free_tcp_port()

        LOG.info(
            "Creating OpenSearch domain %s (image=%s, port=%s)",
            domain_name, image, host_port,
        )

        self._ensure_image(image)

        # OpenSearch requires these env vars to run as single-node
        # Security plugin can be enabled via OPENSEARCH_DOCKER_SECURITY=1 (MEDIUM-03)
        disable_security = "false" if os.environ.get("OPENSEARCH_DOCKER_SECURITY") == "1" else "true"
        env_vars = {
            "discovery.type": "single-node",
            "DISABLE_SECURITY_PLUGIN": disable_security,
            "DISABLE_INSTALL_DEMO_CONFIG": "true",
            "OPENSEARCH_JAVA_OPTS": "-Xms256m -Xmx512m",
            "LOCALEMU_DOMAIN_NAME": domain_name,
        }

        # For Elasticsearch images
        if "elasticsearch" in image.lower():
            env_vars = {
                "discovery.type": "single-node",
                "ES_JAVA_OPTS": "-Xms256m -Xmx512m",
                "xpack.security.enabled": "false",
                "LOCALEMU_DOMAIN_NAME": domain_name,
            }

        ports = PortMappings()
        ports.add(host_port, 9200)

        # Named Docker volume for data persistence. The volume survives
        # container removal, so indices and documents are preserved
        # across LocalEmu restarts when PERSISTENCE=1.
        volumes = VolumeMappings()
        volume_name = f"localemu-opensearch-{domain_name}-data"
        data_dir = "/usr/share/opensearch/data"
        if "elasticsearch" in image.lower():
            data_dir = "/usr/share/elasticsearch/data"
        volumes.add((volume_name, data_dir))

        container_config = ContainerConfiguration(
            image_name=image,
            name=container_name,
            env_vars=env_vars,
            ports=ports,
            volumes=volumes,
            detach=True,
            labels={
                "localemu.service": "opensearch",
                "localemu.domain-name": domain_name,
                "localemu.engine": engine_version or "OpenSearch_2.11",
            },
        )

        DOCKER_CLIENT.create_container_from_config(container_config)
        DOCKER_CLIENT.start_container(container_name)

        endpoint = f"localhost:{host_port}"

        info = ClusterInfo(
            domain_name=domain_name,
            container_name=container_name,
            engine=engine_version or "OpenSearch_2.11",
            image=image,
            host_port=host_port,
            endpoint=endpoint,
        )

        with self._lock:
            self._clusters[domain_name] = info

        # Wait for cluster health in background
        threading.Thread(
            target=self._wait_for_health,
            args=(domain_name, host_port),
            daemon=True,
        ).start()

        LOG.info("OpenSearch domain %s starting at %s", domain_name, endpoint)
        return info

    def _wait_for_health(self, domain_name: str, port: int, timeout: int = 60):
        """Wait for the OpenSearch container to be healthy."""
        import requests

        url = f"http://localhost:{port}/_cluster/health"
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    with self._lock:
                        info = self._clusters.get(domain_name)
                        if info:
                            info.status = "active"
                    LOG.info("OpenSearch domain %s is healthy at localhost:%s", domain_name, port)
                    return
            except Exception:
                pass
            time.sleep(2)
        LOG.warning("OpenSearch domain %s health check timed out after %ds", domain_name, timeout)

    def delete_cluster(self, domain_name: str) -> None:
        """Delete a domain (stop container, remove container, remove data volume)."""
        container_name = self._container_name(domain_name)
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=10)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(container_name)
        except Exception:
            pass
        # Remove the data volume
        volume_name = f"localemu-opensearch-{domain_name}-data"
        try:
            DOCKER_CLIENT.remove_volume(volume_name)
            LOG.debug("Removed OpenSearch volume %s", volume_name)
        except Exception:
            pass
        with self._lock:
            self._clusters.pop(domain_name, None)
        LOG.info("OpenSearch domain %s deleted", domain_name)

    def get_cluster_info(self, domain_name: str) -> ClusterInfo | None:
        return self._clusters.get(domain_name)

    def get_endpoint(self, domain_name: str) -> str | None:
        info = self._clusters.get(domain_name)
        return info.endpoint if info else None

    def cleanup_all(self) -> None:
        """Stop and remove all OpenSearch containers. Called on LocalEmu shutdown."""
        LOG.info("Cleaning up OpenSearch Docker containers...")
        with self._lock:
            domains = list(self._clusters.keys())
        for domain in domains:
            try:
                self.delete_cluster(domain)
            except Exception as e:
                LOG.debug("Failed to clean up OpenSearch domain %s: %s", domain, e)
