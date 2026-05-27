"""Docker-backed Redshift cluster manager.

Redshift's wire protocol is PostgreSQL-compatible. Real Redshift exposes
port 5439 with a custom Trino-flavored SQL dialect on top, but for
local-dev use the SQL surface most CDK/Terraform/Lambda integration
tests need is plain Postgres: connect, create tables, run INSERTs and
SELECTs, validate ResultSets. We boot a ``postgres:15`` container per
cluster on a free host TCP port and surface that port through
``DescribeClusters.Endpoint.Address`` / ``Port`` so ``psql`` and
JDBC/ODBC drivers Just Work.

Opt-in via ``REDSHIFT_DOCKER_BACKEND=1`` (mirrors the RDS / EKS / MSK /
MQ posture). Without the flag the existing moto fallback stays in
place — every API still returns the same metadata, the only thing
missing is a reachable endpoint.

Limitations explicitly documented (and not closed in V1):
* Redshift's own SQL dialect (RA3 distribution keys, sort keys,
  ``COPY FROM s3://``) is NOT honored — those commands hit standard
  Postgres and may parse-fail. Track via design-doc follow-up.
* Multi-node clusters always run a single container regardless of
  ``NumberOfNodes`` — node_type is metadata only.
* No automated snapshotting (``CreateSnapshot`` returns moto metadata).
"""

from __future__ import annotations

import base64
import logging
import socket
import threading
import time
from dataclasses import dataclass

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

REDSHIFT_IMAGE = "postgres:15"
# Real Redshift listens on 5439; we expose that port-for-port inside
# the container so internal-to-container traffic (e.g. Lambda → cluster
# over the VPC network) uses the AWS-expected port even when the host
# port is dynamic.
REDSHIFT_CONTAINER_PORT = 5439

# Label so we can find and clean up our containers on restart.
LABEL_SERVICE = "localemu.service=redshift"
LABEL_CLUSTER_ID = "localemu.cluster-id"
LABEL_MASTER_USER = "localemu.master-username"
LABEL_MASTER_PWD = "localemu.master-password-b64"


@dataclass(slots=True)
class RedshiftContainerInfo:
    cluster_id: str
    container_name: str
    image: str
    host_port: int
    master_username: str
    master_password: str
    db_name: str
    endpoint: str = ""
    status: str = "creating"


class DockerClusterManager:
    """Singleton per LocalEmu process."""

    def __init__(self) -> None:
        self._clusters: dict[str, RedshiftContainerInfo] = {}
        self._lock = threading.Lock()
        self._recover_orphans()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def create_cluster(
        self,
        cluster_id: str,
        master_username: str,
        master_password: str,
        db_name: str = "dev",
    ) -> RedshiftContainerInfo:
        """Boot a postgres:15 container on a free host port.

        Idempotent on the cluster_id key: a duplicate CreateCluster from
        the test suite raises ``ValueError`` here and the provider turns
        it into the AWS-shaped ``ClusterAlreadyExists`` error.
        """
        with self._lock:
            if cluster_id in self._clusters:
                raise ValueError(f"Cluster {cluster_id} already exists")
            # Reservation sentinel so concurrent CreateCluster calls fail
            # the second one cleanly instead of double-booting.
            self._clusters[cluster_id] = None  # type: ignore[assignment]

        try:
            return self._do_create(cluster_id, master_username, master_password, db_name)
        except Exception:
            with self._lock:
                if self._clusters.get(cluster_id) is None:
                    self._clusters.pop(cluster_id, None)
            raise

    def _do_create(
        self, cluster_id: str, master_username: str, master_password: str, db_name: str,
    ) -> RedshiftContainerInfo:
        container_name = self._container_name(cluster_id)
        host_port = get_free_tcp_port()
        LOG.info(
            "Creating Redshift cluster %s (image=%s, host_port=%s)",
            cluster_id, REDSHIFT_IMAGE, host_port,
        )
        self._ensure_image(REDSHIFT_IMAGE)

        # Volume so a container restart preserves the DB (the named
        # volume survives ``docker rm`` of the container itself).
        volume_name = f"localemu-redshift-{cluster_id}-data"
        volumes = VolumeMappings()
        volumes.add((volume_name, "/var/lib/postgresql/data"))

        ports = PortMappings()
        ports.add(host_port, REDSHIFT_CONTAINER_PORT)

        cfg = ContainerConfiguration(
            image_name=REDSHIFT_IMAGE,
            name=container_name,
            env_vars={
                "POSTGRES_USER": master_username,
                "POSTGRES_PASSWORD": master_password,
                "POSTGRES_DB": db_name,
                # Override the default Postgres port so the container
                # listens on Redshift's 5439, matching AWS behavior for
                # any caller that resolves the ARN-derived endpoint.
                "PGPORT": str(REDSHIFT_CONTAINER_PORT),
            },
            ports=ports,
            volumes=volumes,
            detach=True,
            labels={
                "localemu.service": "redshift",
                LABEL_CLUSTER_ID: cluster_id,
                LABEL_MASTER_USER: master_username,
                LABEL_MASTER_PWD: base64.b64encode(
                    master_password.encode(),
                ).decode(),
            },
        )
        DOCKER_CLIENT.create_container_from_config(cfg)
        try:
            DOCKER_CLIENT.start_container(container_name)
        except Exception:
            try:
                DOCKER_CLIENT.remove_container(container_name)
            except Exception:
                pass
            raise

        self._wait_for_port(host_port, timeout=30)

        info = RedshiftContainerInfo(
            cluster_id=cluster_id,
            container_name=container_name,
            image=REDSHIFT_IMAGE,
            host_port=host_port,
            master_username=master_username,
            master_password=master_password,
            db_name=db_name,
            endpoint=f"localhost:{host_port}",
            status="available",
        )
        with self._lock:
            self._clusters[cluster_id] = info
        LOG.info(
            "Redshift cluster %s available at %s (db=%s, user=%s)",
            cluster_id, info.endpoint, db_name, master_username,
        )
        return info

    def delete_cluster(self, cluster_id: str) -> None:
        name = self._container_name(cluster_id)
        try:
            DOCKER_CLIENT.stop_container(name, timeout=5)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(name)
        except Exception:
            pass
        with self._lock:
            self._clusters.pop(cluster_id, None)
        LOG.info("Redshift cluster %s deleted", cluster_id)

    def get_cluster_info(self, cluster_id: str) -> RedshiftContainerInfo | None:
        return self._clusters.get(cluster_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _container_name(cluster_id: str) -> str:
        return f"localemu-redshift-{cluster_id}"

    @staticmethod
    def _ensure_image(image: str) -> None:
        try:
            DOCKER_CLIENT.inspect_image(image)
        except Exception:
            LOG.info("Pulling %s …", image)
            DOCKER_CLIENT.pull_image(image)

    @staticmethod
    def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: int = 30) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except OSError:
                time.sleep(0.5)
        LOG.warning("Redshift port %s did not open within %ss", port, timeout)
        return False

    def _recover_orphans(self) -> None:
        """Pick up any redshift containers left from a previous LocalEmu run."""
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=[f"label={LABEL_SERVICE}"], all=True,
            )
        except Exception:
            return
        for c in containers:
            labels = c.get("labels", {}) or {}
            cid = labels.get(LABEL_CLUSTER_ID)
            if not cid or cid in self._clusters:
                continue
            try:
                inspect_info = DOCKER_CLIENT.inspect_container(c.get("name") or "")
            except Exception:
                continue
            host_port = self._extract_host_port(inspect_info)
            if not host_port:
                continue
            pwd_b64 = labels.get(LABEL_MASTER_PWD, "")
            try:
                pwd = base64.b64decode(pwd_b64.encode()).decode() if pwd_b64 else ""
            except Exception:
                pwd = ""
            info = RedshiftContainerInfo(
                cluster_id=cid,
                container_name=c.get("name", ""),
                image=REDSHIFT_IMAGE,
                host_port=host_port,
                master_username=labels.get(LABEL_MASTER_USER, "admin"),
                master_password=pwd,
                db_name="dev",
                endpoint=f"localhost:{host_port}",
                status="available",
            )
            self._clusters[cid] = info
            LOG.info("Recovered Redshift cluster %s on port %s", cid, host_port)

    @staticmethod
    def _extract_host_port(inspect_info: dict) -> int | None:
        port_bindings = (
            inspect_info.get("HostConfig", {}).get("PortBindings", {})
            or inspect_info.get("NetworkSettings", {}).get("Ports", {})
        )
        for _key, bindings in port_bindings.items():
            if not bindings:
                continue
            try:
                p = int(bindings[0].get("HostPort", 0))
                if p:
                    return p
            except (TypeError, ValueError):
                continue
        return None
