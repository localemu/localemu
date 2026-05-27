"""Apache Kafka cluster manager for MSK emulation.

v1 ships a single-broker KRaft cluster per ``CreateCluster`` — the
broker is its own controller, no ZooKeeper, no multi-node quorum. This
covers the vast majority of integration tests (a kafka-python producer
+ consumer round-trip), and the multi-broker path is incremental on
top of the same primitives (same image, same listener pattern, just
add controller-quorum env vars and sequential start).

Pattern mirrors the MQ broker manager: a process singleton owns
state, the lifecycle ops are thread-safe under one RLock, and the
per-cluster info gets stamped on the container as labels so a
LocalEmu restart can rehydrate from Docker alone.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Iterable

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)


_CONTAINER_NAME_PREFIX = "localemu-msk-"
_LABEL_CLUSTER_ID = "localemu.msk.cluster-id"
_LABEL_CLUSTER_ARN = "localemu.msk.cluster-arn"
_LABEL_BROKER_ID = "localemu.msk.broker-id"
_LABEL_PLAIN_PORT = "localemu.msk.plain-port"
_LABEL_KRAFT_UUID = "localemu.msk.kraft-uuid"

_DEFAULT_VERSION = "3.7.1"
_DEFAULT_IMAGE = f"apache/kafka:{_DEFAULT_VERSION}"

_READINESS_TIMEOUT_SEC = 120
_PORT_PROBE_INTERVAL_SEC = 1.0
_POST_TCP_SETTLE_SEC = 5.0


@dataclass
class BrokerInfo:
    """One Kafka broker container."""

    cluster_arn: str
    broker_id: int
    container_name: str
    host_plain_port: int
    kraft_uuid: str
    kafka_version: str
    state: str = "ACTIVE"


class ClusterManager:
    """Process-singleton owning every MSK cluster's broker containers."""

    _instance: "ClusterManager | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._clusters: dict[str, list[BrokerInfo]] = {}
        self._lock = threading.RLock()
        self._image_pull_lock = threading.Lock()
        self._pulled_images: set[str] = set()

    @classmethod
    def instance(cls) -> "ClusterManager":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = ClusterManager()
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def create_cluster(
        self,
        *,
        cluster_arn: str,
        cluster_id: str,
        kafka_version: str | None = None,
        number_of_brokers: int = 1,
    ) -> list[BrokerInfo]:
        version = (kafka_version or "").strip() or _DEFAULT_VERSION
        image = f"apache/kafka:{version}"
        self._ensure_image(image)
        # v1: single-broker only; multi-broker requires KRaft quorum.
        if number_of_brokers > 1:
            LOG.warning(
                "MSK CreateCluster requested %d brokers; v1 supports 1. "
                "Starting a single broker — multi-broker is on the v1.1 roadmap.",
                number_of_brokers,
            )
        broker_id = 1
        host_port = get_free_tcp_port()
        kraft_uuid = _new_kraft_uuid()
        container_name = self._container_name(cluster_id, broker_id)
        config = self._build_container_config(
            cluster_arn=cluster_arn,
            cluster_id=cluster_id,
            broker_id=broker_id,
            container_name=container_name,
            image=image,
            host_plain_port=host_port,
            kraft_uuid=kraft_uuid,
            kafka_version=version,
        )
        DOCKER_CLIENT.create_container_from_config(config)
        try:
            DOCKER_CLIENT.start_container(container_name)
        except Exception:
            DOCKER_CLIENT.remove_container(container_name, force=True)
            raise
        actual_port = self._reconcile_host_port(container_name) or host_port
        if not self._wait_for_port(actual_port):
            try:
                DOCKER_CLIENT.stop_container(container_name, timeout=5)
                DOCKER_CLIENT.remove_container(container_name, force=True)
            except Exception:
                LOG.debug("cleanup after readiness timeout failed", exc_info=True)
            raise RuntimeError(
                f"Kafka cluster {cluster_id} did not bind on port {actual_port} "
                f"within {_READINESS_TIMEOUT_SEC}s"
            )
        broker = BrokerInfo(
            cluster_arn=cluster_arn,
            broker_id=broker_id,
            container_name=container_name,
            host_plain_port=actual_port,
            kraft_uuid=kraft_uuid,
            kafka_version=version,
        )
        with self._lock:
            self._clusters[cluster_arn] = [broker]
        LOG.info(
            "Kafka cluster %s up (broker_id=%d, host_port=%d)",
            cluster_id, broker_id, actual_port,
        )
        return [broker]

    def delete_cluster(self, cluster_arn: str) -> None:
        with self._lock:
            brokers = self._clusters.pop(cluster_arn, None)
        if brokers is None:
            return
        for broker in brokers:
            try:
                DOCKER_CLIENT.stop_container(broker.container_name, timeout=10)
            except Exception:
                LOG.debug(
                    "stop_container raised for %s",
                    broker.container_name, exc_info=True,
                )
            try:
                DOCKER_CLIENT.remove_container(broker.container_name, force=True)
            except Exception:
                LOG.debug(
                    "remove_container raised for %s",
                    broker.container_name, exc_info=True,
                )

    def get_cluster(self, cluster_arn: str) -> list[BrokerInfo] | None:
        with self._lock:
            brokers = self._clusters.get(cluster_arn)
        if brokers:
            return list(brokers)
        return None

    def bootstrap_brokers(self, cluster_arn: str) -> str:
        brokers = self.get_cluster(cluster_arn) or []
        if not brokers:
            return ""
        return ",".join(f"127.0.0.1:{b.host_plain_port}" for b in brokers)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _container_name(cluster_id: str, broker_id: int) -> str:
        return f"{_CONTAINER_NAME_PREFIX}{cluster_id}-broker-{broker_id}"

    def _build_container_config(
        self,
        *,
        cluster_arn: str,
        cluster_id: str,
        broker_id: int,
        container_name: str,
        image: str,
        host_plain_port: int,
        kraft_uuid: str,
        kafka_version: str,
    ) -> ContainerConfiguration:
        ports = PortMappings()
        ports.add(host_plain_port, 9092)
        # Two listeners: one named ``HOST`` advertised as
        # ``127.0.0.1:<host-port>`` so kafka-python on the host can
        # complete the metadata round-trip; one named ``DOCKER`` for
        # any future in-network consumer (Lambda, Pipes). Both speak
        # plain Kafka over TCP. KRaft inter-broker listener is on
        # ``9091``; for a single-broker quorum the broker itself is
        # the only voter so no extra mapping is needed.
        env_vars = {
            "KAFKA_NODE_ID": str(broker_id),
            "KAFKA_PROCESS_ROLES": "broker,controller",
            "KAFKA_LISTENERS": (
                "HOST://0.0.0.0:9092,"
                "DOCKER://0.0.0.0:9093,"
                "CONTROLLER://0.0.0.0:9091"
            ),
            "KAFKA_ADVERTISED_LISTENERS": (
                f"HOST://127.0.0.1:{host_plain_port},"
                f"DOCKER://{container_name}:9093"
            ),
            "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": (
                "HOST:PLAINTEXT,DOCKER:PLAINTEXT,CONTROLLER:PLAINTEXT"
            ),
            "KAFKA_INTER_BROKER_LISTENER_NAME": "DOCKER",
            "KAFKA_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
            # Single-broker KRaft: the broker is its own controller, so
            # have it reach the quorum at ``localhost`` rather than
            # the container hostname — the container isn't attached to
            # a shared user-defined network with a DNS entry pointing
            # back at itself.
            "KAFKA_CONTROLLER_QUORUM_VOTERS": f"{broker_id}@localhost:9091",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR": "1",
            "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR": "1",
            "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS": "0",
            "KAFKA_AUTO_CREATE_TOPICS_ENABLE": "true",
            # Speed up the very-first metadata refresh so the first
            # producer doesn't wait the default ~300 seconds for
            # auto-topic-creation propagation.
            "KAFKA_LOG_FLUSH_INTERVAL_MESSAGES": "1",
            "KAFKA_NUM_PARTITIONS": "1",
            "CLUSTER_ID": kraft_uuid,
        }
        return ContainerConfiguration(
            image_name=image,
            name=container_name,
            ports=ports,
            env_vars=env_vars,
            detach=True,
            remove=False,
            labels={
                _LABEL_CLUSTER_ID: cluster_id,
                _LABEL_CLUSTER_ARN: cluster_arn,
                _LABEL_BROKER_ID: str(broker_id),
                _LABEL_PLAIN_PORT: str(host_plain_port),
                _LABEL_KRAFT_UUID: kraft_uuid,
                "localemu.service": "msk",
                "localemu.kafka-version": kafka_version,
            },
        )

    def _ensure_image(self, image: str) -> None:
        with self._image_pull_lock:
            if image in self._pulled_images:
                return
            try:
                DOCKER_CLIENT.inspect_image(image)
            except Exception:
                LOG.info("Pulling Kafka image %s (one-time)…", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                except Exception:
                    LOG.warning("pull_image %s failed", image, exc_info=True)
            self._pulled_images.add(image)

    def _reconcile_host_port(self, container_name: str) -> int | None:
        """Read back the host port Docker actually bound to container
        port 9092. Mirrors the same fix as the MQ manager — PortMappings
        merging can shuffle a single mapping, and we'd rather hand the
        AWS caller the URL that actually accepts traffic."""
        try:
            inspect = DOCKER_CLIENT.inspect_container(container_name)
        except Exception:
            return None
        ports_info = (inspect.get("NetworkSettings") or {}).get("Ports") or {}
        bindings = ports_info.get("9092/tcp") or []
        for binding in bindings:
            if binding.get("HostIp") in ("0.0.0.0", "127.0.0.1"):
                try:
                    return int(binding["HostPort"])
                except (KeyError, ValueError):
                    return None
        return None

    def _wait_for_port(
        self,
        port: int,
        host: str = "127.0.0.1",
        timeout: int = _READINESS_TIMEOUT_SEC,
    ) -> bool:
        """Block until *host:port* accepts a TCP connection, then wait
        an extra :data:`_POST_TCP_SETTLE_SEC` for Kafka's controller
        quorum to finish electing before we let an AWS client through.
        First-time client metadata requests can otherwise timeout
        because the broker is still resolving its own role."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    time.sleep(_POST_TCP_SETTLE_SEC)
                    return True
            except OSError:
                time.sleep(_PORT_PROBE_INTERVAL_SEC)
        return False


def _new_kraft_uuid() -> str:
    """A single-broker cluster generates its KRaft cluster UUID once at
    create time. The official Apache image accepts ``CLUSTER_ID`` and
    runs ``kafka-storage.sh format`` automatically on first start, so
    we don't have to shell out for it.
    """
    # KRaft expects a 22-char base64-url uuid; the kafka-storage helper
    # uses python's uuid module under the hood.
    raw = uuid.uuid4().bytes
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _reset_singleton_for_tests() -> None:
    """Test-only: drop the singleton + remove every running cluster's
    container so per-test Docker state is clean."""
    with ClusterManager._instance_lock:
        if ClusterManager._instance is not None:
            for arn in list(ClusterManager._instance._clusters.keys()):
                try:
                    ClusterManager._instance.delete_cluster(arn)
                except Exception:
                    pass
        ClusterManager._instance = None
