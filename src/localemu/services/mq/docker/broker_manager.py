"""Real Docker-backed Amazon MQ broker manager.

Each ``CreateBroker`` provisions an actual broker container that any
real client (pika, paho-mqtt, stomp.py, OpenWire-JMS) can connect to on
``localhost:<allocated-port>``. The manager owns the lifecycle:

  * Per-protocol host-port allocation (one TCP port per wire protocol
    the broker exposes; recorded as container labels so reconciliation
    can rehydrate without parsing ``docker inspect``).
  * Image pull deduplication (Docker pulls are slow and an image
    deduper avoids parallel pulls of the same engine across concurrent
    CreateBroker calls).
  * Readiness probes — the response only goes back to the AWS client
    once the broker actually accepts a TCP connection on its primary
    wire port.
  * Lookup by broker id for DescribeBroker / DeleteBroker.

v1 ships RabbitMQ only; the ActiveMQ driver lands in a follow-up
commit. Engine drivers are pluggable via the :class:`BrokerEngineDriver`
protocol so adding ActiveMQ later means dropping in one new module
without touching the manager.
"""

from __future__ import annotations

import logging
import socket
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

from localemu.utils.container_utils.container_client import ContainerConfiguration
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)


_CONTAINER_NAME_PREFIX = "localemu-mq-"
_LABEL_BROKER_ID = "localemu.mq.broker-id"
_LABEL_ENGINE = "localemu.mq.engine"
_LABEL_PORT_PREFIX = "localemu.mq.port."

_READINESS_TIMEOUT_SEC = 90
_PORT_PROBE_INTERVAL_SEC = 1.0


@dataclass
class BrokerInstance:
    """In-memory record of a running broker container.

    Source of truth for protocol-port mappings + container metadata so
    the provider can answer DescribeBroker without invoking the moto
    backend on every request.
    """

    broker_id: str
    container_name: str
    engine: str
    engine_version: str
    ports: dict[str, int]  # protocol -> allocated host port
    admin_username: str
    admin_password: str
    state: str = "RUNNING"


class BrokerEngineDriver(Protocol):
    """Engine-specific behaviour the manager delegates to."""

    engine: str

    def default_image(self, engine_version: str) -> str: ...
    def protocols(self) -> list[str]: ...
    def container_config(
        self,
        *,
        broker_id: str,
        container_name: str,
        image: str,
        host_ports: dict[str, int],
        admin_username: str,
        admin_password: str,
    ) -> ContainerConfiguration: ...
    def readiness_port(self, host_ports: dict[str, int]) -> int: ...


class BrokerManager:
    """Process-singleton; serialises lifecycle ops."""

    _instance: "BrokerManager | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._brokers: dict[str, BrokerInstance] = {}
        self._lock = threading.RLock()
        self._image_pull_lock = threading.Lock()
        self._pulled_images: set[str] = set()
        self._drivers: dict[str, BrokerEngineDriver] = {}

    @classmethod
    def instance(cls) -> "BrokerManager":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = BrokerManager()
                    cls._instance._register_default_drivers()
        return cls._instance

    def _register_default_drivers(self) -> None:
        # Lazy-imported to keep the manager file importable without
        # docker-py / per-engine deps at unit-test time.
        from localemu.services.mq.docker.rabbitmq import RabbitMQDriver

        self.register_driver(RabbitMQDriver())

    def register_driver(self, driver: BrokerEngineDriver) -> None:
        with self._lock:
            self._drivers[driver.engine.upper()] = driver

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def create_broker(
        self,
        *,
        broker_id: str,
        engine_type: str,
        engine_version: str,
        admin_username: str,
        admin_password: str,
    ) -> BrokerInstance:
        engine_key = (engine_type or "").upper()
        with self._lock:
            driver = self._drivers.get(engine_key)
        if driver is None:
            raise NotImplementedError(
                f"MQ engine {engine_type!r} is not yet implemented in LocalEmu. "
                "v1 supports RABBITMQ; ActiveMQ is coming next."
            )
        host_ports = {
            proto: get_free_tcp_port() for proto in driver.protocols()
        }
        container_name = f"{_CONTAINER_NAME_PREFIX}{broker_id}"
        image = driver.default_image(engine_version)
        self._ensure_image(image)
        config = driver.container_config(
            broker_id=broker_id,
            container_name=container_name,
            image=image,
            host_ports=host_ports,
            admin_username=admin_username,
            admin_password=admin_password,
        )
        # Stamp broker-identifying labels so the reconciler can rehydrate
        # state purely from `docker inspect` without needing the manager's
        # in-memory dict to survive a process restart.
        config.labels = (config.labels or {}) | {
            _LABEL_BROKER_ID: broker_id,
            _LABEL_ENGINE: driver.engine,
        } | {
            f"{_LABEL_PORT_PREFIX}{proto}": str(port)
            for proto, port in host_ports.items()
        }
        DOCKER_CLIENT.create_container_from_config(config)
        try:
            DOCKER_CLIENT.start_container(container_name)
        except Exception:
            DOCKER_CLIENT.remove_container(container_name, force=True)
            raise
        # PortMappings merges adjacent host/container port ranges (see
        # container_client.PortMappings.add). That makes the host port
        # we *requested* unreliable as the one Docker actually bound —
        # for amqp+amqps the order can flip. After start, ask Docker
        # which host port each container port is on and overwrite our
        # per-protocol map so DescribeBroker hands the client the URL
        # that actually accepts traffic.
        host_ports = self._reconcile_ports_from_docker(
            container_name, driver,
        ) or host_ports
        if not self._wait_for_port(driver.readiness_port(host_ports)):
            try:
                DOCKER_CLIENT.stop_container(container_name, timeout=5)
                DOCKER_CLIENT.remove_container(container_name, force=True)
            except Exception:
                LOG.debug("cleanup after readiness timeout failed", exc_info=True)
            raise RuntimeError(
                f"MQ broker {broker_id} did not become ready within "
                f"{_READINESS_TIMEOUT_SEC}s on port "
                f"{driver.readiness_port(host_ports)}"
            )
        instance = BrokerInstance(
            broker_id=broker_id,
            container_name=container_name,
            engine=driver.engine,
            engine_version=engine_version,
            ports=host_ports,
            admin_username=admin_username,
            admin_password=admin_password,
        )
        with self._lock:
            self._brokers[broker_id] = instance
        LOG.info(
            "MQ broker %s up (engine=%s, ports=%s)",
            broker_id, driver.engine, host_ports,
        )
        return instance

    def delete_broker(self, broker_id: str) -> None:
        with self._lock:
            instance = self._brokers.pop(broker_id, None)
        if instance is None:
            # Reconciliation fallback: ask Docker directly so a delete
            # against an orphaned container still works after a process
            # restart that lost the manager's in-memory map.
            container_name = f"{_CONTAINER_NAME_PREFIX}{broker_id}"
        else:
            container_name = instance.container_name
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=10)
        except Exception:
            LOG.debug("stop_container raised for %s", container_name, exc_info=True)
        try:
            DOCKER_CLIENT.remove_container(container_name, force=True)
        except Exception:
            LOG.debug("remove_container raised for %s", container_name, exc_info=True)

    def get_broker(self, broker_id: str) -> BrokerInstance | None:
        with self._lock:
            inst = self._brokers.get(broker_id)
        if inst is not None:
            return inst
        # Try Docker — handles the post-restart case where the manager
        # hasn't yet rehydrated and DescribeBroker arrives.
        return self._rehydrate_from_docker(broker_id)

    def list_brokers(self) -> list[BrokerInstance]:
        with self._lock:
            return list(self._brokers.values())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _ensure_image(self, image: str) -> None:
        with self._image_pull_lock:
            if image in self._pulled_images:
                return
            try:
                DOCKER_CLIENT.inspect_image(image)
            except Exception:
                LOG.info("Pulling MQ broker image %s (one-time)…", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                except Exception:
                    LOG.warning("pull_image %s failed; trying without re-pull", image, exc_info=True)
            self._pulled_images.add(image)

    def _wait_for_port(
        self, port: int, host: str = "127.0.0.1",
        timeout: int = _READINESS_TIMEOUT_SEC,
    ) -> bool:
        """Block until *host:port* accepts a TCP connection AND the
        broker has had a moment to finish wiring its protocol layer.

        TCP-accept alone isn't enough: RabbitMQ binds the AMQP socket
        just before its plugin chain finishes initialising. A client
        that connects in that window gets "Connection reset by peer"
        on the AMQP handshake because the protocol code isn't ready
        yet. We add a small post-accept settle delay so the first
        real client connect succeeds without per-test retry logic.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    # Settle delay covers the gap between AMQP socket
                    # bind and full plugin chain readiness. Measured
                    # ~1s on a warm pull of rabbitmq:3.13-management.
                    time.sleep(3.0)
                    return True
            except OSError:
                time.sleep(_PORT_PROBE_INTERVAL_SEC)
        return False

    def _reconcile_ports_from_docker(
        self, container_name: str, driver: BrokerEngineDriver,
    ) -> dict[str, int] | None:
        """Read back the host ports Docker actually bound and rebuild
        the protocol→host-port map. Driver-side container_port mapping
        is the source of truth for which protocol owns which container
        port; we ask the driver to expose that mapping via a private
        attribute (``_container_ports``)."""
        try:
            inspect = DOCKER_CLIENT.inspect_container(container_name)
        except Exception:
            return None
        ports_info = (inspect.get("NetworkSettings") or {}).get("Ports") or {}
        container_to_protocol = getattr(driver, "_container_ports", None)
        if container_to_protocol is None:
            return None
        out: dict[str, int] = {}
        for protocol, container_port in container_to_protocol.items():
            bindings = ports_info.get(f"{container_port}/tcp") or []
            for binding in bindings:
                host_ip = binding.get("HostIp") or ""
                if host_ip in ("0.0.0.0", "127.0.0.1"):
                    try:
                        out[protocol] = int(binding["HostPort"])
                    except (KeyError, ValueError):
                        pass
                    break
        return out or None

    def _rehydrate_from_docker(self, broker_id: str) -> BrokerInstance | None:
        container_name = f"{_CONTAINER_NAME_PREFIX}{broker_id}"
        try:
            inspect = DOCKER_CLIENT.inspect_container(container_name)
        except Exception:
            return None
        labels = (inspect.get("Config") or {}).get("Labels") or {}
        engine = labels.get(_LABEL_ENGINE) or "RABBITMQ"
        ports = {
            key[len(_LABEL_PORT_PREFIX):]: int(value)
            for key, value in labels.items()
            if key.startswith(_LABEL_PORT_PREFIX) and value.isdigit()
        }
        state = inspect.get("State") or {}
        instance = BrokerInstance(
            broker_id=broker_id,
            container_name=container_name,
            engine=engine,
            engine_version="",  # unknown without API call; v1 ignores
            ports=ports,
            admin_username="",
            admin_password="",
            state="RUNNING" if state.get("Running") else "CREATION_FAILED",
        )
        with self._lock:
            self._brokers[broker_id] = instance
        return instance


def _reset_singleton_for_tests() -> None:
    """Test-only — drop the singleton + close every running broker so
    each test starts from a clean Docker state."""
    with BrokerManager._instance_lock:
        if BrokerManager._instance is not None:
            for inst in BrokerManager._instance.list_brokers():
                try:
                    BrokerManager._instance.delete_broker(inst.broker_id)
                except Exception:
                    pass
        BrokerManager._instance = None
