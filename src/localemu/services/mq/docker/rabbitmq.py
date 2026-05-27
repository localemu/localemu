"""RabbitMQ engine driver for the MQ broker manager.

Spins up a real ``rabbitmq:management`` container with the admin user
pre-seeded via ``RABBITMQ_DEFAULT_USER`` / ``RABBITMQ_DEFAULT_PASS`` so
the very first connect from a real client works without an extra
``rabbitmqctl add_user`` round-trip. The management plugin is included
because it costs ~50 MB but unlocks the HTTP management API at
``http://localhost:<mgmt-port>/api/`` — invaluable for debugging.
"""

from __future__ import annotations

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
)


# Wire protocols the management image exposes by default.
# Keys are the protocol-name labels we stamp on the container so the
# reconciler can rehydrate after a restart; values are the in-container
# ports rabbitmq binds.
_RABBITMQ_PROTOCOLS = {
    "amqp": 5672,
    "amqps": 5671,
    "mgmt": 15672,
    "mqtt": 1883,
    "stomp": 61613,
}

# Real-world tag pattern: ``3.13-management``, ``3.12-management``, ...
# A bare engine version (``"3.13"``) maps to the ``-management`` tag so
# the management plugin is always on. Unknown versions fall back to the
# latest LTS that LocalEmu's been tested with.
_DEFAULT_VERSION = "3.13"


class RabbitMQDriver:
    engine = "RABBITMQ"
    # Exposed for BrokerManager._reconcile_ports_from_docker — protocol
    # name → container-side port the broker listens on. The manager
    # reads it back from ``docker inspect`` after start so we always
    # know the true host port even when ``PortMappings`` merges
    # adjacent ranges in the launch command.
    _container_ports = dict(_RABBITMQ_PROTOCOLS)

    def default_image(self, engine_version: str) -> str:
        version = (engine_version or "").strip() or _DEFAULT_VERSION
        # Strip any ``-management`` suffix the caller might have added.
        version = version.replace("-management", "")
        return f"rabbitmq:{version}-management"

    def protocols(self) -> list[str]:
        return list(_RABBITMQ_PROTOCOLS.keys())

    def readiness_port(self, host_ports: dict[str, int]) -> int:
        # AMQP is the load-bearing protocol — if it's open, the broker
        # is accepting connections. Polling mgmt would also work but
        # spends more bytes per probe.
        return host_ports["amqp"]

    def container_config(
        self,
        *,
        broker_id: str,
        container_name: str,
        image: str,
        host_ports: dict[str, int],
        admin_username: str,
        admin_password: str,
    ) -> ContainerConfiguration:
        ports = PortMappings()
        for protocol, container_port in _RABBITMQ_PROTOCOLS.items():
            ports.add(host_ports[protocol], container_port)
        env_vars = {
            # Seed the admin user so the first AMQP connect works
            # without a follow-up rabbitmqctl call. CreateUser API
            # operations against this broker still flow through
            # rabbitmqctl exec; this is just the bootstrap admin.
            "RABBITMQ_DEFAULT_USER": admin_username or "admin",
            "RABBITMQ_DEFAULT_PASS": admin_password or "password",
        }
        return ContainerConfiguration(
            image_name=image,
            name=container_name,
            ports=ports,
            env_vars=env_vars,
            detach=True,
            remove=False,
        )
