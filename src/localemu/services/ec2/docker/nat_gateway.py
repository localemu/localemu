"""
NAT Gateway emulation via Docker networking.

When a NAT Gateway is created in a public subnet, private containers
in the same VPC can reach the internet through it.  The mechanism:
a lightweight Docker container (alpine) connected to both the VPC's
internal network and a bridge network for internet access.  Private
containers are then connected to this bridge network to gain
internet access through Docker's built-in NAT.

Architecture:
  Private container (--internal network)
      ↓ docker network connect nat-bridge
  NAT container (both internal + bridge)
      ↓ Docker bridge NAT
  Internet
"""

from __future__ import annotations

import logging
import threading

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

NAT_BRIDGE_PREFIX = "localemu-nat-bridge-"


class NatGatewayManager:
    """Manages NAT Gateway Docker containers and bridge networks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # nat_id → {container_name, bridge_network, vpc_id, private_containers: set}
        self._gateways: dict[str, dict] = {}

    def create_nat_gateway(
        self, nat_id: str, vpc_id: str, subnet_id: str,
    ) -> str | None:
        """Create a NAT Gateway as a Docker container.

        Creates a bridge network for NAT traffic and an alpine container
        connected to both the VPC's internal network and the bridge.
        """
        container_name = f"localemu-nat-{nat_id}"
        bridge_network = f"{NAT_BRIDGE_PREFIX}{nat_id}"
        vpc_network = f"localemu-vpc-{vpc_id}"

        try:
            # Create a non-internal bridge for internet access
            DOCKER_CLIENT.create_network(network_name=bridge_network)

            # NAT container: starts on bridge (internet), then joins VPC network
            config = ContainerConfiguration(
                image_name="alpine:3.19",
                name=container_name,
                command=["sh", "-c", "while true; do sleep 3600; done"],
                network=bridge_network,
                detach=True,
                labels={
                    "localemu.service": "nat-gateway",
                    "localemu.nat-id": nat_id,
                    "localemu.vpc-id": vpc_id,
                },
            )
            DOCKER_CLIENT.create_container_from_config(config)
            DOCKER_CLIENT.start_container(container_name)

            # Connect NAT container to VPC's internal network too
            DOCKER_CLIENT.connect_container_to_network(vpc_network, container_name)

            with self._lock:
                self._gateways[nat_id] = {
                    "container_name": container_name,
                    "bridge_network": bridge_network,
                    "vpc_id": vpc_id,
                    "private_containers": set(),
                }

            # Auto-attach every container already on this VPC's network
            # so existing private instances get internet immediately
            # without needing a restart.
            try:
                from localemu.services.ec2.docker.vpc_network import (
                    get_vpc_network_manager,
                )
                vpcm = get_vpc_network_manager()
                with vpcm._lock:
                    existing = list(
                        vpcm._vpcs.get(vpc_id, {}).get("containers", set()),
                    )
                for c in existing:
                    try:
                        DOCKER_CLIENT.connect_container_to_network(bridge_network, c)
                    except Exception:
                        pass
                if existing:
                    LOG.info(
                        "NAT Gateway %s back-attached %d existing container(s)",
                        nat_id, len(existing),
                    )
            except Exception:
                pass

            LOG.info("NAT Gateway %s created (container=%s, bridge=%s)", nat_id, container_name, bridge_network)
            return container_name

        except Exception as e:
            LOG.warning("Failed to create NAT Gateway %s: %s", nat_id, e)
            # Clean up any partially created resources
            try:
                DOCKER_CLIENT.stop_container(container_name, timeout=5)
            except Exception:
                pass
            try:
                DOCKER_CLIENT.remove_container(container_name)
            except Exception:
                pass
            try:
                DOCKER_CLIENT.delete_network(bridge_network)
            except Exception:
                pass
            return None

    def connect_private_container(self, nat_id: str, container_name: str) -> None:
        """Give a private container internet access through this NAT Gateway.

        Connects the container to the NAT's bridge network, which has
        internet access via Docker's built-in NAT.
        """
        with self._lock:
            gw = self._gateways.get(nat_id)
            if not gw:
                return
            bridge = gw["bridge_network"]
            gw["private_containers"].add(container_name)

        try:
            DOCKER_CLIENT.connect_container_to_network(bridge, container_name)
            LOG.debug("Connected %s to NAT Gateway %s bridge", container_name, nat_id)
        except Exception as e:
            LOG.debug("Failed to connect %s to NAT bridge: %s", container_name, e)

    def delete_nat_gateway(self, nat_id: str) -> None:
        """Remove a NAT Gateway container and its bridge network."""
        with self._lock:
            gw = self._gateways.pop(nat_id, None)
            if not gw:
                return
            container_name = gw["container_name"]
            bridge = gw["bridge_network"]
            private_containers = gw["private_containers"]

        # Disconnect private containers from bridge
        for pc in private_containers:
            try:
                DOCKER_CLIENT.disconnect_container_from_network(bridge, pc)
            except Exception:
                pass

        # Stop and remove NAT container
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=5)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(container_name)
        except Exception:
            pass

        # Remove bridge network
        try:
            DOCKER_CLIENT.delete_network(bridge)
        except Exception:
            pass

        LOG.info("NAT Gateway %s deleted", nat_id)

    def get_nat_for_vpc(self, vpc_id: str) -> str | None:
        """Return the NAT Gateway ID for a VPC, if one exists."""
        with self._lock:
            for nat_id, gw in self._gateways.items():
                if gw["vpc_id"] == vpc_id:
                    return nat_id
        return None

    def get_bridge_network_for_vpc(self, vpc_id: str) -> str | None:
        """Return the NAT bridge network name for the VPC's NAT Gateway,
        or ``None`` if no NAT exists for that VPC. Callers that want
        internet from a VPC-internal container connect_container_to_network
        to this bridge so Docker's default NAT carries traffic out.
        """
        with self._lock:
            for gw in self._gateways.values():
                if gw["vpc_id"] == vpc_id:
                    return gw["bridge_network"]
        return None

    def cleanup_all(self) -> None:
        """Remove all NAT Gateway containers. Called on shutdown."""
        with self._lock:
            nat_ids = list(self._gateways.keys())
        for nat_id in nat_ids:
            self.delete_nat_gateway(nat_id)


# Module-level singleton
_nat_manager: NatGatewayManager | None = None
_nat_lock = threading.Lock()


def get_nat_gateway_manager() -> NatGatewayManager:
    global _nat_manager
    if _nat_manager is None:
        with _nat_lock:
            if _nat_manager is None:
                _nat_manager = NatGatewayManager()
    return _nat_manager
