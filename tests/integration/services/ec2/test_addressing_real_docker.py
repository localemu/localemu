"""Real-Docker integration test for the addressing redesign primitives.

This test proves end-to-end that:
  1. The SubnetAllocator hands out an IP inside the requested subnet
  2. Docker accepts ``ipv4_address`` on ``connect_container_to_network``
     and pins the container to that address
  3. ``docker inspect`` reports the same IP back
  4. The AddressIndex correctly resolves IP <-> ENI <-> SG-membership
  5. The cleanup (release + delete_eni) restores the allocator pool

Requires a working Docker daemon. Auto-skips if Docker is unreachable.
Cleans up after itself (delete network, delete container) so it can
re-run idempotently.
"""
from __future__ import annotations

import ipaddress

import pytest

from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)
from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
)
from localemu.utils.docker_utils import DOCKER_CLIENT


# Predictable artifacts so cleanup can find them even after a crash
_NET_NAME = "localemu-vpc-addressing-itest"
_CTR_NAME = "localemu-ec2-i-addressing-itest"
_VPC_ID = "addressing-itest"
_SUBNET_ID = "subnet-addressing-itest"
_SUBNET_CIDR = "10.250.0.0/24"


@pytest.fixture(scope="module", autouse=True)
def _require_docker():
    """Skip the module if Docker is unreachable."""
    try:
        info = DOCKER_CLIENT.get_system_info()
        if not info:
            pytest.skip("Docker daemon not reachable")
    except Exception as exc:
        pytest.skip(f"Docker daemon not reachable: {exc}")


@pytest.fixture
def _clean_state():
    """Reset singletons + tear down any leftover Docker artifacts before
    and after each test."""
    _teardown_docker()
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    yield
    _teardown_docker()
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()


def _teardown_docker():
    try:
        DOCKER_CLIENT.stop_container(_CTR_NAME, timeout=2)
    except Exception:
        pass
    try:
        DOCKER_CLIENT.remove_container(_CTR_NAME, force=True)
    except Exception:
        pass
    try:
        DOCKER_CLIENT.delete_network(_NET_NAME)
    except Exception:
        pass


class TestIpv4PinningEndToEnd:
    def test_pinned_ip_round_trips_through_docker(self, _clean_state):
        # 1. Set up the bridge network with an explicit subnet (required
        # for --ip pinning to be honored by Docker)
        DOCKER_CLIENT.create_network(
            _NET_NAME, subnet=_SUBNET_CIDR, internal=False,
        )

        # 2. Register the subnet pool with the allocator
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            vpc_id=_VPC_ID, subnet_id=_SUBNET_ID,
            aws_cidr=_SUBNET_CIDR, docker_cidr=_SUBNET_CIDR,
            az="us-east-1a",
        )

        # 3. Reserve an IP for our 'instance'
        reserved = alloc.reserve(
            vpc_id=_VPC_ID, subnet_id=_SUBNET_ID,
            owner_key="eni-itest",
        )
        # Should be inside the subnet, not in the AWS-reserved set
        assert reserved in ipaddress.IPv4Network(_SUBNET_CIDR)
        assert int(reserved.packed[-1]) >= 4  # past .0/.1/.2/.3

        # 4. Create a tiny container on that network with the pinned IP
        config = ContainerConfiguration(
            image_name="alpine:3.20",
            name=_CTR_NAME,
            network=_NET_NAME,
            command=["sleep", "60"],
            detach=True,
        )
        DOCKER_CLIENT.create_container_from_config(config)
        DOCKER_CLIENT.start_container(_CTR_NAME)

        # The container was created with auto-IPAM on _NET_NAME because
        # ContainerConfiguration doesn't accept ipv4_address; the actual
        # design-targeted path goes through connect_container_to_network
        # for the VPC bridge as a SECONDARY network. Mimic that here:
        # disconnect first then reconnect with pinning.
        DOCKER_CLIENT.disconnect_container_from_network(_NET_NAME, _CTR_NAME)
        DOCKER_CLIENT.connect_container_to_network(
            network_name=_NET_NAME,
            container_name_or_id=_CTR_NAME,
            ipv4_address=str(reserved),
        )

        # 5. Verify Docker reports the same IP
        live_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
            _CTR_NAME, _NET_NAME,
        )
        assert live_ip == str(reserved), (
            f"Docker IP {live_ip} != reserved {reserved}"
        )

        # 6. Register in AddressIndex and verify reverse lookups
        idx = get_address_index()
        idx.register_eni(
            "eni-itest", _VPC_ID, _SUBNET_ID, reserved,
            sg_ids=["sg-itest"], instance_id="i-itest",
        )
        # IP -> ENI
        assert idx.get_eni_for_ip(reserved).eni_id == "eni-itest"
        # SG -> IPs
        assert reserved in idx.get_ips_for_sg("sg-itest")
        # Instance -> ENI primary
        assert idx.get_primary_ip_for_instance("i-itest") == reserved

        # 7. Cleanup paths: release + delete restores the pool
        removed = idx.delete_eni("eni-itest")
        assert removed is not None
        alloc.release(removed.primary_ip)
        assert alloc.lookup(reserved) is None
        # The reserved IP can be reserved again
        new_ip = alloc.reserve(
            _VPC_ID, _SUBNET_ID, "eni-second", requested=str(reserved),
        )
        assert new_ip == reserved
