"""Pin the runtime subnet-pool realign at ``RunInstances`` time.

When a subnet is registered before its VPC bridge exists, the pool's
``docker_cidr`` is the optimistic AWS CIDR. If the bridge is later
created and falls back to a non-AWS CIDR tier (collision case), the
pool is now stale — reserving an IP from it would return an address
Docker rejects on ``--ip``.

``_realign_subnet_pool_to_vpc_bridge`` runs immediately before
``allocator.reserve()`` and force-re-registers the pool with the
shifted CIDR. These tests pin the realign in three shapes: happy-path
no-op, fallback shift, and missing bridge tolerated.
"""
from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock, patch

from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)
from localemu.services.ec2.docker.vm_manager import (
    _realign_subnet_pool_to_vpc_bridge,
)


def _reset() -> None:
    reset_subnet_allocator_for_tests()


def test_noop_when_bridge_already_matches_pool():
    """No collision: VPC AWS == VPC Docker, pool already uses subnet's
    AWS CIDR. Realign must not touch the pool — calling
    force_unregister would needlessly invalidate live allocations."""
    _reset()
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        vpc_id="vpc-aaa", subnet_id="subnet-aaa",
        aws_cidr="10.86.1.0/24", docker_cidr="10.86.1.0/24",
        az="us-east-1a",
    )
    # Reserve an IP so we'd know if the pool got blown away
    alloc.reserve(vpc_id="vpc-aaa", subnet_id="subnet-aaa", owner_key="eni-x")

    fake_vpc_mgr = MagicMock()
    fake_vpc_mgr.get_docker_cidr_for_vpc.return_value = "10.86.0.0/16"
    fake_vpc_mgr._lookup_vpc_cidr_in_moto.return_value = "10.86.0.0/16"

    with patch(
        "localemu.services.ec2.docker.vpc_network."
        "get_vpc_network_manager", return_value=fake_vpc_mgr,
    ):
        _realign_subnet_pool_to_vpc_bridge("vpc-aaa", "subnet-aaa")

    # Pool is still here, allocation is still recorded
    pools = alloc.all_pools()
    assert len(pools) == 1
    assert pools[0].docker_cidr == ipaddress.IPv4Network("10.86.1.0/24")
    assert len(pools[0].allocated) == 1


def test_shifts_pool_when_bridge_fell_back():
    """The collision case Tarek hit: subnet was registered with
    aws_cidr=docker_cidr=10.86.1.0/24, then the VPC bridge fell back
    to 10.0.0.0/16. Realign must force-re-register the pool with
    docker_cidr=10.0.1.0/24 so the next reserve returns an IP Docker
    will accept on the new bridge."""
    _reset()
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        vpc_id="vpc-bbb", subnet_id="subnet-bbb",
        aws_cidr="10.86.1.0/24", docker_cidr="10.86.1.0/24",
        az="us-east-1a",
    )

    fake_vpc_mgr = MagicMock()
    fake_vpc_mgr.get_docker_cidr_for_vpc.return_value = "10.0.0.0/16"
    fake_vpc_mgr._lookup_vpc_cidr_in_moto.return_value = "10.86.0.0/16"

    with patch(
        "localemu.services.ec2.docker.vpc_network."
        "get_vpc_network_manager", return_value=fake_vpc_mgr,
    ):
        _realign_subnet_pool_to_vpc_bridge("vpc-bbb", "subnet-bbb")

    pools = alloc.all_pools()
    assert len(pools) == 1
    assert pools[0].docker_cidr == ipaddress.IPv4Network("10.0.1.0/24"), (
        f"realign should have shifted to 10.0.1.0/24, got {pools[0].docker_cidr}"
    )
    # AWS CIDR stays at user-visible value
    assert pools[0].aws_cidr == ipaddress.IPv4Network("10.86.1.0/24")

    # Next reserve returns an IP in the SHIFTED range, not the AWS range
    ip = alloc.reserve(
        vpc_id="vpc-bbb", subnet_id="subnet-bbb", owner_key="eni-y",
    )
    assert ip in ipaddress.IPv4Network("10.0.1.0/24"), (
        f"reserve after realign returned {ip}, outside bridge subnet"
    )


def test_tolerates_missing_bridge():
    """Realign is called for every RunInstances; not every code path
    has the VPC bridge tracked (early startup, persistence restore in
    progress). Missing bridge must be a no-op, never an exception —
    the reserve that follows will fail cleanly if the pool is wrong
    and the caller falls back to auto-IPAM."""
    _reset()
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        vpc_id="vpc-ccc", subnet_id="subnet-ccc",
        aws_cidr="10.86.1.0/24", docker_cidr="10.86.1.0/24",
        az="us-east-1a",
    )

    fake_vpc_mgr = MagicMock()
    fake_vpc_mgr.get_docker_cidr_for_vpc.return_value = None
    fake_vpc_mgr._lookup_vpc_cidr_in_moto.return_value = None

    with patch(
        "localemu.services.ec2.docker.vpc_network."
        "get_vpc_network_manager", return_value=fake_vpc_mgr,
    ):
        # Must not raise
        _realign_subnet_pool_to_vpc_bridge("vpc-ccc", "subnet-ccc")

    # Pool untouched
    pools = alloc.all_pools()
    assert len(pools) == 1
    assert pools[0].docker_cidr == ipaddress.IPv4Network("10.86.1.0/24")


def test_tolerates_unregistered_subnet():
    """For non-VPC instances or instances whose subnet hasn't been
    seen by the allocator yet, realign must be a no-op. The reserve
    that follows will raise ``UnknownSubnet`` and the caller falls
    back to auto-IPAM."""
    _reset()
    fake_vpc_mgr = MagicMock()
    fake_vpc_mgr.get_docker_cidr_for_vpc.return_value = "10.0.0.0/16"
    fake_vpc_mgr._lookup_vpc_cidr_in_moto.return_value = "10.86.0.0/16"

    with patch(
        "localemu.services.ec2.docker.vpc_network."
        "get_vpc_network_manager", return_value=fake_vpc_mgr,
    ):
        # Subnet was never registered — realign should silently no-op
        _realign_subnet_pool_to_vpc_bridge("vpc-ddd", "subnet-ddd")
