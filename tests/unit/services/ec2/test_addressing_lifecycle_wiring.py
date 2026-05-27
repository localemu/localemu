"""Tests for the Ec2Provider lifecycle hooks that wire the addressing
redesign into on_after_init (save handler) and on_after_state_load
(reconciler + persistence load + moto subnet walk).
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2 import provider as ec2_provider
from localemu.services.ec2.docker import addressing_persistence
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    addressing_persistence._reset_for_tests()
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    addressing_persistence._reset_for_tests()


class TestReconcileAddressingState:
    def test_no_op_when_flag_off(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            # Should not even attempt to import addressing_persistence —
            # if it does, the empty allocator is the proof of no-op
            ec2_provider._reconcile_addressing_state()
            assert get_subnet_allocator().all_pools() == []

    def test_walks_moto_subnets_when_flag_on(self):
        fake_subnet = mock.MagicMock(
            id="subnet-aaa", vpc_id="vpc-1",
            cidr_block="10.0.1.0/24", availability_zone="us-east-1a",
        )
        fake_backend = mock.MagicMock()
        fake_backend.subnets = {"us-east-1a": {"subnet-aaa": fake_subnet}}
        fake_ec2_backends = {"000000000000": {"us-east-1": fake_backend}}

        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 addressing_persistence, "load_addressing_state",
                 return_value=(False, False),
             ), \
             mock.patch("moto.ec2.ec2_backends", fake_ec2_backends), \
             mock.patch(
                 "localemu.services.ec2.docker.address_reconciler."
                 "reconcile_on_startup",
                 return_value=mock.MagicMock(
                     summary=lambda: "test", matched=0,
                 ),
             ):
            ec2_provider._reconcile_addressing_state()

        # Subnet registered via moto walk
        pools = get_subnet_allocator().describe("vpc-1")
        assert len(pools) == 1
        assert pools[0].subnet_id == "subnet-aaa"

    def test_continues_on_load_failure(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 addressing_persistence, "load_addressing_state",
                 side_effect=RuntimeError("disk corrupt"),
             ), \
             mock.patch("moto.ec2.ec2_backends", {}), \
             mock.patch(
                 "localemu.services.ec2.docker.address_reconciler."
                 "reconcile_on_startup",
                 return_value=mock.MagicMock(
                     summary=lambda: "x", matched=0,
                 ),
             ):
            # Should not raise; reconciler still called
            ec2_provider._reconcile_addressing_state()

    def test_handles_moto_walk_exception(self):
        with mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 addressing_persistence, "load_addressing_state",
                 return_value=(False, False),
             ), \
             mock.patch(
                 "moto.ec2.ec2_backends",
                 new_callable=mock.PropertyMock,
                 side_effect=RuntimeError("moto broken"),
             ):
            # Should not raise
            ec2_provider._reconcile_addressing_state()
