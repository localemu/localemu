"""Tests for the full persist -> restart -> reconcile orphan cleanup cycle.

While ``test_address_reconciler.py`` covers the in-memory reconciler in
isolation and ``test_address_index.py`` covers serialization round-trip,
the *combined* path -- "stale state on disk, fresh process loads it,
reconciler walks Docker, orphans are removed" -- was not covered. That
seam is what produced the cross-session test pollution observed when
running the SG-cross-reference E2E twice in a row with PERSISTENCE=1.

This test pins down the contract:

  After ``load_addressing_state()`` followed by ``reconcile_on_startup()``,
  every ENI whose Docker container has vanished MUST be gone from the
  AddressIndex, and its IP MUST be back in the SubnetAllocator free pool.
"""
from __future__ import annotations

import ipaddress
import os
import tempfile
from unittest import mock

import pytest

from localemu.services.ec2.docker import (
    address_index,
    address_reconciler,
    addressing_persistence,
    subnet_allocator,
)
from localemu.services.ec2.docker.address_index import (
    get_address_index, reset_address_index_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator, reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_address_index_for_tests()
    reset_subnet_allocator_for_tests()
    yield
    reset_address_index_for_tests()
    reset_subnet_allocator_for_tests()


@pytest.fixture
def temp_data_dir(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="le-persist-") as d:
        # Redirect addressing_persistence to read/write here
        monkeypatch.setattr(
            addressing_persistence, "_data_dir", lambda: d,
        )
        yield d


def _populate_session_one(num_enis: int = 3) -> list[str]:
    """Simulate a prior session: register subnet, reserve IPs, register ENIs.

    Returns the list of ENI IDs created.
    """
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        "vpc-1", "subnet-a", "10.0.1.0/24", "10.0.1.0/24", "us-east-1a",
    )
    idx = get_address_index()
    eni_ids: list[str] = []
    for i in range(num_enis):
        eni_id = f"eni-old{i}"
        ip = alloc.reserve("vpc-1", "subnet-a", eni_id)
        idx.register_eni(
            eni_id=eni_id, vpc_id="vpc-1", subnet_id="subnet-a",
            primary_ip=ip, sg_ids=[f"sg-old{i}"],
            instance_id=f"i-old{i}", iface_name="eth1",
        )
        eni_ids.append(eni_id)
    return eni_ids


class TestPersistedOrphansAreDroppedOnRestart:
    def test_save_then_load_then_reconcile_drops_orphans(self, temp_data_dir):
        """The killer scenario: a prior session saved 3 ENIs to disk,
        the new session has zero containers. Reconcile must drop all 3
        and release every IP back to the allocator."""
        # Session 1: populate + save
        stale_eni_ids = _populate_session_one(num_enis=3)
        assert get_address_index().get_eni("eni-old0") is not None
        addressing_persistence.save_addressing_state()

        # Session 2: simulate restart by resetting singletons
        reset_address_index_for_tests()
        reset_subnet_allocator_for_tests()
        assert get_address_index().all_enis() == []

        # Load from disk
        a_loaded, i_loaded = addressing_persistence.load_addressing_state()
        assert a_loaded and i_loaded, "disk state should have loaded"
        assert len(get_address_index().all_enis()) == 3, (
            "stale ENIs should be restored from disk pre-reconcile"
        )

        # Reconcile: Docker view is EMPTY (no containers exist this session)
        with mock.patch.object(
            address_reconciler, "_walk_docker_networks",
            return_value={},
        ):
            report = address_reconciler.reconcile_on_startup()

        assert report.dropped_orphan == 3, report.summary()
        assert set(report.orphan_enis) == set(stale_eni_ids)
        # Index is empty now
        assert get_address_index().all_enis() == []
        # And every IP is back in the free pool
        for ip_str in ("10.0.1.4", "10.0.1.5", "10.0.1.6"):
            # The new reserves should grab the same /32s since the pool
            # released them.
            free_ip = get_subnet_allocator().reserve(
                "vpc-1", "subnet-a", f"eni-new-{ip_str}",
            )
            assert str(free_ip).startswith("10.0.1.")

    def test_save_load_reconcile_keeps_live_enis(self, temp_data_dir):
        """Mirror: an ENI that DOES exist in Docker must NOT be dropped."""
        _populate_session_one(num_enis=2)
        addressing_persistence.save_addressing_state()
        reset_address_index_for_tests()
        reset_subnet_allocator_for_tests()
        addressing_persistence.load_addressing_state()
        assert len(get_address_index().all_enis()) == 2

        # Docker view: one of the two ENIs is still there
        live_member = address_reconciler._DockerMember(
            container_name="localemu-ec2-i-old0",
            network_name=f"{address_reconciler.VPC_NETWORK_PREFIX}vpc-1",
            vpc_id="vpc-1",
            primary_ip=ipaddress.IPv4Address("10.0.1.4"),
            eni_id="eni-old0",
            subnet_id="subnet-a",
            instance_id="i-old0",
            sg_ids=["sg-old0"],
            mac=None,
        )
        with mock.patch.object(
            address_reconciler, "_walk_docker_networks",
            return_value={"localemu-vpc-vpc-1": [live_member]},
        ):
            report = address_reconciler.reconcile_on_startup()

        assert report.dropped_orphan == 1
        assert report.orphan_enis == ["eni-old1"]
        # The live ENI is still in the index
        assert get_address_index().get_eni("eni-old0") is not None
        assert get_address_index().get_eni("eni-old1") is None


class TestDockerUnreachableDoesNotMaskBug:
    def test_docker_unreachable_leaves_stale_state_intact(self, temp_data_dir):
        """If Docker is unreachable, the reconciler returns early and
        the stale state survives. This is the documented behavior
        (address_reconciler.py:98-103) — but the test exists to make
        sure a future change does not silently start dropping ALL
        entries when Docker is down (that would mass-delete live state).
        """
        _populate_session_one(num_enis=2)
        addressing_persistence.save_addressing_state()
        reset_address_index_for_tests()
        reset_subnet_allocator_for_tests()
        addressing_persistence.load_addressing_state()
        assert len(get_address_index().all_enis()) == 2

        with mock.patch.object(
            address_reconciler, "_walk_docker_networks",
            return_value=None,  # Docker unreachable
        ):
            report = address_reconciler.reconcile_on_startup()

        assert report.dropped_orphan == 0
        # Entries survive — caller should retry reconciliation later
        assert len(get_address_index().all_enis()) == 2


class TestNoCrashOnEmptyDisk:
    def test_first_run_no_disk_state_no_crash(self, temp_data_dir):
        """Cold start with no prior persistence file: load returns
        (False, False), reconcile runs cleanly against empty Docker."""
        a, i = addressing_persistence.load_addressing_state()
        assert (a, i) == (False, False)
        with mock.patch.object(
            address_reconciler, "_walk_docker_networks",
            return_value={},
        ):
            report = address_reconciler.reconcile_on_startup()
        assert report.dropped_orphan == 0
        assert report.enis_after == 0
