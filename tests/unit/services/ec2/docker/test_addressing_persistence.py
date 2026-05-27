"""Tests for the SubnetAllocator + AddressIndex persistence wiring."""
from __future__ import annotations

from unittest import mock

import pytest

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


class TestLoadAndSaveRoundTrip:
    def test_round_trip(self, tmp_path):
        with mock.patch.object(
            addressing_persistence, "_data_dir", return_value=str(tmp_path),
        ):
            # Populate allocator + index
            alloc = get_subnet_allocator()
            alloc.register_subnet(
                "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
            )
            ip = alloc.reserve("vpc-1", "sub-a", "eni-1")

            idx = get_address_index()
            idx.register_eni(
                "eni-1", "vpc-1", "sub-a", ip,
                sg_ids=["sg-web"], instance_id="i-1",
            )

            # Save
            addressing_persistence.save_addressing_state()
            assert (tmp_path / addressing_persistence.ALLOCATOR_FILENAME).exists()
            assert (tmp_path / addressing_persistence.INDEX_FILENAME).exists()

            # Reset and reload
            reset_subnet_allocator_for_tests()
            reset_address_index_for_tests()
            a_loaded, i_loaded = addressing_persistence.load_addressing_state()
            assert a_loaded is True
            assert i_loaded is True

            assert get_subnet_allocator().lookup(ip) == ("vpc-1", "sub-a", "eni-1")
            assert get_address_index().get_eni("eni-1").primary_ip == ip

    def test_load_when_files_missing(self, tmp_path):
        with mock.patch.object(
            addressing_persistence, "_data_dir", return_value=str(tmp_path),
        ):
            a_loaded, i_loaded = addressing_persistence.load_addressing_state()
            assert a_loaded is False
            assert i_loaded is False

    def test_save_swallows_errors_per_file(self, tmp_path):
        """A failure on the allocator save must not block the index save
        (and vice versa)."""
        with mock.patch.object(
            addressing_persistence, "_data_dir", return_value=str(tmp_path),
        ):
            alloc = get_subnet_allocator()
            with mock.patch.object(
                alloc, "save_to_file", side_effect=RuntimeError("disk full"),
            ):
                # No raise — error is logged, index save still attempted
                addressing_persistence.save_addressing_state()
            # Index file was still written (empty state)
            assert (tmp_path / addressing_persistence.INDEX_FILENAME).exists()


class TestRegisterSaveHandler:
    def test_idempotent(self):
        with mock.patch("localemu.config.PERSISTENCE", True), \
             mock.patch(
                 "localemu.runtime.shutdown.SHUTDOWN_HANDLERS"
             ) as handlers:
            addressing_persistence.register_save_handler()
            addressing_persistence.register_save_handler()
            addressing_persistence.register_save_handler()
            # Only registered once
            assert handlers.register.call_count == 1

    def test_skipped_when_persistence_off(self):
        with mock.patch("localemu.config.PERSISTENCE", False), \
             mock.patch(
                 "localemu.runtime.shutdown.SHUTDOWN_HANDLERS"
             ) as handlers:
            addressing_persistence.register_save_handler()
            # Nothing registered when persistence is off
            handlers.register.assert_not_called()
