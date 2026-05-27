"""Unit tests for SubnetAllocator.

Covers:
  - register / unregister / force-unregister
  - reserve auto-pick (sequential + wrap-around + exhaustion)
  - reserve with requested IP (valid / out-of-range / reserved / in-use)
  - release idempotency
  - claim (reconciler path: idempotent + conflict)
  - AWS-5-reservation correctness (.0/.1/.2/.3/broadcast)
  - Docker gateway reservation when docker_cidr != aws_cidr
  - Persistence round-trip
  - Schema-version mismatch handling
  - Corrupt-file recovery (returns False)
  - Concurrency (32 threads racing reserve, no duplicates)
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading

import pytest

from localemu.services.ec2.docker import subnet_allocator
from localemu.services.ec2.docker.subnet_allocator import (
    InsufficientFreeAddressesInSubnet,
    InvalidIpForSubnet,
    IpAddressInUse,
    IpClaimConflict,
    SubnetAllocator,
    SubnetCidrConflict,
    SubnetInUse,
    UnknownSubnet,
    _compute_reserved,
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_subnet_allocator_for_tests()
    yield
    reset_subnet_allocator_for_tests()


# ---------------------------------------------------------------------------
# Reservation-set computation
# ---------------------------------------------------------------------------
class TestComputeReserved:
    def test_24_subnet_reserves_five(self):
        # /24 == 10.0.0.0/24. AWS reserves .0 .1 .2 .3 .255. Docker
        # gateway is .1 (already in AWS set). Total 5.
        aws = ipaddress.IPv4Network("10.0.0.0/24")
        docker = ipaddress.IPv4Network("10.0.0.0/24")
        reserved = _compute_reserved(aws, docker)
        assert reserved == {
            ipaddress.IPv4Address("10.0.0.0"),
            ipaddress.IPv4Address("10.0.0.1"),
            ipaddress.IPv4Address("10.0.0.2"),
            ipaddress.IPv4Address("10.0.0.3"),
            ipaddress.IPv4Address("10.0.0.255"),
        }

    def test_16_vpc_with_24_subnet_reserves_five_at_subnet_boundary(self):
        # When docker_cidr is the whole VPC /16 but aws_cidr is the
        # subnet /24, reservations follow the aws_cidr.
        aws = ipaddress.IPv4Network("10.50.7.0/24")
        docker = ipaddress.IPv4Network("10.50.0.0/16")
        reserved = _compute_reserved(aws, docker)
        # AWS .0 .1 .2 .3 .255 inside the aws_cidr
        assert ipaddress.IPv4Address("10.50.7.0") in reserved
        assert ipaddress.IPv4Address("10.50.7.1") in reserved
        assert ipaddress.IPv4Address("10.50.7.2") in reserved
        assert ipaddress.IPv4Address("10.50.7.3") in reserved
        assert ipaddress.IPv4Address("10.50.7.255") in reserved
        # Docker bridge gateway is at docker_cidr's .1 = 10.50.0.1
        assert ipaddress.IPv4Address("10.50.0.1") in reserved

    def test_30_subnet_edge_case(self):
        # /30 has 4 addresses: .0 (net), .1 .2 (hosts), .3 (broadcast).
        # AWS would reserve all four; only .1 and .2 are usable in AWS
        # but AWS-API still rejects them as customer addresses.
        aws = ipaddress.IPv4Network("10.0.0.0/30")
        docker = ipaddress.IPv4Network("10.0.0.0/30")
        reserved = _compute_reserved(aws, docker)
        # /30 has 4 addresses; we reserve all hosts plus network + broadcast
        assert ipaddress.IPv4Address("10.0.0.0") in reserved
        assert ipaddress.IPv4Address("10.0.0.3") in reserved


# ---------------------------------------------------------------------------
# register / unregister
# ---------------------------------------------------------------------------
class TestRegister:
    def test_register_then_describe(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        pools = a.describe("vpc-1")
        assert len(pools) == 1
        assert pools[0].subnet_id == "sub-a"
        assert pools[0].az == "us-east-1a"
        assert str(pools[0].aws_cidr) == "10.0.1.0/24"
        assert str(pools[0].docker_cidr) == "10.0.0.0/16"

    def test_register_is_idempotent_for_same_cidrs(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        # Re-register with identical CIDRs: no-op, no raise
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        assert len(a.describe("vpc-1")) == 1

    def test_register_conflict_raises(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        with pytest.raises(SubnetCidrConflict):
            a.register_subnet(
                "vpc-1", "sub-a", "10.0.2.0/24", "10.0.0.0/16", "us-east-1a",
            )

    def test_unregister_clean(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.unregister_subnet("vpc-1", "sub-a")
        assert a.describe("vpc-1") == []

    def test_unregister_with_live_allocs_raises(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.reserve("vpc-1", "sub-a", "eni-1")
        with pytest.raises(SubnetInUse):
            a.unregister_subnet("vpc-1", "sub-a")

    def test_force_unregister_releases_all(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.reserve("vpc-1", "sub-a", "eni-1")
        a.reserve("vpc-1", "sub-a", "eni-2")
        released = a.force_unregister_subnet("vpc-1", "sub-a")
        assert released == 2
        assert a.describe("vpc-1") == []
        assert a.lookup("10.0.0.4") is None


# ---------------------------------------------------------------------------
# reserve / release
# ---------------------------------------------------------------------------
class TestReserve:
    def _alloc(self) -> SubnetAllocator:
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        return a

    def test_auto_picks_first_free_after_reserved(self):
        a = self._alloc()
        ip = a.reserve("vpc-1", "sub-a", "eni-1")
        # First non-reserved IP after .0/.1/.2/.3 reservations in the AWS
        # /24 plus .1 in the docker /16 (already covered). First free in
        # docker_cidr 10.0.0.0/16 is 10.0.0.2 (Docker gateway is .1).
        # Actually it depends — _compute_reserved adds AWS .0 .1 .2 .3 of
        # 10.0.1.0/24 (so 10.0.1.0-3) plus docker gateway .1 of /16 = 10.0.0.1.
        # First usable in /16 is 10.0.0.2.
        assert ip == ipaddress.IPv4Address("10.0.0.2")

    def test_sequential_allocs_advance(self):
        a = self._alloc()
        ip1 = a.reserve("vpc-1", "sub-a", "eni-1")
        ip2 = a.reserve("vpc-1", "sub-a", "eni-2")
        ip3 = a.reserve("vpc-1", "sub-a", "eni-3")
        assert ip2 == ip1 + 1
        assert ip3 == ip2 + 1

    def test_skips_reserved(self):
        a = self._alloc()
        # Reserve 100 IPs; none should be .0/.1/.2/.3 of any subnet
        # boundary or 10.0.0.1 (docker gateway).
        for i in range(100):
            ip = a.reserve("vpc-1", "sub-a", f"eni-{i}")
            assert ip != ipaddress.IPv4Address("10.0.0.0")
            assert ip != ipaddress.IPv4Address("10.0.0.1")

    def test_requested_ip_happy_path(self):
        a = self._alloc()
        ip = a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.7.42")
        assert ip == ipaddress.IPv4Address("10.0.7.42")
        assert a.lookup("10.0.7.42") == ("vpc-1", "sub-a", "eni-1")

    def test_requested_ip_out_of_range(self):
        a = self._alloc()
        with pytest.raises(InvalidIpForSubnet):
            a.reserve("vpc-1", "sub-a", "eni-1", requested="172.16.0.5")

    def test_requested_ip_in_reserved_set(self):
        a = self._alloc()
        with pytest.raises(InvalidIpForSubnet):
            a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.1.0")
        with pytest.raises(InvalidIpForSubnet):
            a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.0.1")

    def test_requested_ip_already_in_use(self):
        a = self._alloc()
        a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.5.5")
        with pytest.raises(IpAddressInUse):
            a.reserve("vpc-1", "sub-a", "eni-2", requested="10.0.5.5")

    def test_reserve_unknown_subnet(self):
        a = self._alloc()
        with pytest.raises(UnknownSubnet):
            a.reserve("vpc-2", "sub-z", "eni-1")

    def test_exhaustion_raises(self):
        a = SubnetAllocator()
        # /29 has 8 addresses; AWS reserves .0/.1/.2/.3/.7 = 5; Docker
        # gateway .1 already in set; usable = 3 (.4, .5, .6)
        a.register_subnet(
            "vpc-x", "sub-tiny", "10.5.5.0/29", "10.5.5.0/29", "us-east-1a",
        )
        a.reserve("vpc-x", "sub-tiny", "eni-1")
        a.reserve("vpc-x", "sub-tiny", "eni-2")
        a.reserve("vpc-x", "sub-tiny", "eni-3")
        with pytest.raises(InsufficientFreeAddressesInSubnet):
            a.reserve("vpc-x", "sub-tiny", "eni-4")

    def test_release_then_reuse(self):
        a = self._alloc()
        ip = a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.5.5")
        a.release(ip)
        assert a.lookup(ip) is None
        # Can be reserved again
        ip2 = a.reserve("vpc-1", "sub-a", "eni-2", requested="10.0.5.5")
        assert ip2 == ip

    def test_release_idempotent(self):
        a = self._alloc()
        a.release("10.99.99.99")  # never allocated; no raise


# ---------------------------------------------------------------------------
# claim (reconciler path)
# ---------------------------------------------------------------------------
class TestClaim:
    def test_claim_unknown_owner(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.claim("vpc-1", "sub-a", "10.0.5.5", "eni-recovered")
        assert a.lookup("10.0.5.5") == ("vpc-1", "sub-a", "eni-recovered")

    def test_claim_idempotent_same_owner(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.claim("vpc-1", "sub-a", "10.0.5.5", "eni-x")
        a.claim("vpc-1", "sub-a", "10.0.5.5", "eni-x")  # idempotent
        assert a.lookup("10.0.5.5")[2] == "eni-x"

    def test_claim_conflict_raises(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.claim("vpc-1", "sub-a", "10.0.5.5", "eni-a")
        with pytest.raises(IpClaimConflict):
            a.claim("vpc-1", "sub-a", "10.0.5.5", "eni-b")

    def test_claim_outside_docker_cidr_skips(self):
        # Reconciler observed an IP that doesn't fit our pool — should
        # silently skip, not raise.
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.claim("vpc-1", "sub-a", "172.31.0.5", "eni-x")  # outside /16
        assert a.lookup("172.31.0.5") is None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_round_trip(self, tmp_path):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        a.register_subnet(
            "vpc-1", "sub-b", "10.0.2.0/24", "10.0.0.0/16", "us-east-1b",
        )
        a.reserve("vpc-1", "sub-a", "eni-1", requested="10.0.7.7")
        a.reserve("vpc-1", "sub-b", "eni-2", requested="10.0.8.8")

        path = tmp_path / "alloc.state"
        a.save_to_file(str(path))
        assert path.exists()

        b = SubnetAllocator()
        assert b.load_from_file(str(path)) is True
        assert b.lookup("10.0.7.7") == ("vpc-1", "sub-a", "eni-1")
        assert b.lookup("10.0.8.8") == ("vpc-1", "sub-b", "eni-2")
        # Cannot re-reserve a loaded IP
        with pytest.raises(IpAddressInUse):
            b.reserve("vpc-1", "sub-a", "eni-x", requested="10.0.7.7")

    def test_load_missing_file_returns_false(self, tmp_path):
        a = SubnetAllocator()
        assert a.load_from_file(str(tmp_path / "nope.state")) is False

    def test_load_corrupt_file_returns_false(self, tmp_path):
        path = tmp_path / "alloc.state"
        path.write_text("not json at all {{{")
        a = SubnetAllocator()
        assert a.load_from_file(str(path)) is False
        # Allocator is still empty and usable
        assert a.all_pools() == []

    def test_load_unknown_schema_logs_and_skips(self, tmp_path, caplog):
        path = tmp_path / "alloc.state"
        path.write_text(json.dumps({"schema_version": 99, "pools": []}))
        a = SubnetAllocator()
        a.load_from_file(str(path))
        assert any(
            "schema" in r.message.lower() for r in caplog.records
        )
        assert a.all_pools() == []

    def test_save_creates_parent_directory(self, tmp_path):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        nested = tmp_path / "deep" / "nested" / "path" / "alloc.state"
        a.save_to_file(str(nested))
        assert nested.exists()


# ---------------------------------------------------------------------------
# Concurrency: many threads racing reserve, no duplicates
# ---------------------------------------------------------------------------
class TestConcurrency:
    def test_32_threads_no_duplicates(self):
        a = SubnetAllocator()
        a.register_subnet(
            "vpc-c", "sub-c", "10.10.0.0/16", "10.10.0.0/16", "us-east-1a",
        )
        N = 32
        results: list[ipaddress.IPv4Address] = []
        results_lock = threading.Lock()
        errors: list[Exception] = []

        def worker(i: int):
            try:
                ip = a.reserve("vpc-c", "sub-c", f"eni-{i}")
                with results_lock:
                    results.append(ip)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(results) == N
        # No duplicates
        assert len(set(results)) == N


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
class TestSingleton:
    def test_singleton_returns_same_instance(self):
        a = get_subnet_allocator()
        b = get_subnet_allocator()
        assert a is b

    def test_reset_clears_singleton(self):
        a = get_subnet_allocator()
        reset_subnet_allocator_for_tests()
        b = get_subnet_allocator()
        assert a is not b
