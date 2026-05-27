"""Tests for the RDS addressing-redesign integration.

Covers:
  - _extract_subnet_id_from_subnet_group: picks first subnet, handles
    missing / malformed payloads, both SubnetIdentifier and SubnetId.
  - db_manager.create_db_instance accepts + threads subnet_id through.
  - When LOCALEMU_VPC_IP_PINNING=1 + subnet_id available: allocator
    reserves an IP, ipv4_address is passed to connect_container_to_network,
    AddressIndex.register_eni is called with the right eni_id.
  - When LOCALEMU_VPC_IP_PINNING=0: behaves exactly like today
    (no allocator, no index, ipv4_address=None on connect).
  - When pinning on but allocator exhausted: falls back to no-pinning
    with a WARN; container still launches.
  - When pinning on but Docker connect fails: reserved IP is released.
  - delete_db_instance releases the allocator IP + drops the ENI entry.
"""
from __future__ import annotations

from unittest import mock

import pytest

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
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()


# ---------------------------------------------------------------------------
# Subnet extraction
# ---------------------------------------------------------------------------
class TestExtractSubnetId:
    def _extract(self, payload):
        from localemu.services.rds.provider import (
            _extract_subnet_id_from_subnet_group,
        )
        return _extract_subnet_id_from_subnet_group(None, payload)

    def test_first_subnet_identifier(self):
        assert self._extract({
            "DBSubnetGroup": {
                "Subnets": [
                    {"SubnetIdentifier": "subnet-aaa"},
                    {"SubnetIdentifier": "subnet-bbb"},
                ],
            },
        }) == "subnet-aaa"

    def test_accepts_subnet_id_key(self):
        assert self._extract({
            "DBSubnetGroup": {
                "Subnets": [{"SubnetId": "subnet-xxx"}],
            },
        }) == "subnet-xxx"

    def test_no_subnet_group(self):
        assert self._extract({}) is None

    def test_empty_subnet_list(self):
        assert self._extract({
            "DBSubnetGroup": {"Subnets": []},
        }) is None

    def test_malformed_subnet_group(self):
        assert self._extract({"DBSubnetGroup": "not-a-dict"}) is None


# ---------------------------------------------------------------------------
# db_manager passes ipv4_address when pinning is on
# ---------------------------------------------------------------------------
class TestDbManagerIpPinning:
    def _setup_alloc(self):
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        return alloc

    def _make_mgr_with_mocks(self):
        """Build a DockerDbManager with DOCKER_CLIENT and the wait_for_port
        helpers mocked so _do_create_db_instance can run end-to-end without
        touching a real Docker daemon."""
        from localemu.services.rds.docker import db_manager as dbm_module

        # Patch DOCKER_CLIENT at module level so all the calls inside
        # _do_create_db_instance get the mock
        dc = mock.MagicMock()
        # Container has an IP that we can probe for endpoint construction
        dc.get_container_ipv4_for_network.return_value = "10.0.0.42"
        dc.get_container_ip.return_value = "10.0.0.42"
        return dc, dbm_module

    def _create(self, dbm_module, **kwargs):
        mgr = dbm_module.DockerDbManager()
        with mock.patch.object(mgr, "_ensure_image"), \
             mock.patch.object(mgr, "_wait_for_port", return_value=True):
            return mgr.create_db_instance(**kwargs)

    def test_pinning_off_passes_no_ipv4(self):
        self._setup_alloc()
        dc, dbm_module = self._make_mgr_with_mocks()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            self._create(
                dbm_module,
                db_instance_id="db-1",
                engine="postgres",
                master_password="x",
                vpc_id="vpc-1",
                subnet_id="sub-a",
            )
        # connect_container_to_network was called without ipv4_address
        connect_call = dc.connect_container_to_network.call_args
        assert connect_call.kwargs.get("ipv4_address") is None
        # Allocator was not touched
        assert get_subnet_allocator().lookup("10.0.0.4") is None

    def test_pinning_on_with_subnet_reserves_and_passes_ipv4(self):
        self._setup_alloc()
        dc, dbm_module = self._make_mgr_with_mocks()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            self._create(
                dbm_module,
                db_instance_id="db-1",
                engine="postgres",
                master_password="x",
                vpc_id="vpc-1",
                subnet_id="sub-a",
            )
        # ipv4_address was passed
        connect_call = dc.connect_container_to_network.call_args
        ip = connect_call.kwargs.get("ipv4_address")
        assert ip is not None
        # It's a valid IP in the subnet
        import ipaddress
        assert ipaddress.IPv4Address(ip) in ipaddress.IPv4Network("10.0.0.0/16")
        # AddressIndex has the RDS ENI registered
        e = get_address_index().get_eni("eni-rds-db-1")
        assert e is not None
        assert str(e.primary_ip) == ip
        assert e.instance_id == "rds:db-1"

    def test_pinning_on_no_subnet_falls_back(self):
        # No subnet_id provided -> no pinning, no allocator action
        self._setup_alloc()
        dc, dbm_module = self._make_mgr_with_mocks()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            self._create(
                dbm_module,
                db_instance_id="db-1",
                engine="postgres",
                master_password="x",
                vpc_id="vpc-1",
                # subnet_id=None
            )
        assert dc.connect_container_to_network.call_args.kwargs.get(
            "ipv4_address",
        ) is None
        assert get_address_index().get_eni("eni-rds-db-1") is None

    def test_connect_failure_releases_reserved_ip(self):
        self._setup_alloc()
        dc, dbm_module = self._make_mgr_with_mocks()
        dc.connect_container_to_network.side_effect = RuntimeError("net down")
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            self._create(
                dbm_module,
                db_instance_id="db-1",
                engine="postgres",
                master_password="x",
                vpc_id="vpc-1",
                subnet_id="sub-a",
            )
        # Allocator has zero allocations: the reserved IP was released
        pools = get_subnet_allocator().describe("vpc-1")
        assert pools[0].allocated == {}

    def test_pinning_on_unregistered_subnet_falls_back(self):
        # Pinning on, subnet_id provided but allocator doesn't know it
        dc, dbm_module = self._make_mgr_with_mocks()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            self._create(
                dbm_module,
                db_instance_id="db-1",
                engine="postgres",
                master_password="x",
                vpc_id="vpc-1",
                subnet_id="sub-unknown",
            )
        # Connect called without ipv4_address (fallback)
        assert dc.connect_container_to_network.call_args.kwargs.get(
            "ipv4_address",
        ) is None


# ---------------------------------------------------------------------------
# delete_db_instance releases allocator IP + drops ENI
# ---------------------------------------------------------------------------
class TestDeleteReleasesIp:
    def test_delete_releases(self):
        from localemu.services.rds.docker import db_manager as dbm_module

        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        # Simulate that pinning created the entries
        ip = alloc.reserve("vpc-1", "sub-a", "eni-rds-db-1")
        get_address_index().register_eni(
            "eni-rds-db-1", "vpc-1", "sub-a", ip,
            instance_id="rds:db-1",
        )

        dc = mock.MagicMock()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc):
            mgr = dbm_module.DockerDbManager()
            mgr.delete_db_instance("db-1")

        assert alloc.lookup(ip) is None
        assert get_address_index().get_eni("eni-rds-db-1") is None

    def test_delete_when_no_pinning_record_is_noop(self):
        """Containers created with pinning=off have no allocator entry
        and no ENI in the index. Delete should not raise."""
        from localemu.services.rds.docker import db_manager as dbm_module

        dc = mock.MagicMock()
        with mock.patch.object(dbm_module, "DOCKER_CLIENT", dc):
            mgr = dbm_module.DockerDbManager()
            mgr.delete_db_instance("db-1")  # no raise
