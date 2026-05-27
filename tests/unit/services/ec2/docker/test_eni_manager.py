"""Tests for the EniManager orchestration layer.

Covers the four core lifecycle ops (create / attach / detach / delete)
against a mocked Docker client. All paths verify both happy-path and
the AWS-shape error cases (EniAlreadyAttached, EniInUse,
CannotDetachPrimary, etc).
"""
from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from localemu.services.ec2.docker import eni_manager
from localemu.services.ec2.docker.address_index import (
    AddressIndex,
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.eni_manager import (
    CannotDetachPrimary,
    EniAlreadyAttached,
    EniInUse,
    EniManager,
    EniNotAttached,
    EniNotFound,
    InvalidEniState,
    get_eni_manager,
    reset_eni_manager_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    SubnetAllocator,
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()


def _populate_subnet(vpc_id="vpc-1", subnet_id="sub-a"):
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        vpc_id, subnet_id, "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
    )
    return alloc


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------
class TestCreate:
    def test_happy_path(self):
        _populate_subnet()
        mgr = EniManager()
        ip, mac = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a",
            sg_ids=["sg-web"],
        )
        # Allocator records the reservation
        assert get_subnet_allocator().lookup(ip) == ("vpc-1", "sub-a", "eni:eni-1")
        # MAC is derived from IP (Docker bridge OUI scheme)
        assert mac.startswith("02:42:")
        assert mac.endswith(f"{ip.packed[-1]:02x}")
        # Index has the detached entry
        e = get_address_index().get_eni("eni-1")
        assert e is not None
        assert e.primary_ip == ip
        assert e.mac == mac
        assert e.sg_ids == ["sg-web"]
        assert e.instance_id is None
        assert e.iface_name is None
        assert e.delete_on_termination is False  # AWS default for standalone

    def test_requested_ip_honored(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-pinned", vpc_id="vpc-1", subnet_id="sub-a",
            sg_ids=[], requested_ip="10.0.5.42",
        )
        assert str(ip) == "10.0.5.42"

    def test_delete_on_termination_recorded(self):
        _populate_subnet()
        mgr = EniManager()
        mgr.create(
            eni_id="eni-x", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
            delete_on_termination=True,
        )
        assert get_address_index().get_eni("eni-x").delete_on_termination is True

    def test_unknown_subnet_raises(self):
        # Subnet not registered with allocator
        mgr = EniManager()
        with pytest.raises(InvalidEniState):
            mgr.create(
                eni_id="eni-1", vpc_id="vpc-nope", subnet_id="sub-nope",
                sg_ids=[],
            )

    def test_requested_ip_already_in_use_raises(self):
        alloc = _populate_subnet()
        alloc.reserve("vpc-1", "sub-a", "other-owner", requested="10.0.5.42")
        mgr = EniManager()
        with pytest.raises(InvalidEniState):
            mgr.create(
                eni_id="eni-conflict", vpc_id="vpc-1", subnet_id="sub-a",
                sg_ids=[], requested_ip="10.0.5.42",
            )

    def test_rollback_on_index_failure(self):
        _populate_subnet()
        mgr = EniManager()
        with mock.patch.object(
            mgr._index, "register_eni",
            side_effect=RuntimeError("index broken"),
        ):
            with pytest.raises(RuntimeError):
                mgr.create(
                    eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a",
                    sg_ids=[],
                )
        # IP was released (allocator pool empty)
        pools = get_subnet_allocator().describe("vpc-1")
        assert pools[0].allocated == {}


# ---------------------------------------------------------------------------
# attach
# ---------------------------------------------------------------------------
class TestAttach:
    def _setup_eni(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a",
            sg_ids=["sg-web"],
        )
        return mgr, ip

    def test_happy_path(self):
        mgr, ip = self._setup_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc, \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth2",
             ):
            mgr.attach("eni-1", "i-abc", device_index=2)
            # Docker was told to pin the IP
            dc.connect_container_to_network.assert_called_once()
            kwargs = dc.connect_container_to_network.call_args.kwargs
            assert kwargs["network_name"] == "localemu-vpc-vpc-1"
            assert kwargs["container_name_or_id"] == "localemu-ec2-i-abc"
            assert kwargs["ipv4_address"] == str(ip)
        # Index updated
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id == "i-abc"
        assert e.iface_name == "eth2"
        assert e.device_index == 2

    def test_attach_unknown_eni_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.attach("eni-nope", "i-abc", device_index=1)

    def test_attach_already_attached_raises(self):
        mgr, _ = self._setup_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"), \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth1",
             ):
            mgr.attach("eni-1", "i-abc", device_index=1)
        with pytest.raises(EniAlreadyAttached):
            mgr.attach("eni-1", "i-xyz", device_index=2)

    def test_docker_connect_failure_rolls_back_index(self):
        mgr, _ = self._setup_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            dc.connect_container_to_network.side_effect = RuntimeError("net broken")
            with pytest.raises(InvalidEniState):
                mgr.attach("eni-1", "i-abc", device_index=1)
        # Index reverted to detached
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id is None

    def test_secondary_ips_get_ip_addr_add(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        # Add a secondary BEFORE attach (allowed; modeled like AWS)
        get_address_index().add_secondary_ip("eni-1", "10.0.5.50")
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc, \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth1",
             ):
            mgr.attach("eni-1", "i-abc", device_index=1)
            # exec_in_container was called for the secondary
            exec_calls = [c for c in dc.exec_in_container.call_args_list
                          if "ip addr add 10.0.5.50/32" in str(c)]
            assert exec_calls


class TestAttachSharedIface:
    """When the instance container is already on the target VPC bridge
    (the normal case for hot-attach), Docker rejects a second endpoint
    from the same container with "endpoint with name X already exists
    in network Y". EniManager must detect this and fall back to
    shared-iface mode: ``ip addr add`` the ENI's IP onto the existing
    eth0 instead of trying to connect a new endpoint."""

    def _setup_eni(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a",
            sg_ids=["sg-web"],
        )
        return mgr, ip

    def test_already_on_network_falls_back_to_shared_iface(self):
        mgr, ip = self._setup_eni()
        err = RuntimeError(
            "Error response from daemon: endpoint with name "
            "localemu-ec2-i-abc already exists in network localemu-vpc-vpc-1"
        )
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc, \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth0",
             ):
            dc.connect_container_to_network.side_effect = err
            mgr.attach("eni-1", "i-abc", device_index=1)
            # Connect was tried (and rejected)
            dc.connect_container_to_network.assert_called_once()
            # Fallback ran ip addr add for the primary IP on eth0
            exec_calls = [
                str(c) for c in dc.exec_in_container.call_args_list
            ]
            assert any(f"ip addr add {ip}/32 dev eth0" in s for s in exec_calls), exec_calls
        # Index marked shared
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id == "i-abc"
        assert e.iface_name == "eth0"
        assert e.device_index == 1
        assert e.shared_iface is True

    def test_other_docker_errors_still_raise(self):
        """Non-"already exists" errors must still bubble up as
        InvalidEniState and roll back the index. We don't want to mask
        real Docker problems behind the shared-iface fallback."""
        mgr, _ = self._setup_eni()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            dc.connect_container_to_network.side_effect = RuntimeError(
                "Error response from daemon: docker daemon is down"
            )
            with pytest.raises(InvalidEniState):
                mgr.attach("eni-1", "i-abc", device_index=1)
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id is None

    def test_shared_iface_detach_uses_ip_addr_del_not_disconnect(self):
        """In shared mode, detach must NOT call disconnect_container_from_network
        (that would nuke the primary ENI too). It should only ``ip addr del``
        the ENI's IPs from the shared eth0."""
        mgr, ip = self._setup_eni()
        err = RuntimeError(
            "endpoint with name localemu-ec2-i-abc already exists in network "
            "localemu-vpc-vpc-1"
        )
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc, \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth0",
             ):
            dc.connect_container_to_network.side_effect = err
            mgr.attach("eni-1", "i-abc", device_index=1)
            dc.reset_mock()
            mgr.detach("eni-1")
            # NOT called — disconnecting would kill the primary ENI
            dc.disconnect_container_from_network.assert_not_called()
            # IS called — ip addr del to remove the IP
            exec_calls = [
                str(c) for c in dc.exec_in_container.call_args_list
            ]
            assert any(f"ip addr del {ip}/32 dev eth0" in s for s in exec_calls), exec_calls
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id is None
        assert e.shared_iface is False


# ---------------------------------------------------------------------------
# detach
# ---------------------------------------------------------------------------
class TestDetach:
    def _attached(self, device_index=1):
        _populate_subnet()
        mgr = EniManager()
        mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"), \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth1",
             ):
            mgr.attach("eni-1", "i-abc", device_index=device_index)
        return mgr

    def test_happy_path(self):
        mgr = self._attached()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            mgr.detach("eni-1")
            dc.disconnect_container_from_network.assert_called_once()
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id is None
        assert e.iface_name is None
        assert e.device_index is None

    def test_detach_primary_raises(self):
        mgr = self._attached(device_index=0)
        with pytest.raises(CannotDetachPrimary):
            mgr.detach("eni-1")

    def test_detach_unknown_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.detach("eni-nope")

    def test_detach_already_detached_raises(self):
        _populate_subnet()
        mgr = EniManager()
        mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        # Never attached
        with pytest.raises(EniNotAttached):
            mgr.detach("eni-1")

    def test_docker_disconnect_failure_is_logged_but_detach_proceeds(self):
        mgr = self._attached()
        with mock.patch.object(eni_manager, "DOCKER_CLIENT") as dc:
            dc.disconnect_container_from_network.side_effect = RuntimeError("x")
            mgr.detach("eni-1")  # no raise — log + continue
        # Index still cleaned
        e = get_address_index().get_eni("eni-1")
        assert e.instance_id is None


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------
class TestDelete:
    def test_happy_path(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        mgr.delete("eni-1")
        assert get_address_index().get_eni("eni-1") is None
        assert get_subnet_allocator().lookup(ip) is None

    def test_delete_attached_raises_in_use(self):
        _populate_subnet()
        mgr = EniManager()
        mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        with mock.patch.object(eni_manager, "DOCKER_CLIENT"), \
             mock.patch.object(
                 eni_manager, "resolve_iface_for_network",
                 return_value="eth1",
             ):
            mgr.attach("eni-1", "i-abc", device_index=1)
        with pytest.raises(EniInUse):
            mgr.delete("eni-1")
        # ENI still exists
        assert get_address_index().get_eni("eni-1") is not None

    def test_delete_releases_secondary_ips(self):
        _populate_subnet()
        mgr = EniManager()
        ip, _ = mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        sec_ip = get_subnet_allocator().reserve(
            "vpc-1", "sub-a", "eni:eni-1:sec",
        )
        get_address_index().add_secondary_ip("eni-1", sec_ip)
        mgr.delete("eni-1")
        # Both released
        assert get_subnet_allocator().lookup(ip) is None
        assert get_subnet_allocator().lookup(sec_ip) is None

    def test_delete_unknown_raises(self):
        mgr = EniManager()
        with pytest.raises(EniNotFound):
            mgr.delete("eni-nope")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
class TestSingleton:
    def test_same_instance(self):
        assert get_eni_manager() is get_eni_manager()

    def test_reset_clears(self):
        a = get_eni_manager()
        reset_eni_manager_for_tests()
        b = get_eni_manager()
        assert a is not b
