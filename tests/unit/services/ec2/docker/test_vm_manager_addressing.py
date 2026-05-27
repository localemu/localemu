"""Tests for the EC2 addressing-redesign integration in vm_manager.

The full create_instance path has too many real dependencies (Docker
image pull, IMDS sidecar, SSH key injection, user-data exec) to
unit-test end-to-end here. These tests cover the new integration
seams in isolation:

  - terminate_instance releases allocator IP + deletes ENI when
    pinning was active for the instance.
  - terminate_instance is a no-op for the allocator/index when no
    pinning record exists (off-path containers).
  - The synthetic ENI ID convention matches between create and
    terminate (so cleanup actually finds the entry).

Full create_instance behavior with allocator+index+ipv4_address is
verified by the real-Docker integration test in
tests/integration/networking/ (lands in the same PR's final commit).
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


class TestTerminateReleasesAddressing:
    def _build_mgr(self):
        from localemu.services.ec2.docker import vm_manager
        return vm_manager.DockerVmManager(), vm_manager

    def test_terminate_releases_allocator_and_index(self):
        # Simulate a pinned instance: allocator has the IP, index has
        # the ENI, vm_manager.instances has the container info
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        ip = alloc.reserve("vpc-1", "sub-a", "eni-abc123")
        idx = get_address_index()
        idx.register_eni(
            "eni-abc123", "vpc-1", "sub-a", ip,
            instance_id="i-abc123", iface_name="eth1",
        )

        mgr, vm_module = self._build_mgr()
        # Inject a fake container info so terminate_instance has something
        # to look up
        from localemu.services.ec2.docker.vm_manager import Ec2ContainerInfo
        fake_info = Ec2ContainerInfo(
            container_name="localemu-ec2-i-abc123",
            instance_id="i-abc123",
            image="x", instance_type="t2.micro",
            ssh_port=22, private_ip=str(ip),
            console_output="",
            vpc_id="vpc-1",
        )
        mgr._instances["i-abc123"] = fake_info

        # Mock all the Docker operations terminate_instance fires
        with mock.patch.object(vm_module, "DOCKER_CLIENT") as dc, \
             mock.patch.object(
                 vm_module, "_resolve_container_private_ip",
                 return_value=str(ip),
             ):
            dc.list_containers.return_value = []
            mgr.terminate_instance("i-abc123")

        # ENI gone, IP released
        assert idx.get_eni("eni-abc123") is None
        assert alloc.lookup(ip) is None

    def test_terminate_when_no_pinning_record_is_noop(self):
        """Off-path containers (created with pinning=off) have no
        allocator entry and no ENI. Terminate must not raise."""
        mgr, vm_module = self._build_mgr()
        with mock.patch.object(vm_module, "DOCKER_CLIENT") as dc:
            dc.list_containers.return_value = []
            # No info in mgr._instances either; terminate_instance handles
            mgr.terminate_instance("i-orphan")  # no raise

    def test_synth_eni_id_strips_i_prefix(self):
        """create_instance uses 'eni-<id without i->' as the synthesized
        eni_id; terminate_instance must use the same convention."""
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
        )
        ip = alloc.reserve("vpc-1", "sub-a", "eni-from-vmmanager")
        idx = get_address_index()
        # ENI registered with the "i-" stripped (matches what
        # create_instance writes via synth_eni_id)
        idx.register_eni(
            "eni-from-vmmanager", "vpc-1", "sub-a", ip,
            instance_id="i-from-vmmanager",
        )

        mgr, vm_module = self._build_mgr()
        # vm_manager.terminate_instance computes
        # f"eni-{instance_id.removeprefix('i-')}" — for i-from-vmmanager
        # that yields "eni-from-vmmanager".  If we keep the synth in
        # sync, the entry is found and cleaned.
        from localemu.services.ec2.docker.vm_manager import Ec2ContainerInfo
        mgr._instances["i-from-vmmanager"] = Ec2ContainerInfo(
            container_name="localemu-ec2-i-from-vmmanager",
            instance_id="i-from-vmmanager",
            image="x", instance_type="t2.micro",
            ssh_port=22, private_ip=str(ip),
            console_output="", vpc_id="vpc-1",
        )

        with mock.patch.object(vm_module, "DOCKER_CLIENT") as dc:
            dc.list_containers.return_value = []
            mgr.terminate_instance("i-from-vmmanager")

        assert idx.get_eni("eni-from-vmmanager") is None
        assert alloc.lookup(ip) is None
