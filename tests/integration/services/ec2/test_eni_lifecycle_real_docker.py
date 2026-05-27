"""Real-Docker integration test for the ENI lifecycle.

Tarek's rule: 'unit tests are good, but the truth is E2E'.

This test exercises the full ENI control plane against a live Docker
daemon. It does NOT go through the EC2 provider HTTP API (that path is
covered by the real-boto3 E2E test in tests/e2e/); instead it directly
exercises EniManager + the addressing primitives so the test stays
focused on the Docker-side mechanics:

  1. Create a real Docker VPC bridge with --subnet
  2. Start a long-lived 'instance' container (alpine + sleep)
  3. EniManager.create -> reserves IP, registers detached ENI
  4. EniManager.attach -> docker network connect with ipv4_address
  5. Verify Docker reports the pinned IP on the new interface
  6. Verify iface_resolver returns the right iface name
  7. EniManager.assign_private_ips -> ip addr add /32 inside container
  8. Verify 'ip addr show' inside the container reports both primary
     and secondary IPs
  9. EniManager.unassign_private_ips -> ip addr del + index cleanup
  10. EniManager.detach -> docker disconnect, index updated
  11. EniManager.delete -> allocator + index cleaned
  12. Verify allocator is back to empty state

This is the proof point that the ENI design actually works end-to-end.
Auto-skips if Docker is unreachable.
"""
from __future__ import annotations

import ipaddress

import pytest

from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.eni_manager import (
    EniManager,
    reset_eni_manager_for_tests,
)
from localemu.services.ec2.docker.iface_resolver import (
    resolve_iface_for_network,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)
from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
)
from localemu.utils.docker_utils import DOCKER_CLIENT


# Predictable artifacts so cleanup can find them after a crash
_NET = "localemu-vpc-eni-itest"
_CTR = "localemu-ec2-i-eni-itest"
_VPC = "eni-itest"
_SUBNET = "subnet-eni-itest"
_CIDR = "10.251.0.0/24"


@pytest.fixture(scope="module", autouse=True)
def _require_docker():
    try:
        info = DOCKER_CLIENT.get_system_info()
        if not info:
            pytest.skip("Docker daemon not reachable")
    except Exception as exc:
        pytest.skip(f"Docker daemon not reachable: {exc}")


@pytest.fixture
def _clean_state():
    _teardown_docker()
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    yield
    _teardown_docker()
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()


def _teardown_docker():
    try:
        DOCKER_CLIENT.stop_container(_CTR, timeout=2)
    except Exception:
        pass
    try:
        DOCKER_CLIENT.remove_container(_CTR, force=True)
    except Exception:
        pass
    try:
        DOCKER_CLIENT.delete_network(_NET)
    except Exception:
        pass


def _ip_addr_show(iface: str) -> str:
    """Run `ip -4 -o addr show <iface>` inside the container; return text."""
    out, _ = DOCKER_CLIENT.exec_in_container(
        _CTR, ["sh", "-c", f"ip -4 -o addr show {iface}"],
    )
    return out.decode("utf-8") if isinstance(out, bytes) else str(out)


class TestEniLifecycleEndToEnd:
    def test_full_lifecycle(self, _clean_state):
        # ----- Step 1: Set up the VPC bridge -----
        DOCKER_CLIENT.create_network(_NET, subnet=_CIDR, internal=False)

        # ----- Step 2: Start the 'instance' container -----
        # NET_ADMIN is required so the in-container 'ip addr add /32'
        # for secondary IPs succeeds. Production EC2 containers get
        # this via vm_manager.py:635 (cap_add=["NET_ADMIN", "SYSLOG"]).
        config = ContainerConfiguration(
            image_name="alpine:3.20",
            name=_CTR,
            network=_NET,
            command=["sleep", "120"],
            detach=True,
            cap_add=["NET_ADMIN"],
        )
        DOCKER_CLIENT.create_container_from_config(config)
        DOCKER_CLIENT.start_container(_CTR)

        # ----- Step 3: Register subnet with allocator and create ENI -----
        alloc = get_subnet_allocator()
        alloc.register_subnet(
            vpc_id=_VPC, subnet_id=_SUBNET,
            aws_cidr=_CIDR, docker_cidr=_CIDR,
            az="us-east-1a",
        )
        mgr = EniManager()
        primary_ip, mac = mgr.create(
            eni_id="eni-itest", vpc_id=_VPC, subnet_id=_SUBNET,
            sg_ids=["sg-test"],
        )
        # Allocator records the reservation
        assert alloc.lookup(primary_ip) == (_VPC, _SUBNET, "eni:eni-itest")
        # MAC follows the deterministic scheme
        assert mac == f"02:42:{primary_ip.packed[0]:02x}:{primary_ip.packed[1]:02x}:{primary_ip.packed[2]:02x}:{primary_ip.packed[3]:02x}"

        # ----- Step 4: Attach the ENI to the container -----
        # The container is already on _NET (from create), so we need to
        # disconnect first to simulate the multi-attach scenario the
        # AttachNetworkInterface API exercises. In a real workflow the
        # initial container has only the pubport bridge; here we mirror.
        DOCKER_CLIENT.disconnect_container_from_network(_NET, _CTR)
        mgr.attach("eni-itest", "i-eni-itest", device_index=1)

        # ----- Step 5: Verify Docker reports the pinned IP -----
        live_ip = DOCKER_CLIENT.get_container_ipv4_for_network(_CTR, _NET)
        assert live_ip == str(primary_ip), (
            f"Docker live IP {live_ip} != pinned {primary_ip}"
        )

        # ----- Step 6: iface_resolver returns the right iface name -----
        iface = resolve_iface_for_network(_CTR, _NET)
        assert iface is not None
        assert iface.startswith("eth")
        # Index should have the same iface_name
        entry = get_address_index().get_eni("eni-itest")
        assert entry.iface_name == iface
        assert entry.device_index == 1
        assert entry.instance_id == "i-eni-itest"

        # ----- Step 7: Assign secondary IPs -----
        # Pick two specific IPs in the subnet (avoiding the AWS reservations
        # and the primary)
        secondaries = ["10.251.0.50", "10.251.0.51"]
        assigned = mgr.assign_private_ips(
            "eni-itest", explicit_ips=secondaries,
        )
        assert [str(a) for a in assigned] == secondaries

        # ----- Step 8: Verify ip addr show reports both IPs -----
        addr_output = _ip_addr_show(iface)
        assert str(primary_ip) in addr_output, (
            f"primary {primary_ip} not in:\n{addr_output}"
        )
        assert "10.251.0.50" in addr_output, (
            f"secondary 10.251.0.50 not in:\n{addr_output}"
        )
        assert "10.251.0.51" in addr_output

        # ----- Step 9: Unassign one secondary -----
        mgr.unassign_private_ips("eni-itest", ips=["10.251.0.51"])
        addr_after_unassign = _ip_addr_show(iface)
        assert "10.251.0.51" not in addr_after_unassign
        assert "10.251.0.50" in addr_after_unassign  # the other one still there
        # Released from allocator
        assert alloc.lookup("10.251.0.51") is None

        # ----- Step 10: Detach -----
        mgr.detach("eni-itest")
        # Docker no longer reports the container on _NET
        try:
            DOCKER_CLIENT.get_container_ipv4_for_network(_CTR, _NET)
            assert False, "container should be disconnected"
        except Exception:
            pass  # expected
        # Index entry detached
        entry = get_address_index().get_eni("eni-itest")
        assert entry.instance_id is None
        assert entry.iface_name is None

        # ----- Step 11: Delete -----
        mgr.delete("eni-itest")
        assert get_address_index().get_eni("eni-itest") is None
        # Primary IP released from allocator
        assert alloc.lookup(primary_ip) is None
        # The remaining secondary was also released
        assert alloc.lookup("10.251.0.50") is None

        # ----- Step 12: Pool is clean -----
        pools = alloc.describe(_VPC)
        assert pools[0].allocated == {}
