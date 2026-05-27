"""Unit tests for VpcNetworkManager.rebuild_from_docker .

After LocalEmu restart, the ``_vpcs[*].containers`` set and
``_container_subnets`` dict were empty because they lived only in
memory. Containers had been preserved via ``PERSISTENCE=1`` but
VpcNetworkManager didn't know about them, so IGW toggle / peering
add-remove / NACL subnet enforcement silently missed every restored
container.

The rebuild walks Docker's list of labeled LocalEmu-service containers
and reconstructs the tracking from the authoritative sources:

  - Which VPC networks the container is actually attached to
    (``NetworkSettings.Networks`` from inspect).
  - ``localemu.subnet-id`` label when present (EC2 containers; other
    services don't need subnet tracking today).
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import vpc_network as vpc_mod


class TestRebuildFromDocker:
    def _container(
        self, name, service, *, vpcs=None, subnet_id=None,
    ) -> dict:
        labels = {"localemu.service": service}
        if subnet_id:
            labels["localemu.subnet-id"] = subnet_id
        networks = {"bridge": {"IPAddress": "172.17.0.2"}}
        for vpc_id in vpcs or []:
            networks[f"localemu-vpc-{vpc_id}"] = {"IPAddress": "10.0.0.5"}
        return {
            "name": name,
            "id": f"id-{name}",
            "labels": labels,
            "_inspect": {
                "Id": f"id-{name}",
                "Config": {"Labels": labels},
                "NetworkSettings": {"Networks": networks},
                "State": {"Running": True},
                "HostConfig": {},
            },
        }

    def _dc(self, containers):
        dc = mock.MagicMock()
        dc.list_containers.return_value = containers
        dc.inspect_container.side_effect = (
            lambda name: next(c["_inspect"] for c in containers if c["name"] == name)
        )
        return dc

    def test_rebuild_populates_ec2_container_in_vpc(self):
        containers = [
            self._container(
                "localemu-ec2-i-1", "ec2",
                vpcs=["vpc-a"], subnet_id="subnet-1",
            ),
        ]
        mgr = vpc_mod.VpcNetworkManager()
        mgr._vpcs["vpc-a"] = {
            "network_name": "localemu-vpc-vpc-a",
            "cidr": "10.0.0.0/16",
            "network_id": "fake",
            "has_igw": False,
            "containers": set(),
        }
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", self._dc(containers)):
            mgr.rebuild_from_docker()
        assert "localemu-ec2-i-1" in mgr._vpcs["vpc-a"]["containers"]
        assert mgr._container_subnets["localemu-ec2-i-1"] == "subnet-1"

    def test_rebuild_handles_rds_and_ecs_without_subnet_label(self):
        containers = [
            self._container("localemu-rds-mydb", "rds", vpcs=["vpc-b"]),
            self._container(
                "localemu-ecs-c-tid-app", "ecs", vpcs=["vpc-b"],
            ),
        ]
        mgr = vpc_mod.VpcNetworkManager()
        mgr._vpcs["vpc-b"] = {
            "network_name": "localemu-vpc-vpc-b",
            "cidr": "10.1.0.0/16",
            "network_id": "fake",
            "has_igw": False,
            "containers": set(),
        }
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", self._dc(containers)):
            mgr.rebuild_from_docker()
        assert mgr._vpcs["vpc-b"]["containers"] == {
            "localemu-rds-mydb", "localemu-ecs-c-tid-app",
        }
        # No subnet-id labels → no tracking for these two
        assert "localemu-rds-mydb" not in mgr._container_subnets
        assert "localemu-ecs-c-tid-app" not in mgr._container_subnets

    def test_rebuild_lazy_creates_unknown_vpc_entry(self):
        """If a container is on localemu-vpc-X but the manager has no
        record of vpc-X yet, we create a minimal record so subsequent
        peering / IGW ops can find the container."""
        containers = [
            self._container("localemu-ec2-i-9", "ec2", vpcs=["vpc-new"]),
        ]
        mgr = vpc_mod.VpcNetworkManager()
        # no _vpcs["vpc-new"] entry yet
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", self._dc(containers)):
            mgr.rebuild_from_docker()
        assert "vpc-new" in mgr._vpcs
        assert "localemu-ec2-i-9" in mgr._vpcs["vpc-new"]["containers"]

    def test_rebuild_is_idempotent(self):
        containers = [
            self._container("localemu-ec2-i-2", "ec2", vpcs=["vpc-c"]),
        ]
        mgr = vpc_mod.VpcNetworkManager()
        mgr._vpcs["vpc-c"] = {
            "network_name": "localemu-vpc-vpc-c",
            "cidr": "10.2.0.0/16",
            "network_id": "fake",
            "has_igw": False,
            "containers": {"localemu-ec2-i-2"},
        }
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", self._dc(containers)):
            mgr.rebuild_from_docker()
            mgr.rebuild_from_docker()
        assert mgr._vpcs["vpc-c"]["containers"] == {"localemu-ec2-i-2"}

    def test_rebuild_skips_containers_not_on_any_vpc_network(self):
        """A container with only the default bridge attached isn't in any
        VPC — must not pollute _vpcs."""
        containers = [
            self._container("localemu-ec2-i-x", "ec2", vpcs=[]),
        ]
        mgr = vpc_mod.VpcNetworkManager()
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", self._dc(containers)):
            mgr.rebuild_from_docker()
        assert mgr._vpcs == {}

    def test_rebuild_survives_inspect_failures(self):
        dc = mock.MagicMock()
        dc.list_containers.return_value = [
            {"name": "crash", "id": "x", "labels": {"localemu.service": "ec2"}},
        ]
        dc.inspect_container.side_effect = RuntimeError("inspect failed")
        mgr = vpc_mod.VpcNetworkManager()
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", dc):
            # Must not raise
            mgr.rebuild_from_docker()
        assert mgr._vpcs == {}
