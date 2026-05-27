"""Unit tests for ECS awsvpc VPC resolution .

Previously _connect_to_vpc_network shelled out to ``docker network ls``
and took the first ``localemu-vpc-*`` result. With two VPCs, an awsvpc
task could land in the wrong one — silent isolation failure.

The fix uses the subnet IDs from the RunTask request's
``networkConfiguration.awsvpcConfiguration.subnets`` to resolve the
correct VPC via moto before attaching.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ecs.docker import task_manager


class TestConnectToVpcNetwork:
    def _mgr(self):
        mgr = task_manager.DockerTaskManager.__new__(task_manager.DockerTaskManager)
        import threading as _t
        mgr._tasks = {}
        mgr._lock = _t.Lock()
        return mgr

    def test_resolves_vpc_from_subnet_ids(self):
        mgr = self._mgr()
        fake_vpcm = mock.MagicMock()
        fake_vpcm.get_vpc_id_for_subnet.return_value = "vpc-correct"
        with mock.patch.object(
            task_manager, "DOCKER_CLIENT",
        ) as dc, mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=fake_vpcm,
        ):
            dc.get_networks.return_value = ["bridge"]
            mgr._connect_to_vpc_network(
                "ecs-task-x", "arn:aws:ecs:us-east-1:000000000000:cluster/c1",
                subnet_ids=["subnet-abc"],
                account_id="000000000000", region="us-east-1",
            )
            dc.connect_container_to_network.assert_called_once_with(
                "localemu-vpc-vpc-correct", "ecs-task-x",
            )

    def test_already_on_vpc_network_noop(self):
        mgr = self._mgr()
        with mock.patch.object(task_manager, "DOCKER_CLIENT") as dc:
            dc.get_networks.return_value = ["localemu-vpc-vpc-existing", "bridge"]
            mgr._connect_to_vpc_network(
                "ecs-task-y", "c1",
                subnet_ids=["subnet-abc"],
                account_id="000000000000", region="us-east-1",
            )
            dc.connect_container_to_network.assert_not_called()

    def test_no_subnet_ids_logs_and_skips(self):
        """Without subnet IDs we can't know which VPC to attach to —
        don't pick one arbitrarily. Log and skip."""
        mgr = self._mgr()
        with mock.patch.object(task_manager, "DOCKER_CLIENT") as dc:
            dc.get_networks.return_value = ["bridge"]
            mgr._connect_to_vpc_network(
                "ecs-task-z", "c1",
                subnet_ids=None,
                account_id="000000000000", region="us-east-1",
            )
            dc.connect_container_to_network.assert_not_called()

    def test_subnet_resolution_failure_skips(self):
        mgr = self._mgr()
        fake_vpcm = mock.MagicMock()
        fake_vpcm.get_vpc_id_for_subnet.return_value = None
        with mock.patch.object(
            task_manager, "DOCKER_CLIENT",
        ) as dc, mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=fake_vpcm,
        ):
            dc.get_networks.return_value = ["bridge"]
            mgr._connect_to_vpc_network(
                "ecs-task-w", "c1",
                subnet_ids=["subnet-unknown"],
                account_id="000000000000", region="us-east-1",
            )
            dc.connect_container_to_network.assert_not_called()

    def test_first_resolvable_subnet_wins(self):
        """If subnets are in different VPCs (real AWS doesn't allow this
        for awsvpc, but we shouldn't crash), take the first that resolves."""
        mgr = self._mgr()
        fake_vpcm = mock.MagicMock()
        fake_vpcm.get_vpc_id_for_subnet.side_effect = [None, "vpc-B"]
        with mock.patch.object(
            task_manager, "DOCKER_CLIENT",
        ) as dc, mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=fake_vpcm,
        ):
            dc.get_networks.return_value = ["bridge"]
            mgr._connect_to_vpc_network(
                "ecs-task-q", "c1",
                subnet_ids=["subnet-1", "subnet-2"],
                account_id="000000000000", region="us-east-1",
            )
            dc.connect_container_to_network.assert_called_once_with(
                "localemu-vpc-vpc-B", "ecs-task-q",
            )
