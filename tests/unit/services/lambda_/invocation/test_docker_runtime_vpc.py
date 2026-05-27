"""Unit tests for Lambda VpcConfig-aware network attachment .

Before this fix ``_get_networks_for_executor`` only returned networks
from LAMBDA_DOCKER_NETWORK, so ``CreateFunction(VpcConfig=…)`` was
stored in the function model but the actual container never joined
``localemu-vpc-<vpc_id>``. A Lambda configured in a VPC couldn't reach
RDS/EC2/ECS containers in that VPC.

The fix: the executor now appends ``localemu-vpc-<vpc_id>`` to the
network list when ``function_version.config.vpc_config.vpc_id`` is
present. The primary network stays the LocalEmu-main one so the runtime
can still reach the control plane at ``host.docker.internal:4566``.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.lambda_.invocation import docker_runtime_executor as dre


class _FakeFunctionVersion:
    """A minimal stand-in — we only need ``config.vpc_config``."""
    def __init__(self, vpc_config=None):
        self.config = mock.Mock()
        self.config.vpc_config = vpc_config
        self.id = mock.Mock()
        self.id.function_name = "testfn"
        self.id.qualified_arn.return_value = (
            "arn:aws:lambda:us-east-1:000000000000:function:testfn:$LATEST"
        )


def _executor_with_vpc(vpc_config):
    """Build a DockerRuntimeExecutor without touching the real __init__."""
    ex = dre.DockerRuntimeExecutor.__new__(dre.DockerRuntimeExecutor)
    ex.function_version = _FakeFunctionVersion(vpc_config)
    return ex


class TestNetworksForExecutor:
    def test_no_vpc_config_returns_base_networks_unchanged(self):
        ex = _executor_with_vpc(None)
        with mock.patch.object(
            dre, "get_all_container_networks_for_lambda",
            return_value=["bridge"],
        ):
            nets = ex._get_networks_for_executor()
        assert nets == ["bridge"]

    def test_vpc_config_without_vpc_id_returns_base(self):
        """A half-populated VpcConfig (empty subnets → vpc_id == "") must
        behave as though no VPC was configured."""
        vc = mock.Mock()
        vc.vpc_id = ""
        ex = _executor_with_vpc(vc)
        with mock.patch.object(
            dre, "get_all_container_networks_for_lambda",
            return_value=["bridge"],
        ):
            nets = ex._get_networks_for_executor()
        assert nets == ["bridge"]

    def test_vpc_config_with_vpc_id_appends_vpc_network(self):
        vc = mock.Mock()
        vc.vpc_id = "vpc-abc"
        ex = _executor_with_vpc(vc)
        with mock.patch.object(
            dre, "get_all_container_networks_for_lambda",
            return_value=["localemu-main"],
        ):
            nets = ex._get_networks_for_executor()
        assert nets == ["localemu-main", "localemu-vpc-vpc-abc"]
        # Primary (first) is still the control-plane network so the Lambda
        # runtime can reach host.docker.internal:4566.
        assert nets[0] == "localemu-main"

    def test_vpc_network_not_duplicated_if_already_in_base(self):
        vc = mock.Mock()
        vc.vpc_id = "vpc-xyz"
        ex = _executor_with_vpc(vc)
        with mock.patch.object(
            dre, "get_all_container_networks_for_lambda",
            return_value=["localemu-main", "localemu-vpc-vpc-xyz"],
        ):
            nets = ex._get_networks_for_executor()
        # unchanged — no duplicate
        assert nets.count("localemu-vpc-vpc-xyz") == 1
        assert nets == ["localemu-main", "localemu-vpc-vpc-xyz"]

    def test_multiple_base_networks_plus_vpc(self):
        vc = mock.Mock()
        vc.vpc_id = "vpc-123"
        ex = _executor_with_vpc(vc)
        with mock.patch.object(
            dre, "get_all_container_networks_for_lambda",
            return_value=["net-a", "net-b"],
        ):
            nets = ex._get_networks_for_executor()
        assert nets == ["net-a", "net-b", "localemu-vpc-vpc-123"]
