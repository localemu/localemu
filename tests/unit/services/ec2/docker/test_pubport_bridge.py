"""Unit tests for the shared port-publishing bridge.

Rationale: Docker silently ignores ``-p`` on containers whose only
network is ``--internal=True`` (moby/moby#27441). LocalEmu VPC
networks are internal by design, so EC2 instances in a VPC need a
second, non-internal network whose sole purpose is port publishing.
``vpc_network.ensure_pubport_bridge`` guarantees that bridge exists.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import vpc_network


@pytest.fixture(autouse=True)
def _reset_pubport_flag():
    vpc_network._pubport_ready = False
    yield
    vpc_network._pubport_ready = False


class TestEnsurePubportBridge:
    def test_creates_when_missing(self):
        dc = mock.MagicMock()
        dc.inspect_network.side_effect = RuntimeError("not found")
        with mock.patch.object(vpc_network, "DOCKER_CLIENT", dc):
            name = vpc_network.ensure_pubport_bridge()
        assert name == vpc_network.PUBPORT_BRIDGE_NAME
        dc.create_network.assert_called_once()
        # Must NOT be internal — the whole point is to publish ports
        kwargs = dc.create_network.call_args.kwargs
        assert kwargs.get("internal") is False

    def test_noop_when_present(self):
        dc = mock.MagicMock()
        dc.inspect_network.return_value = {"Name": vpc_network.PUBPORT_BRIDGE_NAME}
        with mock.patch.object(vpc_network, "DOCKER_CLIENT", dc):
            vpc_network.ensure_pubport_bridge()
        dc.create_network.assert_not_called()

    def test_idempotent_same_process(self):
        dc = mock.MagicMock()
        dc.inspect_network.side_effect = RuntimeError("not found")
        with mock.patch.object(vpc_network, "DOCKER_CLIENT", dc):
            vpc_network.ensure_pubport_bridge()
            vpc_network.ensure_pubport_bridge()
            vpc_network.ensure_pubport_bridge()
        # Second / third calls short-circuit via _pubport_ready
        assert dc.create_network.call_count == 1

    def test_subnet_conflict_falls_back_to_docker_assigned(self):
        dc = mock.MagicMock()
        dc.inspect_network.side_effect = RuntimeError("not found")
        # First create (with subnet) fails, fallback (no subnet) succeeds
        dc.create_network.side_effect = [RuntimeError("subnet in use"), None]
        with mock.patch.object(vpc_network, "DOCKER_CLIENT", dc):
            vpc_network.ensure_pubport_bridge()
        assert dc.create_network.call_count == 2
        # Second call must omit subnet
        second = dc.create_network.call_args_list[1].kwargs
        assert "subnet" not in second or second.get("subnet") is None

    def test_create_failure_does_not_raise(self):
        dc = mock.MagicMock()
        dc.inspect_network.side_effect = RuntimeError("not found")
        dc.create_network.side_effect = RuntimeError("docker down")
        with mock.patch.object(vpc_network, "DOCKER_CLIENT", dc):
            # Must not raise — callers degrade gracefully
            result = vpc_network.ensure_pubport_bridge()
        assert result == vpc_network.PUBPORT_BRIDGE_NAME


class TestVmManagerSecondaryNetworkWiring:
    """Verify DockerVmManager.create_instance attaches the VPC network
    as a SECONDARY interface after starting on the pubport bridge."""

    def test_create_uses_pubport_primary_and_vpc_secondary(self):
        from localemu.services.ec2.docker import vm_manager

        mgr = vm_manager.DockerVmManager.__new__(vm_manager.DockerVmManager)
        import threading as _t
        mgr._instances = {}
        mgr._lock = _t.Lock()
        mgr._imds_server = mock.MagicMock()
        mgr._imds_server.port = 1666
        mgr._imds_server.allocate_port_for_instance.return_value = 1666
        mgr._flow_log_pollers = {}

        dc = mock.MagicMock()
        dc.inspect_image.return_value = {}
        dc.get_container_ipv4_for_network.return_value = "10.50.0.42"
        dc.get_networks.return_value = ["localemu-pubport-br", "localemu-vpc-vpc-abc"]

        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc), \
             mock.patch.object(vpc_network, "DOCKER_CLIENT", dc), \
             mock.patch("localemu.services.ec2.docker.vm_manager._patch_moto_instance_ip"), \
             mock.patch("localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
                        return_value=True), \
             mock.patch(
                 "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
             ) as vpcm, \
             mock.patch(
                 "localemu.services.ec2.docker.imds_sidecar.ensure_imds_sidecar",
                 return_value=None,
             ):
            vpcm.return_value = mock.MagicMock()
            info = mgr.create_instance(
                instance_id="i-abc123",
                ami_id="ami-ubuntu-22.04",
                vpc_network="localemu-vpc-vpc-abc",
                subnet_id="subnet-1",
            )
        # The create call must have used pubport as primary network
        create_call = dc.create_container_from_config.call_args
        config = create_call.args[0]
        assert config.network == "localemu-pubport-br"
        # And the VPC must have been attached AFTER start
        connect_calls = [
            c.args for c in dc.connect_container_to_network.call_args_list
        ]
        assert any("localemu-vpc-vpc-abc" in args for args in connect_calls), \
            f"VPC network should be attached as secondary; got {connect_calls}"
