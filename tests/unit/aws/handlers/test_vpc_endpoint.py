"""Tests for VpcEndpointContextEnricher - tags context.vpc_endpoint_id from
the port a request's connection was accepted on, so the IAM enforcement
handler can populate aws:SourceVpce/aws:SourceVpc and evaluate the
endpoint's own policy. Port-based (not source-IP-based) because on Docker
Desktop, container->host traffic is NATed to 127.0.0.1, making source IP
useless for telling VPC endpoints apart - see goat-bugs item 5."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from localemu.aws.handlers.vpc_endpoint import VpcEndpointContextEnricher


def _ctx(server_port=None) -> SimpleNamespace:
    environ = {}
    if server_port is not None:
        environ["SERVER_PORT"] = server_port
    request = SimpleNamespace(environ=environ)
    return SimpleNamespace(request=request, vpc_endpoint_id=None)


class TestVpcEndpointContextEnricher:
    def test_no_server_port_leaves_endpoint_id_none(self):
        ctx = _ctx(server_port=None)
        VpcEndpointContextEnricher()(chain=None, context=ctx, response=None)
        assert ctx.vpc_endpoint_id is None

    def test_port_not_registered_to_any_endpoint_leaves_none(self):
        manager = MagicMock()
        manager.get_endpoint_id_for_port.return_value = None
        with patch(
            "localemu.services.ec2.docker.vpc_endpoint.get_vpc_endpoint_manager",
            return_value=manager,
        ):
            ctx = _ctx(server_port="4566")  # the shared main edge port
            VpcEndpointContextEnricher()(chain=None, context=ctx, response=None)
        assert ctx.vpc_endpoint_id is None
        manager.get_endpoint_id_for_port.assert_called_once_with(4566)

    def test_port_registered_to_an_endpoint_tags_context(self):
        manager = MagicMock()
        manager.get_endpoint_id_for_port.return_value = "vpce-abc123"
        with patch(
            "localemu.services.ec2.docker.vpc_endpoint.get_vpc_endpoint_manager",
            return_value=manager,
        ):
            ctx = _ctx(server_port="54321")
            VpcEndpointContextEnricher()(chain=None, context=ctx, response=None)
        assert ctx.vpc_endpoint_id == "vpce-abc123"

    def test_malformed_server_port_is_handled_without_raising(self):
        ctx = _ctx(server_port="not-a-port")
        VpcEndpointContextEnricher()(chain=None, context=ctx, response=None)
        assert ctx.vpc_endpoint_id is None

    def test_lookup_failure_is_swallowed_not_raised(self):
        with patch(
            "localemu.services.ec2.docker.vpc_endpoint.get_vpc_endpoint_manager",
            side_effect=RuntimeError("boom"),
        ):
            ctx = _ctx(server_port="4566")
            VpcEndpointContextEnricher()(chain=None, context=ctx, response=None)
        assert ctx.vpc_endpoint_id is None
