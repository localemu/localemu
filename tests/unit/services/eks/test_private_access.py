"""Unit tests for EKS endpointPrivateAccess request-parsing and the
cluster_manager plumbing that threads it into a real network-isolation
decision (join the VPC's Docker bridge, firewall the public port) -
the default (endpointPrivateAccess unset/false) path must be byte-for-byte
unchanged from before this feature existed."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.services.eks import provider as eks_provider


def _ctx(account_id="000000000000", region="us-east-1"):
    ctx = MagicMock()
    ctx.account_id = account_id
    ctx.region = region
    return ctx


class TestCreateClusterRequestParsing:
    """_handle_create_cluster must extract endpointPrivateAccess and
    resolve vpc_id from resourcesVpcConfig.subnetIds without ever raising,
    and must default to today's exact behavior when the field is absent."""

    def _run(self, request, vpc_id_lookup=None):
        mgr = MagicMock()
        mgr.create_cluster.return_value = MagicMock(
            endpoint="https://127.0.0.1:1234", ca_cert_data="", kubeconfig="",
        )
        moto_result = {"cluster": {"name": "my-cluster"}}
        with patch.object(eks_provider, "_init_cluster_manager", return_value=mgr), \
             patch.object(eks_provider, "call_moto", return_value=moto_result), \
             patch("localemu.services.ec2.docker.vpc_network.get_vpc_network_manager") as get_mgr, \
             patch("moto.backends.get_backend"):
            get_mgr.return_value.get_vpc_id_for_subnet.return_value = vpc_id_lookup
            eks_provider._handle_create_cluster(_ctx(), request)
            # the real work happens in a background thread; join it via
            # the thread target directly isn't exposed, so just allow the
            # mock call to have been scheduled and run inline for the test
            # by invoking threading.Thread's target synchronously instead.
        return mgr

    def test_no_resources_vpc_config_defaults_to_public_unchanged(self):
        """Absence of resourcesVpcConfig entirely (the common case before
        this feature existed) must not raise and must pass
        endpoint_private_access=False, vpc_id=None - today's exact
        behavior."""
        request = {"name": "my-cluster", "version": "1.29"}
        with patch("threading.Thread") as thread_cls:
            mgr = self._run(request)
            # Run the background-thread target synchronously so we can
            # inspect the real create_cluster call it makes.
            target = thread_cls.call_args.kwargs["target"]
            target()
        mgr.create_cluster.assert_called_once()
        kwargs = mgr.create_cluster.call_args.kwargs
        assert kwargs["endpoint_private_access"] is False
        assert kwargs["vpc_id"] is None

    def test_endpoint_private_access_false_explicit(self):
        request = {
            "name": "my-cluster",
            "resourcesVpcConfig": {
                "subnetIds": ["subnet-aaa"], "endpointPrivateAccess": False,
            },
        }
        with patch("threading.Thread") as thread_cls:
            mgr = self._run(request, vpc_id_lookup="vpc-123")
            thread_cls.call_args.kwargs["target"]()
        kwargs = mgr.create_cluster.call_args.kwargs
        assert kwargs["endpoint_private_access"] is False
        assert kwargs["vpc_id"] is None  # never looked up when the flag is off

    def test_endpoint_private_access_true_resolves_vpc_id(self):
        request = {
            "name": "my-cluster",
            "resourcesVpcConfig": {
                "subnetIds": ["subnet-aaa", "subnet-bbb"],
                "endpointPrivateAccess": True,
            },
        }
        with patch("threading.Thread") as thread_cls:
            mgr = self._run(request, vpc_id_lookup="vpc-123")
            thread_cls.call_args.kwargs["target"]()
        kwargs = mgr.create_cluster.call_args.kwargs
        assert kwargs["endpoint_private_access"] is True
        assert kwargs["vpc_id"] == "vpc-123"

    def test_endpoint_private_access_true_but_vpc_unresolvable(self):
        """Must not raise, must not fabricate a vpc_id - just proceed
        with vpc_id=None (cluster_manager treats that as "don't enforce,
        warn loudly"), exactly like having no VPC config at all."""
        request = {
            "name": "my-cluster",
            "resourcesVpcConfig": {
                "subnetIds": ["subnet-does-not-exist"],
                "endpointPrivateAccess": True,
            },
        }
        with patch("threading.Thread") as thread_cls:
            mgr = self._run(request, vpc_id_lookup=None)
            thread_cls.call_args.kwargs["target"]()
        kwargs = mgr.create_cluster.call_args.kwargs
        assert kwargs["endpoint_private_access"] is True
        assert kwargs["vpc_id"] is None

    def test_endpoint_private_access_true_no_subnet_ids_at_all(self):
        request = {
            "name": "my-cluster",
            "resourcesVpcConfig": {"endpointPrivateAccess": True},
        }
        with patch("threading.Thread") as thread_cls:
            mgr = self._run(request)
            thread_cls.call_args.kwargs["target"]()
        kwargs = mgr.create_cluster.call_args.kwargs
        assert kwargs["endpoint_private_access"] is True
        assert kwargs["vpc_id"] is None
