"""Verify ipv4_address / ipv6_address / mac_address kwargs are forwarded
correctly by both concrete container clients (SDK and CLI).

This is the foundational plumbing test for the addressing redesign.
Without these kwargs forwarding to docker-py / docker CLI, the
SubnetAllocator's reserved IPs cannot actually pin to containers.
"""
from __future__ import annotations

import inspect
from unittest import mock

import pytest

from localemu.utils.container_utils.container_client import ContainerClient


# ---------------------------------------------------------------------------
# Abstract method signature
# ---------------------------------------------------------------------------
class TestAbstractSignature:
    def test_connect_container_to_network_has_ipv4_address(self):
        sig = inspect.signature(
            ContainerClient.connect_container_to_network,
        )
        params = sig.parameters
        assert "ipv4_address" in params
        assert params["ipv4_address"].default is None

    def test_has_ipv6_address(self):
        sig = inspect.signature(
            ContainerClient.connect_container_to_network,
        )
        assert "ipv6_address" in sig.parameters

    def test_has_mac_address(self):
        sig = inspect.signature(
            ContainerClient.connect_container_to_network,
        )
        assert "mac_address" in sig.parameters

    def test_existing_params_unchanged(self):
        sig = inspect.signature(
            ContainerClient.connect_container_to_network,
        )
        assert "aliases" in sig.parameters
        assert "link_local_ips" in sig.parameters
        # All new params default to None (backward-compatible)
        assert sig.parameters["ipv4_address"].default is None
        assert sig.parameters["ipv6_address"].default is None
        assert sig.parameters["mac_address"].default is None


# ---------------------------------------------------------------------------
# SDK client forwards to docker-py
# ---------------------------------------------------------------------------
class TestSdkForward:
    def _client(self):
        from localemu.utils.container_utils.docker_sdk_client import (
            SdkDockerClient,
        )
        return SdkDockerClient()

    def test_ipv4_address_forwarded(self):
        client = self._client()
        with mock.patch.object(client, "client") as mock_client:
            net = mock.MagicMock()
            mock_client.return_value.networks.get.return_value = net
            client.connect_container_to_network(
                "the-net", "ctr-1", ipv4_address="10.0.0.5",
            )
            net.connect.assert_called_once()
            kwargs = net.connect.call_args.kwargs
            assert kwargs["ipv4_address"] == "10.0.0.5"
            assert kwargs["ipv6_address"] is None

    def test_ipv6_address_forwarded(self):
        client = self._client()
        with mock.patch.object(client, "client") as mock_client:
            net = mock.MagicMock()
            mock_client.return_value.networks.get.return_value = net
            client.connect_container_to_network(
                "the-net", "ctr-1", ipv6_address="fd00::5",
            )
            kwargs = net.connect.call_args.kwargs
            assert kwargs["ipv6_address"] == "fd00::5"

    def test_aliases_still_forwarded(self):
        client = self._client()
        with mock.patch.object(client, "client") as mock_client:
            net = mock.MagicMock()
            mock_client.return_value.networks.get.return_value = net
            client.connect_container_to_network(
                "the-net", "ctr-1", aliases=["a", "b"],
            )
            kwargs = net.connect.call_args.kwargs
            assert kwargs["aliases"] == ["a", "b"]

    def test_mac_address_logs_warning_but_does_not_forward(self, caplog):
        client = self._client()
        with mock.patch.object(client, "client") as mock_client:
            net = mock.MagicMock()
            mock_client.return_value.networks.get.return_value = net
            with caplog.at_level("WARNING"):
                client.connect_container_to_network(
                    "the-net", "ctr-1", mac_address="aa:bb:cc:dd:ee:ff",
                )
            # network.connect was called without mac_address
            kwargs = net.connect.call_args.kwargs
            assert "mac_address" not in kwargs
            # WARN was logged
            assert any("mac_address" in r.message for r in caplog.records)

    def test_backward_compatible_no_kwargs(self):
        client = self._client()
        with mock.patch.object(client, "client") as mock_client:
            net = mock.MagicMock()
            mock_client.return_value.networks.get.return_value = net
            # Existing call shape works
            client.connect_container_to_network("the-net", "ctr-1")
            kwargs = net.connect.call_args.kwargs
            assert kwargs["ipv4_address"] is None
            assert kwargs["ipv6_address"] is None
            assert kwargs["aliases"] is None


# ---------------------------------------------------------------------------
# CLI client emits the right flags
# ---------------------------------------------------------------------------
class TestCmdForward:
    def _client(self):
        from localemu.utils.container_utils.docker_cmd_client import (
            CmdDockerClient,
        )
        return CmdDockerClient()

    def test_ipv4_emits_ip_flag(self):
        client = self._client()
        with mock.patch(
            "localemu.utils.container_utils.docker_cmd_client.run",
        ) as mock_run:
            client.connect_container_to_network(
                "the-net", "ctr-1", ipv4_address="10.0.0.5",
            )
            cmd = mock_run.call_args[0][0]
            assert "--ip" in cmd
            assert "10.0.0.5" in cmd
            # Argument order: --ip 10.0.0.5
            ip_idx = cmd.index("--ip")
            assert cmd[ip_idx + 1] == "10.0.0.5"

    def test_ipv6_emits_ip6_flag(self):
        client = self._client()
        with mock.patch(
            "localemu.utils.container_utils.docker_cmd_client.run",
        ) as mock_run:
            client.connect_container_to_network(
                "the-net", "ctr-1", ipv6_address="fd00::5",
            )
            cmd = mock_run.call_args[0][0]
            assert "--ip6" in cmd

    def test_no_ip_when_kwarg_omitted(self):
        client = self._client()
        with mock.patch(
            "localemu.utils.container_utils.docker_cmd_client.run",
        ) as mock_run:
            client.connect_container_to_network("the-net", "ctr-1")
            cmd = mock_run.call_args[0][0]
            assert "--ip" not in cmd
            assert "--ip6" not in cmd

    def test_mac_logs_warning_but_no_flag(self, caplog):
        client = self._client()
        with mock.patch(
            "localemu.utils.container_utils.docker_cmd_client.run",
        ):
            with caplog.at_level("WARNING"):
                client.connect_container_to_network(
                    "the-net", "ctr-1", mac_address="aa:bb:cc:dd:ee:ff",
                )
            assert any("mac_address" in r.message for r in caplog.records)
