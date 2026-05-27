"""Unit tests for ``_resolve_container_private_ip`` .

The previous probe only asked the ``bridge`` network, and fell through
to a SHA256-hashed synthetic IP on failure. This made IMDS, DescribeInstances
and any intra-VPC endpoint resolution return a fake address with no
routing. The helper below probes in a real order:

  1. the VPC network the instance was attached to at create time (hint)
  2. any other ``localemu-vpc-*`` network the container is on
  3. the default Docker bridge
  4. None, with a WARNING — NO synthetic fallback
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import vm_manager


class TestResolveContainerPrivateIp:
    def _dc(self, *, networks=None, ip_map=None):
        """Build a mocked DOCKER_CLIENT.

        networks: list of network names returned by get_networks.
        ip_map: {network_name: ip_or_exception}. If the value is an
                Exception subclass, get_container_ipv4_for_network raises;
                otherwise it returns the value (str or None).
        """
        dc = mock.MagicMock()
        dc.get_networks.return_value = networks or []

        def _ip(container_name_or_id, container_network):
            entry = (ip_map or {}).get(container_network)
            if isinstance(entry, Exception):
                raise entry
            if isinstance(entry, type) and issubclass(entry, Exception):
                raise entry("not connected")
            return entry

        dc.get_container_ipv4_for_network.side_effect = _ip
        return dc

    def test_vpc_hint_resolves_first(self):
        dc = self._dc(
            networks=["localemu-vpc-vpc-123", "bridge"],
            ip_map={"localemu-vpc-vpc-123": "10.0.1.42", "bridge": "172.17.0.2"},
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip(
                "ctr", vpc_network_hint="localemu-vpc-vpc-123",
            )
        assert ip == "10.0.1.42"

    def test_falls_through_to_any_localemu_vpc_when_hint_missing(self):
        dc = self._dc(
            networks=["localemu-vpc-vpc-abc", "bridge"],
            ip_map={"localemu-vpc-vpc-abc": "10.7.0.5", "bridge": "172.17.0.3"},
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip("ctr", None)
        assert ip == "10.7.0.5"

    def test_falls_through_to_bridge_when_no_vpc(self):
        dc = self._dc(
            networks=["bridge"],
            ip_map={"bridge": "172.17.0.4"},
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip("ctr", None)
        assert ip == "172.17.0.4"

    def test_returns_none_when_everything_fails_no_sha256_fallback(self):
        dc = self._dc(
            networks=["localemu-vpc-vpc-x", "bridge"],
            ip_map={
                "localemu-vpc-vpc-x": RuntimeError("not attached"),
                "bridge": RuntimeError("not attached"),
            },
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip("ctr", None)
        assert ip is None

    def test_hint_failure_falls_through_to_secondary_vpc(self):
        dc = self._dc(
            networks=["localemu-vpc-vpc-1", "localemu-vpc-vpc-2", "bridge"],
            ip_map={
                "localemu-vpc-vpc-1": RuntimeError("probe failed"),
                "localemu-vpc-vpc-2": "10.8.1.99",
                "bridge": "172.17.0.5",
            },
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip(
                "ctr", vpc_network_hint="localemu-vpc-vpc-1",
            )
        assert ip == "10.8.1.99"

    def test_get_networks_raising_doesnt_break_bridge_fallback(self):
        """If inspect fails, we should still try ``bridge`` blindly."""
        dc = mock.MagicMock()
        dc.get_networks.side_effect = RuntimeError("inspect failed")
        dc.get_container_ipv4_for_network.side_effect = lambda **kw: (
            "172.17.0.6" if kw["container_network"] == "bridge" else None
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip("ctr", None)
        assert ip == "172.17.0.6"

    def test_empty_string_ip_counts_as_unresolved(self):
        """Docker sometimes returns empty string before an IP is allocated
        — treat that as 'not ready' and continue to the next network."""
        dc = self._dc(
            networks=["localemu-vpc-vpc-y", "bridge"],
            ip_map={"localemu-vpc-vpc-y": "", "bridge": "172.17.0.7"},
        )
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc):
            ip = vm_manager._resolve_container_private_ip(
                "ctr", vpc_network_hint="localemu-vpc-vpc-y",
            )
        assert ip == "172.17.0.7"
