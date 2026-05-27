"""Tests for the MAC-based interface-name resolver.

The resolver is the substrate for every per-iface operation in the ENI
design (secondary IP add, per-iface SG chains, source/dest-check FORWARD
rules). It must be tolerant of every Docker failure mode and never raise.
"""
from __future__ import annotations

from unittest import mock

from localemu.services.ec2.docker import iface_resolver
from localemu.services.ec2.docker.container_routing import resolve_pcx_iface


def _ip_link_output(*lines: str) -> bytes:
    """Build `ip -o link show` output. The -o flag puts each iface on ONE
    line, joining the iface header and the link/ether line with a literal
    backslash separator. Tests pass one logical iface per arg as a single
    pre-joined line."""
    return ("\n".join(lines) + "\n").encode()


class TestResolveIfaceForNetwork:
    def test_happy_path(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {
                        "localemu-vpc-vpc-1": {"MacAddress": "02:42:0a:00:00:05"},
                    },
                },
            }
            dc.exec_in_container.return_value = (
                _ip_link_output(
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
                    "3: eth1@if31: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\\    link/ether 02:42:0a:00:00:05 brd ff:ff:ff:ff:ff:ff",
                ),
                b"",
            )
            iface = iface_resolver.resolve_iface_for_network(
                "container", "localemu-vpc-vpc-1",
            )
            assert iface == "eth1"

    def test_strips_at_ifx_suffix(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {
                        "net-x": {"MacAddress": "02:42:ac:14:00:02"},
                    },
                },
            }
            dc.exec_in_container.return_value = (
                _ip_link_output(
                    "5: eth2@if99: <UP> mtu 1500\\    link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff",
                ),
                b"",
            )
            assert iface_resolver.resolve_iface_for_network(
                "c", "net-x",
            ) == "eth2"

    def test_no_at_suffix(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {
                        "net": {"MacAddress": "02:42:00:00:00:01"},
                    },
                },
            }
            dc.exec_in_container.return_value = (
                _ip_link_output(
                    "2: eth0: <UP>\\    link/ether 02:42:00:00:00:01 brd ff:ff:ff:ff:ff:ff",
                ),
                b"",
            )
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) == "eth0"

    def test_case_insensitive_mac_match(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            # MAC from inspect is uppercase, ip-link output is lowercase
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {
                        "net": {"MacAddress": "02:42:AA:BB:CC:DD"},
                    },
                },
            }
            dc.exec_in_container.return_value = (
                _ip_link_output(
                    "3: eth7: <UP>\\    link/ether 02:42:aa:bb:cc:dd brd ff:ff:ff:ff:ff:ff",
                ),
                b"",
            )
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) == "eth7"

    def test_network_not_attached_returns_none(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {"other-net": {"MacAddress": "02:42:00:00:00:01"}},
                },
            }
            assert iface_resolver.resolve_iface_for_network(
                "c", "the-net",
            ) is None

    def test_empty_mac_returns_none(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {"net": {"MacAddress": ""}},
                },
            }
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) is None

    def test_inspect_failure_returns_none(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.side_effect = RuntimeError("docker down")
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) is None

    def test_exec_failure_returns_none(self):
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {"net": {"MacAddress": "02:42:00:00:00:01"}},
                },
            }
            dc.exec_in_container.side_effect = RuntimeError("no shell")
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) is None

    def test_mac_not_found_in_ip_link_output(self):
        """Container has the network attached (MAC known) but the iface
        doesn't appear in `ip -o link show` — typically means iproute2
        isn't installed. Return None, log debug, no raise."""
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT") as dc:
            dc.inspect_container.return_value = {
                "NetworkSettings": {
                    "Networks": {"net": {"MacAddress": "02:42:00:00:00:01"}},
                },
            }
            dc.exec_in_container.return_value = (
                _ip_link_output("(no matching iface here)"),
                b"",
            )
            assert iface_resolver.resolve_iface_for_network(
                "c", "net",
            ) is None

    def test_string_inputs_required(self):
        # Defensive: empty strings short-circuit before any Docker call
        assert iface_resolver.resolve_iface_for_network("", "net") is None
        assert iface_resolver.resolve_iface_for_network("c", "") is None


class TestBackwardCompatWrapper:
    """`container_routing.resolve_pcx_iface` must still work — it just
    delegates to the shared helper now."""

    def test_wrapper_delegates(self):
        with mock.patch(
            "localemu.services.ec2.docker.iface_resolver.resolve_iface_for_network",
            return_value="eth7",
        ) as mock_resolve:
            result = resolve_pcx_iface("ctr", "pcx-net")
        assert result == "eth7"
        mock_resolve.assert_called_once_with("ctr", "pcx-net")
