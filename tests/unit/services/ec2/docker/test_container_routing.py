"""Unit tests for in-container peering route programming."""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import container_routing as cr
from localemu.services.ec2.docker import iface_resolver


class TestResolvePcxIface:
    """``resolve_pcx_iface`` is now a thin wrapper around
    ``iface_resolver.resolve_iface_for_network``. The mock has to patch
    DOCKER_CLIENT at the resolver module, not at container_routing."""

    def test_finds_iface_by_mac(self):
        dc = mock.MagicMock()
        dc.inspect_container.return_value = {
            "NetworkSettings": {
                "Networks": {
                    "localemu-pcx-x": {"MacAddress": "02:42:AC:14:00:02"},
                },
            },
        }
        # ip -o link output shape
        dc.exec_in_container.return_value = (
            b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            b"2: eth0@if30: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP link/ether 02:42:c0:a8:60:02 brd ff:ff:ff:ff:ff:ff\n"
            b"3: eth1@if31: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP link/ether 02:42:ac:14:00:02 brd ff:ff:ff:ff:ff:ff\n",
            b"",
        )
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT", dc):
            iface = cr.resolve_pcx_iface("c1", "localemu-pcx-x")
        assert iface == "eth1"

    def test_missing_network_returns_none(self):
        dc = mock.MagicMock()
        dc.inspect_container.return_value = {"NetworkSettings": {"Networks": {}}}
        with mock.patch.object(iface_resolver, "DOCKER_CLIENT", dc):
            assert cr.resolve_pcx_iface("c1", "localemu-pcx-x") is None


class TestProgramPeeringRoutes:
    def test_full_programming_alias_snat_and_dnat(self):
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            ok = cr.program_peering_routes(
                "c1", "eth2",
                own_vpc_ip="10.80.0.3", own_pcx_ip="172.18.0.2",
                peer_instances=[("10.81.0.3", "172.18.0.3")],
            )
        assert ok is True
        scripts = [
            call.args[1][2] for call in dc.exec_in_container.call_args_list
        ]
        # Alias on pcx for own VPC IP
        assert any("ip addr add 10.80.0.3/32 dev eth2" in s for s in scripts)
        # Blanket SNAT on pcx egress
        assert any(
            "POSTROUTING -o eth2 -j SNAT --to-source 172.18.0.2" in s
            for s in scripts
        )
        # DNAT per peer instance to its pcx IP
        assert any(
            "OUTPUT -d 10.81.0.3/32 -j DNAT --to-destination 172.18.0.3" in s
            for s in scripts
        )
        # /32 route to peer's pcx
        assert any(
            "ip route replace 10.81.0.3/32 via 172.18.0.3 dev eth2" in s
            for s in scripts
        )

    def test_empty_peer_list_still_aliases_and_snats(self):
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            ok = cr.program_peering_routes(
                "c1", "eth2",
                own_vpc_ip="10.80.0.3", own_pcx_ip="172.18.0.2",
                peer_instances=[],
            )
        assert ok is True
        scripts = [
            call.args[1][2] for call in dc.exec_in_container.call_args_list
        ]
        assert any("ip addr add 10.80.0.3/32 dev eth2" in s for s in scripts)
        assert any("SNAT --to-source 172.18.0.2" in s for s in scripts)

    def test_missing_args_noop(self):
        dc = mock.MagicMock()
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            assert cr.add_peer_host_route("", "eth2", "10.1.0.2", "172.18.0.2") is False
            assert cr.add_snat_for_pcx("c", "", "172.18.0.2") is False
        dc.exec_in_container.assert_not_called()


class TestUnprogramPeeringRoutes:
    def test_issues_del_commands(self):
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            cr.unprogram_peering_routes(
                "c1", "eth2", "10.80.0.3",
                peer_vpc_ips=["10.81.0.3"],
            )
        script = dc.exec_in_container.call_args.args[1][2]
        assert "ip route del 10.81.0.3/32 dev eth2" in script
        assert "ip addr del 10.80.0.3/32 dev eth2" in script

    def test_tolerates_errors(self):
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = RuntimeError("iface gone")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            cr.unprogram_peering_routes(
                "c1", "eth2", "10.80.0.3", peer_vpc_ips=["10.81.0.3"],
            )


class TestSnatHelpers:
    def test_add_snat_uses_check_then_add(self):
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            ok = cr.add_snat_for_pcx("c1", "eth2", "172.18.0.2")
        assert ok is True
        script = dc.exec_in_container.call_args.args[1][2]
        assert "iptables -t nat -C POSTROUTING" in script
        assert "iptables -t nat -A POSTROUTING" in script
        assert "SNAT --to-source 172.18.0.2" in script

    def test_del_snat_issues_delete(self):
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")
        with mock.patch.object(cr, "DOCKER_CLIENT", dc):
            cr.del_snat_for_pcx("c1", "eth2", "172.18.0.2")
        script = dc.exec_in_container.call_args.args[1][2]
        assert "iptables -t nat -D POSTROUTING" in script
