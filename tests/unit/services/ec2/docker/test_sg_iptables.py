"""Unit tests for the Security Group iptables applier.

The contract we enforce here:

    apply_sg_to_container returns True only on full success. On any
    failure path (iptables can't be installed, moto rules can't be
    built, the apply script errors) it RAISES so the caller
    (vm_manager) must abort RunInstances. There is no silent
    fail-closed fallback: a "default DROP" rule is itself an iptables
    command, so if iptables is unavailable we cannot honestly
    fail-closed. Returning a "running" instance whose SG is silently
    ignored is the bug this contract exists to prevent.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_iptables
from localemu.utils.container_utils.container_client import ContainerException


class TestProbeIptables:
    def test_probe_success(self):
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT") as dc:
            dc.exec_in_container.return_value = (b"", b"")
            assert sg_iptables._probe_iptables("ctr") is True
            dc.exec_in_container.assert_called_once()

    def test_probe_failure_raises_container_exception(self):
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT") as dc:
            dc.exec_in_container.side_effect = ContainerException("iptables: not found")
            assert sg_iptables._probe_iptables("ctr") is False


class TestBuildChainRules:
    """Verify the iptables argument-builder translates moto SG rules correctly."""

    def _rule(self, *, protocol="6", from_port=22, to_port=22, cidr="10.0.0.0/24"):
        r = mock.Mock()
        r.ip_protocol = protocol
        r.from_port = from_port
        r.to_port = to_port
        r.ip_ranges = [{"CidrIp": cidr}] if cidr else []
        r.source_groups = []
        # moto's SecurityGroupRule has singular ip_range/source_group too;
        # the builder reads both, so pin them to empty here.
        r.ip_range = {}
        r.source_group = {}
        return r

    def test_tcp_single_port_ingress(self):
        rules = sg_iptables._build_chain_rules(
            [self._rule()], chain="SG_IN", is_egress=False,
        )
        body = " || ".join(rules)
        assert "-p tcp" in body
        assert "-s 10.0.0.0/24" in body
        assert "--dport 22" in body
        assert "-j ACCEPT" in body
        assert rules[-1] == "-A SG_IN -j DROP"

    def test_tcp_port_range(self):
        rules = sg_iptables._build_chain_rules(
            [self._rule(from_port=80, to_port=8080)],
            chain="SG_IN", is_egress=False,
        )
        assert any("--dport 80:8080" in r for r in rules)

    def test_all_protocols(self):
        r = self._rule(protocol="-1", from_port=None, to_port=None, cidr="0.0.0.0/0")
        rules = sg_iptables._build_chain_rules([r], chain="SG_IN", is_egress=False)
        assert any("-s 0.0.0.0/0 -j ACCEPT" in x for x in rules)
        # no -p flag for protocol -1 because the rule is allow-all
        matched = [x for x in rules if "-s 0.0.0.0/0 -j ACCEPT" in x]
        assert not any("-p " in x for x in matched)

    def test_egress_uses_destination(self):
        rules = sg_iptables._build_chain_rules(
            [self._rule(cidr="1.2.3.0/24")],
            chain="SG_OUT", is_egress=True,
        )
        body = " ".join(rules)
        assert "-d 1.2.3.0/24" in body
        # egress rules must not carry -s <cidr>
        for r in rules:
            if "ACCEPT" in r:
                # loopback lo rule doesn't use -s either; fine
                assert "-s " not in r

    def test_udp_protocol_translation(self):
        rules = sg_iptables._build_chain_rules(
            [self._rule(protocol="17", from_port=53, to_port=53)],
            chain="SG_IN", is_egress=False,
        )
        assert any("-p udp" in r and "--dport 53" in r for r in rules)

    def test_no_cidr_defaults_to_all(self):
        r = self._rule()
        r.ip_ranges = []  # neither CIDR nor source_groups
        rules = sg_iptables._build_chain_rules(
            [r], chain="SG_IN", is_egress=False,
        )
        body = " ".join(rules)
        assert "0.0.0.0/0" in body


class TestApplySgToContainer:
    """The critical fail-closed / fail-loud contract."""

    def _patch(self, *, probe_ok=True, apply_ok=True, rules_raise=False, emergency_ok=True):
        """Build a mock DOCKER_CLIENT whose exec_in_container call-sequence
        reflects what apply_sg_to_container does.
        """
        calls: list = []
        side_effects: list = []
        if rules_raise:
            # probe happens first, then _collect_rules raises before any
            # further exec. emergency default-drop then runs.
            side_effects.append((b"", b"") if probe_ok else ContainerException("no iptables"))
            side_effects.append((b"", b"") if emergency_ok else ContainerException("emergency failed"))
        else:
            side_effects.append((b"", b"") if probe_ok else ContainerException("no iptables"))
            if probe_ok:
                side_effects.append(
                    (b"", b"") if apply_ok else ContainerException("rule exec failed"),
                )
                if not apply_ok:
                    side_effects.append(
                        (b"", b"") if emergency_ok else ContainerException("emergency failed"),
                    )
            else:
                side_effects.append(
                    (b"", b"") if emergency_ok else ContainerException("emergency failed"),
                )
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = side_effects
        return dc, calls

    def test_happy_path_returns_true(self):
        dc, _ = self._patch()
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT", dc), \
             mock.patch.object(
                 sg_iptables, "_collect_rules",
                 return_value=(["-A SG_IN -j ACCEPT", "-A SG_IN -j DROP"],
                               ["-A SG_OUT -j ACCEPT", "-A SG_OUT -j DROP"]),
             ):
            ok = sg_iptables.apply_sg_to_container(
                "ctr", ["sg-123"], "000000000000", "us-east-1",
            )
        assert ok is True
        # Probe + apply = 2 exec calls
        assert dc.exec_in_container.call_count == 2
        # The second call (apply) must carry both chain's rules
        apply_cmd = dc.exec_in_container.call_args_list[1][0][1]
        assert apply_cmd[0] == "sh"
        apply_script = apply_cmd[2]
        assert "iptables -F SG_IN" in apply_script
        assert "iptables -F SG_OUT" in apply_script
        assert "iptables -A SG_IN -j ACCEPT" in apply_script
        assert "iptables -A SG_OUT -j ACCEPT" in apply_script
        assert "iptables -C INPUT -j SG_IN" in apply_script
        assert "iptables -C OUTPUT -j SG_OUT" in apply_script

    def test_ensure_iptables_fail_raises(self):
        """If iptables truly cannot be installed in the container,
        apply_sg_to_container must raise -- there is no honest
        fail-closed mode without iptables, and lying about
        ``fail-closed DROP`` while the container actually runs
        Docker's default ACCEPT is the bug we're killing."""
        dc = mock.MagicMock()
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT", dc), \
             mock.patch.object(
                 sg_iptables, "ensure_iptables_in_container",
                 return_value=False,
             ):
            with pytest.raises(RuntimeError, match="iptables"):
                sg_iptables.apply_sg_to_container(
                    "ctr", ["sg-123"], "000000000000", "us-east-1",
                )

    def test_moto_build_raises_propagates(self):
        """When ``_collect_rules`` fails (moto unreachable, malformed
        SG, etc.) apply_sg_to_container must raise with the underlying
        cause -- no silent fail-closed fallback."""
        dc = mock.MagicMock()
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT", dc), \
             mock.patch.object(
                 sg_iptables, "ensure_iptables_in_container",
                 return_value=True,
             ), \
             mock.patch.object(
                 sg_iptables, "_collect_rules",
                 side_effect=RuntimeError("moto unavailable"),
             ):
            with pytest.raises(RuntimeError, match="moto unavailable"):
                sg_iptables.apply_sg_to_container(
                    "ctr", ["sg-123"], "000000000000", "us-east-1",
                )

    def test_apply_exec_fails_raises(self):
        """When the iptables apply script fails inside the container,
        apply_sg_to_container must raise -- callers (vm_manager)
        must see this so they can abort RunInstances rather than ship
        a lying instance."""
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = ContainerException("rule exec failed")
        with mock.patch.object(sg_iptables, "DOCKER_CLIENT", dc), \
             mock.patch.object(
                 sg_iptables, "ensure_iptables_in_container",
                 return_value=True,
             ), \
             mock.patch.object(
                 sg_iptables, "_collect_rules",
                 return_value=([], []),
             ):
            with pytest.raises(RuntimeError, match="SG apply script failed"):
                sg_iptables.apply_sg_to_container(
                    "ctr", ["sg-123"], "000000000000", "us-east-1",
                )


class TestCollectRules:
    """Verify _collect_rules pulls ingress/egress from moto and routes them."""

    def test_collects_from_multiple_sgs(self):
        sg1 = mock.Mock()
        sg1.ingress_rules = []
        sg1.egress_rules = []
        sg2 = mock.Mock()
        sg2.ingress_rules = []
        sg2.egress_rules = []

        backend = mock.Mock()
        backend.groups = {"sg-1": sg1, "sg-2": sg2}

        fake_moto = mock.MagicMock()
        fake_moto.get_backend.return_value = {"000000000000": {"us-east-1": backend}}

        with mock.patch.dict(
            "sys.modules", {"moto.backends": fake_moto},
        ):
            in_rules, out_rules = sg_iptables._collect_rules(
                ["sg-1", "sg-2"], "000000000000", "us-east-1",
            )
        # Empty SG rules still produce stateful + loopback + DNS + final DROP
        assert any("ESTABLISHED,RELATED" in r for r in in_rules)
        assert any("-j DROP" in r for r in in_rules)
        assert any("ESTABLISHED,RELATED" in r for r in out_rules)
        assert any("-j DROP" in r for r in out_rules)
