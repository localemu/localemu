"""Tests for nacl_enforcer._build_iptables_rules.

Guards the iptables rule-building from regressing on:

  - Reading moto's flat ``port_range_from`` / ``port_range_to`` attrs
    (moto does NOT expose a composite ``port_range`` attribute on
    NetworkAclEntry; the enforcer must look up the flat fields).
  - Honoring rule_action / egress / protocol / cidr_block.
  - Always closing each chain with a default DROP (the stateless
    deny-all that NACLs imply at rule 32767).

The previous code did ``getattr(entry, "port_range", None)`` and
silently dropped the port filter when moto returned None, producing
``-p tcp -j ACCEPT`` for what should have been
``-p tcp --dport 19090 -j ACCEPT``. That bug was found by the
NACL-stateless E2E.
"""
from __future__ import annotations

from types import SimpleNamespace

from localemu.services.ec2.docker.nacl_enforcer import _build_iptables_rules


def _entry(**kw):
    """Build a moto-shaped NetworkAclEntry double."""
    defaults = dict(
        rule_number=100, protocol="-1", rule_action="allow",
        egress=False, cidr_block="0.0.0.0/0",
        port_range_from=None, port_range_to=None,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestPortRangeFromMotoFlatAttrs:
    def test_single_port_tcp_ingress_uses_dport(self):
        entries = [_entry(
            protocol="6", port_range_from=22, port_range_to=22, egress=False,
        )]
        rules = _build_iptables_rules(entries, egress=False)
        assert any("--dport 22" in r for r in rules), rules
        assert all("--dport" not in r or "22" in r for r in rules)

    def test_port_range_tcp_ingress_uses_range_dport(self):
        entries = [_entry(
            protocol="6", port_range_from=32768, port_range_to=60999,
            egress=False,
        )]
        rules = _build_iptables_rules(entries, egress=False)
        assert any("--dport 32768:60999" in r for r in rules), rules

    def test_udp_port_range_emits_udp_proto(self):
        entries = [_entry(
            protocol="17", port_range_from=53, port_range_to=53, egress=True,
        )]
        rules = _build_iptables_rules(entries, egress=True)
        assert any("-p udp" in r and "--dport 53" in r for r in rules), rules

    def test_proto_all_skips_dport_even_with_ports(self):
        entries = [_entry(
            protocol="-1", port_range_from=22, port_range_to=22, egress=False,
        )]
        rules = _build_iptables_rules(entries, egress=False)
        assert all("--dport" not in r for r in rules), rules

    def test_falls_back_to_composite_port_range_dict(self):
        """Older fixture shape — port_range as a {from,to} dict.
        Kept for forward compatibility with non-moto entry sources."""
        e = _entry(protocol="6", egress=False)
        e.port_range = {"from": 80, "to": 80}
        rules = _build_iptables_rules([e], egress=False)
        assert any("--dport 80" in r for r in rules), rules


class TestActionAndDirection:
    def test_deny_rule_emits_drop(self):
        entries = [_entry(rule_action="deny", egress=True)]
        rules = _build_iptables_rules(entries, egress=True)
        assert any("-j DROP" in r for r in rules)

    def test_ingress_uses_source_filter(self):
        entries = [_entry(
            cidr_block="10.0.0.0/24", egress=False,
        )]
        rules = _build_iptables_rules(entries, egress=False)
        assert any("-s 10.0.0.0/24" in r for r in rules), rules

    def test_egress_uses_destination_filter(self):
        entries = [_entry(
            cidr_block="172.16.0.0/12", egress=True,
        )]
        rules = _build_iptables_rules(entries, egress=True)
        assert any("-d 172.16.0.0/12" in r for r in rules), rules

    def test_chain_always_ends_in_default_drop(self):
        """Stateless default-deny: every chain ends with -j DROP."""
        # Empty entries → only the default DROP exists
        for direction in (False, True):
            rules = _build_iptables_rules([], egress=direction)
            chain = "NACL_OUT" if direction else "NACL_IN"
            assert rules[-1] == f"-A {chain} -j DROP", rules


class TestRuleOrdering:
    def test_lower_rule_numbers_evaluated_first(self):
        """AWS NACL contract: lowest rule number wins (first match).
        iptables evaluates rules in insertion order, so the builder
        must emit lower-numbered rules earlier."""
        entries = [
            _entry(rule_number=200, rule_action="allow", egress=True),
            _entry(rule_number=100, rule_action="deny", egress=True),
        ]
        rules = _build_iptables_rules(entries, egress=True)
        deny_idx = next(i for i, r in enumerate(rules) if "DROP" in r and "NACL_OUT" in r and "0.0.0.0/0" in r)
        allow_idx = next(i for i, r in enumerate(rules) if "ACCEPT" in r and "NACL_OUT" in r)
        assert deny_idx < allow_idx, rules

    def test_rule_32767_implicit_default_skipped(self):
        """Rule 32767 is moto's representation of the implicit
        deny-all sentinel; the builder must not emit it (the chain's
        final -j DROP already encodes the same behavior)."""
        entries = [_entry(rule_number=32767, rule_action="deny", egress=False)]
        rules = _build_iptables_rules(entries, egress=False)
        # Only the trailing default DROP should appear
        assert rules == ["-A NACL_IN -j DROP"]
