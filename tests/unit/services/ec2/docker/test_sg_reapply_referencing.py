"""Tests for ``reapply_sgs_referencing``.

When a fresh ENI joins an SG (sg-X), every OTHER SG with a rule of
the form "allow ... from sg-X" must have its iptables rebuilt so
the new member's IP lands in the ACCEPT list. Without this hook the
data plane drifts from moto state and late-joiners can't reach
services that allow their SG (the cross-reference E2E found this).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_reapply


def _rule(*, source_group_id: str | None = None,
          source_groups: list[dict] | None = None):
    """SecurityGroupRule double — moto exposes a singular
    ``source_group`` plus a plural ``source_groups`` accessor."""
    return SimpleNamespace(
        source_group=({"GroupId": source_group_id} if source_group_id else {}),
        source_groups=(source_groups or []),
    )


def _sg(sg_id, ingress=None, egress=None):
    return SimpleNamespace(
        id=sg_id,
        ingress_rules=ingress or [],
        egress_rules=egress or [],
    )


class TestReapplyReferencingFindsReferencers:
    def test_singular_source_group_match(self):
        sg_db = _sg("sg-db", ingress=[_rule(source_group_id="sg-web")])
        sg_other = _sg("sg-other", ingress=[_rule(source_group_id="sg-irrelevant")])

        backend = mock.MagicMock()
        backend.describe_security_groups.return_value = [sg_db, sg_other]
        with mock.patch("moto.backends.get_backend",
                        return_value={"000000000000": {"us-east-1": backend}}), \
             mock.patch.object(sg_reapply, "reapply_sg_for_sg_id",
                               return_value=1) as m:
            count = sg_reapply.reapply_sgs_referencing(
                ["sg-web"], "000000000000", "us-east-1",
            )
        assert count == 1
        m.assert_called_once_with("sg-db", "000000000000", "us-east-1")

    def test_plural_source_groups_match(self):
        sg_app = _sg("sg-app", ingress=[
            _rule(source_groups=[{"GroupId": "sg-web"}]),
        ])
        backend = mock.MagicMock()
        backend.describe_security_groups.return_value = [sg_app]
        with mock.patch("moto.backends.get_backend",
                        return_value={"000000000000": {"us-east-1": backend}}), \
             mock.patch.object(sg_reapply, "reapply_sg_for_sg_id",
                               return_value=0) as m:
            sg_reapply.reapply_sgs_referencing(
                ["sg-web"], "000000000000", "us-east-1",
            )
        m.assert_called_once_with("sg-app", "000000000000", "us-east-1")

    def test_egress_referencer_also_caught(self):
        """A cross-ref rule can live in EGRESS too (allow outbound to
        members of sg-X). The reapply must catch those too."""
        sg_egress_ref = _sg(
            "sg-eg", egress=[_rule(source_group_id="sg-web")],
        )
        backend = mock.MagicMock()
        backend.describe_security_groups.return_value = [sg_egress_ref]
        with mock.patch("moto.backends.get_backend",
                        return_value={"000000000000": {"us-east-1": backend}}), \
             mock.patch.object(sg_reapply, "reapply_sg_for_sg_id",
                               return_value=0) as m:
            sg_reapply.reapply_sgs_referencing(
                ["sg-web"], "000000000000", "us-east-1",
            )
        m.assert_called_once_with("sg-eg", "000000000000", "us-east-1")

    def test_no_referencers_returns_zero(self):
        sg_other = _sg(
            "sg-other", ingress=[_rule(source_group_id="sg-totally-unrelated")],
        )
        backend = mock.MagicMock()
        backend.describe_security_groups.return_value = [sg_other]
        with mock.patch("moto.backends.get_backend",
                        return_value={"000000000000": {"us-east-1": backend}}), \
             mock.patch.object(sg_reapply, "reapply_sg_for_sg_id",
                               return_value=0) as m:
            count = sg_reapply.reapply_sgs_referencing(
                ["sg-web"], "000000000000", "us-east-1",
            )
        assert count == 0
        m.assert_not_called()


class TestReapplyReferencingEdgeCases:
    def test_empty_changed_sgs_is_noop(self):
        with mock.patch.object(sg_reapply, "reapply_sg_for_sg_id") as m:
            assert sg_reapply.reapply_sgs_referencing(
                [], "000000000000", "us-east-1",
            ) == 0
        m.assert_not_called()

    def test_dedupes_so_one_sg_reapplied_once_even_with_multiple_match(self):
        """An SG with rules referencing two different changed SGs
        must only be reapplied once."""
        sg_app = _sg("sg-app", ingress=[
            _rule(source_group_id="sg-web"),
            _rule(source_group_id="sg-db"),
        ])
        backend = mock.MagicMock()
        backend.describe_security_groups.return_value = [sg_app]
        with mock.patch("moto.backends.get_backend",
                        return_value={"000000000000": {"us-east-1": backend}}), \
             mock.patch.object(sg_reapply, "reapply_sg_for_sg_id",
                               return_value=0) as m:
            sg_reapply.reapply_sgs_referencing(
                ["sg-web", "sg-db"], "000000000000", "us-east-1",
            )
        assert m.call_count == 1, m.call_args_list

    def test_moto_lookup_failure_swallowed(self):
        with mock.patch("moto.backends.get_backend",
                        side_effect=RuntimeError("moto down")):
            # No raise
            assert sg_reapply.reapply_sgs_referencing(
                ["sg-web"], "000000000000", "us-east-1",
            ) == 0
