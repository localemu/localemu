"""Regression test: StartLogging/StopLogging/DeleteTrail/*EventSelectors/
*InsightSelectors accept BOTH the bare trail name AND the full trail ARN
as the ``Name`` / ``TrailName`` parameter.

Real AWS accepts either form, and Terraform's ``aws_cloudtrail`` resource
passes the full ARN. Moto's underlying methods do raw ``self.trails[name]``
dict lookups keyed by bare name, KeyError-ing when handed an ARN. Without
the interceptor, every Terraform deploy hangs on ``start_logging`` retry.
"""

from __future__ import annotations

import pytest

from localemu.services.cloudtrail.provider import _normalize_trail_name


class TestNormalizeTrailName:
    def test_bare_name_is_returned_as_is(self):
        assert _normalize_trail_name("my-trail") == "my-trail"

    def test_full_arn_is_stripped_to_name(self):
        arn = "arn:aws:cloudtrail:us-east-1:000000000000:trail/my-trail"
        assert _normalize_trail_name(arn) == "my-trail"

    def test_aws_cn_partition_arn(self):
        arn = "arn:aws-cn:cloudtrail:cn-north-1:123456789012:trail/tr"
        assert _normalize_trail_name(arn) == "tr"

    def test_name_with_dots_dashes_underscores(self):
        arn = "arn:aws:cloudtrail:us-east-1:000000000000:trail/a.b-c_d"
        assert _normalize_trail_name(arn) == "a.b-c_d"

    def test_empty_or_none(self):
        assert _normalize_trail_name("") == ""
        assert _normalize_trail_name(None) == ""

    def test_arn_without_trail_marker_is_returned_as_is(self):
        # Malformed — not our job to fix, but don't crash.
        assert _normalize_trail_name("arn:aws:cloudtrail:...:foo") == \
            "arn:aws:cloudtrail:...:foo"


class TestDispatchWiring:
    """The five ops that need ARN normalisation must be in ``_INTERCEPTED_OPS``."""

    @pytest.mark.parametrize("op", [
        "StartLogging", "StopLogging", "DeleteTrail",
        "PutEventSelectors", "GetEventSelectors",
        "PutInsightSelectors", "GetInsightSelectors",
    ])
    def test_op_is_intercepted(self, op):
        from localemu.services.cloudtrail.provider import _INTERCEPTED_OPS
        assert op in _INTERCEPTED_OPS, (
            f"{op} must be intercepted so ARN-valued Name/TrailName is "
            f"normalised before reaching moto's keyed-by-name dict lookup."
        )
