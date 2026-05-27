"""Regression: custom host-addressing rules path in ServiceRouter.

The lambda-url and s3-website host suffix dispatch used to subscript a
``ServiceModelIdentifier`` NamedTuple with ``[0]``, which unpacks the
``name`` field as a plain ``str`` and then attempted ``.name`` /
``.protocol`` attribute access on it — crashing every request that
matched the second host-addressing dispatcher branch (i.e. the AWS-style
flow that begins at the "host" lookup tier of the router).
"""

from __future__ import annotations

import pytest

from localemu.aws.protocol.service_router import custom_host_addressing_rules
from localemu.aws.spec import ServiceModelIdentifier


class TestCustomHostAddressingShape:
    @pytest.mark.parametrize(
        "host,expected_name",
        [
            ("abc123.lambda-url.us-east-1.localhost.localemu.cloud", "lambda"),
            ("my-bucket.s3-website.us-west-2.amazonaws.com", "s3"),
        ],
    )
    def test_returns_single_service_model_identifier(self, host, expected_name):
        result = custom_host_addressing_rules(host)
        assert result is not None
        assert isinstance(result, ServiceModelIdentifier)
        assert result.name == expected_name

    def test_unknown_host_returns_none(self):
        assert custom_host_addressing_rules("sqs.us-east-1.amazonaws.com") is None


class TestNoSubscriptOnNamedTuple:
    """The router used to do ``candidate = custom_host_match[0]`` and
    then ``candidate.name`` — that path can only have been exercised if
    the integer-subscript shape was somehow correct, which it never was.
    Confirm by snapshotting the source so we never regress to the broken
    form."""

    def test_router_code_no_longer_subscripts_custom_host_match(self):
        from pathlib import Path

        src = Path(
            "src/localemu/aws/protocol/service_router.py"
        ).read_text()
        # Strip comments so the explanatory string we left at the fix
        # site doesn't trip the guard.
        non_comment = "\n".join(
            line for line in src.split("\n")
            if not line.lstrip().startswith("#")
        )
        assert "custom_host_match[0]" not in non_comment, (
            "Reintroducing custom_host_match[0] would re-break every "
            "request that lands in the host-addressing branch of the "
            "router — it unpacks the NamedTuple's name field as a "
            "plain str and the subsequent .name / .protocol access crashes."
        )
