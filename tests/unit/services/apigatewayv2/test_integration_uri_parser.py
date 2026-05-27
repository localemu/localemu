"""Regression test for `_extract_lambda_arn_from_integration_uri`.

The apigatewayv2 v2-HTTP-API handler receives an AWS_PROXY integration's
``integration_uri`` in the API Gateway "path" ARN form and must extract the
nested Lambda ARN before calling ``lambda:Invoke``. Passing the full path
ARN directly (which the code did prior to this fix) causes ``Invoke`` to
reject the request with a ValidationException — every HTTP request to the
API then returns 500.
"""

from __future__ import annotations

import pytest

from localemu.services.apigatewayv2.handler import (
    _extract_lambda_arn_from_integration_uri as extract,
)


class TestExtractLambdaArn:
    def test_apigateway_path_form_extracts_nested_arn(self):
        uri = (
            "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
            "arn:aws:lambda:us-east-1:000000000000:function:my-fn"
            "/invocations"
        )
        assert extract(uri) == "arn:aws:lambda:us-east-1:000000000000:function:my-fn"

    def test_apigateway_path_form_with_alias(self):
        uri = (
            "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/"
            "arn:aws:lambda:eu-west-1:123456789012:function:my-fn:PROD"
            "/invocations"
        )
        assert extract(uri) == "arn:aws:lambda:eu-west-1:123456789012:function:my-fn:PROD"

    def test_real_aws_account_preserved(self):
        uri = (
            "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
            "arn:aws:lambda:us-east-1:922706684423:function:le-notes-api"
            "/invocations"
        )
        assert extract(uri) == "arn:aws:lambda:us-east-1:922706684423:function:le-notes-api"

    def test_plain_function_name_is_passthrough(self):
        # lambda:Invoke accepts plain function names; must not be mangled.
        assert extract("my-function") == "my-function"

    def test_bare_lambda_arn_is_passthrough(self):
        arn = "arn:aws:lambda:us-east-1:000000000000:function:my-fn"
        assert extract(arn) == arn

    def test_empty_string_returns_empty(self):
        assert extract("") == ""

    def test_no_functions_marker_returns_unchanged(self):
        # An HTTP_PROXY URI (no /functions/ marker) must pass through unchanged —
        # this code path is only hit for AWS_PROXY, but we guard anyway.
        assert extract("http://example.com/api") == "http://example.com/api"

    @pytest.mark.parametrize("uri", [
        # Lambda alias "LIVE"
        "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/"
        "arn:aws:lambda:us-west-2:111111111111:function:worker:LIVE/invocations",
        # Cross-account
        "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
        "arn:aws:lambda:us-east-1:999999999999:function:shared-fn/invocations",
    ])
    def test_various_realistic_forms(self, uri):
        result = extract(uri)
        assert result.startswith("arn:aws:lambda:"), \
            f"expected a Lambda ARN, got {result!r}"
        assert "/invocations" not in result, \
            f"/invocations suffix must be stripped, got {result!r}"
        assert "/functions/" not in result, \
            f"apigateway path prefix must be stripped, got {result!r}"
