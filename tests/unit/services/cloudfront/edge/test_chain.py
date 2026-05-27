"""Unit tests for the Lambda@Edge chain runner.

The actual Lambda invocation is stubbed — we're exercising the
control-flow: association selection, short-circuit propagation,
request/response mutation application. The real Lambda runtime is
covered by the Phase 3 E2E suite.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch as mock_patch

import pytest

from localemu.services.cloudfront.edge import chain
from localemu.services.cloudfront.edge.event_builder import (
    EVENT_ORIGIN_REQUEST,
    EVENT_ORIGIN_RESPONSE,
    EVENT_VIEWER_REQUEST,
    EVENT_VIEWER_RESPONSE,
)


def _behaviour(*associations_in: dict):
    """Build a moto-shape cache behaviour stand-in."""
    objs = []
    for a in associations_in:
        objs.append(SimpleNamespace(
            event_type=a["EventType"],
            arn=a["LambdaFunctionARN"],
            include_body=a.get("IncludeBody", False),
        ))
    return SimpleNamespace(lambda_function_associations=objs)


class TestAssociationsFor:
    def test_filters_by_event_type(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
            {"EventType": "origin-response", "LambdaFunctionARN": "arn:o"},
        )
        assert chain.associations_for(b, "viewer-request") == [
            {"arn": "arn:v", "include_body": False}
        ]

    def test_empty_for_no_matches(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
        )
        assert chain.associations_for(b, "viewer-response") == []

    def test_accepts_dict_shape(self):
        b = {"LambdaFunctionAssociations": {"Items": [
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
        ]}}
        assert chain.associations_for(b, "viewer-request") == [
            {"arn": "arn:v", "include_body": False}
        ]

    def test_none_behaviour_is_noop(self):
        assert chain.associations_for(None, "viewer-request") == []


class TestRequestChain:
    def setup_method(self):
        self.state = chain.RequestState(
            method="GET", uri="/original", querystring="", headers={"Host": "cdn"},
        )

    def test_no_associations_is_noop(self):
        b = _behaviour()
        result = chain.run_request_chain(
            event_type=EVENT_VIEWER_REQUEST,
            cache_behavior=b, distribution_id="E1", request_id="r1",
            request=self.state,
        )
        assert result is None
        assert self.state.uri == "/original"

    def test_short_circuit_returns_response(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
        )
        fake_output = {
            "response": {"status": "302", "body": "", "headers": {}},
        }
        with mock_patch.object(chain, "_invoke", return_value=fake_output):
            result = chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.state,
            )
        assert isinstance(result, chain.ShortCircuit)
        assert result.status == 302

    def test_request_mutation_applies_to_state(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
        )
        fake_output = {
            "request": {
                "method": "GET",
                "uri": "/rewritten",
                "querystring": "key=val",
                "headers": {"x-custom": [{"key": "X-Custom", "value": "1"}]},
            },
        }
        with mock_patch.object(chain, "_invoke", return_value=fake_output):
            result = chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.state,
            )
        assert result is None
        assert self.state.uri == "/rewritten"
        assert self.state.querystring == "key=val"
        assert self.state.headers == {"X-Custom": "1"}

    def test_multiple_associations_run_in_order(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:first"},
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:second"},
        )
        calls: list[str] = []

        def _fake_invoke(arn, _dist, _event):
            calls.append(arn)
            if arn == "arn:first":
                return {"request": {"uri": "/mid", "headers": {}}}
            return {"request": {"uri": "/final", "headers": {}}}

        with mock_patch.object(chain, "_invoke", side_effect=_fake_invoke):
            chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.state,
            )
        assert calls == ["arn:first", "arn:second"]
        assert self.state.uri == "/final"

    def test_short_circuit_stops_subsequent_associations(self):
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:first"},
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:second"},
        )
        calls: list[str] = []

        def _fake(arn, _d, _e):
            calls.append(arn)
            return {"response": {"status": "403", "headers": {}, "body": ""}}

        with mock_patch.object(chain, "_invoke", side_effect=_fake):
            result = chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.state,
            )
        assert isinstance(result, chain.ShortCircuit)
        assert calls == ["arn:first"]  # second never ran

    def test_invoke_failure_continues_chain(self):
        """A broken edge function must not 500 the entire data-plane
        request. Log and continue."""
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:broken"},
        )
        with mock_patch.object(chain, "_invoke", return_value=None):
            result = chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.state,
            )
        assert result is None
        assert self.state.uri == "/original"


class TestResponseChain:
    def setup_method(self):
        self.req = chain.RequestState(
            method="GET", uri="/", querystring="", headers={},
        )
        self.resp = chain.ResponseState(
            status=200, headers={"Content-Type": "text/plain"}, body=b"ok",
        )

    def test_response_mutation(self):
        b = _behaviour(
            {"EventType": "viewer-response", "LambdaFunctionARN": "arn:r"},
        )
        fake = {"response": {"status": "201", "headers": {
            "x-powered-by": [{"key": "X-Powered-By", "value": "LocalEmu"}],
        }}}
        with mock_patch.object(chain, "_invoke", return_value=fake):
            chain.run_response_chain(
                event_type=EVENT_VIEWER_RESPONSE,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=self.req, response=self.resp,
            )
        assert self.resp.status == 201
        assert self.resp.headers == {"X-Powered-By": "LocalEmu"}

    def test_no_associations_is_noop(self):
        b = _behaviour()
        chain.run_response_chain(
            event_type=EVENT_VIEWER_RESPONSE,
            cache_behavior=b, distribution_id="E1", request_id="r1",
            request=self.req, response=self.resp,
        )
        assert self.resp.status == 200
        assert self.resp.body == b"ok"


class TestUnwrapCfOutput:
    def test_full_envelope(self):
        wrapped = {"Records": [{"cf": {"request": {"uri": "/x"}}}]}
        assert chain._unwrap_cf_output(wrapped) == {"request": {"uri": "/x"}}

    def test_bare_cf_dict(self):
        bare = {"request": {"uri": "/x"}}
        assert chain._unwrap_cf_output(bare) == {"request": {"uri": "/x"}}

    def test_non_dict_returns_empty(self):
        assert chain._unwrap_cf_output("garbage") == {}


class TestEnvSwitch:
    def test_disabled_env_skips_chain(self, monkeypatch):
        monkeypatch.setenv("CLOUDFRONT_LAMBDA_EDGE_ENABLE", "0")
        b = _behaviour(
            {"EventType": "viewer-request", "LambdaFunctionARN": "arn:v"},
        )
        state = chain.RequestState(method="GET", uri="/", querystring="", headers={})
        with mock_patch.object(chain, "_invoke") as m:
            chain.run_request_chain(
                event_type=EVENT_VIEWER_REQUEST,
                cache_behavior=b, distribution_id="E1", request_id="r1",
                request=state,
            )
        m.assert_not_called()
