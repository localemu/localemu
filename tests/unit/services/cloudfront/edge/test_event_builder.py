"""Unit tests for the Lambda@Edge event builder."""

from __future__ import annotations

import base64
import json

import pytest

from localemu.services.cloudfront.edge import event_builder as eb


class TestHeadersToCF:
    def test_basic_conversion(self):
        out = eb._headers_to_cf({"Content-Type": "text/html", "X-Custom": "v"})
        assert out == {
            "content-type": [{"key": "Content-Type", "value": "text/html"}],
            "x-custom": [{"key": "X-Custom", "value": "v"}],
        }

    def test_empty_input(self):
        assert eb._headers_to_cf(None) == {}
        assert eb._headers_to_cf({}) == {}


class TestHeadersFromCF:
    def test_basic_roundtrip(self):
        cf = {"content-type": [{"key": "Content-Type", "value": "text/html"}]}
        assert eb._headers_from_cf(cf) == {"Content-Type": "text/html"}

    def test_multiple_values_joined(self):
        cf = {"set-cookie": [
            {"key": "Set-Cookie", "value": "a=1"},
            {"key": "Set-Cookie", "value": "b=2"},
        ]}
        assert eb._headers_from_cf(cf) == {"Set-Cookie": "a=1,b=2"}

    def test_empty(self):
        assert eb._headers_from_cf(None) == {}


class TestBuildRequestEvent:
    def test_produces_canonical_shape(self):
        event = eb.build_request_event(
            event_type=eb.EVENT_VIEWER_REQUEST,
            distribution_id="E1ABC",
            request_id="req-1",
            method="get",
            uri="/foo",
            querystring="a=1",
            headers={"Host": "cdn.example.com"},
            client_ip="1.2.3.4",
        )
        cf = event["Records"][0]["cf"]
        assert cf["config"]["distributionId"] == "E1ABC"
        assert cf["config"]["eventType"] == "viewer-request"
        assert cf["config"]["requestId"] == "req-1"
        assert cf["request"]["method"] == "GET"  # normalised to uppercase
        assert cf["request"]["uri"] == "/foo"
        assert cf["request"]["clientIp"] == "1.2.3.4"
        assert cf["request"]["headers"]["host"] == [
            {"key": "Host", "value": "cdn.example.com"}
        ]

    def test_prepends_slash_to_uri(self):
        event = eb.build_request_event(
            event_type=eb.EVENT_ORIGIN_REQUEST,
            distribution_id="E1", request_id="r", method="GET",
            uri="no-slash", querystring="", headers={},
        )
        assert event["Records"][0]["cf"]["request"]["uri"] == "/no-slash"

    def test_rejects_response_event_type(self):
        with pytest.raises(ValueError, match="not a request-stage"):
            eb.build_request_event(
                event_type=eb.EVENT_VIEWER_RESPONSE,
                distribution_id="E1", request_id="r", method="GET",
                uri="/", querystring="", headers={},
            )

    def test_body_included_when_requested_text(self):
        event = eb.build_request_event(
            event_type=eb.EVENT_VIEWER_REQUEST,
            distribution_id="E1", request_id="r", method="POST",
            uri="/submit", querystring="", headers={},
            body=b"hello world", include_body=True,
        )
        body = event["Records"][0]["cf"]["request"]["body"]
        assert body["data"] == "hello world"
        assert body["encoding"] == "text"

    def test_body_base64_when_binary(self):
        event = eb.build_request_event(
            event_type=eb.EVENT_VIEWER_REQUEST,
            distribution_id="E1", request_id="r", method="POST",
            uri="/submit", querystring="", headers={},
            body=b"\xff\xfe\x00\x01", include_body=True,
        )
        body = event["Records"][0]["cf"]["request"]["body"]
        assert body["encoding"] == "base64"
        assert base64.b64decode(body["data"]) == b"\xff\xfe\x00\x01"

    def test_body_skipped_when_include_false(self):
        event = eb.build_request_event(
            event_type=eb.EVENT_VIEWER_REQUEST,
            distribution_id="E1", request_id="r", method="POST",
            uri="/submit", querystring="", headers={},
            body=b"x", include_body=False,
        )
        assert "body" not in event["Records"][0]["cf"]["request"]

    def test_oversize_raises_value_error(self):
        huge = b"x" * (eb.MAX_BODY_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds"):
            eb.build_request_event(
                event_type=eb.EVENT_VIEWER_REQUEST,
                distribution_id="E1", request_id="r", method="POST",
                uri="/", querystring="", headers={},
                body=huge, include_body=True,
            )


class TestBuildResponseEvent:
    def test_produces_request_and_response(self):
        event = eb.build_response_event(
            event_type=eb.EVENT_VIEWER_RESPONSE,
            distribution_id="E1", request_id="r", method="GET",
            uri="/a", querystring="q=1",
            request_headers={"Host": "cdn"},
            status=200, status_description="OK",
            response_headers={"Content-Type": "text/html"},
        )
        cf = event["Records"][0]["cf"]
        assert cf["config"]["eventType"] == "viewer-response"
        assert cf["request"]["uri"] == "/a"
        assert cf["response"]["status"] == "200"
        assert cf["response"]["headers"]["content-type"] == [
            {"key": "Content-Type", "value": "text/html"}
        ]

    def test_status_description_defaulted(self):
        event = eb.build_response_event(
            event_type=eb.EVENT_ORIGIN_RESPONSE,
            distribution_id="E1", request_id="r", method="GET",
            uri="/", querystring="", request_headers={},
            status=404, status_description=None,
            response_headers={},
        )
        assert event["Records"][0]["cf"]["response"]["statusDescription"] == "Not Found"

    def test_rejects_request_event_type(self):
        with pytest.raises(ValueError, match="not a response-stage"):
            eb.build_response_event(
                event_type=eb.EVENT_VIEWER_REQUEST,
                distribution_id="E1", request_id="r", method="GET",
                uri="/", querystring="", request_headers={},
                status=200, status_description=None, response_headers={},
            )


class TestParseRequestStageOutput:
    def test_short_circuit_with_response(self):
        decision = eb.parse_request_stage_output({
            "response": {"status": "302", "headers": {}, "body": ""},
        })
        assert decision.kind == "short_circuit"
        assert decision.response["status"] == "302"

    def test_mutation_with_request(self):
        decision = eb.parse_request_stage_output({
            "request": {"uri": "/rewritten", "headers": {}},
        })
        assert decision.kind == "mutate_request"
        assert decision.request["uri"] == "/rewritten"

    def test_empty_dict_is_continue_unchanged(self):
        assert eb.parse_request_stage_output({}).kind == "continue-unchanged"

    def test_non_dict_is_continue_unchanged(self):
        assert eb.parse_request_stage_output("garbage").kind == "continue-unchanged"
        assert eb.parse_request_stage_output(None).kind == "continue-unchanged"

    def test_bare_response_is_short_circuit(self):
        """AWS Lambda@Edge contract: user returns the bare response
        dict (with ``status``), NOT wrapped in ``{"response": ...}``."""
        bare = {"status": "302", "headers": {}, "body": ""}
        decision = eb.parse_request_stage_output(bare)
        assert decision.kind == "short_circuit"
        assert decision.response["status"] == "302"

    def test_bare_request_is_mutate(self):
        """User returns the bare request (with ``uri``/``method``)."""
        bare = {"method": "GET", "uri": "/new", "headers": {}}
        decision = eb.parse_request_stage_output(bare)
        assert decision.kind == "mutate_request"
        assert decision.request["uri"] == "/new"


class TestParseResponseStageOutput:
    def test_mutation_with_response(self):
        decision = eb.parse_response_stage_output({
            "response": {"status": "200", "headers": {}},
        })
        assert decision.kind == "mutate_response"

    def test_request_key_is_ignored(self):
        """Response-stage functions can't short-circuit with a request."""
        assert eb.parse_response_stage_output({
            "request": {"uri": "/x"},
        }).kind == "continue-unchanged"

    def test_bare_response_is_mutate(self):
        """Canonical AWS shape: Lambda returns the bare response dict."""
        bare = {"status": "201", "headers": {
            "x-added": [{"key": "X-Added", "value": "1"}],
        }}
        decision = eb.parse_response_stage_output(bare)
        assert decision.kind == "mutate_response"
        assert decision.response["status"] == "201"


class TestApplyRequestMutations:
    def test_header_replacement(self):
        headers, method, uri, qs = eb.apply_request_mutations(
            {"Host": "original"},
            {"headers": {"host": [{"key": "Host", "value": "new"}]}},
        )
        assert headers == {"Host": "new"}

    def test_method_uri_qs_preserved_when_absent(self):
        headers, method, uri, qs = eb.apply_request_mutations(
            {"H": "v"},
            {},  # mutated request has nothing
        )
        assert headers == {"H": "v"}
        assert method == "GET"
        assert uri == "/"


class TestApplyResponseMutations:
    def test_body_text_encoding(self):
        status, headers, body = eb.apply_response_mutations(
            200, {"X": "y"}, b"old",
            {"body": "new body", "bodyEncoding": "text"},
        )
        assert body == b"new body"

    def test_body_base64_encoding(self):
        enc = base64.b64encode(b"binary-body").decode()
        status, headers, body = eb.apply_response_mutations(
            200, {}, b"old",
            {"body": enc, "bodyEncoding": "base64"},
        )
        assert body == b"binary-body"

    def test_invalid_base64_keeps_original(self):
        status, headers, body = eb.apply_response_mutations(
            200, {}, b"original",
            {"body": "not-valid-base64!@#", "bodyEncoding": "base64"},
        )
        # Guard kept body unchanged because b64 decode failed.
        assert body == b"original"

    def test_status_update(self):
        status, _, _ = eb.apply_response_mutations(
            200, {}, b"",
            {"status": "302"},
        )
        assert status == 302

    def test_status_unchanged_on_non_int(self):
        status, _, _ = eb.apply_response_mutations(
            200, {}, b"",
            {"status": "not-a-number"},
        )
        assert status == 200


class TestSynthesizeShortCircuit:
    def test_basic(self):
        status, headers, body = eb.synthesize_response_from_short_circuit({
            "status": "302",
            "headers": {"location": [{"key": "Location", "value": "/new"}]},
            "body": "", "bodyEncoding": "text",
        })
        assert status == 302
        assert headers == {"Location": "/new"}

    def test_defaults_to_200(self):
        status, _, _ = eb.synthesize_response_from_short_circuit({})
        assert status == 200
