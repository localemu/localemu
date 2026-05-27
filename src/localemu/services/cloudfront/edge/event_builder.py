"""CloudFront Lambda@Edge event / response objects.

Follows the canonical schema documented by AWS:
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html

The event is a single-record envelope containing a ``cf`` dict with
``config`` and either ``request`` or ``response`` sub-objects. Header
values are nested as ``{lowercased-name: [{key, value}, ...]}`` — one
of the footguns for function authors coming from plain-HTTP APIs. The
builders here produce that canonical shape; response-parsers validate
it on the way back.

This module is pure-data — no Lambda invocation, no HTTP. The chain
runner (:mod:`chain`) drives the invocation loop.
"""

from __future__ import annotations

from typing import Any

EVENT_VIEWER_REQUEST = "viewer-request"
EVENT_ORIGIN_REQUEST = "origin-request"
EVENT_ORIGIN_RESPONSE = "origin-response"
EVENT_VIEWER_RESPONSE = "viewer-response"

_REQUEST_EVENT_TYPES = {EVENT_VIEWER_REQUEST, EVENT_ORIGIN_REQUEST}
_RESPONSE_EVENT_TYPES = {EVENT_ORIGIN_RESPONSE, EVENT_VIEWER_RESPONSE}

# Size caps per AWS spec — the whole cf object must fit within this.
# We use the request-event cap by default; response events use the same
# limit since both are 1 MB.
MAX_BODY_BYTES = 1_048_576  # 1 MB


def _headers_to_cf(headers: dict[str, str] | None) -> dict[str, list[dict[str, str]]]:
    """Convert a plain ``{Name: Value}`` header dict to CloudFront's
    ``{lowercased-name: [{key, value}]}`` shape.

    Header names are preserved in the ``key`` field, lower-cased in the
    outer key so lookups in user code match AWS's behaviour.
    """
    out: dict[str, list[dict[str, str]]] = {}
    if not headers:
        return out
    # Headers may arrive as a werkzeug EnvironHeaders — iterate items().
    items = headers.items() if hasattr(headers, "items") else headers
    for k, v in items:
        key = k.lower()
        out.setdefault(key, []).append({"key": k, "value": v})
    return out


def _headers_from_cf(cf_headers: dict[str, list[dict[str, str]]] | None) -> dict[str, str]:
    """Inverse of :func:`_headers_to_cf`. Flattens to a single string per
    name; multi-valued headers are joined with ``,`` (matches AWS).
    """
    out: dict[str, str] = {}
    if not cf_headers:
        return out
    for _, entries in cf_headers.items():
        if not entries:
            continue
        name = entries[0].get("key") or ""
        values = [e.get("value", "") for e in entries]
        out[name] = ",".join(values)
    return out


def build_request_event(
    *,
    event_type: str,
    distribution_id: str,
    request_id: str,
    method: str,
    uri: str,
    querystring: str,
    headers: dict[str, str] | None,
    client_ip: str = "127.0.0.1",
    body: bytes | None = None,
    include_body: bool = False,
) -> dict[str, Any]:
    """Build a Lambda@Edge event for a request-stage association.

    Raises ``ValueError`` if the payload would exceed the 1 MB cap.
    """
    if event_type not in _REQUEST_EVENT_TYPES:
        raise ValueError(f"{event_type!r} is not a request-stage event type")

    request: dict[str, Any] = {
        "clientIp": client_ip,
        "method": method.upper(),
        "uri": uri if uri.startswith("/") else "/" + uri,
        "querystring": querystring or "",
        "headers": _headers_to_cf(headers),
    }
    if include_body and body is not None:
        encoded_body, body_enc = _encode_body_for_event(body)
        request["body"] = {
            "inputTruncated": False,
            "action": "read-only",
            "encoding": body_enc,
            "data": encoded_body,
        }

    event = {
        "Records": [{
            "cf": {
                "config": {
                    "distributionDomainName": f"{distribution_id}.cloudfront.net",
                    "distributionId": distribution_id,
                    "eventType": event_type,
                    "requestId": request_id,
                },
                "request": request,
            },
        }],
    }
    _check_size(event)
    return event


def build_response_event(
    *,
    event_type: str,
    distribution_id: str,
    request_id: str,
    method: str,
    uri: str,
    querystring: str,
    request_headers: dict[str, str] | None,
    status: int,
    status_description: str | None,
    response_headers: dict[str, str] | None,
    client_ip: str = "127.0.0.1",
) -> dict[str, Any]:
    """Build a Lambda@Edge event for a response-stage association."""
    if event_type not in _RESPONSE_EVENT_TYPES:
        raise ValueError(f"{event_type!r} is not a response-stage event type")

    event = {
        "Records": [{
            "cf": {
                "config": {
                    "distributionDomainName": f"{distribution_id}.cloudfront.net",
                    "distributionId": distribution_id,
                    "eventType": event_type,
                    "requestId": request_id,
                },
                "request": {
                    "clientIp": client_ip,
                    "method": method.upper(),
                    "uri": uri if uri.startswith("/") else "/" + uri,
                    "querystring": querystring or "",
                    "headers": _headers_to_cf(request_headers),
                },
                "response": {
                    "status": str(status),
                    "statusDescription": status_description or _STATUS_DESC.get(status, ""),
                    "headers": _headers_to_cf(response_headers),
                },
            },
        }],
    }
    _check_size(event)
    return event


def _encode_body_for_event(body: bytes) -> tuple[str, str]:
    """Encode a request body for the event. Returns (data, encoding)."""
    import base64
    try:
        return body.decode("utf-8"), "text"
    except UnicodeDecodeError:
        return base64.b64encode(body).decode("ascii"), "base64"


def _check_size(event: dict) -> None:
    """Raise if the serialized event would exceed the AWS-documented cap."""
    import json
    size = len(json.dumps(event, separators=(",", ":"), default=str).encode())
    if size > MAX_BODY_BYTES:
        raise ValueError(
            f"Lambda@Edge event size {size} exceeds the {MAX_BODY_BYTES}-byte AWS limit",
        )


# ---------------------------------------------------------------------------
# Response parsers — read the Lambda output and extract the intent.
# ---------------------------------------------------------------------------

class EdgeDecision:
    """Outcome of a Lambda@Edge invocation.

    Three shapes correspond to the three things a function can do:

      - ``mutate_request``: rewrite the request and pass through to the
        next stage. Fields to apply back to the request.
      - ``short_circuit``: synthesize a response and skip the remaining
        request-stage chain + the origin entirely.
      - ``mutate_response``: rewrite the response (only valid on
        response-stage events).
    """

    def __init__(self, kind: str, *, request: dict | None = None,
                 response: dict | None = None) -> None:
        self.kind = kind
        self.request = request
        self.response = response


def parse_request_stage_output(output: dict[str, Any]) -> EdgeDecision:
    """Interpret a viewer-request / origin-request Lambda output.

    AWS Lambda@Edge contract: the function returns the **bare** object
    (request or response), NOT wrapped in ``{"request": ...}`` or
    ``{"response": ...}``. Envelope-style returns
    (``{Records:[{cf:{...}}]}``) are also supported by some tooling —
    :func:`_unwrap_cf_output` on the chain side strips those before
    passing here, but we still accept the wrapped shape for defensive
    robustness.

    Distinguishing request vs response on the bare shape:
      - response has ``status``
      - request has ``uri`` or ``method``
    """
    if not isinstance(output, dict):
        return EdgeDecision("continue-unchanged")

    # Wrapped form (legacy / envelope survivor).
    if "response" in output and isinstance(output["response"], dict):
        return EdgeDecision("short_circuit", response=output["response"])
    if "request" in output and isinstance(output["request"], dict):
        return EdgeDecision("mutate_request", request=output["request"])

    # Bare form — the canonical AWS contract.
    if "status" in output:
        return EdgeDecision("short_circuit", response=output)
    if "uri" in output or "method" in output:
        return EdgeDecision("mutate_request", request=output)

    return EdgeDecision("continue-unchanged")


def parse_response_stage_output(output: dict[str, Any]) -> EdgeDecision:
    """Interpret an origin-response / viewer-response Lambda output.

    Only response mutations are meaningful; the presence of a ``request``
    key is explicitly documented as illegal at these stages.

    As with :func:`parse_request_stage_output`, the canonical contract
    is a bare response dict (has ``status``); we also accept wrapped.
    """
    if not isinstance(output, dict):
        return EdgeDecision("continue-unchanged")

    if "response" in output and isinstance(output["response"], dict):
        return EdgeDecision("mutate_response", response=output["response"])

    if "status" in output:
        return EdgeDecision("mutate_response", response=output)

    return EdgeDecision("continue-unchanged")


def apply_request_mutations(
    current: dict[str, str], mutated_request: dict[str, Any],
) -> tuple[dict[str, str], str, str, str]:
    """Apply a Lambda-returned ``request`` dict back onto our internal
    request state.

    Returns (headers_dict, method, uri, querystring). URI / method /
    querystring are passed through from the mutated request with sane
    fallbacks to the current state.
    """
    headers = _headers_from_cf(mutated_request.get("headers")) or dict(current)
    method = (mutated_request.get("method") or "").upper() or None
    uri = mutated_request.get("uri") or None
    qs = mutated_request.get("querystring")
    return headers, method or "GET", uri or "/", qs if qs is not None else ""


def apply_response_mutations(
    status: int,
    headers: dict[str, str],
    body: bytes,
    mutated_response: dict[str, Any],
) -> tuple[int, dict[str, str], bytes]:
    """Apply response-stage mutations. Body comes from the mutated
    response's ``body`` field if set; otherwise the current body is kept.
    """
    new_status = status
    try:
        new_status = int(mutated_response.get("status") or status)
    except (TypeError, ValueError):
        pass
    new_headers = _headers_from_cf(mutated_response.get("headers")) or dict(headers)
    new_body = body
    if "body" in mutated_response:
        encoding = (mutated_response.get("bodyEncoding") or "text").lower()
        raw = mutated_response.get("body") or ""
        if encoding == "base64":
            import base64
            try:
                new_body = base64.b64decode(raw)
            except Exception:
                new_body = body  # reject garbage; keep the origin body
        else:
            new_body = raw.encode() if isinstance(raw, str) else bytes(raw)
    return new_status, new_headers, new_body


def synthesize_response_from_short_circuit(
    short_circuit: dict[str, Any],
) -> tuple[int, dict[str, str], bytes]:
    """Turn a request-stage short-circuit ``response`` dict into a
    concrete (status, headers, body) triple.
    """
    status = 200
    try:
        status = int(short_circuit.get("status") or 200)
    except (TypeError, ValueError):
        pass
    headers = _headers_from_cf(short_circuit.get("headers"))
    body = b""
    if "body" in short_circuit:
        encoding = (short_circuit.get("bodyEncoding") or "text").lower()
        raw = short_circuit.get("body") or ""
        if encoding == "base64":
            import base64
            try:
                body = base64.b64decode(raw)
            except Exception:
                body = b""
        else:
            body = raw.encode() if isinstance(raw, str) else bytes(raw)
    return status, headers, body


_STATUS_DESC = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}
