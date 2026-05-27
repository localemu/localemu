"""Lambda@Edge chain runner.

Walks the ``LambdaFunctionAssociations`` on a cache behaviour, invokes
each association through LocalEmu's internal Lambda client, and applies
the returned mutations (or short-circuit) in order.

The chain is a four-phase pipeline:

  1. viewer-request  — client hits CloudFront. Can short-circuit.
  2. origin-request  — after cache MISS, before origin fetch. Can short-
     circuit or rewrite which origin (we honour only request mutations
     in v1; re-targeting to a different origin is a Phase 3.1 feature).
  3. origin-response — after origin returned 2xx. Can rewrite.
  4. viewer-response — right before returning to client. Can rewrite.

The runner is deliberately stateless between calls — all mutable state
is passed in as function arguments. This keeps it reusable from tests
without spinning up the full data-plane router.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from . import event_builder as _eb
from .event_builder import EdgeDecision

LOG = logging.getLogger(__name__)


def _edge_enabled() -> bool:
    """Master switch. Set ``CLOUDFRONT_LAMBDA_EDGE_ENABLE=0`` to skip."""
    raw = os.environ.get("CLOUDFRONT_LAMBDA_EDGE_ENABLE", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


@dataclass
class RequestState:
    """Mutable request shape shared across request-stage associations."""

    method: str
    uri: str
    querystring: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass
class ResponseState:
    """Mutable response shape shared across response-stage associations."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass
class ShortCircuit:
    """Sentinel returned from request-stage chains when a Lambda
    produced a ``response`` — the data-plane router must use this and
    skip the remaining request-stage work plus the origin fetch.
    """

    status: int
    headers: dict[str, str]
    body: bytes


# ---------------------------------------------------------------------------
# Association selection
# ---------------------------------------------------------------------------

def associations_for(
    cache_behavior: Any, event_type: str,
) -> list[dict[str, Any]]:
    """Return the subset of Lambda associations on the cache behavior that
    match ``event_type``. ``cache_behavior`` can be moto's dataclass-like
    object (attribute access) or a dict (projected by the router).

    Moto's DefaultCacheBehaviour stores associations in an object at
    ``lambda_function_associations`` — a list whose elements have
    ``event_type`` and ``lambda_function_arn`` attributes.
    """
    if cache_behavior is None:
        return []

    # Accept dict shape (common after our router's projection)
    if isinstance(cache_behavior, dict):
        assoc_wrapper = cache_behavior.get("LambdaFunctionAssociations") or {}
        items = assoc_wrapper.get("Items") or []
    else:
        items = getattr(cache_behavior, "lambda_function_associations", None) or []
        # Moto wraps the list in a container object; accept either.
        if hasattr(items, "items"):
            items = items.items
        elif hasattr(items, "Items"):
            items = items.Items

    out: list[dict[str, Any]] = []
    for entry in items:
        if isinstance(entry, dict):
            et = entry.get("EventType") or entry.get("event_type")
            arn = (
                entry.get("LambdaFunctionARN")
                or entry.get("lambda_function_arn")
                or entry.get("arn")
            )
            include_body = bool(entry.get("IncludeBody") or entry.get("include_body"))
        else:
            et = getattr(entry, "event_type", None) or getattr(entry, "EventType", None)
            # Moto's LambdaFunctionAssociation uses a bare ``arn`` attribute;
            # accept the wire names too for robustness across moto versions.
            arn = (
                getattr(entry, "arn", None)
                or getattr(entry, "lambda_function_arn", None)
                or getattr(entry, "LambdaFunctionARN", None)
            )
            include_body = bool(
                getattr(entry, "include_body", False)
                or getattr(entry, "IncludeBody", False)
            )
        if et == event_type and arn:
            out.append({"arn": arn, "include_body": include_body})
    return out


# ---------------------------------------------------------------------------
# Invocation — invokes the Lambda via LocalEmu's internal client
# ---------------------------------------------------------------------------

def _invoke(
    function_arn: str, distribution_id: str, event: dict[str, Any],
) -> dict[str, Any] | None:
    """Call the Lambda; return the parsed output dict or ``None`` on
    any failure (which lets the chain continue unchanged — the
    alternative of propagating exceptions would surface a broken edge
    function as a 500, which is worse than continuing without it).
    """
    from localemu.aws.connect import connect_to
    from localemu.utils.aws.arns import (
        extract_account_id_from_arn, extract_region_from_arn,
    )

    region = extract_region_from_arn(function_arn) or "us-east-1"
    account_id = extract_account_id_from_arn(function_arn) or "000000000000"
    try:
        lambda_client = connect_to(
            aws_access_key_id=account_id, region_name=region,
        ).lambda_
        # Pre-serialize the event so we can report size problems clearly.
        payload = json.dumps(event, separators=(",", ":"), default=str).encode()
        result = lambda_client.invoke(
            FunctionName=function_arn,
            Payload=payload,
            InvocationType="RequestResponse",
        )
    except Exception:
        LOG.warning(
            "Lambda@Edge invocation failed for %s (dist=%s); continuing chain unchanged",
            function_arn, distribution_id, exc_info=True,
        )
        return None

    if result.get("FunctionError"):
        LOG.warning(
            "Lambda@Edge function %s returned FunctionError=%s; chain unchanged",
            function_arn, result["FunctionError"],
        )
        return None

    body = result.get("Payload")
    if body is None:
        return None
    try:
        raw = body.read() if hasattr(body, "read") else body
        return json.loads(raw)
    except Exception:
        LOG.warning(
            "Lambda@Edge function %s returned non-JSON payload; chain unchanged",
            function_arn, exc_info=True,
        )
        return None


# ---------------------------------------------------------------------------
# Chain drivers
# ---------------------------------------------------------------------------

def run_request_chain(
    *,
    event_type: str,
    cache_behavior: Any,
    distribution_id: str,
    request_id: str,
    request: RequestState,
    client_ip: str = "127.0.0.1",
) -> ShortCircuit | None:
    """Run the viewer-request or origin-request chain.

    Mutates ``request`` in place on mutation returns. Returns a
    :class:`ShortCircuit` when any function produced a response (caller
    must abort the remaining request-stage work and the origin fetch).
    """
    if not _edge_enabled():
        return None
    associations = associations_for(cache_behavior, event_type)
    if not associations:
        return None

    for assoc in associations:
        try:
            event = _eb.build_request_event(
                event_type=event_type,
                distribution_id=distribution_id,
                request_id=request_id,
                method=request.method,
                uri=request.uri,
                querystring=request.querystring,
                headers=request.headers,
                client_ip=client_ip,
                body=request.body,
                include_body=assoc["include_body"],
            )
        except ValueError:
            LOG.warning(
                "Lambda@Edge event would exceed size cap for %s; skipping association",
                assoc["arn"],
            )
            continue

        output = _invoke(assoc["arn"], distribution_id, event)
        if output is None:
            continue

        # Output shape: {"Records":[{"cf":{"request": {...}}}]} OR
        # {"Records":[{"cf":{"response": {...}}}]} OR the bare
        # ``request`` / ``response`` dict (some templates).
        payload = _unwrap_cf_output(output)
        decision = _eb.parse_request_stage_output(payload)
        if decision.kind == "short_circuit":
            status, headers, body = _eb.synthesize_response_from_short_circuit(
                decision.response,
            )
            return ShortCircuit(status=status, headers=headers, body=body)
        if decision.kind == "mutate_request":
            h, m, u, qs = _eb.apply_request_mutations(
                request.headers, decision.request,
            )
            request.headers = h
            request.method = m
            request.uri = u
            request.querystring = qs
    return None


def run_response_chain(
    *,
    event_type: str,
    cache_behavior: Any,
    distribution_id: str,
    request_id: str,
    request: RequestState,
    response: ResponseState,
    client_ip: str = "127.0.0.1",
) -> None:
    """Run the origin-response or viewer-response chain. Mutates
    ``response`` in place; short-circuits are not legal at these stages
    in AWS semantics and are treated as ``continue-unchanged``.
    """
    if not _edge_enabled():
        return
    associations = associations_for(cache_behavior, event_type)
    if not associations:
        return

    for assoc in associations:
        try:
            event = _eb.build_response_event(
                event_type=event_type,
                distribution_id=distribution_id,
                request_id=request_id,
                method=request.method,
                uri=request.uri,
                querystring=request.querystring,
                request_headers=request.headers,
                status=response.status,
                status_description=None,
                response_headers=response.headers,
                client_ip=client_ip,
            )
        except ValueError:
            LOG.warning(
                "Lambda@Edge response event would exceed size cap for %s; skipping",
                assoc["arn"],
            )
            continue

        output = _invoke(assoc["arn"], distribution_id, event)
        if output is None:
            continue

        payload = _unwrap_cf_output(output)
        decision = _eb.parse_response_stage_output(payload)
        if decision.kind == "mutate_response":
            new_status, new_headers, new_body = _eb.apply_response_mutations(
                response.status, response.headers, response.body,
                decision.response,
            )
            response.status = new_status
            response.headers = new_headers
            response.body = new_body


def _unwrap_cf_output(output: Any) -> dict[str, Any]:
    """Accept both the full ``{Records:[{cf:{...}}]}`` envelope and the
    bare inner dict, whichever the user's Lambda returned.
    """
    if isinstance(output, dict) and "Records" in output:
        records = output.get("Records") or []
        if records and isinstance(records[0], dict):
            return records[0].get("cf") or {}
    if isinstance(output, dict):
        return output
    return {}
