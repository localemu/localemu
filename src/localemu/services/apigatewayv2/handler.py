"""HTTP API request handler for API Gateway V2.

Receives HTTP requests routed by the gateway, matches them to API routes,
builds Lambda proxy V2 events, invokes Lambda, and returns responses.
"""

import gzip
import json
import logging
import threading
import time
from base64 import b64decode, b64encode
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from urllib.parse import parse_qs

import requests as http_requests

from rolo import Request

from localemu.aws.connect import connect_to
from localemu.http import Response
from localemu.utils.strings import short_uid

from .route_matcher import RouteMatcher

LOG = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
# Headers that MUST NOT be forwarded to upstream HTTP integrations
# ────────────────────────────────────────────────────────────────────

# BUG-15: Hop-by-hop headers per RFC 2616 §13.5.1
_HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in [
        "Host",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Upgrade",
    ]
)

# SEC-05: Sensitive headers that must not leak to upstream
_SENSITIVE_HEADERS = frozenset(h.lower() for h in ["Authorization", "Cookie"])

# BUG-14: Text content types that should NOT be treated as binary
_TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "application/graphql",
    "multipart/form-data",
)

# ────────────────────────────────────────────────────────────────────
# PARITY-14: Simple in-memory API key usage counters
# PERF-R2-04: bounded — per-API map capped; total API count capped via eviction
# ────────────────────────────────────────────────────────────────────
_API_KEY_USAGE_MAX_APIS = 1000
_API_KEY_USAGE_MAX_KEYS_PER_API = 10000
_api_key_usage_lock = threading.Lock()
_api_key_usage: "OrderedDict[str, OrderedDict[str, int]]" = OrderedDict()

# ────────────────────────────────────────────────────────────────────
# PARITY-04: Basic in-memory response cache
# PERF-R2-02: bounded LRU cache (evict oldest when full)
# ────────────────────────────────────────────────────────────────────
_RESPONSE_CACHE_MAXSIZE = 1000
_response_cache_lock = threading.Lock()
_response_cache: "OrderedDict[str, tuple[float, Response]]" = OrderedDict()
_CACHE_DEFAULT_TTL = 300  # seconds

# ────────────────────────────────────────────────────────────────────
# PARITY-16: Basic in-memory rate-limiting state
# PERF-R2-03: cleaned up on API/stage deletion via invalidate_throttle_state()
# ────────────────────────────────────────────────────────────────────
_throttle_lock = threading.Lock()
_throttle_state: dict[str, list[float]] = defaultdict(list)


def invalidate_throttle_state(api_id: str | None = None, stage: str | None = None) -> None:
    """Remove throttle counters for a deleted API or API/stage pair.

    Called from the apigatewayv2 provider whenever an API or Stage resource
    is deleted so the in-memory ``_throttle_state`` map does not grow
    without bound (PERF-R2-03).
    """
    with _throttle_lock:
        if api_id is None:
            _throttle_state.clear()
            return
        prefix = f"{api_id}:" if stage is None else f"{api_id}:{stage}"
        to_remove = [k for k in _throttle_state if k == prefix or k.startswith(prefix)]
        for k in to_remove:
            _throttle_state.pop(k, None)


def invalidate_api_key_usage(api_id: str | None = None) -> None:
    """Drop API-key usage counters for a deleted API (PERF-R2-04)."""
    with _api_key_usage_lock:
        if api_id is None:
            _api_key_usage.clear()
        else:
            _api_key_usage.pop(api_id, None)


class HttpApiHandler:
    """Handles HTTP API (V2) requests.

    For each incoming request:
    1. Load API configuration from moto
    2. Enforce authorization (JWT, AWS_IAM, API key)
    3. Match request to a route
    4. Build Lambda proxy V2 event (or forward to HTTP integration)
    5. Invoke Lambda and return response
    """

    # BUG-02 fix: Cache compiled RouteMatcher per API ID
    _matcher_cache: dict[str, tuple[int, RouteMatcher]] = {}
    _matcher_cache_lock = threading.Lock()

    @classmethod
    def invalidate_matcher_cache(cls, api_id: str | None = None):
        """Invalidate cached RouteMatcher(s). Called on route/integration changes."""
        with cls._matcher_cache_lock:
            if api_id:
                cls._matcher_cache.pop(api_id, None)
            else:
                cls._matcher_cache.clear()

    def _get_matcher(self, api) -> RouteMatcher:
        """Return a cached RouteMatcher for the API, rebuilding on route changes."""
        api_id = getattr(api, "api_id", "") or getattr(api, "id", "")
        routes = list(api.routes.values())
        route_version = len(routes)  # cheap change-detection heuristic

        with self._matcher_cache_lock:
            cached = self._matcher_cache.get(api_id)
            if cached and cached[0] == route_version:
                return cached[1]

        matcher = RouteMatcher()
        matcher.compile_routes([self._route_to_dict(r) for r in routes])

        with self._matcher_cache_lock:
            self._matcher_cache[api_id] = (route_version, matcher)

        return matcher

    def handle(
        self,
        request: Request,
        api_id: str,
        stage: str,
        path: str,
        account_id: str,
        region: str,
    ) -> Response:
        """Handle an incoming HTTP API request."""
        from moto.apigatewayv2.models import apigatewayv2_backends

        backend = apigatewayv2_backends[account_id][region]

        # Load API
        api = backend.apis.get(api_id)
        if not api:
            return _json_error(404, "Not Found")

        # PARITY-02: WebSocket APIs are not yet supported
        protocol = getattr(api, "protocol_type", "HTTP")
        if protocol == "WEBSOCKET":
            return _json_error(
                400,
                "WebSocket APIs are not yet supported in LocalEmu. "
                "Use HTTP APIs (protocol_type=HTTP) instead.",
            )

        # BUG-02 fix: use cached matcher
        matcher = self._get_matcher(api)

        # Ensure path starts with /
        if not path.startswith("/"):
            path = f"/{path}"

        # Match request
        route_match = matcher.match(request.method, path)
        if not route_match:
            return _json_error(404, "Not Found")

        # ── Authorization enforcement ──────────────────────────────

        # Resolve the moto route object to check auth settings
        moto_route = api.routes.get(route_match.route_id)
        auth_type = getattr(moto_route, "authorization_type", "NONE") if moto_route else "NONE"
        auth_type = auth_type or "NONE"

        authorizer_context: dict = {}

        # SEC-01 / PARITY-01: JWT authorizer enforcement
        if auth_type == "JWT" and route_match.authorizer_id:
            authorizer = api.authorizers.get(route_match.authorizer_id)
            if authorizer:
                jwt_result = _enforce_jwt_authorizer(request, moto_route, authorizer)
                if jwt_result is not None:
                    return jwt_result
                authorizer_context = _extract_jwt_claims(request)

        # PARITY-07: IAM authorization stub
        if auth_type == "AWS_IAM":
            auth_header = request.headers.get("Authorization", "")
            if not auth_header or "AWS4-HMAC-SHA256" not in auth_header:
                return _json_error(403, "Missing Authentication Token")
            # In local emulation we accept any valid SigV4-shaped header
            authorizer_context = {"principalId": account_id}

        # SEC-03: API key validation
        if getattr(moto_route, "api_key_required", False):
            api_key_result = _enforce_api_key(request, api, api_id)
            if api_key_result is not None:
                return api_key_result

        # ── Stage-level throttling ─────────────────────────────────
        # PARITY-16: basic rate limiting when stage has route throttling
        stage_obj = api.stages.get(stage) if hasattr(api, "stages") else None
        throttle_result = _check_throttle(api_id, stage, stage_obj)
        if throttle_result is not None:
            return throttle_result

        # ── Response cache check ───────────────────────────────────
        # PARITY-04: check cache before invoking integration
        cache_key = None
        if stage_obj and getattr(stage_obj, "cache_cluster_enabled", False):
            cache_key = f"{api_id}:{stage}:{request.method}:{path}:{request.query_string}"
            cached = _cache_get(cache_key)
            if cached is not None:
                return cached

        # Get integration
        integration = api.integrations.get(route_match.integration_id)
        if not integration:
            LOG.warning(
                "No integration found for route %s (integration_id=%s)",
                route_match.route_key,
                route_match.integration_id,
            )
            return _json_error(500, "Internal Server Error")

        integration_type = getattr(integration, "integration_type", "")

        if integration_type == "AWS_PROXY":
            response = self._invoke_lambda_proxy(
                request=request,
                api=api,
                api_id=api_id,
                stage=stage,
                path=path,
                route_match=route_match,
                integration=integration,
                account_id=account_id,
                region=region,
                authorizer_context=authorizer_context,
            )
        elif integration_type == "HTTP_PROXY":
            response = self._forward_http_proxy(
                request=request,
                integration=integration,
            )
        else:
            LOG.warning("Unsupported integration type: %s", integration_type)
            return _json_error(500, "Internal Server Error")

        # ── PARITY-10: gzip compression ────────────────────────────
        min_compress = getattr(api, "minimum_compression_size", None)
        if min_compress is not None and min_compress >= 0:
            accept_enc = request.headers.get("Accept-Encoding", "")
            if "gzip" in accept_enc:
                body = response.get_data()
                if len(body) >= min_compress:
                    response.set_data(gzip.compress(body))
                    response.headers["Content-Encoding"] = "gzip"

        # ── PARITY-04: store in cache ──────────────────────────────
        if cache_key is not None:
            ttl = getattr(stage_obj, "cache_cluster_size_ttl", _CACHE_DEFAULT_TTL) or _CACHE_DEFAULT_TTL
            _cache_put(cache_key, response, ttl)

        # ── PARITY-06: access logging ─────────────────────────────
        if stage_obj:
            _write_access_log(
                stage_obj, api_id, stage, request, response, route_match, account_id, region
            )

        return response

    def _invoke_lambda_proxy(
        self,
        request: Request,
        api,
        api_id: str,
        stage: str,
        path: str,
        route_match,
        integration,
        account_id: str,
        region: str,
        authorizer_context: dict | None = None,
    ) -> Response:
        """Invoke a Lambda function with V2 proxy event format."""
        integration_uri = getattr(integration, "integration_uri", "")
        payload_format = getattr(integration, "payload_format_version", "2.0")

        # Build event
        if payload_format == "1.0":
            event = self._build_v1_event(
                request, api_id, stage, path, route_match, account_id, region,
                authorizer_context=authorizer_context,
            )
        else:
            event = self._build_v2_event(
                request, api_id, stage, path, route_match, account_id, region,
                authorizer_context=authorizer_context,
            )

        # Invoke Lambda. The integration_uri stored on AWS_PROXY integrations
        # is the API Gateway "path" form:
        #   arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/<lambda-arn>/invocations
        # Real AWS API Gateway parses this transparently; ``lambda:Invoke`` itself
        # only accepts a function name, a function ARN, or a partial ARN. Extract
        # the nested Lambda ARN before invoking.
        function_name = _extract_lambda_arn_from_integration_uri(integration_uri)
        try:
            lambda_client = connect_to(
                aws_access_key_id=account_id,
                region_name=region,
            ).lambda_
            result = lambda_client.invoke(
                FunctionName=function_name,
                Payload=json.dumps(event).encode("utf-8"),
                InvocationType="RequestResponse",
            )
            payload = result.get("Payload")
            if payload:
                response_bytes = payload.read() if hasattr(payload, "read") else payload
                return self._parse_lambda_response(response_bytes, payload_format)
            else:
                return _json_error(502, "No response from Lambda")
        except Exception as e:
            LOG.error("Lambda invocation failed: %s", e)
            return _json_error(500, "Internal Server Error")

    def _build_v2_event(
        self,
        request: Request,
        api_id: str,
        stage: str,
        path: str,
        route_match,
        account_id: str,
        region: str,
        authorizer_context: dict | None = None,
    ) -> dict:
        """Build Lambda proxy V2 payload format (payload format version 2.0)."""
        now = datetime.now(timezone.utc)

        # Headers (lowercase keys, single value in V2)
        headers = {}
        for key, value in request.headers:
            headers[key.lower()] = value

        # Cookies
        cookies = []
        cookie_header = headers.get("cookie", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(";")]

        # Query string parameters (single value per key in V2)
        query_params = None
        raw_query = request.query_string.decode("utf-8") if request.query_string else ""
        if raw_query:
            parsed = parse_qs(raw_query, keep_blank_values=True)
            query_params = {k: v[-1] for k, v in parsed.items()}

        # Body — PARITY-15: multipart/form-data passed through without transformation
        body = request.get_data(as_text=True)
        is_base64 = False
        if body and _is_binary_content_type(headers.get("content-type", "")):
            body = b64encode(request.get_data()).decode("utf-8")
            is_base64 = True

        # BUG-09 fix: populate requestContext.authorizer when authorizer context present
        request_context: dict = {
            "accountId": account_id,
            "apiId": api_id,
            "domainName": f"{api_id}.execute-api.localhost.localemu.cloud",
            "domainPrefix": api_id,
            "http": {
                "method": request.method,
                "path": path,
                "protocol": "HTTP/1.1",
                "sourceIp": request.remote_addr or "127.0.0.1",
                "userAgent": headers.get("user-agent", ""),
            },
            "requestId": short_uid(),
            "routeKey": route_match.route_key,
            "stage": stage,
            "time": now.strftime("%d/%b/%Y:%H:%M:%S %z"),
            "timeEpoch": int(now.timestamp() * 1000),
        }
        if authorizer_context:
            request_context["authorizer"] = {"jwt": {"claims": authorizer_context}}

        return {
            "version": "2.0",
            "routeKey": route_match.route_key,
            "rawPath": path,
            "rawQueryString": raw_query,
            "cookies": cookies if cookies else None,
            "headers": headers,
            "queryStringParameters": query_params,
            "pathParameters": route_match.path_parameters or None,
            "requestContext": request_context,
            "body": body if body else None,
            "isBase64Encoded": is_base64,
        }

    def _build_v1_event(
        self,
        request: Request,
        api_id: str,
        stage: str,
        path: str,
        route_match,
        account_id: str,
        region: str,
        authorizer_context: dict | None = None,
    ) -> dict:
        """Build Lambda proxy V1 payload format (payload format version 1.0)."""
        now = datetime.now(timezone.utc)

        # Headers
        headers = {}
        multi_value_headers = {}
        for key, value in request.headers:
            headers[key] = value
            multi_value_headers.setdefault(key, []).append(value)

        # Query parameters
        query_params = None
        multi_query_params = None
        raw_query = request.query_string.decode("utf-8") if request.query_string else ""
        if raw_query:
            parsed = parse_qs(raw_query, keep_blank_values=True)
            query_params = {k: v[-1] for k, v in parsed.items()}
            multi_query_params = dict(parsed)

        body = request.get_data(as_text=True)
        is_base64 = False
        if body and _is_binary_content_type(headers.get("Content-Type", "")):
            body = b64encode(request.get_data()).decode("utf-8")
            is_base64 = True

        # Extract resource pattern from route key
        parts = route_match.route_key.split(" ", 1)
        resource = parts[1] if len(parts) == 2 else parts[0]

        # BUG-09 fix: populate authorizer context in V1 events too
        authorizer_block = authorizer_context if authorizer_context else {}

        return {
            "resource": resource,
            "path": path,
            "httpMethod": request.method,
            "headers": headers,
            "multiValueHeaders": multi_value_headers,
            "queryStringParameters": query_params,
            "multiValueQueryStringParameters": multi_query_params,
            "pathParameters": route_match.path_parameters or None,
            "stageVariables": None,
            "requestContext": {
                "accountId": account_id,
                "apiId": api_id,
                "authorizer": authorizer_block,
                "httpMethod": request.method,
                "identity": {
                    "sourceIp": request.remote_addr or "127.0.0.1",
                    "userAgent": headers.get("User-Agent", ""),
                },
                "path": f"/{stage}{path}",
                "protocol": "HTTP/1.1",
                "requestId": short_uid(),
                "requestTime": now.strftime("%d/%b/%Y:%H:%M:%S %z"),
                "requestTimeEpoch": int(now.timestamp() * 1000),
                "resourceId": route_match.route_id,
                "resourcePath": resource,
                "stage": stage,
            },
            "body": body if body else None,
            "isBase64Encoded": is_base64,
        }

    def _parse_lambda_response(self, response_bytes: bytes, payload_format: str) -> Response:
        """Parse Lambda response into an HTTP Response.

        V2 format supports simple string returns (status 200, body = string)
        and structured returns with statusCode, headers, body, cookies.
        """
        try:
            result = json.loads(response_bytes)
        except (json.JSONDecodeError, TypeError):
            # If Lambda returns non-JSON, treat as plain text 200
            return Response(
                response=response_bytes,
                status=200,
                content_type="application/json",
            )

        # V2 format: if result is a string, return it directly
        if isinstance(result, str):
            return Response(response=result, status=200, content_type="application/json")

        # V2 format: if result is a dict without statusCode, wrap as JSON body
        if isinstance(result, dict) and "statusCode" not in result:
            return Response(
                response=json.dumps(result),
                status=200,
                content_type="application/json",
            )

        # Structured response format
        # PARITY-17: validate statusCode is integer
        raw_status = result.get("statusCode", 200)
        try:
            status_code = int(raw_status)
        except (ValueError, TypeError):
            LOG.warning("Invalid statusCode '%s', defaulting to 200", raw_status)
            status_code = 200

        response_headers = result.get("headers", {})
        body = result.get("body", "")
        is_base64 = result.get("isBase64Encoded", False)

        if is_base64 and body:
            body = b64decode(body)

        # Handle cookies (V2 feature)
        cookies = result.get("cookies", [])

        resp = Response(response=body, status=status_code)

        # Set headers
        for key, value in response_headers.items():
            resp.headers[key] = value

        # Set cookies
        for cookie in cookies:
            resp.headers.add("Set-Cookie", cookie)

        # Default content type
        if "content-type" not in {k.lower() for k in response_headers}:
            resp.content_type = "application/json"

        return resp

    def _forward_http_proxy(self, request: Request, integration) -> Response:
        """Forward request to an HTTP proxy integration.

        BUG-15: Strips hop-by-hop headers before forwarding.
        SEC-05: Strips sensitive headers (Authorization, Cookie) before forwarding.
        """
        integration_uri = getattr(integration, "integration_uri", "")
        # IntegrationMethod "ANY" (the default for the create-api --target
        # HTTP_PROXY shortcut) is a wildcard meaning "pass the caller's method
        # through". Forwarding the literal string "ANY" produces a request no
        # backend route accepts (405), so resolve it to the incoming method.
        configured_method = getattr(integration, "integration_method", None)
        method = request.method if (not configured_method or configured_method == "ANY") else configured_method

        # Build sanitized headers
        forwarded_headers = {}
        for key, value in request.headers:
            lower_key = key.lower()
            if lower_key in _HOP_BY_HOP_HEADERS:
                continue
            if lower_key in _SENSITIVE_HEADERS:
                continue
            forwarded_headers[key] = value

        try:
            resp = http_requests.request(
                method=method,
                url=integration_uri,
                headers=forwarded_headers,
                data=request.get_data(),
                timeout=30,
            )
            return Response(
                response=resp.content,
                status=resp.status_code,
                headers=dict(resp.headers),
            )
        except Exception as e:
            LOG.error("HTTP proxy integration failed: %s", e)
            return _json_error(502, "Bad Gateway")

    @staticmethod
    def _route_to_dict(route) -> dict:
        """Convert a moto route object to a dict for the RouteMatcher."""
        return {
            "RouteKey": getattr(route, "route_key", ""),
            "RouteId": getattr(route, "route_id", ""),
            "Target": getattr(route, "target", ""),
            "AuthorizerId": getattr(route, "authorizer_id", None),
            "OperationName": getattr(route, "operation_name", None),
        }


# ════════════════════════════════════════════════════════════════════
# Module-level helpers
# ════════════════════════════════════════════════════════════════════


def _json_error(status: int, message: str) -> Response:
    """SEC-09: Consistent error response formatting."""
    return Response(
        response=json.dumps({"message": message}),
        status=status,
        content_type="application/json",
    )


def _extract_lambda_arn_from_integration_uri(integration_uri: str) -> str:
    """Extract the Lambda function ARN from an API Gateway integration URI.

    Terraform writes the full API Gateway path form::

        arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/<lambda-arn>/invocations

    But ``lambda:Invoke``'s ``FunctionName`` parameter only accepts:
      - a plain function name (``my-function``)
      - a function ARN (``arn:aws:lambda:<region>:<account>:function:<name>``)
      - a partial ARN (``<account>:function:<name>``)

    This helper returns the nested Lambda ARN when the input is in the
    API Gateway path form; otherwise it returns the input unchanged (so
    already-plain function names and bare Lambda ARNs keep working).
    """
    if not integration_uri:
        return integration_uri
    marker = "/functions/"
    idx = integration_uri.find(marker)
    if idx < 0:
        return integration_uri
    tail = integration_uri[idx + len(marker):]
    # Strip the trailing "/invocations" (with any suffix like ":alias") that
    # API Gateway appends after the Lambda ARN.
    end = tail.find("/invocations")
    if end >= 0:
        tail = tail[:end]
    return tail


def _is_binary_content_type(content_type: str) -> bool:
    """Check if a content type is binary (should be base64 encoded).

    BUG-14 fix: application/x-www-form-urlencoded, application/graphql,
    and multipart/form-data are NOT binary.
    """
    if not content_type:
        return False
    return not any(content_type.startswith(t) for t in _TEXT_CONTENT_TYPES)


# ────────────────────────────────────────────────────────────────────
# SEC-01 / PARITY-01: JWT authorizer enforcement
# ────────────────────────────────────────────────────────────────────


def _enforce_jwt_authorizer(request: Request, route, authorizer) -> Response | None:
    """Validate JWT token against the authorizer configuration.

    Returns an error Response if validation fails, or None if the token is valid.
    Checks:
      1. Token is present in the configured identity source
      2. Token is a valid JWT (decodes successfully)
      3. Issuer matches the authorizer's configured issuer
      4. Audience includes at least one configured audience
      5. Route-level authorization scopes are satisfied
    """
    import base64

    # Determine identity source (default: $request.header.Authorization).
    # AWS models IdentitySource as a list of strings; older callers / stored
    # configs may carry a single comma-separated string. Normalise both shapes.
    identity_sources = getattr(authorizer, "identity_source", None)
    if not identity_sources:
        identity_sources = ["$request.header.Authorization"]
    if isinstance(identity_sources, str):
        identity_sources = identity_sources.split(",")

    token = None
    for source in identity_sources:
        source = source.strip()
        if source.startswith("$request.header."):
            header_name = source[len("$request.header."):]
            raw = request.headers.get(header_name, "")
            # Strip "Bearer " prefix if present
            if raw.lower().startswith("bearer "):
                raw = raw[7:]
            if raw:
                token = raw
                break
        elif source.startswith("$request.querystring."):
            param_name = source[len("$request.querystring."):]
            raw_qs = request.query_string.decode("utf-8") if request.query_string else ""
            parsed_qs = parse_qs(raw_qs)
            vals = parsed_qs.get(param_name, [])
            if vals:
                token = vals[0]
                break

    if not token:
        return _json_error(401, "Unauthorized")

    # Decode JWT payload (no signature verification in local emulation —
    # we trust tokens structurally, matching AWS behavior for local dev)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return _json_error(401, "Unauthorized")
        # Base64url decode the payload
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        claims = json.loads(payload_bytes)
    except Exception:
        return _json_error(401, "Unauthorized")

    # Cryptographically verify the signature + expiry for tokens minted by a
    # LocalEmu Cognito user pool (we hold the signing key). Tokens from an
    # external IdP, whose key we do not have, fall through to the structural
    # issuer/audience/scope checks below.
    from localemu.services.cognito_idp.verify import (
        TokenVerificationError,
        is_known_pool_token,
        verify_cognito_token,
    )

    if is_known_pool_token(token):
        try:
            verify_cognito_token(token)
        except TokenVerificationError:
            return _json_error(401, "Unauthorized")

    # Check issuer
    jwt_config = getattr(authorizer, "jwt_configuration", {}) or {}
    if isinstance(jwt_config, dict):
        configured_issuer = jwt_config.get("Issuer") or jwt_config.get("issuer")
        configured_audiences = jwt_config.get("Audience") or jwt_config.get("audience") or []
    else:
        configured_issuer = getattr(jwt_config, "issuer", None)
        configured_audiences = getattr(jwt_config, "audience", []) or []

    if configured_issuer:
        token_issuer = claims.get("iss", "")
        if token_issuer != configured_issuer:
            return _json_error(401, "Unauthorized")

    # Check audience
    if configured_audiences:
        token_aud = claims.get("aud", "")
        if isinstance(token_aud, str):
            token_aud = [token_aud]
        if not any(aud in token_aud for aud in configured_audiences):
            return _json_error(401, "Unauthorized")

    # Check scopes (route-level authorizationScopes)
    required_scopes = getattr(route, "authorization_scopes", []) or []
    if required_scopes:
        token_scopes_str = claims.get("scope", "") or claims.get("scp", "")
        if isinstance(token_scopes_str, list):
            token_scopes = set(token_scopes_str)
        else:
            token_scopes = set(token_scopes_str.split())
        if not set(required_scopes).issubset(token_scopes):
            return _json_error(403, "Forbidden")

    return None  # Validation passed


def _extract_jwt_claims(request: Request) -> dict:
    """Extract JWT claims from the Authorization header for authorizer context."""
    import base64

    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
    else:
        token = auth_header

    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


# ────────────────────────────────────────────────────────────────────
# SEC-03: API key enforcement
# ────────────────────────────────────────────────────────────────────


def _enforce_api_key(request: Request, api, api_id: str) -> Response | None:
    """Check x-api-key header against configured API keys.

    Returns error Response if invalid, None if valid.
    Also increments usage counter (PARITY-14).
    """
    api_key_header = request.headers.get("x-api-key", "")
    if not api_key_header:
        return _json_error(403, "Forbidden")

    # Look up valid keys from the moto backend
    # API keys in V2 are typically managed through stages or usage plans.
    # We check the api_key attribute on stages for simplicity.
    valid = False
    if hasattr(api, "stages"):
        for stage in api.stages.values():
            stage_api_key = getattr(stage, "api_key", None)
            if stage_api_key and stage_api_key == api_key_header:
                valid = True
                break

    # Also check top-level API tags for x-api-key (common pattern)
    if not valid:
        tags = getattr(api, "tags", {}) or {}
        configured_keys = tags.get("x-api-keys", "").split(",")
        if api_key_header in [k.strip() for k in configured_keys if k.strip()]:
            valid = True

    # In local emulation, accept any non-empty key when no keys are explicitly configured
    # (matches LocalStack behavior — avoids blocking users who haven't set keys in moto)
    if not valid:
        # Check if any keys are actually configured; if none, accept any key
        has_configured_keys = False
        if hasattr(api, "stages"):
            for stage in api.stages.values():
                if getattr(stage, "api_key", None):
                    has_configured_keys = True
                    break
        if has_configured_keys:
            return _json_error(403, "Forbidden")

    # PARITY-14: increment usage counter (PERF-R2-04: bounded LRU)
    with _api_key_usage_lock:
        api_map = _api_key_usage.get(api_id)
        if api_map is None:
            if len(_api_key_usage) >= _API_KEY_USAGE_MAX_APIS:
                _api_key_usage.popitem(last=False)
            api_map = OrderedDict()
            _api_key_usage[api_id] = api_map
        else:
            _api_key_usage.move_to_end(api_id)

        current = api_map.get(api_key_header, 0)
        if api_key_header not in api_map:
            if len(api_map) >= _API_KEY_USAGE_MAX_KEYS_PER_API:
                api_map.popitem(last=False)
        api_map[api_key_header] = current + 1
        api_map.move_to_end(api_key_header)

    return None


# ────────────────────────────────────────────────────────────────────
# PARITY-04: Basic in-memory response cache
# ────────────────────────────────────────────────────────────────────


def _cache_get(key: str) -> Response | None:
    """Retrieve a cached response if still valid (PERF-R2-02 LRU)."""
    with _response_cache_lock:
        entry = _response_cache.get(key)
        if entry is None:
            return None
        expires, response = entry
        if time.monotonic() > expires:
            del _response_cache[key]
            return None
        _response_cache.move_to_end(key)
        return response


def _cache_put(key: str, response: Response, ttl: float):
    """Store a response in the cache (PERF-R2-02: bounded LRU, evict oldest)."""
    with _response_cache_lock:
        if key in _response_cache:
            _response_cache.move_to_end(key)
        elif len(_response_cache) >= _RESPONSE_CACHE_MAXSIZE:
            _response_cache.popitem(last=False)
        _response_cache[key] = (time.monotonic() + ttl, response)


# ────────────────────────────────────────────────────────────────────
# PARITY-06: Access logging to CloudWatch Logs
# ────────────────────────────────────────────────────────────────────


def _write_access_log(stage_obj, api_id, stage, request, response, route_match, account_id, region):
    """Write an access log entry to CloudWatch Logs when accessLogSettings is configured."""
    access_log_settings = getattr(stage_obj, "access_log_settings", None)
    if not access_log_settings:
        return
    destination_arn = None
    if isinstance(access_log_settings, dict):
        destination_arn = access_log_settings.get("DestinationArn")
    else:
        destination_arn = getattr(access_log_settings, "destination_arn", None)

    if not destination_arn:
        return

    try:
        # Extract log group name from ARN (arn:aws:logs:region:account:log-group:NAME)
        arn_parts = destination_arn.split(":")
        log_group_name = arn_parts[-1] if len(arn_parts) > 5 else destination_arn

        now = datetime.now(timezone.utc)
        log_entry = json.dumps({
            "requestId": short_uid(),
            "ip": request.remote_addr or "127.0.0.1",
            "httpMethod": request.method,
            "routeKey": route_match.route_key,
            "status": response.status_code if hasattr(response, "status_code") else 200,
            "protocol": "HTTP/1.1",
            "responseLength": len(response.get_data()) if hasattr(response, "get_data") else 0,
            "path": request.path,
            "stage": stage,
            "apiId": api_id,
            "time": now.isoformat(),
        })

        logs_client = connect_to(
            aws_access_key_id=account_id,
            region_name=region,
        ).logs

        log_stream_name = f"apigw-v2-{api_id}-{stage}"

        # Ensure stream exists (idempotent)
        try:
            logs_client.create_log_group(logGroupName=log_group_name)
        except Exception:
            pass  # Already exists
        try:
            logs_client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
            )
        except Exception:
            pass  # Already exists

        logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    "timestamp": int(now.timestamp() * 1000),
                    "message": log_entry,
                }
            ],
        )
    except Exception as e:
        LOG.debug("Access log write failed (non-fatal): %s", e)


# ────────────────────────────────────────────────────────────────────
# PARITY-16: Basic stage-level throttling
# ────────────────────────────────────────────────────────────────────


def _check_throttle(api_id: str, stage: str, stage_obj) -> Response | None:
    """Enforce basic rate limiting when stage has throttling configured.

    Returns 429 if rate exceeded, None otherwise.
    """
    if not stage_obj:
        return None

    # Check for default route throttling settings
    throttle_settings = getattr(stage_obj, "default_route_settings", None)
    if not throttle_settings:
        return None

    if isinstance(throttle_settings, dict):
        rate_limit = throttle_settings.get("ThrottlingRateLimit")
        burst_limit = throttle_settings.get("ThrottlingBurstLimit")
    else:
        rate_limit = getattr(throttle_settings, "throttling_rate_limit", None)
        burst_limit = getattr(throttle_settings, "throttling_burst_limit", None)

    if not rate_limit and not burst_limit:
        return None

    effective_rate = rate_limit or 1000  # default high
    key = f"{api_id}:{stage}"
    now = time.monotonic()
    window = 1.0  # 1-second window

    with _throttle_lock:
        timestamps = _throttle_state[key]
        # Prune old entries
        cutoff = now - window
        _throttle_state[key] = [t for t in timestamps if t > cutoff]
        timestamps = _throttle_state[key]

        if len(timestamps) >= effective_rate:
            return _json_error(429, "Too Many Requests")
        timestamps.append(now)

    return None
