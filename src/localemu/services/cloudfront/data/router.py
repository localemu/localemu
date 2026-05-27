"""CloudFront distribution URL router.

Mounts path-based routes on LocalEmu's edge ``ROUTER`` at the first
provider construction so ``http://localhost:4566/cloudfront/<dist-id>/<path>``
serves through our cache + origin chain. Hostname-based routing
(``<dist-id>.cloudfront.local``) can follow in a later phase.

Request flow:

  1. Match distribution id from URL → look up distribution config via
     moto.
  2. Match a cache behavior for the request path (first match in the
     user's PathPattern list; falls back to DefaultCacheBehavior).
  3. Build a cache key from (URI, whitelisted query params,
     whitelisted headers) as declared by the cache policy.
  4. Cache HIT → return the cached body + headers.
  5. Cache MISS → route to the first origin whose ``Id`` matches the
     behavior's ``TargetOriginId`` and fetch; on 2xx, cache with TTL
     derived from the behavior's min/max/default TTL (v1 uses
     DefaultTTL).
  6. Return origin's response with a synthetic ``X-Cache: Hit from
     cloudfront`` or ``Miss from cloudfront`` header.

The router keeps its registered rules so ``unregister_routes`` can cleanly
detach them at service shutdown or when tests tear the edge down.
"""

from __future__ import annotations

import logging
import re
import threading
import urllib.parse
from typing import Any

from rolo import Request, Router
from rolo.routing.handler import Handler
from werkzeug.routing import Rule

from localemu.http import Response
from localemu.services.edge import ROUTER

from .cache import CacheEntry, DistributionCache, get_cache
from . import origin_http, origin_s3
from .origin_s3 import OriginResponse
from ..edge import chain as edge_chain
from ..edge.event_builder import (
    EVENT_ORIGIN_REQUEST,
    EVENT_ORIGIN_RESPONSE,
    EVENT_VIEWER_REQUEST,
    EVENT_VIEWER_RESPONSE,
)

LOG = logging.getLogger(__name__)


# Public path prefix. Independent of any DNS-based routing we may add later.
INTERNAL_PATH_PREFIX = "/cloudfront"


class CloudFrontEndpoint:
    """Router endpoint that serves data-plane requests.

    Request flow with Lambda@Edge integration:

      1. Resolve distribution + behaviour + origin.
      2. Build initial :class:`~..edge.chain.RequestState` from the
         inbound request.
      3. Run the viewer-request chain. If a function short-circuits,
         jump to step 9 with the synthesised response.
      4. Consult the cache with the (possibly mutated) request.
      5. Cache MISS: run the origin-request chain. Short-circuit has
         the same effect as step 3.
      6. Fetch from origin.
      7. Build :class:`~..edge.chain.ResponseState` and run the
         origin-response chain.
      8. Cache 2xx responses.
      9. Run the viewer-response chain on the final response.
     10. Return to the client.
    """

    def __init__(self, cache: DistributionCache | None = None) -> None:
        self._cache = cache or get_cache()

    def __call__(self, request: Request, **kwargs: Any) -> Response:
        dist_id = kwargs.get("dist_id") or ""
        object_path = kwargs.get("path") or ""

        distribution = _load_distribution(dist_id)
        if distribution is None:
            return Response(status=404, response=b"NoSuchDistribution")

        if _distribution_status(distribution) not in (None, "Deployed"):
            return Response(status=403, response=b"Distribution not yet deployed")

        behavior = _match_cache_behavior(distribution, object_path)
        moto_default_cb = _moto_default_cache_behaviour(distribution)
        origins = _origins_of(distribution)
        origin = _pick_origin(origins, behavior.get("TargetOriginId"))
        if origin is None:
            return Response(status=502, response=b"No matching origin")

        # ------------------------------------------------------------------
        # Build request state
        # ------------------------------------------------------------------
        req_state = edge_chain.RequestState(
            method=request.method or "GET",
            uri=f"/{object_path}" if object_path else "/",
            querystring=request.query_string.decode() if request.query_string else "",
            headers=_headers_as_dict(request.headers),
            body=request.get_data(cache=True) if request.content_length else None,
        )
        account_id = _owner_account_id(distribution)
        request_id = _new_request_id()
        client_ip = request.remote_addr or "127.0.0.1"

        # ------------------------------------------------------------------
        # Viewer-request chain
        # ------------------------------------------------------------------
        short = edge_chain.run_request_chain(
            event_type=EVENT_VIEWER_REQUEST,
            cache_behavior=moto_default_cb,
            distribution_id=dist_id,
            request_id=request_id,
            request=req_state,
            client_ip=client_ip,
        )
        if short is not None:
            return self._finish_with_viewer_response(
                short_circuit_to_response(short), req_state, dist_id,
                request_id, client_ip, moto_default_cb,
            )

        # ------------------------------------------------------------------
        # Cache lookup against the (possibly mutated) request.
        # ------------------------------------------------------------------
        cache_uri = req_state.uri.lstrip("/")
        cache_key = _build_cache_key(
            path=cache_uri, query_string=req_state.querystring,
            behavior=behavior, headers=req_state.headers,
        )
        cached = self._cache.get(dist_id, cache_key)
        if cached is not None:
            resp_state = edge_chain.ResponseState(
                status=cached.status, headers=dict(cached.headers), body=cached.body,
            )
            return self._finish_with_viewer_response(
                resp_state, req_state, dist_id, request_id, client_ip, moto_default_cb,
                from_cache=True,
            )

        # ------------------------------------------------------------------
        # Origin-request chain (cache miss path only)
        # ------------------------------------------------------------------
        short = edge_chain.run_request_chain(
            event_type=EVENT_ORIGIN_REQUEST,
            cache_behavior=moto_default_cb,
            distribution_id=dist_id,
            request_id=request_id,
            request=req_state,
            client_ip=client_ip,
        )
        if short is not None:
            return self._finish_with_viewer_response(
                short_circuit_to_response(short), req_state, dist_id,
                request_id, client_ip, moto_default_cb,
            )

        # ------------------------------------------------------------------
        # Origin fetch
        # ------------------------------------------------------------------
        origin_path = (origin.get("OriginPath") or "").rstrip("/")
        fetch_key = req_state.uri.lstrip("/")
        if origin_path:
            fetch_key = (origin_path + "/" + fetch_key).lstrip("/")

        fetched = _fetch_from_origin(
            origin=origin,
            object_key=fetch_key,
            distribution_id=dist_id,
            account_id=account_id,
            region="us-east-1",
            range_header=req_state.headers.get("Range"),
            if_none_match=req_state.headers.get("If-None-Match"),
        )

        resp_state = edge_chain.ResponseState(
            status=fetched.status,
            headers=dict(fetched.headers),
            body=fetched.body,
        )

        # ------------------------------------------------------------------
        # Origin-response chain
        # ------------------------------------------------------------------
        edge_chain.run_response_chain(
            event_type=EVENT_ORIGIN_RESPONSE,
            cache_behavior=moto_default_cb,
            distribution_id=dist_id,
            request_id=request_id,
            request=req_state,
            response=resp_state,
            client_ip=client_ip,
        )

        # Cache 2xx after origin-response mutations.
        if 200 <= resp_state.status < 300:
            ttl = _default_ttl(behavior)
            if ttl > 0:
                import time as _time
                entry = CacheEntry(
                    body=resp_state.body,
                    headers=dict(resp_state.headers),
                    status=resp_state.status,
                    expires_at=_time.time() + ttl,
                    uri_path=_normalized_uri_for_cache(req_state.uri),
                )
                self._cache.put(dist_id, cache_key, entry)

        return self._finish_with_viewer_response(
            resp_state, req_state, dist_id, request_id, client_ip, moto_default_cb,
        )

    def _finish_with_viewer_response(
        self,
        resp_state: edge_chain.ResponseState,
        req_state: edge_chain.RequestState,
        dist_id: str,
        request_id: str,
        client_ip: str,
        cache_behavior: Any,
        *,
        from_cache: bool = False,
    ) -> Response:
        """Final stage: run viewer-response chain and emit the HTTP Response."""
        edge_chain.run_response_chain(
            event_type=EVENT_VIEWER_RESPONSE,
            cache_behavior=cache_behavior,
            distribution_id=dist_id,
            request_id=request_id,
            request=req_state,
            response=resp_state,
            client_ip=client_ip,
        )
        resp = Response(status=resp_state.status, response=resp_state.body)
        for k, v in resp_state.headers.items():
            resp.headers[k] = v
        resp.headers["X-Cache"] = (
            "Hit from cloudfront" if from_cache else "Miss from cloudfront"
        )
        return resp


def short_circuit_to_response(
    short: edge_chain.ShortCircuit,
) -> edge_chain.ResponseState:
    """Wrap a short-circuit into a ResponseState so the viewer-response
    chain can still run against it (AWS applies viewer-response even to
    short-circuited responses).
    """
    return edge_chain.ResponseState(
        status=short.status,
        headers=dict(short.headers),
        body=short.body,
    )


def _new_request_id() -> str:
    """CloudFront request ids are base64-looking ~56-char opaque strings.
    A uuid4 hex is close enough for local emulation."""
    import uuid
    return uuid.uuid4().hex


def _headers_as_dict(headers) -> dict[str, str]:
    """werkzeug EnvironHeaders → plain dict, preserving the first value
    for multi-valued headers (same convention as AWS)."""
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        return out
    for k, v in items:
        if k not in out:
            out[k] = v
    return out


def _moto_default_cache_behaviour(distribution: Any) -> Any:
    """Return moto's raw DefaultCacheBehaviour object (not our projection).

    The chain runner needs the raw object because it carries
    ``lambda_function_associations`` which our projection does not (yet)
    round-trip.
    """
    try:
        return distribution.distribution_config.default_cache_behavior
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

class CloudFrontRouter:
    """Manages the lifecycle of CloudFront data-plane routes on ``ROUTER``.

    Singleton-use: call :func:`ensure_routes_registered` once from the
    provider's lifecycle hook.
    """

    def __init__(
        self, router: Router[Handler] | None = None,
        endpoint: CloudFrontEndpoint | None = None,
    ) -> None:
        self.router = router or ROUTER
        self.endpoint = endpoint or CloudFrontEndpoint()
        self.registered: list[Rule] = []
        self._lock = threading.Lock()

    def register(self) -> None:
        with self._lock:
            if self.registered:
                return
            rules = [
                # Default root object: /cloudfront/<dist_id>/
                self.router.add(
                    path=f"{INTERNAL_PATH_PREFIX}/<dist_id>/",
                    endpoint=self.endpoint,
                    defaults={"path": ""},
                    strict_slashes=False,
                ),
                # Catch-all: /cloudfront/<dist_id>/<path>
                self.router.add(
                    path=f"{INTERNAL_PATH_PREFIX}/<dist_id>/<path:path>",
                    endpoint=self.endpoint,
                    strict_slashes=True,
                ),
            ]
            self.registered.extend(rules)
            LOG.info("cloudfront router mounted at %s/<dist-id>/*", INTERNAL_PATH_PREFIX)

    def unregister(self) -> None:
        with self._lock:
            for rule in self.registered:
                try:
                    self.router.remove(rule)
                except Exception:
                    LOG.debug("failed to unregister cloudfront rule", exc_info=True)
            self.registered.clear()


_singleton: CloudFrontRouter | None = None
_singleton_lock = threading.Lock()


def ensure_routes_registered() -> CloudFrontRouter:
    """Idempotent: returns the process-wide router, registering on first call."""
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            r = CloudFrontRouter()
            r.register()
            _singleton = r
    return _singleton


def reset_router_for_tests() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.unregister()
        _singleton = None


# ---------------------------------------------------------------------------
# Helpers (kept at module level so they're unit-testable without a router)
# ---------------------------------------------------------------------------

def _load_distribution(dist_id: str) -> Any | None:
    """Return moto's Distribution object for ``dist_id``, searching across
    every account because CloudFront is a global service and we don't
    know which account owns which id at route time.
    """
    try:
        from moto.cloudfront.models import cloudfront_backends
    except ImportError:
        return None
    # cloudfront_backends is account-keyed. Walk all accounts (usually 1).
    try:
        for account_id in cloudfront_backends:
            backend = cloudfront_backends[account_id]["global"]
            dist = getattr(backend, "distributions", {}).get(dist_id)
            if dist is not None:
                return dist
    except Exception:
        LOG.debug("failed to load distribution %s", dist_id, exc_info=True)
    return None


def _distribution_status(distribution: Any) -> str | None:
    """Read ``distribution.status``; moto's ManagedState makes this a
    property that performs the time-based status flip on read."""
    try:
        return distribution.status
    except Exception:
        return None


def _owner_account_id(distribution: Any) -> str:
    """Extract account id from the distribution ARN; fall back to default."""
    arn = getattr(distribution, "arn", "") or ""
    parts = arn.split(":")
    if len(parts) >= 5 and parts[4]:
        return parts[4]
    return "000000000000"


def _origins_of(distribution: Any) -> list[dict[str, Any]]:
    """Project distribution origins back into dict form matching the
    request-payload shape the rest of the data plane expects.

    Moto's Origin objects don't match the wire schema 1:1 (s3_access_identity
    instead of S3OriginConfig, custom_origin instead of CustomOriginConfig,
    etc.), so we rebuild the shape here. The origin_access_control_id
    attribute added by our moto patch is propagated through.
    """
    try:
        dist_config = distribution.distribution_config
        origins = getattr(dist_config, "origins", []) or []
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for o in origins:
        entry: dict[str, Any] = {
            "Id": getattr(o, "id", ""),
            "DomainName": getattr(o, "domain_name", ""),
            "OriginPath": getattr(o, "origin_path", "") or "",
        }
        oac = getattr(o, "origin_access_control_id", "")
        if oac:
            entry["OriginAccessControlId"] = oac
        s3_access_identity = getattr(o, "s3_access_identity", "")
        if s3_access_identity:
            entry["S3OriginConfig"] = {"OriginAccessIdentity": s3_access_identity}
        custom = getattr(o, "custom_origin", None)
        if custom is not None:
            entry["CustomOriginConfig"] = {
                "HTTPPort": getattr(custom, "http_port", 80),
                "HTTPSPort": getattr(custom, "https_port", 443),
                "OriginProtocolPolicy": getattr(custom, "protocol_policy",
                                                 "match-viewer"),
                "OriginReadTimeout": getattr(custom, "read_timeout", 30),
            }
        custom_headers = getattr(o, "custom_headers", None)
        if custom_headers:
            entry["CustomHeaders"] = {"Items": list(custom_headers)}
        out.append(entry)
    return out


def _pick_origin(origins: list[dict[str, Any]], target_id: str) -> dict[str, Any] | None:
    for o in origins:
        if o.get("Id") == target_id:
            return o
    # Fallback: if there's exactly one origin, use it. Covers the common
    # single-origin distribution where the user didn't care to set
    # TargetOriginId explicitly.
    if len(origins) == 1:
        return origins[0]
    return None


def _match_cache_behavior(distribution: Any, object_path: str) -> dict[str, Any]:
    """Return a cache-behavior dict for the given path.

    v1 uses DefaultCacheBehavior exclusively. Path-pattern-based cache
    behaviors can follow in a later phase — they require walking
    ``distribution.distribution_config.cache_behaviors`` (Phase 2.1).
    """
    try:
        default = distribution.distribution_config.default_cache_behavior
    except Exception:
        return {}
    return {
        "TargetOriginId": getattr(default, "target_origin_id", ""),
        "DefaultTTL": getattr(default, "default_ttl", 0),
        "MinTTL": getattr(default, "min_ttl", 0),
        "MaxTTL": getattr(default, "max_ttl", 0),
        "Compress": getattr(default, "compress", False),
    }


def _default_ttl(behavior: dict[str, Any]) -> int:
    """The TTL we apply to fresh cache entries.

    CloudFront semantics: if origin returns Cache-Control max-age, honour
    it clamped by min/max TTL. v1 ignores origin headers and uses
    DefaultTTL directly — good enough for the common case where users
    set DefaultTTL on the behavior and don't tune per-response.
    """
    try:
        return max(0, int(behavior.get("DefaultTTL") or 0))
    except (TypeError, ValueError):
        return 0


_MULTI_SLASH_RE = re.compile(r"/+")


def _normalized_uri_for_cache(path: str) -> str:
    """Collapse redundant slashes and prepend ``/``.

    Used as the ``uri_path`` on a CacheEntry so invalidation pattern
    matching (which assumes ``/foo/bar`` form) works regardless of how
    the router received the path.
    """
    if not path:
        return "/"
    p = path if path.startswith("/") else "/" + path
    return _MULTI_SLASH_RE.sub("/", p)


def _build_cache_key(
    *,
    path: str,
    query_string: str,
    behavior: dict[str, Any],
    headers: Any,
) -> tuple:
    """Build a tuple cache key.

    v1 minimal policy:
      - full URI path
      - raw query string (stable-sorted for cache coherence regardless of
        arrival order)
      - empty header contribution (we don't forward headers to origin in v1)

    Path-pattern-based header / cookie / query whitelists come in Phase 2.1.
    """
    norm_path = _normalized_uri_for_cache(path)
    # Stable-sort query string: ?b=2&a=1 and ?a=1&b=2 should hit the same entry.
    pairs = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
    pairs.sort()
    canon_qs = urllib.parse.urlencode(pairs)
    return (norm_path, canon_qs)


def _fetch_from_origin(
    *,
    origin: dict[str, Any],
    object_key: str,
    distribution_id: str,
    account_id: str,
    region: str,
    range_header: str | None,
    if_none_match: str | None,
) -> OriginResponse:
    if origin_s3.is_s3_origin(origin.get("DomainName", "")):
        return origin_s3.fetch(
            origin=origin,
            object_key=object_key,
            distribution_id=distribution_id,
            account_id=account_id,
            region=region,
            range_header=range_header,
            if_none_match=if_none_match,
        )
    if origin_http.is_http_origin(origin):
        return origin_http.fetch(
            origin=origin,
            object_key=object_key,
            range_header=range_header,
            if_none_match=if_none_match,
        )
    return OriginResponse(status=502, body=b"", headers={})


def _response_from_entry(entry: CacheEntry, *, from_cache: bool) -> Response:
    resp = Response(status=entry.status, response=entry.body)
    for k, v in entry.headers.items():
        resp.headers[k] = v
    resp.headers["X-Cache"] = "Hit from cloudfront" if from_cache else "Miss from cloudfront"
    return resp
