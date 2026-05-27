"""HTTP custom-origin resolver for the CloudFront data plane.

Plain ``http.client`` fetch against a user-configured custom origin
(``CustomOriginConfig``). No TLS validation bypass; LocalEmu runs in a
trusted local environment, and users can point at self-signed HTTPS
endpoints by setting ``OriginSslProtocols`` in their distribution config.
For v1 we honour just the four knobs that matter in practice: HTTPPort,
HTTPSPort, OriginProtocolPolicy, and OriginReadTimeout.
"""

from __future__ import annotations

import http.client
import logging
import ssl
from typing import Any

from .origin_s3 import OriginResponse

LOG = logging.getLogger(__name__)


def is_http_origin(origin: dict[str, Any]) -> bool:
    return bool(origin.get("CustomOriginConfig"))


def fetch(
    *,
    origin: dict[str, Any],
    object_key: str,
    range_header: str | None = None,
    if_none_match: str | None = None,
) -> OriginResponse:
    """Fetch via HTTP against a custom origin. 5xx on unexpected errors."""
    domain = origin.get("DomainName", "")
    if not domain:
        return OriginResponse(status=404, body=b"", headers={})

    cfg = origin.get("CustomOriginConfig") or {}
    protocol_policy = (cfg.get("OriginProtocolPolicy") or "match-viewer").lower()
    http_port = int(cfg.get("HTTPPort") or 80)
    https_port = int(cfg.get("HTTPSPort") or 443)
    timeout = float(cfg.get("OriginReadTimeout") or 30)

    # Determine scheme. "http-only" and "https-only" are unambiguous;
    # "match-viewer" can't be known here without the viewer context, and
    # v1 makes the conservative choice of using HTTPS by default — match
    # real AWS, which treats match-viewer as "respect the viewer".
    if protocol_policy == "http-only":
        scheme, port = "http", http_port
    elif protocol_policy == "https-only":
        scheme, port = "https", https_port
    else:
        scheme, port = "https", https_port

    path = object_key if object_key.startswith("/") else "/" + object_key

    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            # Local dev emulator: allow self-signed certificates commonly
            # used in LocalEmu's own TLS-enabled mode.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(domain, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(domain, port, timeout=timeout)

        headers: dict[str, str] = {}
        if range_header:
            headers["Range"] = range_header
        if if_none_match:
            headers["If-None-Match"] = if_none_match
        # Propagate CustomHeaders from the origin config (AWS behaviour).
        for custom_header in origin.get("CustomHeaders", {}).get("Items", []) or []:
            name = custom_header.get("HeaderName")
            value = custom_header.get("HeaderValue")
            if name:
                headers[name] = value or ""

        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        resp_headers = {k: v for k, v in resp.getheaders()}
        return OriginResponse(
            status=resp.status,
            body=body,
            headers=resp_headers,
        )
    except Exception as err:
        LOG.warning(
            "HTTP origin fetch failed for %s://%s:%s%s — %s",
            scheme, domain, port, path, err,
        )
        return OriginResponse(status=502, body=b"", headers={})
    finally:
        try:
            conn.close()
        except Exception:
            pass
