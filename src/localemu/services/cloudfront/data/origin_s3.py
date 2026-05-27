"""S3 origin resolver for the CloudFront data plane.

Fetches an object from a bucket referenced by a CloudFront distribution
origin. Uses LocalEmu's internal ``connect_to`` client — the request
stays on localhost and passes through S3's full handler chain so the
OAC S3 guard sees the marker header we inject and decides whether to
allow or block.

Intentionally thin: one function, one responsibility.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from localemu.aws.connect import connect_to

LOG = logging.getLogger(__name__)


_S3_HOST_RE = re.compile(
    r"^(?P<bucket>[^./]+)\.s3[.-](?:(?P<region>[a-z0-9-]+)\.)?amazonaws\.com$"
)

_DISTRIBUTION_HEADER = "X-Localemu-Cloudfront-Distribution"


@dataclass
class OriginResponse:
    """What the router gets back from an origin fetch.

    ``None`` for ``body`` and a 4xx/5xx status means the origin could not
    serve the object; the router returns the status as-is without caching.
    """

    status: int
    body: bytes
    headers: dict[str, str]


def is_s3_origin(domain_name: str) -> bool:
    """True if ``DomainName`` matches an S3 virtual-hosted pattern."""
    return bool(_S3_HOST_RE.match(domain_name or ""))


def bucket_from_origin(domain_name: str) -> str | None:
    """Extract the S3 bucket name from an S3-style origin DomainName."""
    m = _S3_HOST_RE.match(domain_name or "")
    return m.group("bucket") if m else None


def fetch(
    *,
    origin: dict[str, Any],
    object_key: str,
    distribution_id: str,
    account_id: str,
    region: str,
    range_header: str | None = None,
    if_none_match: str | None = None,
) -> OriginResponse:
    """Fetch an object from an S3 origin.

    Args:
        origin: The origin dict from the distribution config. Must carry
            ``DomainName``.
        object_key: The object key relative to the bucket root. The router
            is responsible for applying the origin's ``OriginPath`` prefix.
        distribution_id: The CloudFront distribution id making this fetch.
            Propagated to S3 via a header so the OAC guard can recognize
            the call as a legitimate CloudFront origin pull.
        account_id / region: used to target the internal boto3 client.
        range_header: Optional ``Range:`` header value to pass through.
        if_none_match: Optional ``If-None-Match:`` ETag value.

    Returns:
        :class:`OriginResponse`. On 404 / 403 / 5xx the caller must NOT
        cache — those statuses propagate unchanged.
    """
    bucket = bucket_from_origin(origin.get("DomainName", ""))
    if not bucket:
        return OriginResponse(status=404, body=b"", headers={})

    extra_kwargs: dict[str, Any] = {}
    if range_header:
        extra_kwargs["Range"] = range_header
    if if_none_match:
        extra_kwargs["IfNoneMatch"] = if_none_match

    client = connect_to(
        aws_access_key_id=account_id, region_name=region,
    ).s3

    # Inject the distribution marker on the outgoing HTTP request so the
    # OAC/OAI S3 guard (auth/oac_guard.py) can recognize that this
    # request is a CloudFront origin pull and not an outside attempt to
    # reach a locked bucket directly.
    def _inject_marker(request, **_kw):
        request.headers[_DISTRIBUTION_HEADER] = distribution_id

    client.meta.events.register("before-send.s3.*", _inject_marker)

    try:
        resp = client.get_object(Bucket=bucket, Key=object_key, **extra_kwargs)
    except client.exceptions.NoSuchKey:
        return OriginResponse(status=404, body=b"", headers={})
    except client.exceptions.NoSuchBucket:
        return OriginResponse(status=404, body=b"", headers={})
    except Exception as err:
        err_code = getattr(err, "response", {}).get("Error", {}).get("Code", "")
        if err_code in {"NoSuchKey", "NoSuchBucket"}:
            return OriginResponse(status=404, body=b"", headers={})
        if err_code == "AccessDenied":
            return OriginResponse(status=403, body=b"", headers={})
        LOG.warning(
            "S3 origin fetch failed for %s/%s (dist=%s): %s",
            bucket, object_key, distribution_id, err, exc_info=True,
        )
        return OriginResponse(status=502, body=b"", headers={})
    finally:
        # Detach the hook so the client (which may be cached by connect_to)
        # doesn't carry our marker to unrelated callers.
        try:
            client.meta.events.unregister("before-send.s3.*", _inject_marker)
        except Exception:
            pass

    body = resp["Body"].read() if "Body" in resp else b""
    headers: dict[str, str] = {}
    if "ContentType" in resp:
        headers["Content-Type"] = resp["ContentType"]
    if "ETag" in resp:
        headers["ETag"] = resp["ETag"]
    if "LastModified" in resp:
        headers["Last-Modified"] = resp["LastModified"].strftime(
            "%a, %d %b %Y %H:%M:%S GMT",
        )
    if "ContentLength" in resp:
        headers["Content-Length"] = str(resp["ContentLength"])
    if "ContentRange" in resp:
        headers["Content-Range"] = resp["ContentRange"]
    # Caller uses status 206 for range responses; s3 signals this via ContentRange.
    status = 206 if "ContentRange" in resp else 200
    return OriginResponse(status=status, body=body, headers=headers)
