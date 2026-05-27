"""OAC / OAI enforcement on S3.

When a CloudFront distribution is created with an Origin Access Control
binding to an S3 bucket, AWS blocks direct S3 reads against that bucket
from anyone other than the CloudFront service principal. We simulate this
locally:

  - Our data-plane router tags every CloudFront → S3 origin fetch with
    an ``X-Localemu-Cloudfront-Distribution`` header.
  - A :class:`OACGuard` handler in the gateway's request chain inspects
    each S3 request. When the target bucket has an active OAC / OAI
    binding and the CloudFront marker is absent, the handler returns
    403 before the request reaches the S3 provider.

The handler is a peer of IAM enforcement — a cross-cutting policy check
that sits in the chain rather than wrapping individual provider methods.
Method-level patching was the first approach I tried; it fails because
LocalEmu's skeleton builds S3's dispatch table at service construction
and our patch applies later, so the already-built table keeps a
reference to the unpatched method.

Users who find this too strict can set ``CLOUDFRONT_OAC_ENFORCE=0`` to
disable the guard globally.
"""

from __future__ import annotations

import logging
import os

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.aws.chain import Handler, HandlerChain
from localemu.http import Response

LOG = logging.getLogger(__name__)

_DISTRIBUTION_HEADER = "X-Localemu-Cloudfront-Distribution"

# S3 read operations that load actual bucket content. Write operations
# (PutObject, DeleteObject) aren't guarded — AWS's OAC is read-path only.
_GUARDED_OPERATIONS = {"GetObject", "HeadObject"}


def _enforce_enabled() -> bool:
    raw = os.environ.get("CLOUDFRONT_OAC_ENFORCE", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _bucket_is_oac_locked(account_id: str, bucket: str) -> bool:
    """True if the bucket has any active OAC or OAI binding from any
    distribution in the given account.
    """
    try:
        from localemu.services.cloudfront.models import get_cloudfront_store
    except ImportError:
        return False

    try:
        store = get_cloudfront_store(account_id or "000000000000")
    except Exception:
        return False

    arn = f"arn:aws:s3:::{bucket}"
    return bool(
        store.oac_bucket_bindings.get(arn)
        or store.oai_bucket_bindings.get(arn)
    )


def _from_cloudfront_router(headers) -> bool:
    """True if the request carries our data-plane marker header.

    Header name matching is case-insensitive — rolo / werkzeug headers
    are case-insensitive but older callers sometimes interact with raw
    dicts so we check both forms explicitly.
    """
    for name in (_DISTRIBUTION_HEADER, _DISTRIBUTION_HEADER.lower()):
        try:
            if name in headers:
                return True
        except TypeError:
            # headers object may not support ``in`` cleanly on all shapes
            pass
    return False


class OACGuard(Handler):
    """Handler-chain entry that blocks direct reads of OAC-locked S3 buckets.

    Runs on every request. Fast path: if the request isn't S3 or isn't a
    guarded operation, return immediately with zero work.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not _enforce_enabled():
            return
        if context.service is None or context.service.service_name != "s3":
            return
        op = context.operation
        if op is None or op.name not in _GUARDED_OPERATIONS:
            return
        if _from_cloudfront_router(context.request.headers):
            return
        bucket = (context.service_request or {}).get("Bucket", "")
        if not bucket:
            return
        account_id = getattr(context, "account_id", "") or "000000000000"
        if not _bucket_is_oac_locked(account_id, bucket):
            return

        LOG.info(
            "CloudFront OAC guard: blocking direct %s on OAC-locked bucket %s",
            op.name, bucket,
        )
        raise CommonServiceException(
            code="AccessDenied",
            message=(
                "Access Denied: this S3 bucket is protected by a CloudFront "
                "Origin Access Control. Direct reads are only permitted "
                "through the associated CloudFront distribution. "
                "(LocalEmu simulation — set CLOUDFRONT_OAC_ENFORCE=0 to "
                "disable.)"
            ),
            status_code=403,
        )


_guard_instance: OACGuard | None = None


def get_handler() -> OACGuard:
    """Return the singleton guard handler."""
    global _guard_instance
    if _guard_instance is None:
        _guard_instance = OACGuard()
    return _guard_instance


def apply() -> None:
    """Kept for symmetry with ``_moto_patches.apply``. The handler is
    actually installed into the gateway's chain by ``aws/app.py`` at
    construction time; this function exists so module import doesn't
    miss a setup hook the reader would otherwise expect.
    """
    # Ensure the singleton is eagerly constructed so the chain has a
    # concrete instance to call.
    get_handler()
