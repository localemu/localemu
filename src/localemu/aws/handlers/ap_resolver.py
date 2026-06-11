"""Request-chain handlers for S3 access-point resolution.

Two handlers cooperate:

1. :class:`AccessPointHostRewriter` runs EARLY in the chain (right after
   ``parse_service_name`` and before ``parse_service_request``). It
   inspects the ``Host`` header and the raw URL ; when the request is
   addressed to an access point via the boto3-with-custom-endpoint
   hostname form (``<name>-<account>.<endpoint-host>``) it rewrites the
   ``Host`` header to the underlying-bucket virtual-host form so the
   existing S3 service-request parser produces the right ``Bucket``
   parameter. AP metadata is stashed on a request-scoped header
   ``x-localemu-resolved-ap-arn`` for the post-parse handler.

2. :class:`AccessPointResolver` runs AFTER ``parse_service_request`` and
   before ``iam_enforcement``. It detects the remaining addressing
   forms (Bucket=ARN, Bucket=alias), reads the
   ``x-localemu-resolved-ap-arn`` hint left by the rewriter, looks up
   the AP record once authoritatively, populates the ``context._ap_*``
   fields, and enforces AP-incompatible operations + VPC origin.

The handlers are no-ops for non-S3 requests and S3 requests that
don't address an access point.
"""

from __future__ import annotations

import logging
import re

from localemu.aws.api import RequestContext
from localemu.aws.chain import Handler, HandlerChain
from localemu.http import Response

LOG = logging.getLogger(__name__)


# Boto3-with-custom-endpoint emits this for `Bucket=<AP ARN>` calls:
#   host = <ap-name>-<account>.<endpoint-host>[:port]
# We match the first dot-segment ; the underlying bucket is looked up
# against moto's s3control backend, and on hit the Host is rewritten to
# `<underlying-bucket>.<endpoint-host>:port`. The existing virtual-host
# parser in services/s3/utils.py already handles `<bucket>.<anyhost>`.
_AP_BOTO_HOST_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*[a-z0-9])-(?P<account>\d{12})\.(?P<rest>.+)$"
)


class AccessPointHostRewriter(Handler):
    """Rewrite AP-style hostnames so the S3 parser sees the underlying bucket."""

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        try:
            if context.service is None or context.service.service_name != "s3":
                return
        except Exception:
            return

        host = context.request.headers.get("host") if context.request else None
        if not host:
            return

        m = _AP_BOTO_HOST_RE.match(host)
        if m is None:
            return

        # Confirm the AP exists before rewriting — otherwise this could
        # be a legitimate bucket whose name happens to contain a
        # 12-digit suffix.
        from localemu.services.s3.access_point_router import _find_ap

        ap = _find_ap(m.group("account"), "us-east-1", m.group("name"))
        if ap is None:
            return

        underlying = getattr(ap, "bucket", None)
        if not underlying:
            return

        # Rewrite the Host header so downstream parsers extract
        # ``Bucket=<underlying>`` from the now-conventional virtual host.
        # The existing S3 virtual-host regex in services/s3/utils.py
        # requires ``.s3.<region>.`` between bucket and tail, so we
        # inject that segment regardless of the upstream endpoint host.
        new_host = f"{underlying}.s3.us-east-1.{m.group('rest')}"
        context.request.headers["host"] = new_host
        # Leave a breadcrumb the post-parse resolver can read to avoid
        # re-doing the AP lookup.
        context.request.headers["x-localemu-resolved-ap-arn"] = \
            getattr(ap, "arn", "") or ""
        context.request.headers["x-localemu-resolved-ap-account"] = \
            m.group("account")
        context.request.headers["x-localemu-resolved-ap-name"] = \
            m.group("name")
        LOG.debug(
            "AP host rewrite: %s -> %s (underlying=%s)",
            host, new_host, underlying,
        )


access_point_host_rewriter = AccessPointHostRewriter()


class AccessPointResolver(Handler):
    """Resolve access-point addressing and stash AP context."""

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Only relevant for S3 service requests.
        try:
            if context.service is None or context.service.service_name != "s3":
                return
        except Exception:
            return

        from localemu.services.s3.access_point_router import (
            AccessPointFsxUnsupported,
            AccessPointMrapUnsupported,
            AccessPointNotFound,
            AP_INCOMPATIBLE_OPS,
            resolve_access_point,
        )
        from localemu.aws.api import CommonServiceException

        params = context.service_request or {}
        bucket_param = params.get("Bucket") if isinstance(params, dict) else None
        host = context.request.headers.get("host") if context.request else None

        # Fast path: the early host-rewriter already resolved this and
        # left a breadcrumb header. Build the context from it without
        # re-walking moto.
        resolved_arn = context.request.headers.get("x-localemu-resolved-ap-arn")
        resolved_acct = context.request.headers.get("x-localemu-resolved-ap-account")
        resolved_name = context.request.headers.get("x-localemu-resolved-ap-name")
        ap_ctx = None
        if resolved_arn and resolved_acct and resolved_name:
            from localemu.services.s3.access_point_router import (
                _find_ap, AccessPointContext, _load_ap_policy,
            )
            ap = _find_ap(resolved_acct, "us-east-1", resolved_name)
            if ap is not None:
                ap_ctx = AccessPointContext(
                    arn=resolved_arn,
                    account=resolved_acct,
                    region=getattr(ap, "region_name", "us-east-1"),
                    name=resolved_name,
                    network_origin=getattr(ap, "network_origin", "Internet"),
                    vpc_id=getattr(ap, "vpc_id", None),
                    policy=_load_ap_policy(ap),
                    underlying_bucket=getattr(ap, "bucket", ""),
                )

        try:
            if ap_ctx is None:
                ap_ctx = resolve_access_point(bucket_param, host)
        except AccessPointMrapUnsupported as e:
            raise CommonServiceException(
                code="InvalidRequest", message=str(e), status_code=400,
            )
        except AccessPointFsxUnsupported as e:
            raise CommonServiceException(
                code="InvalidRequest", message=str(e), status_code=400,
            )
        except AccessPointNotFound:
            raise CommonServiceException(
                code="NoSuchBucket",
                message="The specified access point does not exist",
                status_code=404,
            )

        if ap_ctx is None:
            return

        # AP-incompatible operation?
        op_name = ""
        try:
            op_name = context.operation.name
        except Exception:
            pass
        if op_name in AP_INCOMPATIBLE_OPS:
            raise CommonServiceException(
                code="InvalidRequest",
                message="The specified method is not allowed against this resource.",
                status_code=400,
            )

        # Stash the context for downstream consumers.
        context._ap_arn = ap_ctx.arn
        context._ap_account = ap_ctx.account
        context._ap_region = ap_ctx.region
        context._ap_name = ap_ctx.name
        context._ap_origin = ap_ctx.network_origin
        context._ap_vpc_id = ap_ctx.vpc_id
        context._ap_policy = ap_ctx.policy
        context._ap_underlying_bucket = ap_ctx.underlying_bucket

        # Rewrite the Bucket param to the underlying bucket name so the S3
        # provider's existing lookup path serves the request as usual.
        if isinstance(params, dict):
            params["Bucket"] = ap_ctx.underlying_bucket
            context.service_request = params

        # VPC-origin enforcement: requests to a VPC-restricted AP must
        # carry the ``x-localemu-from-vpc-id`` header matching the AP's
        # ``VpcConfiguration.VpcId``. Real AWS enforces this via network
        # isolation (PrivateLink); LocalEmu has no PrivateLink emulation
        # so the header is the per-request "from VPC" assertion.
        if ap_ctx.network_origin == "VPC":
            from_vpc = context.request.headers.get("x-localemu-from-vpc-id") \
                or context.request.headers.get("X-LocalEmu-From-Vpc-Id")
            if not from_vpc or from_vpc != (ap_ctx.vpc_id or ""):
                raise CommonServiceException(
                    code="AccessDenied",
                    message="This access point does not allow requests "
                            "from this network.",
                    status_code=403,
                )

        LOG.debug(
            "AP routed: %s -> bucket=%s (origin=%s, vpc=%s)",
            ap_ctx.arn, ap_ctx.underlying_bucket,
            ap_ctx.network_origin, ap_ctx.vpc_id,
        )


# Singleton instance for the request chain.
access_point_resolver = AccessPointResolver()
