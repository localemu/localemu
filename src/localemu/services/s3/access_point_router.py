"""S3 Access Point routing - the data-plane glue.

When a client addresses an S3 access point (via ARN, alias, or hostname),
this module resolves the access point to its underlying bucket, stashes
the access-point context on the request, and rewrites the `Bucket`
parameter so the rest of the S3 provider can serve the request as if it
came in against the underlying bucket directly.

Three addressing forms are detected (all map to the same access-point
record in moto's ``s3control_backends``):

1. **ARN**: ``arn:aws:s3:<region>:<account>:accesspoint/<name>``
2. **Alias**: ``<name>-<34-hex>-s3alias`` (lives in the bucket-name namespace)
3. **Hostname**: ``<name>-<account>.s3-accesspoint.<region>.amazonaws.com``

The resolver does NOT perform the underlying-bucket cross-account lookup;
that stays with ``_get_cross_account_bucket`` in the S3 provider.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Detection regexes
# --------------------------------------------------------------------------

# Full access-point ARN. Captures region (may be empty for MRAP - we reject
# empty), 12-digit account, and access-point name.
_AP_ARN_RE = re.compile(
    r"^arn:aws:s3:(?P<region>[a-z0-9-]*):(?P<account>\d{12}):accesspoint/(?P<name>[a-z0-9][a-z0-9-]{1,48}[a-z0-9])$"
)

# Alias form: <ap-name>-<34-hex>-s3alias (or -ext-s3alias for FSx-backed,
# which we don't support in 1.1.0 but still detect to give a typed error).
_AP_ALIAS_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*[a-z0-9])-(?P<rnd>[0-9a-f]{34})(?P<ext>-ext)?-s3alias$"
)

# Hostname form: <ap-name>-<account>.s3-accesspoint.<region>.amazonaws.com
# Also accept LocalEmu-style host `<ap-name>-<account>.s3-accesspoint.localhost:<port>`
_AP_HOST_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*[a-z0-9])-(?P<account>\d{12})\."
    r"s3-accesspoint\.(?P<region>[a-z0-9-]+)\.(?:amazonaws\.com|localhost(?::\d+)?)$"
)

# LocalEmu-hybrid form: when boto3 is pointed at a custom endpoint
# (``--endpoint-url http://localhost:4578``) and given an AP ARN as
# ``Bucket``, it rewrites the host to ``<ap-name>-<account>.<custom-host>``
# without the ``s3-accesspoint.<region>.`` segment. The existing S3 virtual-
# host parser then sets ``service_request["Bucket"] = <ap-name>-<account>``.
# We detect this by matching the truncated bucket value against the
# ``<name>-<12-digit-account>`` pattern AND verifying the AP record exists.
_AP_HYBRID_RE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*[a-z0-9])-(?P<account>\d{12})$"
)


# --------------------------------------------------------------------------
# Operations that AWS rejects when called through an access point
# --------------------------------------------------------------------------

AP_INCOMPATIBLE_OPS = frozenset({
    # Bucket lifecycle / configuration ops - all bucket-only
    "CreateBucket", "DeleteBucket", "ListBuckets",
    "GetBucketLifecycleConfiguration", "PutBucketLifecycleConfiguration",
    "DeleteBucketLifecycle",
    "PutBucketReplication", "GetBucketReplication", "DeleteBucketReplication",
    "PutBucketVersioning", "GetBucketVersioning",
    "PutBucketEncryption", "GetBucketEncryption", "DeleteBucketEncryption",
    "PutBucketWebsite", "GetBucketWebsite", "DeleteBucketWebsite",
    "PutBucketTagging", "GetBucketTagging", "DeleteBucketTagging",
    "PutBucketLogging", "GetBucketLogging",
    "PutBucketAcl",
    "PutBucketCors", "DeleteBucketCors",
    "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketNotificationConfiguration",
    "PutBucketRequestPayment", "GetBucketRequestPayment",
    "PutBucketInventoryConfiguration", "GetBucketInventoryConfiguration",
    "DeleteBucketInventoryConfiguration", "ListBucketInventoryConfigurations",
    "PutBucketMetricsConfiguration", "GetBucketMetricsConfiguration",
    "DeleteBucketMetricsConfiguration", "ListBucketMetricsConfigurations",
    "PutBucketAnalyticsConfiguration", "GetBucketAnalyticsConfiguration",
    "DeleteBucketAnalyticsConfiguration", "ListBucketAnalyticsConfigurations",
    "PutBucketIntelligentTieringConfiguration",
    "GetBucketIntelligentTieringConfiguration",
    "DeleteBucketIntelligentTieringConfiguration",
    "ListBucketIntelligentTieringConfigurations",
    "PutBucketOwnershipControls", "GetBucketOwnershipControls",
    "DeleteBucketOwnershipControls",
    "PutObjectLockConfiguration", "GetObjectLockConfiguration",
    "PutPublicAccessBlock", "GetPublicAccessBlock", "DeletePublicAccessBlock",
})


# --------------------------------------------------------------------------
# Context shape stashed on the RequestContext
# --------------------------------------------------------------------------


@dataclass
class AccessPointContext:
    """Everything downstream code needs about the AP this request hit."""
    arn: str
    account: str
    region: str
    name: str
    network_origin: str       # "Internet" or "VPC"
    vpc_id: str | None
    policy: dict | None
    underlying_bucket: str
    underlying_bucket_account: str | None = None  # for cross-account APs


# --------------------------------------------------------------------------
# Look-up
# --------------------------------------------------------------------------


def _find_ap(account: str, region: str, name: str):
    """Locate the AP record in moto's s3control backend.

    Returns the moto ``AccessPoint`` object or None.
    """
    try:
        from moto.s3control.models import s3control_backends
        backend = s3control_backends[account]["global"]
        ap_index = getattr(backend, "access_points", {}) or {}
        # moto keys ap_index by bucket -> {name: AP} or by name. Handle both.
        if name in ap_index:
            return ap_index[name]
        # nested-by-bucket form
        for bucket_name, by_name in ap_index.items():
            if isinstance(by_name, dict) and name in by_name:
                return by_name[name]
        return None
    except Exception as e:
        LOG.debug("AP lookup failed for %s/%s/%s: %s", account, region, name, e)
        return None


def _find_ap_by_alias(alias: str):
    """Scan every account / region in s3control_backends to find an AP whose
    alias matches. Aliases are globally unique so the first hit wins.
    """
    try:
        from moto.s3control.models import s3control_backends
        for acct_id, by_partition in dict(s3control_backends).items():
            if not isinstance(by_partition, dict):
                continue
            for _partition, backend in by_partition.items():
                ap_index = getattr(backend, "access_points", {}) or {}
                # flat or nested-by-bucket
                candidates = []
                for k, v in ap_index.items():
                    if isinstance(v, dict):
                        candidates.extend(v.values())
                    else:
                        candidates.append(v)
                for ap in candidates:
                    if getattr(ap, "alias", None) == alias:
                        return ap, acct_id
        return None, None
    except Exception as e:
        LOG.debug("AP alias scan failed for %s: %s", alias, e)
        return None, None


# --------------------------------------------------------------------------
# Detection entry point
# --------------------------------------------------------------------------


def detect_access_point(bucket_param: str | None, host: str | None) -> tuple[str, dict] | None:
    """Determine whether this request is addressed to an access point.

    Returns ``(form, fields)`` where:
      * ``form`` is one of ``"arn"``, ``"alias"``, ``"host"``
      * ``fields`` is a dict carrying the parsed components

    Returns ``None`` for non-AP requests.
    """
    if bucket_param:
        m = _AP_ARN_RE.match(bucket_param)
        if m:
            if not m.group("region"):
                # Empty region segment = MRAP; out of scope for 1.1.0.
                return ("arn_mrap", m.groupdict())
            return ("arn", m.groupdict())
        m = _AP_ALIAS_RE.match(bucket_param)
        if m:
            return ("alias", m.groupdict())
        # LocalEmu-hybrid: ``<ap-name>-<account>`` left over after the
        # custom-endpoint virtual-host strip. Only treat as AP if the
        # record actually exists in s3control_backends; otherwise this
        # could be a legitimate bucket name ending in a 12-digit suffix.
        m = _AP_HYBRID_RE.match(bucket_param)
        if m:
            if _find_ap(m.group("account"), "us-east-1", m.group("name")) is not None:
                return ("hybrid", m.groupdict())
    if host:
        # strip any leading bucket-virtual-host prefix that some clients add
        host_only = host.split(":", 1)[0] if "//" not in host else host
        m = _AP_HOST_RE.match(host)
        if m:
            return ("host", m.groupdict())
        m = _AP_HOST_RE.match(host_only)
        if m:
            return ("host", m.groupdict())
    return None


def resolve_access_point(
    bucket_param: str | None,
    host: str | None,
) -> AccessPointContext | None:
    """Resolve a Bucket param / host header to an :class:`AccessPointContext`.

    Returns ``None`` when the request is not addressed to an access point.
    Raises :class:`AccessPointNotFound` when the address is well-formed but
    no matching AP record exists.
    """
    detected = detect_access_point(bucket_param, host)
    if detected is None:
        return None
    form, fields = detected

    if form == "arn_mrap":
        raise AccessPointMrapUnsupported(
            "Multi-Region Access Points are not implemented in LocalEmu 1.2.0",
        )

    if form == "arn":
        ap = _find_ap(fields["account"], fields["region"], fields["name"])
        ap_account = fields["account"]
    elif form == "alias":
        if fields.get("ext"):
            raise AccessPointFsxUnsupported(
                "FSx-backed access point aliases are not implemented",
            )
        ap, ap_account = _find_ap_by_alias(bucket_param)
    elif form == "host":
        ap = _find_ap(fields["account"], fields["region"], fields["name"])
        ap_account = fields["account"]
    elif form == "hybrid":
        ap = _find_ap(fields["account"], "us-east-1", fields["name"])
        ap_account = fields["account"]
    else:  # pragma: no cover
        return None

    if ap is None:
        raise AccessPointNotFound(
            f"The specified access point does not exist (form={form})",
        )

    return AccessPointContext(
        arn=getattr(ap, "arn", ""),
        account=ap_account,
        region=getattr(ap, "region_name", None) or fields.get("region", "us-east-1"),
        name=getattr(ap, "name", fields.get("name", "")),
        network_origin=getattr(ap, "network_origin", None) or "Internet",
        vpc_id=getattr(ap, "vpc_id", None),
        policy=_load_ap_policy(ap),
        underlying_bucket=getattr(ap, "bucket", ""),
    )


def _load_ap_policy(ap) -> dict | None:
    raw = getattr(ap, "policy", None)
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    import json
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class AccessPointNotFound(Exception):
    """Raised when a well-formed AP address doesn't resolve."""


class AccessPointMrapUnsupported(Exception):
    """Raised when an MRAP ARN (empty region) is encountered."""


class AccessPointFsxUnsupported(Exception):
    """Raised when an FSx-backed alias (``-ext-s3alias``) is encountered."""
