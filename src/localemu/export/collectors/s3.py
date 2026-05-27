"""S3 collector: enumerate buckets (and optionally object keys) from LocalEmu.

Reads from :mod:`localemu.services.s3.models` (``s3_stores``) rather than
re-querying the provider over HTTP — collectors run in-process and want
the authoritative in-memory state, not a serialized round-trip.

Bucket metadata is always emitted. Object bodies are *never* emitted from
this collector (they balloon snapshot size); when ``include_data=True``
we include the list of object keys (and version ids, for versioned
buckets) so the snapshot can be replayed against a live store — actual
body bytes are expected to come from a separate sidecar mechanism.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

# Soft-cap on the number of object keys we list per bucket. Past this we
# truncate and emit a warning; exporting hundreds of thousands of keys
# inline in a Terraform state is never what the user wants.
_OBJECT_KEY_SOFT_CAP = 10_000


@register_collector("s3")
class S3Collector(BaseCollector):
    """Collect S3 buckets for a single (account, region)."""

    service = "s3"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            from localemu.services.s3.models import s3_stores
        except Exception:  # pragma: no cover - import-time service failure
            LOG.warning("Failed to import s3_stores; skipping S3", exc_info=True)
            return []

        try:
            store = s3_stores[account_id][region]
        except Exception:
            LOG.warning(
                "No S3 store for account=%s region=%s", account_id, region, exc_info=True
            )
            return []

        resources: list[Resource] = []
        buckets = getattr(store, "buckets", {}) or {}
        for bucket_name, bucket in dict(buckets).items():
            # S3 buckets are global but bound to a home region. Only emit
            # each bucket in its own region to avoid double-counting.
            bucket_region = getattr(bucket, "bucket_region", region) or region
            if bucket_region != region:
                continue
            try:
                resources.append(
                    self._build_bucket_resource(
                        bucket_name, bucket, account_id, region, include_data
                    )
                )
                # Emit a separate ``aws_s3_bucket_policy`` /
                # ``AWS::S3::BucketPolicy`` resource when the bucket
                # carries a Policy. ``aws_s3_bucket`` itself has no
                # ``policy`` attribute in modern AWS provider versions —
                # leaving the policy inline on the bucket silently dropped
                # it on apply, which broke services that depend on it
                # (CloudTrail's "InsufficientS3BucketPolicyException" at
                # CreateTrail being the canonical example).
                policy = getattr(bucket, "policy", None)
                policy_dict = _policy_as_dict(policy)
                if policy_dict:
                    resources.append(
                        self._build_bucket_policy_resource(
                            bucket_name, policy_dict, account_id, region,
                        )
                    )
            except Exception:
                LOG.warning(
                    "Failed to serialize S3 bucket %r; skipping",
                    bucket_name,
                    exc_info=True,
                )
                continue
        return resources

    def _build_bucket_policy_resource(
        self, bucket_name: str, policy: dict, account_id: str, region: str,
    ) -> Resource:
        from localemu.export.ir import Ref
        return Resource(
            service="s3",
            resource_type="bucket_policy",
            resource_id=bucket_name,
            account_id=account_id,
            region=region,
            attributes={
                "bucket": Ref("s3", "bucket", bucket_name, attribute="id"),
                "policy": policy,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_bucket_resource(
        self,
        bucket_name: str,
        bucket: Any,
        account_id: str,
        region: str,
        include_data: bool,
    ) -> Resource:
        attrs: dict[str, Any] = {
            "bucket_name": bucket_name,
            "region": region,
        }

        versioning = getattr(bucket, "versioning_status", None)
        attrs["versioning_status"] = versioning  # Enabled / Suspended / None

        pab = getattr(bucket, "public_access_block", None)
        attrs["public_access_block"] = _as_plain(pab)

        attrs["lifecycle_configuration"] = _as_plain(
            getattr(bucket, "lifecycle_rules", None)
        )
        attrs["notification_configuration"] = _as_plain(
            getattr(bucket, "notification_configuration", None)
        )
        attrs["cors_configuration"] = _as_plain(getattr(bucket, "cors_rules", None))

        # Bucket policy is emitted as a separate Resource in the parent
        # loop (see ``_build_bucket_policy_resource``); it is NOT a valid
        # ``aws_s3_bucket`` attribute in modern hashicorp/aws.

        attrs["encryption_configuration"] = _as_plain(
            getattr(bucket, "encryption_rule", None)
        )

        attrs["object_lock_enabled"] = bool(
            getattr(bucket, "object_lock_enabled", False)
        )
        attrs["object_ownership"] = _as_plain(getattr(bucket, "object_ownership", None))

        # Website / replication / accelerate are not in the required set
        # but are cheap to include when present.
        website = getattr(bucket, "website_configuration", None)
        if website:
            attrs["website_configuration"] = _as_plain(website)
        accelerate = getattr(bucket, "accelerate_status", None)
        if accelerate:
            attrs["accelerate_status"] = _as_plain(accelerate)

        if include_data:
            attrs["objects"] = _list_objects(bucket_name, bucket)

        tags = _extract_tags(bucket)

        creation = getattr(bucket, "creation_date", None)
        created_at = creation.isoformat() if creation is not None else None

        return Resource(
            service="s3",
            resource_type="bucket",
            resource_id=bucket_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )


def _as_plain(value: Any) -> Any:
    """Best-effort conversion of service model values into JSON-plain data."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {k: _as_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_as_plain(v) for v in value]
    # Pydantic-style / dataclass-ish objects often expose ``dict()`` or
    # ``__dict__``. We do *not* touch private attributes.
    for meth in ("model_dump", "dict"):
        fn = getattr(value, meth, None)
        if callable(fn):
            try:
                return _as_plain(fn())
            except Exception:
                pass
    if hasattr(value, "__dict__"):
        return {
            k: _as_plain(v)
            for k, v in vars(value).items()
            if not k.startswith("_")
        }
    return str(value)


def _policy_as_dict(policy: Any) -> dict[str, Any] | None:
    if policy is None:
        return None
    if isinstance(policy, dict):
        return policy
    if isinstance(policy, (bytes, bytearray)):
        policy = policy.decode("utf-8", errors="replace")
    if isinstance(policy, str):
        import json

        try:
            return json.loads(policy)
        except Exception:
            LOG.warning("S3 bucket policy is not valid JSON; dropping", exc_info=True)
            return None
    return _as_plain(policy)


def _extract_tags(bucket: Any) -> dict[str, str]:
    # S3Bucket stores tags on the owning S3Object/S3Bucket via a separate
    # ``tagging`` attribute in some code paths; moto-era buckets use a
    # ``tagging`` dict directly. Probe both.
    tagging = getattr(bucket, "tagging", None)
    if isinstance(tagging, dict):
        return {str(k): str(v) for k, v in tagging.items()}
    tag_set = getattr(bucket, "tag_set", None)
    if isinstance(tag_set, list):
        out: dict[str, str] = {}
        for entry in tag_set:
            if isinstance(entry, dict) and "Key" in entry and "Value" in entry:
                out[str(entry["Key"])] = str(entry["Value"])
        return out
    return {}


def _list_objects(bucket_name: str, bucket: Any) -> list[dict[str, Any]]:
    """Return a light-weight listing of object keys (no bodies)."""
    objects_store = getattr(bucket, "objects", None)
    if objects_store is None:
        return []

    results: list[dict[str, Any]] = []
    versioning = getattr(bucket, "versioning_status", None)

    try:
        # KeyStore and VersionedKeyStore both expose iteration over keys;
        # versioned stores keep (key, version_id) tuples so we must iterate
        # versions rather than flattening to current-only.
        if versioning is not None:
            # Versioned: iterate all versions in insertion order.
            values_iter = _iter_versioned_objects(objects_store)
        else:
            values_iter = _iter_flat_objects(objects_store)

        for s3_obj in values_iter:
            if len(results) >= _OBJECT_KEY_SOFT_CAP:
                LOG.warning(
                    "S3 bucket %r has more than %d objects; truncating object "
                    "list in export snapshot",
                    bucket_name,
                    _OBJECT_KEY_SOFT_CAP,
                )
                break
            entry: dict[str, Any] = {
                "key": getattr(s3_obj, "key", None),
                "size": getattr(s3_obj, "size", None),
                "etag": getattr(s3_obj, "etag", None),
                "storage_class": _as_plain(getattr(s3_obj, "storage_class", None)),
            }
            version_id = getattr(s3_obj, "version_id", None)
            if version_id is not None:
                entry["version_id"] = version_id
            is_delete_marker = type(s3_obj).__name__ == "S3DeleteMarker"
            if is_delete_marker:
                entry["delete_marker"] = True
            results.append(entry)
    except Exception:
        LOG.warning(
            "Failed to enumerate objects for bucket %r; returning partial list",
            bucket_name,
            exc_info=True,
        )

    return results


def _iter_flat_objects(store: Any) -> Any:
    """Iterate a non-versioned KeyStore's S3Object values."""
    # KeyStore exposes ``values`` / ``items`` similar to a dict. Fall back
    # to iterating the underlying mapping if those aren't present.
    values = getattr(store, "values", None)
    if callable(values):
        return list(values())
    return list(iter(store))


def _iter_versioned_objects(store: Any) -> Any:
    """Iterate (all versions of) a VersionedKeyStore."""
    # VersionedKeyStore typically exposes a helper that flattens to every
    # version. Be defensive: fall back to ``values`` if needed.
    for meth in ("values", "iter_all_versions", "all_values"):
        fn = getattr(store, meth, None)
        if callable(fn):
            try:
                return list(fn())
            except Exception:
                continue
    return list(iter(store))
