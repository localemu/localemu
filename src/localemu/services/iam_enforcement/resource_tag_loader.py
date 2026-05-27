"""Load ``aws:ResourceTag/<key>`` values for the target resource of a request.

The ``aws:ResourceTag/*`` global condition key is one of the most-used
ABAC patterns: a policy says
``Condition: {StringEquals: {"aws:ResourceTag/env": "prod"}}`` and the
enforcer needs to ask "what's the value of the ``env`` tag on the
resource this request targets?" Real AWS pulls those from each
service's own tag store.

Switching on the resource ARN's service prefix because each service has
its own moto backend shape. Best-effort: when the backend layout has
moved between moto versions or the tagger isn't initialized we return
an empty dict — the condition then doesn't match and the call falls
through to the next statement (same as AWS when a resource has no
tags). This module is the V1 implementation of design-doc gap G3.
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


def _parse_arn(arn: str) -> tuple[str, str, str, str]:
    """Split an ARN into ``(service, region, account, resource_path)``.

    Returns empty strings on a malformed ARN so callers can short-circuit.
    """
    if not arn or not arn.startswith("arn:"):
        return "", "", "", ""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "", "", "", ""
    return parts[2], parts[3], parts[4], parts[5]


def _s3_bucket_tags(arn: str, account_id: str) -> dict[str, str]:
    """Pull bucket tags from LocalEmu's native S3 store.

    LocalEmu re-implements S3 (``services/s3/provider.py`` +
    ``services/s3/models.py``) rather than using moto's S3 backend.
    Bucket tags live on the per-account+region ``S3Store.tags`` keyed by
    ``bucket_arn``. The moto path doesn't see them.
    """
    bucket_name = arn.split(":::", 1)[-1].split("/", 1)[0]
    try:
        from localemu.services.s3.models import s3_stores
    except Exception:
        return {}
    # S3 buckets are partition-scoped but ``s3_stores`` is an
    # AccountRegionBundle, so we iterate every region's store under the
    # owner account and look up the bucket by name. The bucket's
    # owner_account is recorded on the global_bucket_map.
    for region_name, store in s3_stores[account_id].items():
        try:
            bucket = store.buckets.get(bucket_name)
        except Exception:
            continue
        if bucket is None:
            continue
        bucket_arn = getattr(bucket, "bucket_arn", None) or f"arn:aws:s3:::{bucket_name}"
        try:
            tags = store.tags.get_tags(bucket_arn)
        except Exception:
            tags = {}
        return dict(tags or {})
    return {}


def _ddb_table_tags(arn: str, account_id: str, region: str) -> dict[str, str]:
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("dynamodb")[account_id][region]
    except Exception:
        return {}
    table_name = arn.rsplit("/", 1)[-1]
    table = backend.tables.get(table_name) if hasattr(backend, "tables") else None
    if table is None:
        return {}
    tags = getattr(table, "tags", []) or []
    if isinstance(tags, dict):
        return dict(tags)
    return {t.get("Key", ""): t.get("Value", "") for t in tags if isinstance(t, dict)}


def _lambda_function_tags(arn: str, account_id: str, region: str) -> dict[str, str]:
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("lambda")[account_id][region]
    except Exception:
        return {}
    fn_name = arn.rsplit(":", 1)[-1].split("/")[-1]
    try:
        fn = backend.get_function(fn_name)
    except Exception:
        return {}
    return dict(getattr(fn, "tags", {}) or {})


def _iam_resource_tags(arn: str, account_id: str) -> dict[str, str]:
    """Tags for an IAM user or role (resource path looks like
    ``user/<name>`` or ``role/<name>``)."""
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("iam")[account_id]["global"]
    except Exception:
        return {}
    path = arn.split(":", 5)[-1] if ":" in arn else ""
    if path.startswith("user/"):
        name = path.split("/", 1)[1]
        try:
            user = backend.get_user(name)
        except Exception:
            return {}
        return _normalize_tag_list(getattr(user, "tags", []))
    if path.startswith("role/"):
        name = path.split("/", 1)[1]
        try:
            role = backend.get_role(name)
        except Exception:
            return {}
        return _normalize_tag_list(getattr(role, "tags", []))
    return {}


def _kms_key_tags(arn: str, account_id: str, region: str) -> dict[str, str]:
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("kms")[account_id][region]
    except Exception:
        return {}
    key_id = arn.rsplit("/", 1)[-1]
    key = backend.keys.get(key_id) if hasattr(backend, "keys") else None
    if key is None:
        return {}
    return _normalize_tag_list(getattr(key, "tags", []))


def _sqs_queue_tags(arn: str, account_id: str, region: str) -> dict[str, str]:
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("sqs")[account_id][region]
    except Exception:
        return {}
    queue_name = arn.rsplit(":", 1)[-1]
    queue = backend.queues.get(queue_name) if hasattr(backend, "queues") else None
    if queue is None:
        return {}
    return dict(getattr(queue, "tags", {}) or {})


def _sns_topic_tags(arn: str, account_id: str, region: str) -> dict[str, str]:
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("sns")[account_id][region]
    except Exception:
        return {}
    topic = backend.topics.get(arn) if hasattr(backend, "topics") else None
    if topic is None:
        return {}
    return _normalize_tag_list(getattr(topic, "_tags", getattr(topic, "tags", [])))


def _normalize_tag_list(raw) -> dict[str, str]:
    """Accept moto's various tag shapes: dict, list-of-{Key,Value} dicts,
    list-of-(Key, Value) tuples."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for entry in raw:
            if isinstance(entry, dict):
                out[entry.get("Key", "")] = entry.get("Value", "")
            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                out[str(entry[0])] = str(entry[1])
        return out
    return {}


# Switch by ARN service prefix.
_LOADERS = {
    "s3":       _s3_bucket_tags,           # (arn, account_id)
    "dynamodb": _ddb_table_tags,           # (arn, account_id, region)
    "lambda":   _lambda_function_tags,     # (arn, account_id, region)
    "iam":      _iam_resource_tags,        # (arn, account_id)
    "kms":      _kms_key_tags,             # (arn, account_id, region)
    "sqs":      _sqs_queue_tags,           # (arn, account_id, region)
    "sns":      _sns_topic_tags,           # (arn, account_id, region)
}


def load_resource_tags(resource_arn: str, account_id: str, region: str) -> dict[str, str]:
    """Return ``{tag_key: value}`` for the target resource, or {} if unknown.

    Returning {} cleanly makes ``aws:ResourceTag/<key>`` conditions evaluate
    to "absent" — matching the behaviour AWS exhibits for an untagged
    resource. Never raises: the enforcer must not be brought down by a
    backend shape change in moto.
    """
    service, region_arn, acct_arn, _ = _parse_arn(resource_arn)
    if not service:
        return {}
    loader = _LOADERS.get(service)
    if loader is None:
        return {}
    eff_account = acct_arn or account_id
    eff_region = region_arn or region or "us-east-1"
    try:
        # IAM + S3 are partition-scoped (no per-region tag store), so they
        # take 2 args; the rest take 3.
        if service in ("s3", "iam"):
            return loader(resource_arn, eff_account)
        return loader(resource_arn, eff_account, eff_region)
    except Exception:
        LOG.debug(
            "resource_tag_loader: failed to load tags for %s",
            resource_arn, exc_info=True,
        )
        return {}
