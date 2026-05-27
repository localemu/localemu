"""Systemic bridge between LocalEmu's native S3 store and moto's S3 backend.

Background (audit section G)
---------------------------
LocalEmu's S3 provider is native — buckets and objects live in
``localemu.services.s3.models.s3_stores``. A number of moto services,
however, resolve bucket identity by consulting their *own* S3 backend
(``moto.s3.models.s3_backends``), which is an entirely separate data
structure. Any such consumer sees LocalEmu-created buckets as missing.

The audit enumerates 11 affected consumers (CloudTrail, CloudWatch Logs
``CreateExportTask``, Firehose, Lambda ``CreateFunction`` from S3,
CloudFormation ``TemplateURL``, SES ``ReceiptRule`` S3 action, DynamoDB
import/export, ResourceGroupsTaggingAPI, SageMaker, Athena output,
AWS Config).

Scope of this bridge — be honest about what it fixes
----------------------------------------------------
This module monkey-patches ``moto.s3.models.S3Backend.get_bucket`` and
``head_bucket`` so that, for any bucket name moto does not know but
LocalEmu does, a minimal ``FakeBucket`` shim is synthesised and
registered in moto's backend dict. This:

1. **Fully resolves** every consumer whose code path only needs the
   bucket to *exist* (validation checks). The 11 consumers are analysed
   individually in the audit follow-up; the bridge fixes all
   existence-based validation paths reliably.

2. **Does NOT auto-synchronise object contents.** A moto consumer that
   subsequently calls ``get_object`` on the synthesised bucket will miss,
   because LocalEmu's native object storage is not wired into
   ``FakeBucket.keys``. Cross-service flows that actually *read* bytes
   from S3 (Lambda code download, Firehose writes, Athena output,
   DynamoDB import) need per-service adapters and are explicitly out of
   scope for this round.

This is a deliberately conservative design: the bridge only ADDS
positive bucket recognition; it never removes anything, so every moto
code path that works today continues to work.

Idempotency
-----------
The patch is guarded by a ``_le_moto_bridge_patched`` attribute on the
patched methods (same pattern as ``_patch_moto_bucket_check``). Multiple
calls to :func:`install_moto_s3_bridge` are safe.
"""

from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger(__name__)

_PATCH_MARKER = "_le_moto_bridge_patched"


def _localemu_has_bucket(account_id: str, bucket_name: str) -> tuple[bool, str | None]:
    """Return ``(exists, region)``. Looks up every region for the account."""
    try:
        from localemu.services.s3.models import s3_stores
    except Exception:
        return False, None
    try:
        account_stores = s3_stores[account_id]
    except Exception:
        return False, None
    try:
        for region, region_store in dict(account_stores).items():
            try:
                if bucket_name in region_store.buckets:
                    return True, region
            except Exception:
                continue
    except Exception:
        return False, None
    return False, None


def _synthesise_moto_bucket(
    moto_backend: Any,
    account_id: str,
    bucket_name: str,
    region: str,
) -> Any | None:
    """Create a minimal ``FakeBucket`` in moto's backend so subsequent
    moto code (which expects a ``FakeBucket`` instance with the standard
    attributes) finds the bucket. Returns the FakeBucket, or None on
    failure (we then fall back to moto's original ``MissingBucket``)."""
    try:
        from moto.s3.models import FakeBucket
    except Exception:
        return None
    try:
        bucket = FakeBucket(
            name=bucket_name, account_id=account_id, region_name=region,
        )
    except Exception:
        LOG.debug(
            "S3 bridge: failed to synthesise FakeBucket for %s",
            bucket_name,
            exc_info=True,
        )
        return None
    try:
        moto_backend.buckets[bucket_name] = bucket
    except Exception:
        # Bucket dict is always present on S3Backend; this is defensive.
        LOG.debug("S3 bridge: failed to register synthesised bucket", exc_info=True)
        return None
    LOG.debug(
        "S3 bridge: surfaced LocalEmu bucket %s to moto (%s/%s)",
        bucket_name, account_id, region,
    )
    return bucket


def install_moto_s3_bridge() -> None:
    """Install the systemic S3 bridge. Idempotent.

    Patches ``moto.s3.models.S3Backend.get_bucket`` and ``head_bucket``
    to consult LocalEmu's native S3 store as a fallback, and to surface
    matching buckets as ``FakeBucket`` shims so that moto code paths
    downstream of the check still work.
    """
    try:
        from moto.s3.models import S3Backend
    except Exception:
        LOG.debug("moto S3 backend not importable; bridge not installed")
        return

    original_get_bucket = S3Backend.get_bucket
    if getattr(original_get_bucket, _PATCH_MARKER, False):
        return

    def patched_get_bucket(self, bucket_name: str):
        # 1) Fast path: bucket known to moto in any form.
        try:
            return original_get_bucket(self, bucket_name)
        except Exception as missing_exc:
            original_exc = missing_exc
        # 2) LocalEmu fallback.
        try:
            account_id = getattr(self, "account_id", None) or "000000000000"
        except Exception:
            account_id = "000000000000"
        exists, region = _localemu_has_bucket(account_id, bucket_name)
        if not exists:
            raise original_exc
        bucket = _synthesise_moto_bucket(
            self, account_id, bucket_name, region or "us-east-1",
        )
        if bucket is None:
            raise original_exc
        return bucket

    patched_get_bucket.__wrapped__ = original_get_bucket  # type: ignore[attr-defined]
    setattr(patched_get_bucket, _PATCH_MARKER, True)
    S3Backend.get_bucket = patched_get_bucket  # type: ignore[assignment]

    # head_bucket in moto simply delegates to get_bucket, so patching
    # get_bucket is sufficient — but we mark head_bucket as well so that
    # re-installation detection works if moto ever decouples them.
    original_head_bucket = S3Backend.head_bucket

    def patched_head_bucket(self, bucket_name: str):
        return self.get_bucket(bucket_name)

    patched_head_bucket.__wrapped__ = original_head_bucket  # type: ignore[attr-defined]
    setattr(patched_head_bucket, _PATCH_MARKER, True)
    S3Backend.head_bucket = patched_head_bucket  # type: ignore[assignment]

    LOG.debug("moto S3 bridge installed on S3Backend.get_bucket/head_bucket")


# Auto-install on first import — the bridge is side-effect-free for code
# paths that already work (every pre-existing moto bucket still resolves
# via the moto fast path before we consult LocalEmu). Auto-install means
# that services other than CloudTrail (Lambda, Firehose, ...) benefit
# from the fix without each service having to remember to install it.
try:
    install_moto_s3_bridge()
except Exception:  # pragma: no cover - defensive
    LOG.debug("Auto-install of moto S3 bridge failed", exc_info=True)
