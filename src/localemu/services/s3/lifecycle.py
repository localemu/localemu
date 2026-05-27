"""S3 Lifecycle Expiration Worker.

Background thread that periodically scans all buckets for lifecycle rules
with Expiration configuration, and deletes objects that have expired.

AWS lifecycle expiration behavior:
- Objects expire at midnight UTC on the day after their last_modified + Days
- Date-based expiration uses an absolute ISO 8601 date
- Only rules with Status="Enabled" are evaluated
- Filter matching: Prefix, Tag, ObjectSize, And (combinations)
- ExpiredObjectDeleteMarker: remove delete markers in versioned buckets
  when they are the only remaining version
"""

import datetime
import logging
import threading
import time

from localemu.services.s3.models import (
    S3Bucket,
    S3DeleteMarker,
    S3Object,
    s3_stores,
)
from localemu.services.s3.utils import get_lifecycle_rule_from_object

LOG = logging.getLogger(__name__)

# How often to run the lifecycle scan (seconds)
_LIFECYCLE_SCAN_INTERVAL = 60

# Module-level thread state
_lifecycle_thread: threading.Thread | None = None
_lifecycle_stop = threading.Event()


def start_lifecycle_worker(storage_backend) -> None:
    """Start the background lifecycle expiration thread."""
    global _lifecycle_thread
    if _lifecycle_thread and _lifecycle_thread.is_alive():
        return

    _lifecycle_stop.clear()
    _lifecycle_thread = threading.Thread(
        target=_lifecycle_loop,
        args=(storage_backend,),
        name="s3-lifecycle-worker",
        daemon=True,
    )
    _lifecycle_thread.start()
    LOG.info("S3 lifecycle expiration worker started (interval=%ds)", _LIFECYCLE_SCAN_INTERVAL)


def stop_lifecycle_worker() -> None:
    """Stop the background lifecycle expiration thread."""
    global _lifecycle_thread
    _lifecycle_stop.set()
    if _lifecycle_thread:
        _lifecycle_thread.join(timeout=5)
        _lifecycle_thread = None
    LOG.debug("S3 lifecycle expiration worker stopped")


def _lifecycle_loop(storage_backend) -> None:
    """Main loop: sleep, then scan all buckets."""
    while not _lifecycle_stop.wait(timeout=_LIFECYCLE_SCAN_INTERVAL):
        try:
            _scan_all_buckets(storage_backend)
        except Exception:
            LOG.warning("S3 lifecycle scan error", exc_info=True)


def _scan_all_buckets(storage_backend) -> None:
    """Iterate all accounts/regions/buckets and expire matching objects."""
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    total_expired = 0

    for account_id, regions in dict(s3_stores).items():
        for region_name, store in dict(regions).items():
            for bucket_name, bucket in dict(store.buckets).items():
                # FakeBucket instances from moto-only test setups can lack
                # the lifecycle_rules attribute; fall back to None so the
                # scanner moves on instead of crashing the whole sweep.
                lifecycle_rules = getattr(bucket, "lifecycle_rules", None)
                if not lifecycle_rules:
                    continue

                # Only process rules with Status=Enabled and Expiration
                enabled_rules = [
                    r for r in lifecycle_rules
                    if r.get("Status") == "Enabled" and r.get("Expiration")
                ]
                if not enabled_rules:
                    continue

                expired = _expire_bucket_objects(
                    bucket_name, bucket, enabled_rules, now, storage_backend, store
                )
                total_expired += expired

    if total_expired > 0:
        LOG.info("S3 lifecycle: expired %d objects", total_expired)


def _expire_bucket_objects(
    bucket_name: str,
    bucket: S3Bucket,
    rules,
    now: datetime.datetime,
    storage_backend,
    store,
) -> int:
    """Check and delete expired objects in a single bucket. Returns count deleted."""
    expired_count = 0

    # Get all objects in the bucket
    all_objects = bucket.objects.values()

    for s3_obj in all_objects:
        if isinstance(s3_obj, S3DeleteMarker):
            continue
        if not isinstance(s3_obj, S3Object):
            continue

        # Get tags for this object (needed for tag-based lifecycle filters)
        from localemu.services.s3.utils import get_unique_key_id
        unique_key = get_unique_key_id(bucket_name, s3_obj.key, s3_obj.version_id)
        object_tags = {}
        try:
            tag_set = store.tags.tags.get(unique_key, {})
            if isinstance(tag_set, dict):
                object_tags = tag_set
        except Exception:
            pass

        # Find matching lifecycle rule
        matching_rule = get_lifecycle_rule_from_object(
            rules, s3_obj.key, s3_obj.size or 0, object_tags
        )
        if not matching_rule:
            continue

        expiration = matching_rule.get("Expiration", {})
        if not _is_expired(s3_obj, expiration, now):
            continue

        # Object is expired — delete it
        try:
            bucket.objects.pop(s3_obj.key)
            storage_backend.remove(bucket_name, s3_obj)
            store.tags.delete_all_tags(unique_key)
            expired_count += 1
            LOG.debug(
                "S3 lifecycle: expired %s/%s (rule %s)",
                bucket_name, s3_obj.key, matching_rule.get("ID", "?"),
            )
        except Exception as e:
            LOG.debug("S3 lifecycle: failed to delete %s/%s: %s", bucket_name, s3_obj.key, e)

    return expired_count


def _is_expired(
    s3_obj: S3Object,
    expiration: dict,
    now: datetime.datetime,
) -> bool:
    """Check if an object has passed its lifecycle expiration deadline."""
    if exp_days := expiration.get("Days"):
        # AWS expires at midnight UTC, Days after last_modified
        last_mod = s3_obj.last_modified
        if last_mod.tzinfo is None:
            last_mod = last_mod.replace(tzinfo=datetime.timezone.utc)
        # Round to next midnight after last_modified + Days
        expiry = (last_mod + datetime.timedelta(days=int(exp_days))).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) + datetime.timedelta(days=1)
        return now >= expiry

    if exp_date := expiration.get("Date"):
        # Absolute expiration date (ISO 8601)
        if isinstance(exp_date, str):
            try:
                exp_dt = datetime.datetime.fromisoformat(exp_date.replace("Z", "+00:00"))
            except ValueError:
                return False
        elif isinstance(exp_date, datetime.datetime):
            exp_dt = exp_date
        else:
            return False
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
        return now >= exp_dt

    return False
