"""S3 live replication data plane.

When a bucket has a ``ReplicationConfiguration`` and a new object/delete
marker is written, the engine asynchronously copies the object to each
matching ``Destination`` bucket, tracks state transitions
(``PENDING`` -> ``COMPLETED`` / ``FAILED``) on the source and marks the
destination object with ``REPLICA``.

Scope (matches AWS):
- Live replication only. Existing-object replication via S3 Batch is OUT.
- Filter: empty / Prefix / Tag / And{Prefix?, Tag+} all matched.
- Priority resolved per destination bucket.
- DeleteMarkerReplication gated (tag-rule + lifecycle exclusions honored).
- VersionId preserved on the replica.
- Metadata + tags + content-type carry-over.
- StorageClass override per rule.
- GLACIER / DEEP_ARCHIVE skipped.
- Replicas-of-replicas blocked (no chained replication).
- Multi-destination supported.
- Cross-account destinations supported via the central account registry
  + multi-account S3 backends. AWS-correct: destination bucket policy
  must grant the source bucket owner (read via the
  cross-account resource-policy evaluator).

Out-of-scope (parsed but no enforcement):
- KMS replica re-encryption with ReplicaKmsKeyID.
- RTC 15-minute SLA.
- ACL replication ownership translation.

The engine uses a 3-worker ``ThreadPoolExecutor`` (same shape as the
notification dispatcher) so the source PutObject returns immediately.
For deterministic testing the engine exposes ``run_synchronously``
flag which routes ``dispatch`` straight through to the per-copy worker
without crossing thread boundaries.
"""

from __future__ import annotations

import fnmatch
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Status constants (mirror aws.api.s3.ReplicationStatus)
# --------------------------------------------------------------------------

STATUS_PENDING = "PENDING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_REPLICA = "REPLICA"

_GLACIER_CLASSES = frozenset({
    "GLACIER", "DEEP_ARCHIVE",
    "INTELLIGENT_TIERING_ARCHIVE_ACCESS",
    "INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS",
})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _normalize_rules(replication_config: dict) -> list[dict]:
    if not replication_config:
        return []
    rules = replication_config.get("Rules") or []
    if isinstance(rules, dict):
        rules = [rules]
    return [r for r in rules if isinstance(r, dict)]


def _filter_matches(rule: dict, key: str, tags: dict[str, str]) -> bool:
    """Evaluate a rule's Filter against the object key + tag set."""
    f = rule.get("Filter")
    if not f:
        return True
    if isinstance(f, dict):
        if "Prefix" in f and not f.get("And") and not f.get("Tag"):
            return key.startswith(f.get("Prefix") or "")
        if "Tag" in f and not f.get("And") and not f.get("Prefix"):
            tag = f["Tag"] or {}
            return tags.get(tag.get("Key")) == tag.get("Value")
        if "And" in f:
            and_block = f["And"] or {}
            prefix = and_block.get("Prefix")
            if prefix is not None and not key.startswith(prefix):
                return False
            for t in and_block.get("Tags", []) or []:
                if tags.get(t.get("Key")) != t.get("Value"):
                    return False
            return True
    return True


def _is_tag_based_rule(rule: dict) -> bool:
    f = rule.get("Filter") or {}
    if "Tag" in f:
        return True
    and_block = f.get("And") or {}
    return bool(and_block.get("Tags"))


def _dest_bucket_name_from_arn(destination: dict) -> str | None:
    arn = (destination or {}).get("Bucket")
    if not arn:
        return None
    # arn form: arn:aws:s3:::bucket-name
    if ":::" in arn:
        return arn.split(":::", 1)[1]
    return arn


def _resolve_dest_account(destination: dict, source_account: str) -> str:
    """Destination.Account is optional; default to source account."""
    return (destination or {}).get("Account") or source_account


def _eligible(src_bucket, s3_object, is_delete_marker: bool) -> bool:
    if getattr(src_bucket, "replication", None) is None:
        return False
    if (getattr(src_bucket, "versioning_status", "") or "").lower() != "enabled":
        return False
    if getattr(s3_object, "replication_status", None) == STATUS_REPLICA:
        return False
    if not is_delete_marker:
        sc = (getattr(s3_object, "storage_class", None) or "STANDARD")
        sc = str(sc).upper().replace("-", "_")
        if sc in _GLACIER_CLASSES:
            return False
    return True


# --------------------------------------------------------------------------
# Rule resolution
# --------------------------------------------------------------------------


def resolve_rules_for_object(
    src_bucket,
    key: str,
    tags: dict[str, str] | None,
    is_delete_marker: bool,
    lifecycle: bool = False,
    src_account: str | None = None,
) -> list[tuple[dict, str, str]]:
    """Walk rules, apply filter + delete-marker + priority resolution.

    Returns a list of ``(rule, dest_bucket_name, dest_account_id)`` tuples,
    one per destination that the object should replicate to.

    ``src_account`` is the AWS account ID that owns the source bucket.
    It is supplied by the engine's dispatch() rather than read off
    ``src_bucket.account_id`` because the S3 bucket model does not
    expose its owning account directly; the store key does.
    """
    config = getattr(src_bucket, "replication", None) or {}
    rules = _normalize_rules(config)
    tags = tags or {}
    source_account = src_account or getattr(src_bucket, "account_id", None) \
        or "000000000000"

    matched = []
    for rule in rules:
        if str(rule.get("Status", "Enabled")) != "Enabled":
            continue
        if not _filter_matches(rule, key, tags):
            continue
        if is_delete_marker:
            # Delete-marker gating per AWS:
            dmr = (rule.get("DeleteMarkerReplication") or {}).get("Status", "Disabled")
            if dmr != "Enabled":
                continue
            if _is_tag_based_rule(rule):
                continue
            if lifecycle:
                continue
        dest_bucket = _dest_bucket_name_from_arn(rule.get("Destination") or {})
        if not dest_bucket:
            continue
        dest_account = _resolve_dest_account(rule.get("Destination"), source_account)
        matched.append((rule, dest_bucket, dest_account))

    # Priority resolution: when multiple rules point at the SAME destination,
    # only the highest-priority rule wins.
    by_dest: dict[tuple[str, str], tuple[dict, str, str]] = {}
    for rule, dest_bucket, dest_account in matched:
        key_t = (dest_account, dest_bucket)
        prio = int(rule.get("Priority", 0) or 0)
        existing = by_dest.get(key_t)
        if existing is None or int(existing[0].get("Priority", 0) or 0) < prio:
            by_dest[key_t] = (rule, dest_bucket, dest_account)
    return list(by_dest.values())


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class ReplicationEngine:
    """Process-wide live-replication engine for the S3 provider."""

    def __init__(self, max_workers: int = 3):
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="s3_repl",
        )
        # Locks per (src_account, src_bucket, key, version_id) so the
        # multi-destination finalize() doesn't race itself.
        self._key_locks: dict[tuple, threading.Lock] = {}
        self._locks_lock = threading.Lock()
        # Test seam: when True, ``dispatch`` runs everything inline so
        # source HeadObject right after PutObject sees COMPLETED.
        self.run_synchronously = False

    def shutdown(self, wait: bool = True, timeout: float = 10.0) -> None:
        try:
            self._executor.shutdown(wait=wait)
        except Exception:
            pass

    def _key_lock(self, key_tuple: tuple) -> threading.Lock:
        with self._locks_lock:
            lock = self._key_locks.get(key_tuple)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key_tuple] = lock
            return lock

    # ---- dispatch ----------------------------------------------------------

    def dispatch(
        self,
        src_account: str,
        src_bucket,
        s3_object,
        *,
        is_delete_marker: bool = False,
        lifecycle: bool = False,
        tags: dict[str, str] | None = None,
        storage_backend=None,
    ) -> None:
        """Inspect rules, set source status to PENDING, schedule the copies.

        Called by the S3 provider after the object/delete marker has been
        committed to the source bucket. Non-blocking by default.
        """
        try:
            if not _eligible(src_bucket, s3_object, is_delete_marker):
                return
            rules = resolve_rules_for_object(
                src_bucket, s3_object.key, tags or {},
                is_delete_marker, lifecycle,
                src_account=src_account,
            )
            if not rules:
                return
            # Source PENDING immediately so HeadObject right after PutObject
            # shows the canonical AWS state.
            try:
                s3_object.replication_status = STATUS_PENDING
            except Exception:
                pass

            key_tuple = (
                src_account, getattr(src_bucket, "name", "?"),
                s3_object.key, getattr(s3_object, "version_id", None),
            )

            def _run_all():
                outcomes = []
                for rule, dest_bucket_name, dest_account in rules:
                    ok = False
                    try:
                        ok = self._copy_one(
                            src_account=src_account,
                            src_bucket=src_bucket,
                            s3_object=s3_object,
                            is_delete_marker=is_delete_marker,
                            rule=rule,
                            dest_bucket_name=dest_bucket_name,
                            dest_account=dest_account,
                            storage_backend=storage_backend,
                        )
                    except Exception as e:
                        LOG.warning(
                            "Replication copy failed: src=%s/%s key=%s "
                            "dest=%s/%s: %s",
                            src_account, getattr(src_bucket, "name", "?"),
                            s3_object.key, dest_account, dest_bucket_name, e,
                        )
                    outcomes.append(ok)
                # Finalize: COMPLETED if every destination succeeded, else FAILED.
                with self._key_lock(key_tuple):
                    try:
                        if outcomes and all(outcomes):
                            s3_object.replication_status = STATUS_COMPLETED
                        else:
                            s3_object.replication_status = STATUS_FAILED
                    except Exception:
                        pass

            if self.run_synchronously:
                _run_all()
            else:
                self._executor.submit(_run_all)
        except Exception as e:
            LOG.warning("replication.dispatch outer guard fired: %s", e,
                        exc_info=True)

    # ---- per-destination copy --------------------------------------------

    def _copy_one(
        self,
        *,
        src_account: str,
        src_bucket,
        s3_object,
        is_delete_marker: bool,
        rule: dict,
        dest_bucket_name: str,
        dest_account: str,
        storage_backend=None,
    ) -> bool:
        """Copy one object/delete marker to one destination. Return True on success."""

        from localemu.constants import AWS_REGION_US_EAST_1
        from localemu.services.s3.models import S3DeleteMarker, S3Object, s3_stores

        # Resolve destination bucket. Cross-account: look up under dest_account.
        try:
            dest_store = s3_stores[dest_account][AWS_REGION_US_EAST_1]
        except Exception as e:
            LOG.warning("Replication FAILED (dest store lookup %s/%s: %s)",
                        dest_account, dest_bucket_name, e)
            return False
        dest_bucket = dest_store.buckets.get(dest_bucket_name)
        if dest_bucket is None:
            # Try global owner map for the destination bucket
            owner = dest_store.global_bucket_map.get(dest_bucket_name) \
                if hasattr(dest_store, "global_bucket_map") else None
            if owner:
                try:
                    dest_bucket = s3_stores[owner][AWS_REGION_US_EAST_1].buckets.get(
                        dest_bucket_name,
                    )
                except Exception:
                    dest_bucket = None
        if dest_bucket is None:
            LOG.warning(
                "Replication FAILED (dest bucket %s not found in account %s; "
                "dest_store has buckets=%s)",
                dest_bucket_name, dest_account,
                list(getattr(dest_store, "buckets", {}).keys())[:5],
            )
            return False
        if (getattr(dest_bucket, "versioning_status", "") or "").lower() != "enabled":
            LOG.warning(
                "Replication FAILED (dest %s/%s versioning=%r not enabled)",
                dest_account, dest_bucket_name,
                getattr(dest_bucket, "versioning_status", None),
            )
            return False

        # Cross-account check: if destination is in a different account,
        # the destination bucket policy must explicitly allow the source.
        if dest_account != src_account:
            try:
                from localemu.services.iam_enforcement.resource_policies import (
                    Decision,
                    ResourceTarget,
                    evaluate_cross_account,
                )

                target = ResourceTarget(
                    service="s3",
                    arn=f"arn:aws:s3:::{dest_bucket_name}/{s3_object.key}",
                    account_id=dest_account,
                    region=AWS_REGION_US_EAST_1,
                    name=dest_bucket_name,
                )
                decision = evaluate_cross_account(
                    caller_account=src_account,
                    caller_arn=f"arn:aws:iam::{src_account}:root",
                    target=target,
                    action="s3:ReplicateObject",
                )
                # NEUTRAL means no explicit allow on the destination policy.
                # AWS would mark replication FAILED in this case.
                if decision == Decision.EXPLICIT_DENY:
                    LOG.info(
                        "Replication FAILED (cross-account explicit deny on %s)",
                        dest_bucket_name,
                    )
                    return False
                if decision == Decision.NEUTRAL:
                    LOG.info(
                        "Replication FAILED (no explicit allow on dest %s for source %s)",
                        dest_bucket_name, src_account,
                    )
                    return False
            except Exception as e:
                LOG.debug("cross-account policy check skipped: %s", e)

        # Delete-marker replica
        if is_delete_marker:
            try:
                marker = S3DeleteMarker(
                    key=s3_object.key,
                    version_id=getattr(s3_object, "version_id", None),
                )
                marker.replication_status = STATUS_REPLICA
                # Drop into the destination version index. We bypass the
                # provider's put_object path so we don't re-enter replication
                # for the replica itself.
                dest_bucket.objects.set(marker.key, marker)
                return True
            except Exception as e:
                LOG.warning("delete-marker replica failed: %s", e)
                return False

        # Object replica: build a fresh S3Object preserving the source's
        # version_id, metadata, tags, content-type, storage-class override.
        sc_override = (rule.get("Destination") or {}).get("StorageClass")
        try:
            replica = S3Object(
                key=s3_object.key,
                etag=s3_object.etag,
                size=s3_object.size,
                version_id=getattr(s3_object, "version_id", None),
                user_metadata=dict(getattr(s3_object, "user_metadata", {}) or {}),
                system_metadata=dict(getattr(s3_object, "system_metadata", {}) or {}),
                storage_class=sc_override or s3_object.storage_class,
                checksum_algorithm=getattr(s3_object, "checksum_algorithm", None),
                checksum_value=getattr(s3_object, "checksum_value", None),
                checksum_type=getattr(s3_object, "checksum_type", None),
            )
            replica.replication_status = STATUS_REPLICA
            replica.is_current = True
        except Exception as e:
            LOG.warning("replica construction failed: %s", e)
            return False

        # Stream bytes via the storage backend so this works for files
        # that don't fit in RAM. The storage backend abstracts source
        # vs destination filesystem layout.
        try:
            from localemu.services.s3.storage.core import (  # noqa: F401
                S3StoredObject,  # type: ignore
            )
        except Exception:
            S3StoredObject = None  # noqa: N806

        try:
            backend = storage_backend if storage_backend is not None \
                else _get_storage_backend()
            if backend is not None:
                # ``S3ObjectStore.copy`` is the dedicated cross-bucket
                # object copy primitive — same one CopyObject uses. It
                # handles streaming + filesystem layout internally and
                # returns the destination ``S3StoredObject`` so the
                # storage backend's bookkeeping (etag, size, checksum)
                # stays correct on the destination side.
                with backend.copy(
                    src_bucket=getattr(src_bucket, "name", "?"),
                    src_object=s3_object,
                    dest_bucket=dest_bucket_name,
                    dest_object=replica,
                ):
                    pass
            else:
                LOG.warning(
                    "Replication: storage backend not available, replica "
                    "metadata committed without body bytes",
                )
        except Exception as e:
            LOG.warning(
                "Replication: storage-backend copy failed for "
                "%s/%s -> %s/%s: %s",
                src_account, getattr(src_bucket, "name", "?"),
                dest_account, dest_bucket_name, e,
            )
            return False

        # Commit version on the destination bucket.
        try:
            dest_bucket.objects.set(replica.key, replica)

            # Also copy the object tags via the destination store's tag
            # index. The source tag set lives in src_store.tags keyed by
            # (bucket_name, object_key, version_id).
            try:
                from localemu.constants import AWS_REGION_US_EAST_1 as _R
                from localemu.services.s3.models import s3_stores as _stores

                src_store = _stores[src_account][_R]
                src_tags = src_store.tags.get_tags(
                    (getattr(src_bucket, "name", "?"), s3_object.key,
                     getattr(s3_object, "version_id", None))
                ) or {}
                if src_tags:
                    dest_store_tags = _stores[dest_account][_R]
                    dest_store_tags.tags.update_tags(
                        (dest_bucket_name, replica.key,
                         getattr(replica, "version_id", None)),
                        src_tags,
                    )
            except Exception as e:
                LOG.debug("replica tag carry-over skipped: %s", e)
            return True
        except Exception as e:
            LOG.warning("replica commit failed: %s", e)
            return False


# --------------------------------------------------------------------------
# Module-level singleton
# --------------------------------------------------------------------------


_ENGINE: ReplicationEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> ReplicationEngine:
    global _ENGINE
    with _engine_lock:
        if _ENGINE is None:
            _ENGINE = ReplicationEngine()
        return _ENGINE


def reset_engine_for_tests() -> None:
    """Reset the engine (drops in-flight tasks). Test-only."""
    global _ENGINE
    with _engine_lock:
        if _ENGINE is not None:
            _ENGINE.shutdown()
        _ENGINE = None


# --------------------------------------------------------------------------
# Storage backend resolution
# --------------------------------------------------------------------------


def _get_storage_backend():
    """Return the live S3 storage backend instance, or None if unavailable.

    The S3 provider owns the storage backend (ephemeral, on-disk, etc.)
    via ``self._storage_backend``. We grab it through the provider
    registry; if the registry isn't ready yet we silently bail and the
    caller skips the byte-stream copy (the version record still lands).
    """
    try:
        from localemu.services.plugins import SERVICE_PLUGINS

        plugin = SERVICE_PLUGINS.plugins.get("s3")  # type: ignore[union-attr]
        if plugin is None:
            return None
        provider = getattr(plugin, "_provider", None) \
            or getattr(plugin, "provider", None)
        if provider is None:
            return None
        return getattr(provider, "_storage_backend", None)
    except Exception:
        return None
