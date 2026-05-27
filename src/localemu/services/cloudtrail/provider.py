"""
CloudTrail provider with real LookupEvents implementation.

Intercepts LookupEvents to return real API activity recorded by the
gateway handler chain.  All other CloudTrail operations (CreateTrail,
DescribeTrails, StartLogging, etc.) route directly to Moto.

Architecture (same pattern as ECS/RDS providers):
  1. Moto owns trail configuration state (trails, selectors, tags).
  2. The shared CloudTrailEventStore owns event data (populated by the
     response handler hook in dashboard/plugins.py).
  3. LookupEvents queries the shared store with proper filtering,
     pagination, and CloudTrail-compatible response formatting.

CloudTrail Lake / EventDataStore
--------------------------------

EventDataStore resources (Create/Get/Update/Delete/List/Restore and
Start/Stop ingestion) are handled natively in this module.  Data stores
live in an in-memory registry keyed by ``(account_id, region, arn)``.

**Limitation — metadata only.** CloudTrail Lake is, in real AWS, a
queryable data lake.  We faithfully track the lifecycle of a data store
(status transitions ``ENABLED``/``STOPPED_INGESTION``/``PENDING_DELETION``,
termination protection, retention, billing mode, timestamps, advanced
event selectors, tags) so customer tooling that creates/lists/describes/
updates/deletes data stores behaves correctly.  We do NOT ingest events
into the store or execute SQL queries against it — the Query APIs
(``StartQuery``, ``GetQueryResults``, ``DescribeQuery``, ...) remain the
scope of a separate provider agent and still return
``501 NotImplementedError``.  Do not rely on querying events from a data
store created here.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from localemu.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
)
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto
from localemu.services.plugins import Service, ServiceLifecycleHook

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared S3 log-delivery state (B5).
#
# Moto's ``Trail.description()`` rewrites ``LatestDeliveryTime`` to
# ``utcnow()`` every time it is called — the value is therefore a lie, not
# a measurement of real delivery. This dict is the single source of truth
# for ``GetTrailStatus.LatestDelivery*`` fields. The S3 delivery thread
# writes into it after each attempt; ``_handle_get_trail_status`` reads it
# and overwrites moto's synthetic fields on the response.
#
# Key:   (account_id, region, trail_name)
# Value: dict with:
#   - "LatestDeliveryTime":              datetime | None  (UTC) — last
#                                        successful delivery
#   - "LatestDeliveryError":             str  ("" on success)
#   - "LatestDeliveryAttemptTime":       str  (ISO-8601 Z, last attempt)
#   - "LatestDeliveryAttemptSucceeded":  str  ("true"/"false"/"")
# ---------------------------------------------------------------------------
_delivery_state: dict[tuple[str, str, str], dict] = {}
_delivery_state_lock = threading.Lock()


def _record_delivery_attempt(
    account_id: str,
    region: str,
    trail_name: str,
    *,
    success: bool,
    error: str = "",
    when: datetime | None = None,
) -> None:
    """Record the outcome of an S3 log-delivery attempt so that
    ``GetTrailStatus`` can report real data instead of moto's synthetic
    ``utcnow()``.  Thread-safe."""
    when = when or datetime.now(timezone.utc)
    attempt_iso = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _delivery_state_lock:
        state = _delivery_state.setdefault(
            (account_id, region, trail_name),
            {
                "LatestDeliveryTime": None,
                "LatestDeliveryError": "",
                "LatestDeliveryAttemptTime": "",
                "LatestDeliveryAttemptSucceeded": "",
            },
        )
        state["LatestDeliveryAttemptTime"] = attempt_iso
        state["LatestDeliveryAttemptSucceeded"] = "true" if success else "false"
        if success:
            state["LatestDeliveryTime"] = when
            state["LatestDeliveryError"] = ""
        else:
            state["LatestDeliveryError"] = error or "InternalError"


def _get_delivery_state(
    account_id: str, region: str, trail_name: str
) -> dict | None:
    """Return a copy of the delivery state, or ``None`` if never recorded."""
    with _delivery_state_lock:
        state = _delivery_state.get((account_id, region, trail_name))
        return dict(state) if state is not None else None


def _clear_delivery_state() -> None:
    """Reset the shared delivery-state map. For tests only."""
    with _delivery_state_lock:
        _delivery_state.clear()

# ---------------------------------------------------------------------------
# PARITY-04: Periodic S3 log delivery
# ---------------------------------------------------------------------------
_s3_delivery_thread: threading.Thread | None = None
# D6: the stop Event is (re)created on every start so the new thread's
# first ``wait()`` honors the full 60s cycle instead of returning
# immediately because a previous shutdown left the flag set. Initialized
# lazily via ``_reset_stop_event`` at start time.
_s3_delivery_stop: threading.Event = threading.Event()

# D3: cache boto3 client bundles keyed by ``(account_id, region)`` so the
# delivery thread does not allocate fresh connection pools on every
# iteration. The bundle is the object returned by ``connect_to(...)``
# (exposes ``.s3`` and ``.sns``). Cleared on shutdown so sockets held by
# the underlying botocore session can be released.
_s3_delivery_client_cache: dict[tuple[str, str], object] = {}
_s3_delivery_client_cache_lock = threading.Lock()

# D7: guard so the shutdown handler is registered once, even if
# ``_start_s3_log_delivery`` is called repeatedly (hot-reload, test
# re-init, service restart).
_s3_delivery_shutdown_registered: bool = False


def _get_delivery_clients(account_id: str, region: str):
    """Return a cached internal-client bundle for ``(account_id, region)``.

    The first call creates the bundle via ``connect_to(...)``; subsequent
    calls return the same object so the delivery thread does not leak
    sockets by re-instantiating botocore clients every 60 seconds (D3).
    """
    from localemu.aws.connect import connect_to
    from localemu.constants import INTERNAL_AWS_SECRET_ACCESS_KEY

    key = (account_id, region)
    with _s3_delivery_client_cache_lock:
        clients = _s3_delivery_client_cache.get(key)
        if clients is None:
            clients = connect_to(
                aws_access_key_id=account_id,
                aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                region_name=region,
            )
            _s3_delivery_client_cache[key] = clients
    return clients


def _clear_delivery_client_cache() -> None:
    """Drop all cached delivery clients. Called on shutdown (D3)."""
    with _s3_delivery_client_cache_lock:
        _s3_delivery_client_cache.clear()


def _deliver_log_file(
    *,
    trail,
    s3_client,
    sns_client,
    account_id: str,
    region: str,
    bucket_name: str,
    s3_key: str,
    body: bytes,
) -> None:
    """Write one CloudTrail log file to S3 and optionally publish an SNS
    notification, honoring the trail's ``kms_key_id`` and ``sns_topic_name``.

    Parity rules (see AWS docs "Configuring Amazon SNS notifications for
    CloudTrail" and "Encrypting CloudTrail log files with AWS KMS-managed
    keys"):

    * If the trail has ``kms_key_id`` set, ``put_object`` is called with
      ``ServerSideEncryption="aws:kms"`` and ``SSEKMSKeyId=<key id>`` so the
      log file is encrypted with the configured CMK.
    * If the trail has ``sns_topic_name`` set, after a successful put we
      publish an SNS message to the trail's topic with the AWS-documented
      body ``{"s3Bucket": <bucket>, "s3ObjectKey": [<key>]}``.
    * Failure of the SNS publish MUST NOT abort or unwind the S3 delivery.
    """
    put_kwargs: dict = {
        "Bucket": bucket_name,
        "Key": s3_key,
        "Body": body,
        "ContentType": "application/x-gzip",
    }
    kms_key_id = getattr(trail, "kms_key_id", None)
    if kms_key_id:
        put_kwargs["ServerSideEncryption"] = "aws:kms"
        put_kwargs["SSEKMSKeyId"] = kms_key_id

    s3_client.put_object(**put_kwargs)

    sns_topic_name = getattr(trail, "sns_topic_name", None)
    if not sns_topic_name:
        return

    try:
        topic_arn = getattr(trail, "topic_arn", None)
        if not topic_arn:
            partition = getattr(trail, "partition", "aws")
            topic_arn = (
                f"arn:{partition}:sns:{region}:{account_id}:{sns_topic_name}"
            )
        payload = json.dumps({
            "s3Bucket": bucket_name,
            "s3ObjectKey": [s3_key],
        })
        sns_client.publish(TopicArn=topic_arn, Message=payload)
        LOG.debug(
            "Published CloudTrail log delivery SNS notification to %s",
            topic_arn,
        )
    except Exception as sns_err:
        LOG.debug(
            "Failed to publish CloudTrail SNS notification: %s",
            sns_err,
        )


def _run_delivery_cycle(stop_event: threading.Event) -> None:
    """Run one iteration of the CloudTrail S3 log-delivery loop.

    Extracted from the thread body so it can be exercised directly from
    tests and so D4/D5/D2/D1/D3 fixes are localized to a single function.

    Fixes applied here:

    * **D1** Cursor keyed by ``(account_id, region, trail_name)`` — trails
      sharing a name across accounts/regions no longer step on each other.
    * **D2** Cursor is the event's ``event_time`` (a monotonic UTC
      datetime assigned at record time), not an event_id. Even when the
      cursor event has aged out of the 500-event recent window, any
      event strictly newer than the cursor is still correctly identified
      as already-delivered and skipped.
    * **D3** Clients are cached per ``(account_id, region)`` via
      ``_get_delivery_clients`` — no more per-iteration botocore client
      construction.
    * **D4** Iterate over ``list(ct_backend.trails.items())`` (a snapshot)
      so concurrent ``CreateTrail`` cannot raise
      ``RuntimeError: dictionary changed size during iteration``.
    * **D5** All three nested error handlers log at WARNING with
      ``exc_info=True``. Loop-continuation semantics preserved.
    """
    from localemu.dashboard.api import _iter_moto_backends
    from localemu.services.cloudtrail.event_store import get_event_store

    store = get_event_store()

    # D1: the cursor dict lives on the enclosing thread state. We use a
    # mutable attribute on the function so the cycle is stateless from
    # the caller's perspective but persists across iterations on the
    # same thread.
    last_delivered: dict[tuple[str, str, str], datetime] = getattr(
        _run_delivery_cycle, "_last_delivered", None
    )
    if last_delivered is None:
        last_delivered = {}
        _run_delivery_cycle._last_delivered = last_delivered  # type: ignore[attr-defined]

    for account_id, region, ct_backend in _iter_moto_backends("cloudtrail"):
        if stop_event.is_set():
            return
        try:
            # D4: snapshot the trails dict so concurrent CreateTrail on
            # the gateway/reactor thread cannot raise RuntimeError.
            trails_snapshot = list(getattr(ct_backend, "trails", {}).items())
        except Exception:
            LOG.warning(
                "CloudTrail delivery: failed to snapshot trails for %s/%s",
                account_id, region, exc_info=True,
            )
            continue

        for trail_name, trail in trails_snapshot:
            try:
                if not getattr(trail, "is_logging", True):
                    continue
                # moto's ``Trail`` exposes the S3 bucket as ``bucket_name``
                # (see moto/cloudtrail/models.py). The older attribute name
                # ``s3_bucket_name`` is accepted as a fallback so a future
                # moto rename or a non-moto Trail implementation keeps
                # working.
                bucket_name = (
                    getattr(trail, "bucket_name", None)
                    or getattr(trail, "s3_bucket_name", None)
                )
                if not bucket_name:
                    continue
                prefix = (
                    getattr(trail, "s3_key_prefix", None)
                    or getattr(trail, "key_prefix", None)
                    or ""
                )

                events = store.get_recent(limit=500)
                if not events:
                    continue

                # D1 + D2: cursor is (account, region, trail) -> event_time.
                # Timestamps are assigned by the event store at record time
                # and are stable across cache eviction, so we correctly
                # skip already-delivered events even if they have aged
                # out of the 500-event window.
                cursor_key = (account_id, region, trail_name)
                last_time = last_delivered.get(cursor_key)
                new_events = [
                    evt for evt in events
                    if evt.aws_region == region
                    and (last_time is None or evt.event_time > last_time)
                ]
                if not new_events:
                    continue

                # events are newest-first; advance the cursor to the max
                # event_time observed this cycle (the first element).
                last_delivered[cursor_key] = new_events[0].event_time

                now = datetime.now(timezone.utc)
                key_parts = []
                if prefix:
                    key_parts.append(prefix)
                key_parts.extend([
                    "AWSLogs", account_id, "CloudTrail", region,
                    str(now.year),
                    f"{now.month:02d}",
                    f"{now.day:02d}",
                    f"{account_id}_CloudTrail_{region}_{now.strftime('%Y%m%dT%H%M%SZ')}.json.gz",
                ])
                s3_key = "/".join(key_parts)

                records = []
                for evt in new_events:
                    try:
                        records.append(json.loads(evt.to_cloudtrail_event_json()))
                    except Exception:
                        LOG.warning(
                            "CloudTrail delivery: failed to serialize event %s",
                            getattr(evt, "event_id", "?"), exc_info=True,
                        )
                log_content = json.dumps({"Records": records}, default=str)
                compressed = gzip.compress(log_content.encode("utf-8"))

                try:
                    # D3: reuse the cached client bundle.
                    clients = _get_delivery_clients(account_id, region)
                    _deliver_log_file(
                        trail=trail,
                        s3_client=clients.s3,
                        sns_client=clients.sns,
                        account_id=account_id,
                        region=region,
                        bucket_name=bucket_name,
                        s3_key=s3_key,
                        body=compressed,
                    )
                    LOG.debug(
                        "Delivered %d CloudTrail events to s3://%s/%s",
                        len(new_events), bucket_name, s3_key,
                    )
                    # B5: record real delivery for GetTrailStatus
                    _record_delivery_attempt(
                        account_id, region, trail_name,
                        success=True,
                    )
                except Exception as e:
                    LOG.warning(
                        "CloudTrail delivery to s3://%s/%s failed: %s",
                        bucket_name, s3_key, e, exc_info=True,
                    )
                    # B5: surface the failure via GetTrailStatus
                    _record_delivery_attempt(
                        account_id, region, trail_name,
                        success=False,
                        error=type(e).__name__,
                    )
            except Exception:
                # D5: one bad trail must not abort the whole cycle, but
                # the failure MUST be visible in logs.
                LOG.warning(
                    "CloudTrail delivery: unexpected error processing trail %s in %s/%s",
                    trail_name, account_id, region, exc_info=True,
                )


def _start_s3_log_delivery() -> None:
    """Start a background daemon that periodically writes CloudTrail events
    to S3 buckets configured on each trail (PARITY-04).

    Events are written as gzipped JSON files following the AWS key format:
    ``AWSLogs/{account_id}/CloudTrail/{region}/{year}/{month}/{day}/...json.gz``

    Safe to call multiple times: if the thread is already alive, it's a
    no-op; the shutdown handler is registered exactly once (D7).
    """
    global _s3_delivery_thread, _s3_delivery_stop, _s3_delivery_shutdown_registered

    if _s3_delivery_thread and _s3_delivery_thread.is_alive():
        return

    # D6: a previous shutdown may have set the module-global Event. A new
    # thread that inherits that flag would observe ``wait(60)`` returning
    # True immediately and spin the loop at 100% CPU. Replace the Event
    # with a fresh, un-set instance before starting the thread. Captured
    # by closure so the new thread always talks to the right Event even
    # if a later shutdown swaps the module global again.
    _s3_delivery_stop = threading.Event()
    stop_event = _s3_delivery_stop

    # D1 fresh start: drop any stale cursor state from a previous run.
    _run_delivery_cycle._last_delivered = {}  # type: ignore[attr-defined]

    def _delivery_loop() -> None:
        while not stop_event.wait(timeout=60):
            try:
                _run_delivery_cycle(stop_event)
            except Exception:
                # D5: top-level catch so the thread never dies silently,
                # but failures are visible at WARNING.
                LOG.warning(
                    "CloudTrail S3 delivery cycle failed", exc_info=True,
                )

    _s3_delivery_thread = threading.Thread(
        target=_delivery_loop, daemon=True, name="cloudtrail-s3-delivery",
    )
    _s3_delivery_thread.start()

    # D7: register the shutdown hook exactly once. Without this guard
    # each call to ``_start_s3_log_delivery`` (hot-reload, test setup,
    # service restart) grows SHUTDOWN_HANDLERS unbounded.
    if not _s3_delivery_shutdown_registered:
        try:
            from localemu.runtime.shutdown import SHUTDOWN_HANDLERS

            SHUTDOWN_HANDLERS.register(_stop_s3_log_delivery)
            _s3_delivery_shutdown_registered = True
        except Exception:
            LOG.warning(
                "Unable to register CloudTrail S3 delivery shutdown hook",
                exc_info=True,
            )

    LOG.info("CloudTrail S3 log delivery thread started.")


def _stop_s3_log_delivery() -> None:
    """Stop the CloudTrail S3 delivery background thread (ISSUE-05).

    Also clears the cached delivery clients (D3) so the underlying
    botocore sockets can be released.
    """
    global _s3_delivery_thread
    _s3_delivery_stop.set()
    thread = _s3_delivery_thread
    if thread and thread.is_alive():
        thread.join(timeout=5)
    _s3_delivery_thread = None
    _clear_delivery_client_cache()


def _handle_lookup_events(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """LookupEvents: query the shared CloudTrail event store.

    B6/B7/B9/B10 compliance:
      * ``EventCategory`` is forwarded to the store and validated against
        ``Management``/``Data``/``Insight``.
      * ``MaxResults`` is clamped to ``[1, 50]`` server-side so raw-HTTP
        callers sending ``0`` / negative / oversized values are normalized
        instead of silently coerced to 50.
      * Store-raised ``Invalid{EventCategory,LookupAttributes,NextToken}``
        errors are translated to ``CommonServiceException`` (400, sender
        fault) with AWS's canonical error codes.
    """
    from localemu.services.cloudtrail.event_store import (
        InvalidEventCategoryError,
        InvalidLookupAttributesError,
        InvalidNextTokenError,
        get_event_store,
    )

    store = get_event_store()

    # Parse request parameters
    lookup_attributes = request.get("LookupAttributes") or []
    raw_max_results = request.get("MaxResults")
    next_token = request.get("NextToken")
    event_category = request.get("EventCategory")

    # B10: clamp MaxResults to [1, 50] server-side. Raw-HTTP clients can
    # send 0 or negative values; boto3 defaults to 50. AWS documents the
    # valid range as 1..50 — enforce it before hitting the store.
    if raw_max_results is None:
        max_results = 50
    else:
        try:
            max_results = max(1, min(50, int(raw_max_results)))
        except (TypeError, ValueError):
            max_results = 50

    # Parse time range
    start_time = request.get("StartTime")
    end_time = request.get("EndTime")

    # Convert to datetime if needed (boto3 sends datetime objects)
    if start_time and not isinstance(start_time, datetime):
        try:
            start_time = datetime.fromisoformat(str(start_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            start_time = None

    if end_time and not isinstance(end_time, datetime):
        try:
            end_time = datetime.fromisoformat(str(end_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            end_time = None

    # Query the store — translate typed errors into CommonServiceException.
    try:
        events, new_token = store.query(
            start_time=start_time,
            end_time=end_time,
            lookup_attributes=lookup_attributes,
            max_results=max_results,
            next_token=next_token,
            event_category=event_category,
        )
    except InvalidLookupAttributesError as exc:
        raise CommonServiceException(
            code="InvalidLookupAttributesException",
            message=str(exc),
            status_code=400,
            sender_fault=True,
        ) from exc
    except InvalidNextTokenError as exc:
        raise CommonServiceException(
            code="InvalidNextTokenException",
            message=str(exc),
            status_code=400,
            sender_fault=True,
        ) from exc
    except InvalidEventCategoryError as exc:
        raise CommonServiceException(
            code="InvalidEventCategoryException",
            message=str(exc),
            status_code=400,
            sender_fault=True,
        ) from exc

    # Build response
    response: dict = {
        "Events": [e.to_lookup_event() for e in events],
    }
    if new_token:
        response["NextToken"] = new_token

    return response


# ---------------------------------------------------------------------------
# B3: KMS validation for CreateTrail / UpdateTrail
# ---------------------------------------------------------------------------
def _validate_kms_key_id(
    kms_key_id: str,
    account_id: str,
    region: str,
) -> None:
    """Validate that ``kms_key_id`` resolves to a real KMS key in LocalEmu's
    native KMS store. Accepts a bare key id (UUID), a key ARN, an alias
    name (``alias/...``) or an alias ARN — mirroring the AWS CloudTrail
    API surface.

    Raises ``CommonServiceException("KmsKeyNotFoundException")`` — the
    error code the real CloudTrail service uses for this condition — if
    the key is absent, or if a key ARN references a region other than
    the trail's region.
    """
    if not kms_key_id:
        return
    try:
        from localemu.services.kms.models import kms_stores
    except Exception:
        # KMS service not loaded in this build — skip validation rather
        # than block CreateTrail on an unrelated misconfiguration.
        return

    def _fail(msg: str) -> None:
        raise CommonServiceException(
            code="KmsKeyNotFoundException",
            message=msg,
            status_code=400,
            sender_fault=True,
        )

    key_id: str | None = None
    alias_name: str | None = None

    if kms_key_id.startswith("arn:"):
        if ":alias/" in kms_key_id:
            alias_name = "alias/" + kms_key_id.split(":alias/", 1)[1]
        elif ":key/" in kms_key_id:
            parts = kms_key_id.split(":")
            if len(parts) < 6:
                _fail(f"Invalid KMS key ARN: {kms_key_id}")
            arn_region = parts[3]
            if arn_region and arn_region != region:
                _fail(
                    f"KMS key {kms_key_id} is in region {arn_region}; "
                    f"trail is in {region}"
                )
            key_id = kms_key_id.split(":key/", 1)[1]
        else:
            _fail(f"Invalid KMS key identifier: {kms_key_id}")
    elif kms_key_id.startswith("alias/"):
        alias_name = kms_key_id
    else:
        key_id = kms_key_id

    store = kms_stores[account_id][region]

    if alias_name is not None:
        target = store.aliases.get(alias_name)
        if target is None:
            _fail(f"Alias {alias_name} is not found.")
        try:
            key_id = target.metadata["TargetKeyId"]  # type: ignore[index]
        except Exception:
            key_id = getattr(target, "target_key_id", None)

    if not key_id or key_id not in store.keys:
        _fail(
            f"Key 'arn:aws:kms:{region}:{account_id}:key/{key_id}' "
            "does not exist"
        )


def _patch_moto_topic_check() -> None:
    """B2 — sibling of :func:`_patch_moto_bucket_check`.

    Moto's ``Trail.check_topic_exists`` consults moto's own SNS backend;
    LocalEmu's SNS is native (``localemu.services.sns.models.sns_stores``),
    so any ``CreateTrail``/``UpdateTrail`` specifying ``SnsTopicName``
    failed with ``InsufficientSnsTopicPolicyException`` even when the
    topic existed per ``aws sns list-topics``.

    Rewire the check to consult LocalEmu's native SNS store first,
    falling back to moto's original implementation only if the topic is
    absent locally. Idempotent via the ``_le_patched`` marker.
    """
    try:
        from moto.cloudtrail.models import (
            InsufficientSnsTopicPolicyException,
            Trail,
        )
        from localemu.services.sns.models import sns_stores
    except Exception:
        return

    _original = Trail.check_topic_exists
    if getattr(_original, "_le_patched", False):
        return

    def _patched(self: "Trail") -> None:
        topic_arn = self.topic_arn
        if not topic_arn:
            return
        try:
            region_store = sns_stores[self.account_id][self.region_name]
            if topic_arn in region_store.topics:
                return
        except Exception:
            pass
        try:
            _original(self)
        except Exception:
            raise InsufficientSnsTopicPolicyException(
                "SNS Topic does not exist or the topic policy is incorrect!"
            )

    _patched._le_patched = True  # type: ignore[attr-defined]
    Trail.check_topic_exists = _patched  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# B3 / B4: CreateTrail & UpdateTrail intercepts
# ---------------------------------------------------------------------------
def _handle_create_trail(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """B3 — validate ``KmsKeyId`` against LocalEmu's native KMS before
    delegating to moto. Bucket and SNS-topic existence are already
    enforced by moto's ``Trail.__init__`` via our patched
    ``check_bucket_exists`` / ``check_topic_exists`` hooks."""
    kms_key_id = request.get("KmsKeyId")
    if kms_key_id:
        _validate_kms_key_id(kms_key_id, context.account_id, context.region)
    return _proxy_moto(context, request)


def _handle_update_trail(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """B4 — moto's ``update_trail`` does not re-run
    ``check_bucket_exists`` or ``check_topic_exists``, so a trail can be
    silently mutated to point at a bucket or topic that does not exist.

    Replay those checks locally before proxying. We build a throwaway
    ``Trail``-shaped probe (same pattern as the B1 regression test) so we
    can reuse the patched methods without mutating moto's trail state on
    failure.
    """
    trail_name = request.get("Name")
    s3_bucket_name = request.get("S3BucketName")
    sns_topic_name = request.get("SnsTopicName")
    kms_key_id = request.get("KmsKeyId")

    if kms_key_id:
        _validate_kms_key_id(kms_key_id, context.account_id, context.region)

    if s3_bucket_name or sns_topic_name:
        try:
            from moto.cloudtrail.models import Trail
            from moto.utilities.utils import get_partition
        except Exception:
            Trail = None  # type: ignore[assignment]
            get_partition = None  # type: ignore[assignment]

        if Trail is not None and get_partition is not None:
            probe = Trail.__new__(Trail)
            probe.account_id = context.account_id
            probe.region_name = context.region
            probe.partition = get_partition(context.region)
            probe.trail_name = trail_name or ""
            probe.bucket_name = s3_bucket_name or ""
            probe.sns_topic_name = sns_topic_name or ""
            if s3_bucket_name:
                probe.check_bucket_exists()
            if sns_topic_name:
                probe.check_topic_exists()

    return _proxy_moto(context, request)


# ---------------------------------------------------------------------------
# B5: GetTrailStatus — overlay real delivery state on moto's response
# ---------------------------------------------------------------------------
def _handle_get_trail_status(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """Let moto answer ``GetTrailStatus`` (trail existence, ``IsLogging``,
    ``StartLoggingTime``, etc.), then overwrite the delivery-related
    fields with values from our shared delivery-state dict so callers see
    truthful ``LatestDeliveryTime`` / ``LatestDeliveryError`` instead of
    moto's ``utcnow()`` lie.

    When no delivery has been recorded yet (freshly created trail) the
    delivery fields are returned empty — parity with real AWS for trails
    that have just started logging.
    """
    response = _proxy_moto(context, request) or {}

    trail_name = request.get("Name") or ""
    if trail_name.startswith("arn:") and ":trail/" in trail_name:
        trail_name_key = trail_name.split(":trail/", 1)[1]
    else:
        trail_name_key = trail_name

    state: dict | None = None
    try:
        from localemu.dashboard.api import _iter_moto_backends

        for acct_id, rgn, ct_backend in _iter_moto_backends("cloudtrail"):
            if acct_id != context.account_id:
                continue
            if trail_name_key in getattr(ct_backend, "trails", {}):
                state = _get_delivery_state(acct_id, rgn, trail_name_key)
                if state is not None:
                    break
    except Exception:
        state = _get_delivery_state(
            context.account_id, context.region, trail_name_key
        )

    if state is None:
        response["LatestDeliveryTime"] = None
        response["LatestDeliveryError"] = ""
        response["LatestDeliveryAttemptTime"] = ""
        response["LatestDeliveryAttemptSucceeded"] = ""
    else:
        response["LatestDeliveryTime"] = state["LatestDeliveryTime"]
        response["LatestDeliveryError"] = state["LatestDeliveryError"]
        response["LatestDeliveryAttemptTime"] = state[
            "LatestDeliveryAttemptTime"
        ]
        response["LatestDeliveryAttemptSucceeded"] = state[
            "LatestDeliveryAttemptSucceeded"
        ]

    return response


# ---------------------------------------------------------------------------
# StartLogging / StopLogging — ARN-to-name normalisation
#
# Real AWS accepts either the trail name OR the full trail ARN as the ``Name``
# parameter. Terraform's ``aws_cloudtrail`` resource passes the ARN. Moto's
# ``start_logging``/``stop_logging`` do a raw ``self.trails[name]`` dict
# lookup keyed by bare name, and KeyError out when handed an ARN — surfacing
# as a 500 InternalError to the caller. Intercept to resolve the ARN to the
# bare trail name before proxying to moto.
# ---------------------------------------------------------------------------
def _normalize_trail_name(name: str | None) -> str:
    if not name:
        return ""
    if name.startswith("arn:") and ":trail/" in name:
        return name.split(":trail/", 1)[1]
    return name


def _proxy_moto_with_normalized_trail_name(
    context: RequestContext,
    request: ServiceRequest,
    *,
    field: str = "Name",
) -> ServiceResponse:
    """Normalise ``request[field]`` from ARN to bare name, then forward to
    moto via ``call_moto_with_request`` — which (unlike ``_proxy_moto``)
    actually rebuilds the HTTP request with the mutated body, so moto sees
    the corrected parameter.
    """
    from localemu.services.moto import call_moto_with_request

    mutated = dict(request)
    mutated[field] = _normalize_trail_name(mutated.get(field))
    return call_moto_with_request(context, mutated) or {}


def _handle_start_logging(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(context, request, field="Name")


def _handle_stop_logging(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(context, request, field="Name")


def _handle_delete_trail(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(context, request, field="Name")


def _handle_put_event_selectors(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(
        context, request, field="TrailName"
    )


def _handle_get_event_selectors(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(
        context, request, field="TrailName"
    )


def _handle_put_insight_selectors(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(
        context, request, field="TrailName"
    )


def _handle_get_insight_selectors(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    return _proxy_moto_with_normalized_trail_name(
        context, request, field="TrailName"
    )


# ---------------------------------------------------------------------------
# CloudTrail Lake — Query APIs
# ---------------------------------------------------------------------------
def _handle_start_query(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """StartQuery: register a new query and schedule async execution."""
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import (
        get_query_store,
        schedule_query,
    )

    statement = request.get("QueryStatement")
    if not statement:
        raise CommonServiceException(
            "InvalidParameterCombination",
            "QueryStatement is required.",
        )

    store = get_query_store()
    q = store.create(
        statement=statement,
        delivery_s3_uri=request.get("DeliveryS3Uri"),
        query_alias=request.get("QueryAlias"),
    )
    # Kick off the runner on a background thread so the client can call
    # Describe/GetResults shortly afterwards.
    schedule_query(q.query_id, delay_seconds=0.1)

    response: dict = {"QueryId": q.query_id}
    owner = request.get("EventDataStoreOwnerAccountId")
    if owner:
        response["EventDataStoreOwnerAccountId"] = owner
    return response


def _handle_cancel_query(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import get_query_store

    query_id = request.get("QueryId")
    if not query_id:
        raise CommonServiceException(
            "InvalidParameterCombination", "QueryId is required."
        )

    q = get_query_store().cancel(query_id)
    if q is None:
        raise CommonServiceException(
            "QueryIdNotFound", f"Query {query_id} was not found."
        )
    return {"QueryId": q.query_id, "QueryStatus": q.status}


def _handle_describe_query(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import get_query_store

    query_id = request.get("QueryId")
    if not query_id:
        raise CommonServiceException(
            "InvalidParameterCombination",
            "QueryId is required (QueryAlias/RefreshId not supported by LocalEmu).",
        )

    q = get_query_store().get(query_id)
    if q is None:
        raise CommonServiceException(
            "QueryIdNotFound", f"Query {query_id} was not found."
        )

    response: dict = {
        "QueryId": q.query_id,
        "QueryString": q.statement,
        "QueryStatus": q.status,
        "QueryStatistics": {
            "EventsMatched": len(q.rows),
            "EventsScanned": q.events_scanned,
            "BytesScanned": q.bytes_scanned,
            "ExecutionTimeInMillis": q.execution_ms,
            "CreationTime": q.creation_time,
        },
    }
    if q.error_message:
        response["ErrorMessage"] = q.error_message
    if q.delivery_s3_uri:
        response["DeliveryS3Uri"] = q.delivery_s3_uri
    if q.delivery_status:
        response["DeliveryStatus"] = q.delivery_status
    if q.prompt:
        response["Prompt"] = q.prompt
    return response


def _handle_get_query_results(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import get_query_store

    query_id = request.get("QueryId")
    if not query_id:
        raise CommonServiceException(
            "InvalidParameterCombination", "QueryId is required."
        )

    q = get_query_store().get(query_id)
    if q is None:
        raise CommonServiceException(
            "QueryIdNotFound", f"Query {query_id} was not found."
        )

    max_results = request.get("MaxQueryResults") or 1000
    next_token = request.get("NextToken")
    offset = 0
    if next_token:
        try:
            offset = int(next_token)
        except ValueError:
            offset = 0

    page = q.rows[offset : offset + max_results]
    new_token = None
    if offset + max_results < len(q.rows):
        new_token = str(offset + max_results)

    response: dict = {
        "QueryStatus": q.status,
        "QueryStatistics": {
            "ResultsCount": len(page),
            "TotalResultsCount": len(q.rows),
            "BytesScanned": q.bytes_scanned,
        },
        "QueryResultRows": page,
    }
    if new_token:
        response["NextToken"] = new_token
    if q.error_message:
        response["ErrorMessage"] = q.error_message
    return response


def _handle_list_queries(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import get_query_store

    eds = request.get("EventDataStore")
    if not eds:
        raise CommonServiceException(
            "InvalidParameterCombination", "EventDataStore is required."
        )

    start_time = request.get("StartTime")
    end_time = request.get("EndTime")
    if start_time and not isinstance(start_time, datetime):
        try:
            start_time = datetime.fromisoformat(str(start_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            start_time = None
    if end_time and not isinstance(end_time, datetime):
        try:
            end_time = datetime.fromisoformat(str(end_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            end_time = None

    queries = get_query_store().list(
        event_data_store=eds,
        status=request.get("QueryStatus"),
        start_time=start_time,
        end_time=end_time,
    )

    max_results = request.get("MaxResults") or 50
    next_token = request.get("NextToken")
    offset = 0
    if next_token:
        try:
            offset = int(next_token)
        except ValueError:
            offset = 0

    page = queries[offset : offset + max_results]
    new_token = None
    if offset + max_results < len(queries):
        new_token = str(offset + max_results)

    response: dict = {
        "Queries": [
            {
                "QueryId": q.query_id,
                "QueryStatus": q.status,
                "CreationTime": q.creation_time,
            }
            for q in page
        ],
    }
    if new_token:
        response["NextToken"] = new_token
    return response


def _handle_search_sample_queries(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.services.cloudtrail.query_store import search_samples

    phrase = request.get("SearchPhrase") or ""
    max_results = request.get("MaxResults") or 10
    return {"SearchResults": search_samples(phrase, max_results=max_results)}


def _handle_generate_query(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    from localemu.aws.api.core import CommonServiceException
    from localemu.services.cloudtrail.query_store import generate_sql_from_prompt

    prompt = request.get("Prompt") or ""
    event_data_stores = request.get("EventDataStores") or []
    try:
        sql = generate_sql_from_prompt(prompt, event_data_stores)
    except ValueError as e:
        raise CommonServiceException("InvalidParameterCombination", str(e))
    return {"QueryStatement": sql, "QueryAlias": "localemu-generated"}


# ---------------------------------------------------------------------------
# CloudTrail Lake / EventDataStore
# ---------------------------------------------------------------------------
#
# In-memory registry of data stores, keyed by ``(account_id, region, arn)``.
# Access is guarded by ``_EDS_LOCK``; nothing is persisted to disk.
#
# AWS's default ``DeleteEventDataStore`` behavior is a *soft delete*: the
# store moves to ``PENDING_DELETION`` and can be restored within 7 days.
# We keep the store in the registry and evaluate expiry lazily.
#
# NOTE: This implementation is metadata-only — it does NOT ingest events
# into the store.  The Lake Query APIs (StartQuery/GetQueryResults/...)
# are handled separately above.

_EDS_LOCK = threading.Lock()
_EVENT_DATA_STORES: dict[tuple[str, str, str], dict[str, Any]] = {}

_PENDING_DELETION_WINDOW = timedelta(days=7)
_EDS_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{3,128}$")
_VALID_BILLING_MODES = {"EXTENDABLE_RETENTION_PRICING", "FIXED_RETENTION_PRICING"}


class _EDSAlreadyExists(CommonServiceException):
    def __init__(self, name: str) -> None:
        super().__init__(
            "EventDataStoreAlreadyExistsException",
            f"An event data store with the name '{name}' already exists.",
            400,
            True,
        )


class _EDSNotFound(CommonServiceException):
    def __init__(self) -> None:
        super().__init__(
            "EventDataStoreNotFoundException",
            "The specified event data store was not found.",
            400,
            True,
        )


class _EDSArnInvalid(CommonServiceException):
    def __init__(self, value: str) -> None:
        super().__init__(
            "EventDataStoreARNInvalidException",
            f"The specified event data store ARN is not valid: {value}",
            400,
            True,
        )


class _EDSTerminationProtected(CommonServiceException):
    def __init__(self) -> None:
        super().__init__(
            "EventDataStoreTerminationProtectedException",
            "The event data store cannot be deleted because termination protection is enabled.",
            400,
            True,
        )


class _EDSInvalidStatus(CommonServiceException):
    def __init__(self, message: str) -> None:
        super().__init__(
            "InvalidEventDataStoreStatusException", message, 400, True
        )


class _EDSInvalidParameter(CommonServiceException):
    def __init__(self, message: str) -> None:
        super().__init__("InvalidParameterException", message, 400, True)


def _eds_now() -> datetime:
    return datetime.now(timezone.utc)


def _build_eds_arn(account_id: str, region: str, store_id: str) -> str:
    return f"arn:aws:cloudtrail:{region}:{account_id}:eventdatastore/{store_id}"


def _resolve_eds_arn(context: RequestContext, value: str | None) -> str:
    """Accept either a full EDS ARN or the UUID suffix (AWS behavior)."""
    if not value:
        raise _EDSArnInvalid(str(value))
    if value.startswith("arn:"):
        parts = value.split(":")
        if (
            len(parts) < 6
            or parts[2] != "cloudtrail"
            or not parts[5].startswith("eventdatastore/")
        ):
            raise _EDSArnInvalid(value)
        return value
    return _build_eds_arn(context.account_id, context.region, value)


def _default_advanced_event_selectors() -> list[dict[str, Any]]:
    return [
        {
            "Name": "Default management events",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
            ],
        }
    ]


def _validate_retention(retention: int | None, billing_mode: str) -> int:
    if retention is None:
        return 366 if billing_mode == "EXTENDABLE_RETENTION_PRICING" else 2557
    if not isinstance(retention, int):
        raise _EDSInvalidParameter("RetentionPeriod must be an integer.")
    if retention < 7:
        raise _EDSInvalidParameter("RetentionPeriod must be at least 7 days.")
    upper = 3653 if billing_mode == "EXTENDABLE_RETENTION_PRICING" else 2557
    if retention > upper:
        raise _EDSInvalidParameter(
            f"RetentionPeriod for BillingMode {billing_mode} must be at most {upper} days."
        )
    return retention


def _validate_eds_name(name: str | None) -> str:
    if not name or not isinstance(name, str):
        raise _EDSInvalidParameter("Name is required.")
    if not _EDS_NAME_RE.match(name):
        raise _EDSInvalidParameter(
            "Name must be 3-128 characters and contain only letters, digits, '.', '_', or '-'."
        )
    return name


def _find_store(arn: str) -> dict[str, Any] | None:
    for key, store in _EVENT_DATA_STORES.items():
        if key[2] == arn:
            return store
    return None


def _sweep_expired_eds() -> None:
    now = _eds_now()
    expired = [
        key
        for key, store in _EVENT_DATA_STORES.items()
        if store["Status"] == "PENDING_DELETION"
        and store.get("_PendingDeletionSince")
        and (now - store["_PendingDeletionSince"]) > _PENDING_DELETION_WINDOW
    ]
    for key in expired:
        _EVENT_DATA_STORES.pop(key, None)


def _serialize_eds_full(store: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "EventDataStoreArn": store["EventDataStoreArn"],
        "Name": store["Name"],
        "Status": store["Status"],
        "AdvancedEventSelectors": store["AdvancedEventSelectors"],
        "MultiRegionEnabled": store["MultiRegionEnabled"],
        "OrganizationEnabled": store["OrganizationEnabled"],
        "RetentionPeriod": store["RetentionPeriod"],
        "TerminationProtectionEnabled": store["TerminationProtectionEnabled"],
        "CreatedTimestamp": store["CreatedTimestamp"],
        "UpdatedTimestamp": store["UpdatedTimestamp"],
        "BillingMode": store["BillingMode"],
    }
    if store.get("KmsKeyId"):
        out["KmsKeyId"] = store["KmsKeyId"]
    return out


def reset_event_data_stores() -> None:
    """Reset the in-memory EventDataStore registry. For tests only."""
    with _EDS_LOCK:
        _EVENT_DATA_STORES.clear()


def _handle_create_event_data_store(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    name = _validate_eds_name(request.get("Name"))
    billing_mode = request.get("BillingMode") or "EXTENDABLE_RETENTION_PRICING"
    if billing_mode not in _VALID_BILLING_MODES:
        raise _EDSInvalidParameter(f"Invalid BillingMode: {billing_mode}")
    retention = _validate_retention(request.get("RetentionPeriod"), billing_mode)
    multi_region = bool(request.get("MultiRegionEnabled", True))
    org_enabled = bool(request.get("OrganizationEnabled", False))
    termination_protected = bool(request.get("TerminationProtectionEnabled", True))
    advanced_selectors = (
        request.get("AdvancedEventSelectors") or _default_advanced_event_selectors()
    )
    tags_list = request.get("TagsList") or []
    kms_key_id = request.get("KmsKeyId")
    start_ingestion = bool(request.get("StartIngestion", True))

    account_id, region = context.account_id, context.region
    with _EDS_LOCK:
        _sweep_expired_eds()
        for (acct, rgn, _), existing in _EVENT_DATA_STORES.items():
            if (
                acct == account_id
                and rgn == region
                and existing["Name"] == name
                and existing["Status"] != "PENDING_DELETION"
            ):
                raise _EDSAlreadyExists(name)

        store_id = str(uuid.uuid4())
        arn = _build_eds_arn(account_id, region, store_id)
        now = _eds_now()
        status = "ENABLED" if start_ingestion else "STOPPED_INGESTION"
        store: dict[str, Any] = {
            "EventDataStoreArn": arn,
            "Name": name,
            "Status": status,
            "AdvancedEventSelectors": advanced_selectors,
            "MultiRegionEnabled": multi_region,
            "OrganizationEnabled": org_enabled,
            "RetentionPeriod": retention,
            "TerminationProtectionEnabled": termination_protected,
            "CreatedTimestamp": now,
            "UpdatedTimestamp": now,
            "BillingMode": billing_mode,
            "TagsList": tags_list,
        }
        if kms_key_id:
            store["KmsKeyId"] = kms_key_id
        _EVENT_DATA_STORES[(account_id, region, arn)] = store

    out = _serialize_eds_full(store)
    out["TagsList"] = tags_list
    return out


def _handle_get_event_data_store(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        _sweep_expired_eds()
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        out = _serialize_eds_full(store)
    out["FederationStatus"] = "DISABLED"
    out["PartitionKeys"] = [{"Name": "eventTime", "Type": "bigint"}]
    return out


def _handle_update_event_data_store(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        _sweep_expired_eds()
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        if store["Status"] == "PENDING_DELETION":
            raise _EDSInvalidStatus(
                "The event data store is pending deletion and cannot be updated."
            )

        new_name = request.get("Name")
        if new_name is not None:
            new_name = _validate_eds_name(new_name)
            account_id, region = context.account_id, context.region
            for (acct, rgn, other_arn), other in _EVENT_DATA_STORES.items():
                if (
                    acct == account_id
                    and rgn == region
                    and other_arn != arn
                    and other["Name"] == new_name
                    and other["Status"] != "PENDING_DELETION"
                ):
                    raise _EDSAlreadyExists(new_name)
            store["Name"] = new_name

        new_bm = request.get("BillingMode")
        if new_bm is not None:
            if new_bm not in _VALID_BILLING_MODES:
                raise _EDSInvalidParameter(f"Invalid BillingMode: {new_bm}")
            if (
                store["BillingMode"] == "EXTENDABLE_RETENTION_PRICING"
                and new_bm == "FIXED_RETENTION_PRICING"
            ):
                raise _EDSInvalidParameter(
                    "Cannot change BillingMode from EXTENDABLE_RETENTION_PRICING to FIXED_RETENTION_PRICING."
                )
            store["BillingMode"] = new_bm

        new_retention = request.get("RetentionPeriod")
        if new_retention is not None:
            store["RetentionPeriod"] = _validate_retention(
                new_retention, store["BillingMode"]
            )

        if request.get("MultiRegionEnabled") is not None:
            store["MultiRegionEnabled"] = bool(request["MultiRegionEnabled"])
        if request.get("OrganizationEnabled") is not None:
            store["OrganizationEnabled"] = bool(request["OrganizationEnabled"])
        if request.get("TerminationProtectionEnabled") is not None:
            store["TerminationProtectionEnabled"] = bool(
                request["TerminationProtectionEnabled"]
            )
        if request.get("AdvancedEventSelectors") is not None:
            store["AdvancedEventSelectors"] = request["AdvancedEventSelectors"]
        if request.get("KmsKeyId"):
            store["KmsKeyId"] = request["KmsKeyId"]

        store["UpdatedTimestamp"] = _eds_now()
        snapshot = _serialize_eds_full(store)

    snapshot["FederationStatus"] = "DISABLED"
    return snapshot


def _handle_delete_event_data_store(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        _sweep_expired_eds()
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        if store["TerminationProtectionEnabled"]:
            raise _EDSTerminationProtected()
        if store["Status"] == "PENDING_DELETION":
            raise _EDSInvalidStatus(
                "The event data store is already pending deletion."
            )
        store["Status"] = "PENDING_DELETION"
        store["_PendingDeletionSince"] = _eds_now()
        store["UpdatedTimestamp"] = _eds_now()
    return {}


def _handle_restore_event_data_store(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        _sweep_expired_eds()
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        if store["Status"] != "PENDING_DELETION":
            raise _EDSInvalidStatus(
                "The event data store is not in PENDING_DELETION status."
            )
        store["Status"] = "ENABLED"
        store.pop("_PendingDeletionSince", None)
        store["UpdatedTimestamp"] = _eds_now()
        snapshot = _serialize_eds_full(store)
    return snapshot


def _handle_list_event_data_stores(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    max_results = request.get("MaxResults") or 100
    next_token = request.get("NextToken")

    with _EDS_LOCK:
        _sweep_expired_eds()
        account_id, region = context.account_id, context.region
        items = [
            store
            for (acct, rgn, _), store in _EVENT_DATA_STORES.items()
            if acct == account_id and rgn == region
        ]
        items.sort(key=lambda s: s["CreatedTimestamp"])

    try:
        offset = int(next_token) if next_token else 0
    except (ValueError, TypeError):
        raise _EDSInvalidParameter("Invalid NextToken.")
    page = items[offset : offset + max_results]
    new_token = (
        str(offset + max_results) if (offset + max_results) < len(items) else None
    )

    summaries = [
        {
            "EventDataStoreArn": s["EventDataStoreArn"],
            "Name": s["Name"],
            "TerminationProtectionEnabled": s["TerminationProtectionEnabled"],
            "Status": s["Status"],
            "AdvancedEventSelectors": s["AdvancedEventSelectors"],
            "MultiRegionEnabled": s["MultiRegionEnabled"],
            "OrganizationEnabled": s["OrganizationEnabled"],
            "RetentionPeriod": s["RetentionPeriod"],
            "CreatedTimestamp": s["CreatedTimestamp"],
            "UpdatedTimestamp": s["UpdatedTimestamp"],
        }
        for s in page
    ]
    out: dict[str, Any] = {"EventDataStores": summaries}
    if new_token:
        out["NextToken"] = new_token
    return out


def _handle_start_event_data_store_ingestion(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        if store["Status"] == "PENDING_DELETION":
            raise _EDSInvalidStatus(
                "The event data store is pending deletion; ingestion cannot be started."
            )
        if store["Status"] == "ENABLED":
            raise _EDSInvalidStatus(
                "The event data store is already ingesting events."
            )
        store["Status"] = "ENABLED"
        store["UpdatedTimestamp"] = _eds_now()
    return {}


def _handle_stop_event_data_store_ingestion(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    arn = _resolve_eds_arn(context, request.get("EventDataStore"))
    with _EDS_LOCK:
        store = _find_store(arn)
        if store is None:
            raise _EDSNotFound()
        if store["Status"] == "PENDING_DELETION":
            raise _EDSInvalidStatus(
                "The event data store is pending deletion; ingestion cannot be stopped."
            )
        if store["Status"] == "STOPPED_INGESTION":
            raise _EDSInvalidStatus(
                "The event data store ingestion is already stopped."
            )
        store["Status"] = "STOPPED_INGESTION"
        store["UpdatedTimestamp"] = _eds_now()
    return {}


# ---------------------------------------------------------------------------
# Dispatch table: intercept LookupEvents + Lake Query APIs + EventDataStore,
# proxy everything else to Moto. Native implementations for modern
# CloudTrail APIs (Channels, Dashboards, Imports, etc.) are layered on top.
# ---------------------------------------------------------------------------
_INTERCEPTED_OPS = {
    "LookupEvents": _handle_lookup_events,
    "CreateTrail": _handle_create_trail,
    "UpdateTrail": _handle_update_trail,
    "DeleteTrail": _handle_delete_trail,
    "GetTrailStatus": _handle_get_trail_status,
    "StartLogging": _handle_start_logging,
    "StopLogging": _handle_stop_logging,
    "PutEventSelectors": _handle_put_event_selectors,
    "GetEventSelectors": _handle_get_event_selectors,
    "PutInsightSelectors": _handle_put_insight_selectors,
    "GetInsightSelectors": _handle_get_insight_selectors,
    # CloudTrail Lake — EventDataStore
    "CreateEventDataStore": _handle_create_event_data_store,
    "GetEventDataStore": _handle_get_event_data_store,
    "UpdateEventDataStore": _handle_update_event_data_store,
    "DeleteEventDataStore": _handle_delete_event_data_store,
    "RestoreEventDataStore": _handle_restore_event_data_store,
    "ListEventDataStores": _handle_list_event_data_stores,
    "StartEventDataStoreIngestion": _handle_start_event_data_store_ingestion,
    "StopEventDataStoreIngestion": _handle_stop_event_data_store_ingestion,
    # CloudTrail Lake — Query APIs
    "StartQuery": _handle_start_query,
    "CancelQuery": _handle_cancel_query,
    "DescribeQuery": _handle_describe_query,
    "GetQueryResults": _handle_get_query_results,
    "ListQueries": _handle_list_queries,
    "SearchSampleQueries": _handle_search_sample_queries,
    "GenerateQuery": _handle_generate_query,
}

# Modern CloudTrail APIs that moto does not implement (Channels, Dashboards,
# Imports, Resource Policy, Federation, Organization delegated admin, Event
# configuration, Insights list APIs) are implemented natively in
# ``localemu.services.cloudtrail.native``. Without these entries the
# dispatcher would proxy the calls to moto, which returns 501.
from localemu.services.cloudtrail.native import NATIVE_OPS as _CLOUDTRAIL_NATIVE_OPS  # noqa: E402

_INTERCEPTED_OPS.update(_CLOUDTRAIL_NATIVE_OPS)


def CloudTrailDispatcher(service_model) -> DispatchTable:
    """Create a dispatch table for CloudTrail.

    LookupEvents goes through our event store implementation.
    All other operations (CreateTrail, DescribeTrails, StartLogging,
    StopLogging, etc.) route directly to Moto.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


def _patch_moto_bucket_check() -> None:
    """Moto's ``Trail.check_bucket_exists`` consults moto's own S3 backend.
    In LocalEmu, S3 is NOT moto-backed — it's our own provider with its own
    store. As a result, a bucket that clearly exists per ``s3api list-buckets``
    was invisible to moto's CloudTrail, breaking ``CreateTrail`` with
    ``S3BucketDoesNotExistException``.

    Rewire the check to consult LocalEmu's actual S3 store first; fall back
    to moto's original check afterwards (so nothing that used to work breaks).
    """
    try:
        from moto.cloudtrail.models import S3BucketDoesNotExistException, Trail
        from localemu.services.s3.models import s3_stores
    except Exception:
        return

    _original = Trail.check_bucket_exists
    if getattr(_original, "_le_patched", False):
        return

    def _patched(self: "Trail") -> None:
        try:
            for region_stores in s3_stores[self.account_id].values():
                if self.bucket_name in region_stores.buckets:
                    return
        except Exception:
            pass
        try:
            _original(self)
        except Exception:
            raise S3BucketDoesNotExistException(
                f"S3 bucket {self.bucket_name} does not exist!"
            )

    _patched._le_patched = True  # type: ignore[attr-defined]
    Trail.check_bucket_exists = _patched  # type: ignore[assignment]


class CloudTrailLifecycleHook(ServiceLifecycleHook):
    """Lifecycle hook owned by the CloudTrail service (F1 + F2).

    * ``on_before_start`` registers the activity-recording response handler
      so recording works even when the dashboard plugin is disabled (F2).
    * ``on_before_stop`` stops the S3 log-delivery background thread
      cleanly on service restart, rather than waiting for interpreter
      shutdown (F1). It also unregisters the recording hook so a
      subsequent start re-installs a fresh one without duplicates.
    """

    def on_before_start(self):  # pragma: no cover - exercised via service lifecycle
        try:
            from localemu.services.cloudtrail.recording_hook import (
                register_recording_hook,
            )
            register_recording_hook()
        except Exception:
            LOG.debug(
                "CloudTrail recording hook registration failed",
                exc_info=True,
            )

    def on_before_stop(self):
        try:
            _stop_s3_log_delivery()
        except Exception:
            LOG.debug(
                "CloudTrail S3 delivery thread stop failed",
                exc_info=True,
            )
        try:
            from localemu.services.cloudtrail.recording_hook import (
                unregister_recording_hook,
            )
            unregister_recording_hook()
        except Exception:
            LOG.debug(
                "CloudTrail recording hook unregister failed",
                exc_info=True,
            )


def create_cloudtrail_service() -> Service:
    """Create the CloudTrail service with LookupEvents support."""
    from localemu.aws.spec import load_service

    service_model = load_service("cloudtrail")
    dispatch_table = CloudTrailDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)

    # G: install the systemic moto<->LocalEmu S3 bridge. Covers all moto
    # services that consult moto.s3.models.s3_backends for bucket lookups.
    try:
        from localemu.services.s3.moto_bridge import install_moto_s3_bridge
        install_moto_s3_bridge()
    except Exception:
        LOG.debug("Failed to install moto S3 bridge", exc_info=True)

    # Defence-in-depth: keep the CloudTrail-specific bucket-existence
    # patch alongside the systemic bridge. Both are idempotent.
    _patch_moto_bucket_check()
    # B2: sibling patch so moto's ``Trail.check_topic_exists`` consults
    # LocalEmu's native SNS store.
    _patch_moto_topic_check()

    # PARITY-04: Start S3 log delivery background thread
    _start_s3_log_delivery()

    # F2: register the activity-recording response handler via the
    # CloudTrail service itself. This used to live in
    # dashboard/plugins.py, which meant CloudTrail silently broke when
    # the dashboard was disabled. The dashboard can still READ from the
    # event store; it just no longer OWNS the write path.
    try:
        from localemu.services.cloudtrail.recording_hook import (
            register_recording_hook,
        )
        register_recording_hook()
    except Exception:
        LOG.debug(
            "CloudTrail recording hook registration failed",
            exc_info=True,
        )

    # QUALITY-03: Load persisted events if PERSISTENCE is enabled
    try:
        from localemu import config
        if getattr(config, "PERSISTENCE", False):
            from localemu.services.cloudtrail.event_store import get_event_store
            store = get_event_store()
            store.load_from_disk()
    except Exception:
        LOG.debug("Failed to load persisted CloudTrail events", exc_info=True)

    return Service(
        name="cloudtrail",
        skeleton=skeleton,
        lifecycle_hook=CloudTrailLifecycleHook(),
    )
