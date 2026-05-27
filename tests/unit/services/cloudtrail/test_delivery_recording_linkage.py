"""Regression tests for the CloudTrail recording -> delivery linkage.

These tests exist because the live E2E probe shows:

* ``aws cloudtrail create-trail --sns-topic-name ...`` succeeds,
* every 60s the daemon writes a log file to S3,
* BUT: **zero** SNS messages are ever published.

The unit suite already in place (`test_log_delivery_integrations.py`)
passes, because it calls ``_deliver_log_file`` with a hand-built
``SimpleNamespace`` that already exposes the "right-shaped" attributes.
That bypasses the WIRING between
``CloudTrailEvent.aws_region`` / ``_iter_moto_backends("cloudtrail")`` /
moto's ``Trail`` attribute names, so the real bug never surfaces.

These tests use:
* the real ``CloudTrailEventStore``,
* a real moto ``Trail`` object (the exact class the delivery loop
  pulls out of ``moto.backends``),
* the real ``_run_delivery_cycle`` invoked with a fresh stop event.

Each test is written to fail loudly, identifying exactly which link in
the chain is broken on the live daemon.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.cloudtrail import provider as ct_provider
from localemu.services.cloudtrail.event_store import (
    CloudTrailEvent,
    create_event_from_context,
    get_event_store,
)


ACCOUNT = "000000000000"
REGION = "us-east-1"


def _reset_moto_cloudtrail_backends():
    """Clear trails + backend-dict state from every moto CloudTrail backend that
    has been instantiated. Without this, a trail created in one test remains
    visible to the next and the delivery cycle double-fires SNS publish.
    """
    import moto.backends as moto_backends
    bd = moto_backends.get_backend("cloudtrail")
    try:
        for account_id, region_map in list(bd.items()):
            if not isinstance(region_map, dict):
                continue
            for region, backend in list(region_map.items()):
                for attr in ("trails", "event_data_stores", "channels"):
                    d = getattr(backend, attr, None)
                    if isinstance(d, dict):
                        d.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_state():
    get_event_store().reset()
    ct_provider._run_delivery_cycle._last_delivered = {}  # type: ignore[attr-defined]
    ct_provider._clear_delivery_client_cache()
    ct_provider._clear_delivery_state()
    _reset_moto_cloudtrail_backends()
    yield
    get_event_store().reset()
    _reset_moto_cloudtrail_backends()


# ---------------------------------------------------------------------------
# 1) create_event_from_context default region and account
# ---------------------------------------------------------------------------
class TestEventDefaults:
    def test_event_default_region_when_context_passes_empty(self):
        """`cloudtrail_activity_handler` reads `context.region` and passes
        it into `create_event_from_context`. On the very first early-boot
        request (or a malformed SigV4 header) the region/account may come
        through as an empty string. Prove what the stored event's
        `aws_region` ends up as then."""
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            account_id="",
            region="",
        )
        # This is what falls into the store.
        assert evt.aws_region == "us-east-1"
        assert evt.account_id == "000000000000"

    def test_event_region_is_populated_when_context_has_region(self):
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            account_id=ACCOUNT,
            region=REGION,
        )
        assert evt.aws_region == REGION
        assert evt.account_id == ACCOUNT


# ---------------------------------------------------------------------------
# 2) moto Trail attribute shape
# ---------------------------------------------------------------------------
class TestMotoTrailAttributes:
    """Moto's Trail class is what `_run_delivery_cycle` actually iterates.
    If the provider reads an attribute that moto does NOT expose, delivery
    silently skips that trail."""

    def _make_trail(self):
        # Create a real moto Trail with no S3 / SNS side effects.
        from moto.cloudtrail.models import Trail

        # `Trail.__init__` calls `check_bucket_exists()` / `check_topic_exists()`
        # against moto's s3 / sns backends. We don't need real buckets for
        # these attribute-shape assertions, so patch the checks away.
        with patch.object(Trail, "check_bucket_exists", lambda self: None), \
             patch.object(Trail, "check_topic_exists", lambda self: None):
            return Trail(
                account_id=ACCOUNT,
                region_name=REGION,
                trail_name="ct-trail",
                bucket_name="audit-bucket",
                s3_key_prefix="",
                sns_topic_name="ct-topic",
                is_global=False,
                is_multi_region=False,
                log_validation=False,
                is_org_trail=False,
                cw_log_group_arn="",
                cw_role_arn="",
                kms_key_id="",
            )

    def test_moto_trail_exposes_sns_topic_name(self):
        trail = self._make_trail()
        assert hasattr(trail, "sns_topic_name")
        assert trail.sns_topic_name == "ct-topic"

    def test_moto_trail_exposes_topic_arn_property(self):
        trail = self._make_trail()
        assert trail.topic_arn == (
            f"arn:aws:sns:{REGION}:{ACCOUNT}:ct-topic"
        )

    def test_moto_trail_bucket_attribute_is_bucket_name_not_s3_bucket_name(self):
        """CRITICAL: the S3 bucket attribute on moto's Trail is
        ``bucket_name`` — NOT ``s3_bucket_name``. The provider's
        delivery cycle reads ``getattr(trail, "s3_bucket_name", None)``,
        so it will get ``None`` and SKIP delivery entirely → no S3 put
        → no SNS publish."""
        trail = self._make_trail()
        assert hasattr(trail, "bucket_name"), \
            "moto Trail should expose `bucket_name`"
        assert trail.bucket_name == "audit-bucket"
        # This is the key finding — the attribute the provider looks up
        # does NOT exist on moto's Trail:
        assert not hasattr(trail, "s3_bucket_name"), (
            "moto Trail does NOT define `s3_bucket_name` — yet "
            "`_run_delivery_cycle` reads `getattr(trail, 's3_bucket_name', "
            "None)`. This returns None, the `if not bucket_name: continue` "
            "branch fires, and delivery skips the trail entirely."
        )


# ---------------------------------------------------------------------------
# 3) recording → delivery region match
# ---------------------------------------------------------------------------
class TestRecordingToDeliveryRegionMatch:
    def test_recorded_event_region_matches_backend_region(self):
        """If a CreateBucket in us-east-1 stores an event with
        aws_region=us-east-1 and `_iter_moto_backends('cloudtrail')`
        yields (000000000000, us-east-1, backend), they match and the
        region filter accepts the event."""
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            account_id=ACCOUNT,
            region=REGION,
        )
        get_event_store().record(evt)
        recent = get_event_store().get_recent(limit=10)
        assert any(
            e.aws_region == REGION and e.account_id == ACCOUNT
            for e in recent
        )


# ---------------------------------------------------------------------------
# 4) End-to-end: real store + real moto backend + real _run_delivery_cycle
# ---------------------------------------------------------------------------
class TestDeliveryCycleEndToEnd:
    """This is the cross-check. Everything real except the boto3 clients
    (we substitute MagicMocks so we can *observe* whether put_object and
    sns.publish were invoked — the whole question)."""

    def _install_trail_in_moto(self, sns_topic_name="ct-topic"):
        import moto.backends as moto_backends
        from moto.cloudtrail.models import Trail

        ct_backend = moto_backends.get_backend("cloudtrail")[ACCOUNT][REGION]
        with patch.object(Trail, "check_bucket_exists", lambda self: None), \
             patch.object(Trail, "check_topic_exists", lambda self: None):
            trail = Trail(
                account_id=ACCOUNT,
                region_name=REGION,
                trail_name="ct-trail",
                bucket_name="audit-bucket",
                s3_key_prefix="",
                sns_topic_name=sns_topic_name,
                is_global=False,
                is_multi_region=False,
                log_validation=False,
                is_org_trail=False,
                cw_log_group_arn="",
                cw_role_arn="",
                kms_key_id="",
            )
        trail.start_logging()
        ct_backend.trails["ct-trail"] = trail
        return ct_backend, trail

    def _record_write_event(self):
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            account_id=ACCOUNT,
            region=REGION,
        )
        get_event_store().record(evt)
        return evt

    def test_delivery_cycle_invokes_s3_put_for_recorded_event(self):
        """Baseline: if the linkage is healthy at all, the delivery cycle
        must at minimum call put_object once."""
        self._install_trail_in_moto()
        self._record_write_event()

        s3 = MagicMock()
        sns = MagicMock()
        clients = MagicMock(s3=s3, sns=sns)
        with patch.object(ct_provider, "_get_delivery_clients",
                          return_value=clients):
            ct_provider._run_delivery_cycle(threading.Event())

        assert s3.put_object.call_count == 1, (
            "Delivery cycle did NOT call put_object. Candidates:\n"
            " - stored event aws_region != backend region\n"
            " - moto Trail attribute name mismatch "
            "(provider reads s3_bucket_name; moto exposes bucket_name)\n"
            " - trail.is_logging is False"
        )

    def test_delivery_cycle_invokes_sns_publish_when_topic_set(self):
        """The bug: trail has sns_topic_name='ct-topic' but delivery
        cycle never calls sns.publish on live daemon. Repro here with
        REAL store + REAL moto Trail."""
        self._install_trail_in_moto(sns_topic_name="ct-topic")
        self._record_write_event()

        s3 = MagicMock()
        sns = MagicMock()
        clients = MagicMock(s3=s3, sns=sns)
        with patch.object(ct_provider, "_get_delivery_clients",
                          return_value=clients):
            ct_provider._run_delivery_cycle(threading.Event())

        assert sns.publish.call_count == 1, (
            "SNS publish NOT called. With a real moto Trail in place, "
            "_run_delivery_cycle reads `getattr(trail, 's3_bucket_name', "
            "None)` which is None on moto (the real attr is `bucket_name`). "
            "So delivery short-circuits before ever reaching "
            "_deliver_log_file → no S3 put, no SNS publish."
        )

    def test_delivery_cycle_region_mismatch_skips_events(self):
        """Prove the filter behavior: if the stored event's aws_region is
        NOT the backend's region, the event is excluded from the log
        file. This is the second latent failure mode."""
        self._install_trail_in_moto()
        # Simulate an event that (somehow) got recorded for another region.
        evt = CloudTrailEvent(
            event_id="evt-xy",
            event_time=datetime.now(timezone.utc),
            event_source="s3.amazonaws.com",
            event_name="CreateBucket",
            aws_region="eu-west-1",          # <-- mismatched
            source_ip="127.0.0.1",
            user_agent="",
            account_id=ACCOUNT,
            read_only=False,
            username="localemu",
            access_key_id="ANONYMOUS",
            error_code=None,
            error_message=None,
            resources=[],
            request_id="req-xy",
        )
        get_event_store().record(evt)

        s3 = MagicMock()
        sns = MagicMock()
        clients = MagicMock(s3=s3, sns=sns)
        with patch.object(ct_provider, "_get_delivery_clients",
                          return_value=clients):
            ct_provider._run_delivery_cycle(threading.Event())

        # No event survives the region filter → continue fires at
        # `if not new_events: continue` → no put_object. (This test
        # currently also fails-open because of the bucket_name bug, but
        # documents intent.)
        assert s3.put_object.call_count == 0
        assert sns.publish.call_count == 0
