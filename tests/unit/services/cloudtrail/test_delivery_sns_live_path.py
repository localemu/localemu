"""Regression test: prove the SNS-publish live-path bug in the CloudTrail
S3 log-delivery thread.

Scenario modelled one-for-one on the shell reproduction from the bug
report:

1. A real moto CloudTrail backend is materialized (the same way
   ``CreateTrail`` materializes it at runtime) with a Trail that carries
   ``sns_topic_name``.
2. The real LocalEmu ``CloudTrailEventStore`` is pre-populated with a
   few events in the matching region.
3. ``boto3.Session`` (the underlying plumbing of ``connect_to``) is
   patched so the delivery cycle's ``s3.put_object`` and ``sns.publish``
   calls land on ``MagicMock`` objects we can assert on.
4. We call ``_run_delivery_cycle`` synchronously (no thread, no sleep)
   and assert that exactly one ``sns.publish`` call was made with the
   AWS-documented payload ``{"s3Bucket": ..., "s3ObjectKey": [...]}``.

If this test fails, the delivery cycle did not publish. The ``_instances``
snapshot printed in the assertion message pinpoints why.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _materialize_cloudtrail_backend_with_trail():
    """Do exactly what moto's ``CreateTrail`` op does: first access
    ``cloudtrail_backends[account][region]`` to instantiate the backend,
    then call ``create_trail`` on it.

    Returns the ``(BackendDict, CloudTrailBackend, Trail)`` triple.
    """
    import moto.backends as moto_backends

    # moto's ``Trail.__init__`` validates that the S3 bucket exists in the
    # moto S3 backend — precisely because AWS CloudTrail validates it too.
    # Create the bucket in moto's backend so ``create_trail`` succeeds.
    s3_bd = moto_backends.get_backend("s3")
    s3_be = s3_bd[ACCOUNT_ID]["aws"]  # s3 is partition-keyed in moto
    s3_be.create_bucket("ct-c2-bkt", REGION)

    # Same reason: ``Trail`` validates the SNS topic exists in moto when
    # ``sns_topic_name`` is set (``InsufficientSnsTopicPolicyException``).
    sns_bd = moto_backends.get_backend("sns")
    sns_be = sns_bd[ACCOUNT_ID][REGION]
    sns_be.create_topic("ct-c2-topic")

    bd = moto_backends.get_backend("cloudtrail")
    be = bd[ACCOUNT_ID][REGION]
    trail = be.create_trail(
        name="ct-c2",
        bucket_name="ct-c2-bkt",
        s3_key_prefix=None,
        sns_topic_name="ct-c2-topic",
        is_global=False,
        is_multi_region=False,
        log_validation=False,
        is_org_trail=False,
        cw_log_group_arn=None,
        cw_role_arn=None,
        kms_key_id=None,
        tags_list=[],
    )
    trail.start_logging()
    return bd, be, trail


def _seed_event_store():
    """Record two real ``CloudTrailEvent``s in the real event store."""
    from localemu.services.cloudtrail.event_store import (
        CloudTrailEvent,
        get_event_store,
    )

    store = get_event_store()
    # Reset deque/index to a known-empty state.
    with store._lock:
        store._events.clear()
        store._by_request_id.clear()

    now = datetime.now(timezone.utc)
    for i in range(2):
        store.record(CloudTrailEvent(
            event_id=f"evt-{i}",
            event_time=now,
            event_source="s3.amazonaws.com",
            event_name="CreateBucket",
            aws_region=REGION,
            source_ip="127.0.0.1",
            user_agent="aws-cli/test",
            account_id=ACCOUNT_ID,
            read_only=False,
            username="test",
            access_key_id="AKIATEST",
            error_code=None,
            error_message=None,
            resources=[],
            request_id=f"req-{i}",
            request_parameters=None,
            response_elements=None,
            http_status_code=200,
            event_category="Management",
        ))
    return store


def _reset_cloudtrail_backend_dict():
    """Clear moto's CloudTrail ``_instances`` so the test starts clean."""
    import moto.backends as moto_backends

    bd = moto_backends.get_backend("cloudtrail")
    try:
        bd.clear()
    except Exception:
        pass
    try:
        # _instances is a class-level list shared across all BackendDicts;
        # only drop entries that belong to the cloudtrail service.
        from moto.core.base_backend import BackendDict

        BackendDict._instances[:] = [
            inst for inst in BackendDict._instances
            if getattr(inst, "service_name", None) != "cloudtrail"
        ]
    except Exception:
        pass


@pytest.fixture
def fake_clients():
    """Build a ``connect_to``-shaped bundle whose ``.s3`` and ``.sns`` are
    MagicMocks we can assert on."""
    bundle = MagicMock(name="internal-client-bundle")
    bundle.s3 = MagicMock(name="s3-client")
    bundle.sns = MagicMock(name="sns-client")
    bundle.s3.put_object.return_value = {"ETag": '"deadbeef"'}
    bundle.sns.publish.return_value = {"MessageId": "mid-1"}
    return bundle


def test_run_delivery_cycle_publishes_sns_notification(fake_clients):
    """A trail with ``sns_topic_name`` must produce exactly one
    ``sns.publish`` call per delivered log file, with the AWS-documented
    ``{"s3Bucket", "s3ObjectKey"}`` payload.

    If this fails, the message includes a snapshot of moto's
    ``_instances`` and what ``_iter_moto_backends('cloudtrail')`` yields,
    so the failing layer is obvious at a glance.
    """
    from localemu.services.cloudtrail import provider as ct_provider
    from localemu.dashboard.api import _iter_moto_backends

    # Reset provider cursor + client cache so nothing leaks from earlier tests.
    ct_provider._run_delivery_cycle._last_delivered = {}  # type: ignore[attr-defined]
    ct_provider._clear_delivery_client_cache()

    _reset_cloudtrail_backend_dict()
    bd, be, trail = _materialize_cloudtrail_backend_with_trail()
    _seed_event_store()

    # Diagnostic snapshot: what does _iter_moto_backends actually see?
    iterated = list(_iter_moto_backends("cloudtrail"))

    with patch.object(
        ct_provider, "_get_delivery_clients", return_value=fake_clients,
    ):
        stop_event = threading.Event()
        ct_provider._run_delivery_cycle(stop_event)

    # --- assertions ---------------------------------------------------
    # (A) Did the iterator reach the trail's backend at all?
    assert any(
        acct == ACCOUNT_ID and rgn == REGION and b is be
        for acct, rgn, b in iterated
    ), (
        "FAILURE STEP 1 — _iter_moto_backends('cloudtrail') did NOT yield "
        "the backend that holds the trail.\n"
        f"  moto _instances          = {bd._instances!r}\n"
        f"  iter_moto_backends yields = {iterated!r}\n"
        f"  expected account/region   = {ACCOUNT_ID}/{REGION}\n"
        f"  expected backend object   = {be!r}\n"
        "Root cause lives in localemu/dashboard/api.py::_iter_moto_backends."
    )

    # (B) Did the delivery write an S3 object?
    assert fake_clients.s3.put_object.called, (
        "FAILURE STEP 2 — delivery cycle reached the backend but never "
        "called s3.put_object. Check _run_delivery_cycle guard conditions "
        "(is_logging / s3_bucket_name / new_events filter)."
    )
    put_kwargs = fake_clients.s3.put_object.call_args.kwargs
    assert put_kwargs["Bucket"] == "ct-c2-bkt"

    # (C) Did the delivery publish the SNS notification?
    assert fake_clients.sns.publish.called, (
        "FAILURE STEP 3 — S3 put succeeded but sns.publish was never "
        "called. Check _deliver_log_file's SNS branch — either "
        "sns_topic_name was empty on the moto Trail or the publish path "
        "was skipped."
    )
    assert fake_clients.sns.publish.call_count == 1

    pub_kwargs = fake_clients.sns.publish.call_args.kwargs
    assert pub_kwargs["TopicArn"].endswith(":ct-c2-topic"), pub_kwargs
    body = json.loads(pub_kwargs["Message"])
    assert body["s3Bucket"] == "ct-c2-bkt"
    assert isinstance(body["s3ObjectKey"], list)
    assert len(body["s3ObjectKey"]) == 1
    assert body["s3ObjectKey"][0] == put_kwargs["Key"]
