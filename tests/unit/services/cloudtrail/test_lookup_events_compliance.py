"""Regression tests for LookupEvents AWS compliance (audit B6-B11).

Each test exercises one compliance bug fixed in
``cloudtrail/event_store.py`` and ``cloudtrail/provider.py``.

Coverage:
  * B6: ``EventCategory`` filter (Management / Data / Insight) + invalid value
  * B7: stale / unknown ``NextToken`` raises ``InvalidNextTokenException``
  * B8: ``CloudTrailEvent`` JSON shape — ``eventCategory`` present,
        ``managementEvent`` tracks category, ``eventTime`` is UTC with
        second precision (no microseconds)
  * B9: multiple ``LookupAttributes`` raise
        ``InvalidLookupAttributesException``
  * B10: ``MaxResults`` clamped to ``[1, 50]``
  * B11: B11 is covered indirectly — the ``"localemu"`` string literal no
         longer appears in the recording path. Checked via a unit assert
         on ``create_event_from_context`` defaults.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.cloudtrail import event_store as es
from localemu.services.cloudtrail.event_store import (
    CloudTrailEvent,
    CloudTrailEventStore,
    InvalidEventCategoryError,
    InvalidLookupAttributesError,
    InvalidNextTokenError,
    create_event_from_context,
)
from localemu.services.cloudtrail.provider import _handle_lookup_events


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_event(
    *,
    event_id: str = "evt-1",
    event_name: str = "CreateBucket",
    event_source: str = "s3.amazonaws.com",
    category: str = "Management",
    when: datetime | None = None,
) -> CloudTrailEvent:
    return CloudTrailEvent(
        event_id=event_id,
        event_time=when or datetime.now(timezone.utc),
        event_source=event_source,
        event_name=event_name,
        aws_region="us-east-1",
        source_ip="127.0.0.1",
        user_agent="aws-cli/2.0",
        account_id="000000000000",
        read_only=False,
        username="AKIAEXAMPLE",
        access_key_id="AKIAEXAMPLE",
        error_code=None,
        error_message=None,
        resources=[],
        request_id=f"req-{event_id}",
        event_category=category,
    )


@pytest.fixture
def store() -> CloudTrailEventStore:
    """A fresh, isolated event store for each test. Bypasses the module
    singleton so one test's data cannot leak into another's."""
    return CloudTrailEventStore()


@pytest.fixture
def provider_store(monkeypatch) -> CloudTrailEventStore:
    """Make the provider's ``get_event_store`` return a fresh store so
    ``_handle_lookup_events`` can be exercised end-to-end without going
    through the gateway."""
    s = CloudTrailEventStore()
    monkeypatch.setattr(
        "localemu.services.cloudtrail.event_store.get_event_store",
        lambda: s,
    )
    return s


# ---------------------------------------------------------------------------
# B6: EventCategory filter
# ---------------------------------------------------------------------------


def test_B6_event_category_management_returns_only_management(store):
    store.record(_make_event(event_id="mgmt-1", category="Management"))
    store.record(_make_event(event_id="data-1", category="Data"))
    store.record(_make_event(event_id="insight-1", category="Insight"))

    events, _ = store.query(event_category="Management")

    assert {e.event_id for e in events} == {"mgmt-1"}


def test_B6_event_category_data_returns_only_data(store):
    store.record(_make_event(event_id="mgmt-1", category="Management"))
    store.record(_make_event(event_id="data-1", category="Data"))
    store.record(_make_event(event_id="data-2", category="Data"))

    events, _ = store.query(event_category="Data")

    assert {e.event_id for e in events} == {"data-1", "data-2"}


def test_B6_event_category_insight_returns_only_insight(store):
    store.record(_make_event(event_id="mgmt-1", category="Management"))
    store.record(_make_event(event_id="insight-1", category="Insight"))

    events, _ = store.query(event_category="Insight")

    assert {e.event_id for e in events} == {"insight-1"}


def test_B6_invalid_event_category_raises(store):
    store.record(_make_event())
    with pytest.raises(InvalidEventCategoryError):
        store.query(event_category="Bogus")


def test_B6_provider_translates_invalid_category_to_common_service_exception(
    provider_store,
):
    provider_store.record(_make_event())

    with pytest.raises(CommonServiceException) as excinfo:
        _handle_lookup_events(
            context=MagicMock(),
            request={"EventCategory": "Bogus"},
        )

    assert excinfo.value.code == "InvalidEventCategoryException"
    assert excinfo.value.status_code == 400
    assert excinfo.value.sender_fault is True


# ---------------------------------------------------------------------------
# B7: invalid NextToken
# ---------------------------------------------------------------------------


def test_B7_unknown_next_token_raises_invalid_next_token_error(store):
    # Populate enough events that pagination is realistic.
    for i in range(3):
        store.record(_make_event(event_id=f"evt-{i}"))

    with pytest.raises(InvalidNextTokenError):
        store.query(next_token="this-cursor-does-not-exist")


def test_B7_provider_translates_invalid_next_token_to_common_service_exception(
    provider_store,
):
    provider_store.record(_make_event())

    with pytest.raises(CommonServiceException) as excinfo:
        _handle_lookup_events(
            context=MagicMock(),
            request={"NextToken": "stale-token"},
        )

    assert excinfo.value.code == "InvalidNextTokenException"
    assert excinfo.value.status_code == 400
    assert excinfo.value.sender_fault is True


def test_B7_valid_next_token_still_paginates(store):
    # Record 3 newest-first: evt-2, evt-1, evt-0
    for i in range(3):
        store.record(_make_event(event_id=f"evt-{i}"))

    first, token = store.query(max_results=1)
    assert token is not None
    # Second page — cursor must resolve cleanly.
    second, _ = store.query(max_results=1, next_token=token)
    assert first[0].event_id != second[0].event_id


# ---------------------------------------------------------------------------
# B8: CloudTrailEvent JSON shape
# ---------------------------------------------------------------------------


def test_B8_management_event_json_has_event_category_and_management_true():
    when = datetime(2026, 4, 16, 10, 30, 45, 123456, tzinfo=timezone.utc)
    evt = _make_event(category="Management", when=when)
    payload = json.loads(evt.to_cloudtrail_event_json())

    assert payload["eventCategory"] == "Management"
    assert payload["managementEvent"] is True


def test_B8_data_event_json_has_management_event_false():
    evt = _make_event(event_id="d1", category="Data")
    payload = json.loads(evt.to_cloudtrail_event_json())

    assert payload["eventCategory"] == "Data"
    assert payload["managementEvent"] is False


def test_B8_insight_event_json_has_management_event_false():
    evt = _make_event(event_id="i1", category="Insight")
    payload = json.loads(evt.to_cloudtrail_event_json())

    assert payload["eventCategory"] == "Insight"
    assert payload["managementEvent"] is False


def test_B8_event_time_is_utc_second_precision_no_microseconds():
    when = datetime(2026, 4, 16, 10, 30, 45, 123456, tzinfo=timezone.utc)
    evt = _make_event(when=when)
    payload = json.loads(evt.to_cloudtrail_event_json())

    # Exact AWS format: second precision, trailing Z (UTC), no microseconds.
    assert payload["eventTime"] == "2026-04-16T10:30:45Z"
    assert "." not in payload["eventTime"]  # no microseconds


def test_B8_naive_event_time_is_assumed_utc():
    naive = datetime(2026, 4, 16, 10, 30, 45)
    evt = _make_event(when=naive)
    payload = json.loads(evt.to_cloudtrail_event_json())

    assert payload["eventTime"] == "2026-04-16T10:30:45Z"


# ---------------------------------------------------------------------------
# B9: multiple LookupAttributes
# ---------------------------------------------------------------------------


def test_B9_two_lookup_attributes_raises_invalid_lookup_attributes_error(store):
    store.record(_make_event())
    with pytest.raises(InvalidLookupAttributesError):
        store.query(
            lookup_attributes=[
                {"AttributeKey": "EventName", "AttributeValue": "CreateBucket"},
                {"AttributeKey": "EventSource", "AttributeValue": "s3.amazonaws.com"},
            ]
        )


def test_B9_provider_translates_multi_attribute_to_common_service_exception(
    provider_store,
):
    provider_store.record(_make_event())

    with pytest.raises(CommonServiceException) as excinfo:
        _handle_lookup_events(
            context=MagicMock(),
            request={
                "LookupAttributes": [
                    {"AttributeKey": "EventName", "AttributeValue": "CreateBucket"},
                    {"AttributeKey": "EventSource",
                     "AttributeValue": "s3.amazonaws.com"},
                ],
            },
        )

    assert excinfo.value.code == "InvalidLookupAttributesException"
    assert excinfo.value.status_code == 400
    assert excinfo.value.sender_fault is True


def test_B9_single_lookup_attribute_still_works(store):
    store.record(_make_event(event_name="CreateBucket"))
    store.record(_make_event(event_id="evt-2", event_name="DeleteBucket"))

    events, _ = store.query(
        lookup_attributes=[
            {"AttributeKey": "EventName", "AttributeValue": "CreateBucket"},
        ]
    )

    assert {e.event_name for e in events} == {"CreateBucket"}


# ---------------------------------------------------------------------------
# B10: MaxResults clamping
# ---------------------------------------------------------------------------


def test_B10_max_results_zero_is_clamped_to_one(provider_store):
    """Documented policy: ``MaxResults=0`` is clamped to 1 (AWS's lower
    bound) rather than rejected. AWS docs the valid range as 1..50;
    LocalEmu normalises below-range values to the minimum."""
    for i in range(3):
        provider_store.record(_make_event(event_id=f"evt-{i}"))

    resp = _handle_lookup_events(
        context=MagicMock(),
        request={"MaxResults": 0},
    )

    assert len(resp["Events"]) == 1


def test_B10_max_results_negative_is_clamped_to_one(provider_store):
    for i in range(3):
        provider_store.record(_make_event(event_id=f"evt-{i}"))

    resp = _handle_lookup_events(
        context=MagicMock(),
        request={"MaxResults": -5},
    )

    assert len(resp["Events"]) == 1


def test_B10_max_results_above_fifty_is_clamped_to_fifty(provider_store):
    for i in range(75):
        provider_store.record(_make_event(event_id=f"evt-{i}"))

    resp = _handle_lookup_events(
        context=MagicMock(),
        request={"MaxResults": 1000},
    )

    assert len(resp["Events"]) == 50


def test_B10_max_results_non_int_defaults_to_fifty(provider_store):
    for i in range(75):
        provider_store.record(_make_event(event_id=f"evt-{i}"))

    resp = _handle_lookup_events(
        context=MagicMock(),
        request={"MaxResults": "not-a-number"},
    )

    assert len(resp["Events"]) == 50


# ---------------------------------------------------------------------------
# B11: dead "localemu" fallback removed
# ---------------------------------------------------------------------------


def test_B11_create_event_from_context_no_longer_defaults_to_localemu():
    """Regression: previously ``username or access_key_id or "localemu"``
    was dead code (access_key_id is always truthy at the call site). The
    fallback string is now ``"anonymous"`` and only triggers when both
    ``username`` and ``access_key_id`` are blank — the only legitimate
    unauthenticated path."""
    evt = create_event_from_context(
        service_name="s3",
        operation_name="CreateBucket",
        account_id="000000000000",
        region="us-east-1",
        access_key_id="",   # unauthenticated
        username="",
    )
    assert evt.username == "anonymous"
    assert evt.username != "localemu"


def test_B11_create_event_from_context_uses_access_key_when_present():
    evt = create_event_from_context(
        service_name="s3",
        operation_name="CreateBucket",
        account_id="000000000000",
        region="us-east-1",
        access_key_id="AKIAEXAMPLE",
        username="",
    )
    assert evt.username == "AKIAEXAMPLE"


def test_B11_create_event_from_context_prefers_explicit_username():
    evt = create_event_from_context(
        service_name="s3",
        operation_name="CreateBucket",
        account_id="000000000000",
        region="us-east-1",
        access_key_id="AKIAEXAMPLE",
        username="alice",
    )
    assert evt.username == "alice"
