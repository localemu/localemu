"""Regression test for the dashboard CloudTrail endpoint count bug.

The dashboard CloudTrail page used to show "200 events" even when the
backing event store had thousands of events. Root cause: the API
computed ``total = len(events)`` *after* trimming the list to the
window size, so ``total`` could never exceed ``limit + offset``. The
sidebar, which calls ``get_event_count()`` directly, reported the true
6170; the CloudTrail page, fetching ``/api/cloudtrail?limit=200``,
got back ``total: 200`` and rendered the wrong number.

The fix: ``total`` is now read from the store directly via
``get_event_count()`` (and, when a service filter is active, computed
on the filtered list pulled from the full store).
"""

from __future__ import annotations

import datetime as dt
import json
from unittest.mock import MagicMock

from localemu.dashboard.api import CloudTrailResource


def _seed_store(monkeypatch, total_events: int):
    """Replace get_event_store() with a fake holding `total_events` rows."""

    class _Evt:
        def __init__(self, i):
            self.event_time = dt.datetime(2026, 5, 23, 12, 0, i % 60, tzinfo=dt.timezone.utc)
            self.event_source = "s3.amazonaws.com"
            self.event_name = f"GetObject{i}"
            self.source_ip = "127.0.0.1"
            self.user_agent = "boto3"
            self.request_id = f"req-{i}"
            self.aws_region = "us-east-1"
            self.http_status_code = 200
            self.account_id = "000000000000"
            self.read_only = True
            self.error_code = None
            self.resources = []
            self.request_parameters = {}

    events = [_Evt(i) for i in range(total_events)]

    class _Store:
        def get_event_count(self):
            return len(events)

        def get_recent(self, limit=100):
            # Mirror the real store: most-recent-first, capped at limit.
            return list(reversed(events))[:limit]

    monkeypatch.setattr(
        "localemu.services.cloudtrail.event_store.get_event_store",
        lambda: _Store(),
    )


def _fake_request(args: dict):
    req = MagicMock()
    req.args = args
    req.remote_addr = "127.0.0.1"
    return req


def test_total_reflects_store_size_not_window(monkeypatch):
    """The true total must come from get_event_count(), not the windowed slice."""
    _seed_store(monkeypatch, total_events=6170)

    resp = CloudTrailResource().on_get(_fake_request({"limit": "200"}))
    body = json.loads(resp.data)

    assert body["total"] == 6170, "total must reflect the store size, not the slice length"
    assert len(body["events"]) == 200, "events should be capped to the requested limit"


def test_total_is_filtered_count_when_service_filter_set(monkeypatch):
    """With a service filter, total must reflect the filtered count, not the store size."""
    # 6 store events, but all from s3 in the seed; filtering for "lambda" returns 0.
    _seed_store(monkeypatch, total_events=6)

    resp = CloudTrailResource().on_get(_fake_request({"limit": "200", "service": "lambda"}))
    body = json.loads(resp.data)

    assert body["total"] == 0, "service filter must compute total on the filtered set"
    assert body["events"] == []


def test_total_matches_window_when_store_is_small(monkeypatch):
    """When the store has fewer events than the limit, total == len(events)."""
    _seed_store(monkeypatch, total_events=12)

    resp = CloudTrailResource().on_get(_fake_request({"limit": "200"}))
    body = json.loads(resp.data)

    assert body["total"] == 12
    assert len(body["events"]) == 12
