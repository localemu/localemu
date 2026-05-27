"""Regression tests for ListInsightsData / ListInsightsMetricData.

LocalEmu does NOT implement CloudTrail insight detection — the baseline
learning + unusual-activity emission machinery is out of scope. These
APIs therefore return empty-but-valid responses, with echo-back fields
on the metric API so the shape matches the spec.
"""

from __future__ import annotations

from localemu.services.cloudtrail import native


def test_list_insights_data_returns_empty_events(ctx):
    resp = native.list_insights_data(
        ctx,
        {
            "InsightSource": "arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/eds1",
            "DataType": "INSIGHT_EVENT",
            "StartTime": "2026-04-01T00:00:00Z",
            "EndTime": "2026-04-15T00:00:00Z",
        },
    )
    assert resp == {"Events": []}


def test_list_insights_metric_data_echoes_request_fields(ctx):
    resp = native.list_insights_metric_data(
        ctx,
        {
            "EventSource": "s3.amazonaws.com",
            "EventName": "PutObject",
            "InsightType": "ApiCallRateInsight",
            "StartTime": "2026-04-01T00:00:00Z",
            "EndTime": "2026-04-15T00:00:00Z",
            "Period": 3600,
            "DataType": "BaselineAverage",
        },
    )
    assert resp["EventSource"] == "s3.amazonaws.com"
    assert resp["EventName"] == "PutObject"
    assert resp["InsightType"] == "ApiCallRateInsight"
    assert resp["Timestamps"] == []
    assert resp["Values"] == []


def test_list_insights_metric_data_missing_fields_does_not_crash(ctx):
    # AWS requires EventSource/EventName/InsightType; at the native
    # layer we don't enforce them (the serializer would, upstream), but
    # we must not crash on missing keys.
    resp = native.list_insights_metric_data(ctx, {})
    assert resp["Timestamps"] == []
    assert resp["Values"] == []
