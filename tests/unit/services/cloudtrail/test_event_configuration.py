"""Round-trip tests for Put/GetEventConfiguration."""

from __future__ import annotations

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:000000000000:trail/audit"
EDS_ARN = "arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/eds1"


def test_put_then_get_by_trail_round_trip(ctx):
    native.put_event_configuration(
        ctx,
        {
            "TrailName": TRAIL_ARN,
            "MaxEventSize": "Large",
            "ContextKeySelectors": [{"Type": "TagContext", "Equals": ["env"]}],
            "AggregationConfigurations": [{"Templates": ["t1"], "EventCategory": "Data"}],
        },
    )
    got = native.get_event_configuration(ctx, {"TrailName": TRAIL_ARN})
    assert got["MaxEventSize"] == "Large"
    assert got["ContextKeySelectors"][0]["Type"] == "TagContext"
    assert got["TrailARN"] == TRAIL_ARN
    assert got["AggregationConfigurations"][0]["EventCategory"] == "Data"


def test_put_then_get_by_event_data_store_round_trip(ctx):
    native.put_event_configuration(
        ctx,
        {"EventDataStore": EDS_ARN, "MaxEventSize": "Standard"},
    )
    got = native.get_event_configuration(ctx, {"EventDataStore": EDS_ARN})
    assert got["EventDataStoreArn"] == EDS_ARN
    assert got["MaxEventSize"] == "Standard"
    assert got["ContextKeySelectors"] == []
    assert got["AggregationConfigurations"] == []


def test_get_missing_configuration_raises(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.get_event_configuration(ctx, {"TrailName": TRAIL_ARN})
    assert exc.value.code == "EventConfigurationNotFoundException"


def test_put_requires_trail_or_event_data_store(ctx):
    with pytest.raises(CommonServiceException):
        native.put_event_configuration(ctx, {"MaxEventSize": "Standard"})
    with pytest.raises(CommonServiceException):
        native.get_event_configuration(ctx, {})


def test_trail_and_eds_are_independent_keys(ctx):
    native.put_event_configuration(ctx, {"TrailName": TRAIL_ARN, "MaxEventSize": "Standard"})
    native.put_event_configuration(ctx, {"EventDataStore": EDS_ARN, "MaxEventSize": "Large"})
    t = native.get_event_configuration(ctx, {"TrailName": TRAIL_ARN})
    e = native.get_event_configuration(ctx, {"EventDataStore": EDS_ARN})
    assert t["MaxEventSize"] == "Standard"
    assert e["MaxEventSize"] == "Large"
