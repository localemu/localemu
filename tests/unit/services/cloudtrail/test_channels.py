"""CRUD + error cases for the native CloudTrail Channels API."""

from __future__ import annotations

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


def test_create_channel_returns_arn_and_echoes_fields(ctx):
    resp = native.create_channel(
        ctx,
        {
            "Name": "probe-channel",
            "Source": "aws.events",
            "Destinations": [
                {"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/eds1"}
            ],
            "Tags": [{"Key": "env", "Value": "test"}],
        },
    )
    assert resp["Name"] == "probe-channel"
    assert resp["Source"] == "aws.events"
    assert resp["ChannelArn"].startswith("arn:aws:cloudtrail:us-east-1:000000000000:channel/")
    assert resp["Destinations"][0]["Type"] == "EVENT_DATA_STORE"
    assert resp["Tags"][0]["Key"] == "env"


def test_create_channel_duplicate_name_rejected(ctx):
    req = {
        "Name": "dup",
        "Source": "aws.events",
        "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}],
    }
    native.create_channel(ctx, req)
    with pytest.raises(CommonServiceException) as exc:
        native.create_channel(ctx, req)
    assert exc.value.code == "ChannelAlreadyExistsException"


def test_get_channel_by_arn_and_by_name(ctx):
    created = native.create_channel(
        ctx,
        {
            "Name": "c1",
            "Source": "aws.events",
            "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}],
        },
    )
    by_arn = native.get_channel(ctx, {"Channel": created["ChannelArn"]})
    by_name = native.get_channel(ctx, {"Channel": "c1"})
    assert by_arn["ChannelArn"] == by_name["ChannelArn"] == created["ChannelArn"]
    assert "IngestionStatus" in by_arn
    assert "SourceConfig" in by_arn


def test_get_channel_not_found(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.get_channel(ctx, {"Channel": "nope"})
    assert exc.value.code == "ChannelNotFoundException"


def test_list_channels_returns_created_only(ctx):
    assert native.list_channels(ctx, {})["Channels"] == []
    native.create_channel(
        ctx,
        {
            "Name": "c1",
            "Source": "aws.events",
            "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}],
        },
    )
    native.create_channel(
        ctx,
        {
            "Name": "c2",
            "Source": "aws.events",
            "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "y"}],
        },
    )
    listed = native.list_channels(ctx, {})
    names = sorted(c["Name"] for c in listed["Channels"])
    assert names == ["c1", "c2"]
    # Shape: only ChannelArn + Name on list items (per spec).
    for item in listed["Channels"]:
        assert set(item.keys()) == {"ChannelArn", "Name"}


def test_update_channel_renames_and_replaces_destinations(ctx):
    created = native.create_channel(
        ctx,
        {
            "Name": "c1",
            "Source": "aws.events",
            "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}],
        },
    )
    resp = native.update_channel(
        ctx,
        {
            "Channel": created["ChannelArn"],
            "Name": "c1-renamed",
            "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "y"}],
        },
    )
    assert resp["Name"] == "c1-renamed"
    assert resp["Destinations"][0]["Location"] == "y"
    # Round-trip via Get
    got = native.get_channel(ctx, {"Channel": "c1-renamed"})
    assert got["Destinations"][0]["Location"] == "y"


def test_update_channel_rename_collision(ctx):
    native.create_channel(ctx, {"Name": "a", "Source": "aws.events", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}]})
    b = native.create_channel(ctx, {"Name": "b", "Source": "aws.events", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "y"}]})
    with pytest.raises(CommonServiceException) as exc:
        native.update_channel(ctx, {"Channel": b["ChannelArn"], "Name": "a"})
    assert exc.value.code == "ChannelAlreadyExistsException"


def test_delete_channel_removes_from_list(ctx):
    created = native.create_channel(ctx, {"Name": "doomed", "Source": "aws.events", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "x"}]})
    native.delete_channel(ctx, {"Channel": created["ChannelArn"]})
    assert native.list_channels(ctx, {})["Channels"] == []
    with pytest.raises(CommonServiceException):
        native.get_channel(ctx, {"Channel": "doomed"})


def test_create_channel_missing_required_fields(ctx):
    with pytest.raises(CommonServiceException):
        native.create_channel(ctx, {"Source": "aws.events", "Destinations": []})
