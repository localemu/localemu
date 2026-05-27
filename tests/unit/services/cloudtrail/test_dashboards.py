"""CRUD + refresh for the native CloudTrail Dashboards API."""

from __future__ import annotations

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


def _basic_widgets():
    return [
        {
            "QueryAlias": "top-errors",
            "QueryStatement": "SELECT eventName FROM <eds>",
            "ViewProperties": {"view": "table"},
        }
    ]


def test_create_dashboard_returns_arn_and_echoes_widgets(ctx):
    resp = native.create_dashboard(
        ctx,
        {
            "Name": "my-dash",
            "Widgets": _basic_widgets(),
            "TagsList": [{"Key": "env", "Value": "test"}],
            "TerminationProtectionEnabled": True,
            "RefreshSchedule": {"Frequency": {"Unit": "HOURS", "Value": 6}, "Status": "ENABLED"},
        },
    )
    assert resp["DashboardArn"].endswith(":dashboard/my-dash")
    assert resp["Type"] == "CUSTOM"
    assert resp["TerminationProtectionEnabled"] is True
    assert resp["Widgets"] == _basic_widgets()
    assert resp["RefreshSchedule"]["Frequency"]["Unit"] == "HOURS"


def test_create_dashboard_duplicate_rejected(ctx):
    native.create_dashboard(ctx, {"Name": "x"})
    with pytest.raises(CommonServiceException) as exc:
        native.create_dashboard(ctx, {"Name": "x"})
    assert exc.value.code == "ResourceAlreadyExistsException"


def test_get_dashboard_round_trip(ctx):
    native.create_dashboard(ctx, {"Name": "d1", "Widgets": _basic_widgets()})
    got = native.get_dashboard(ctx, {"DashboardId": "d1"})
    assert got["Widgets"] == _basic_widgets()
    assert got["Status"] == "CREATED"
    assert "CreatedTimestamp" in got
    assert "UpdatedTimestamp" in got


def test_get_dashboard_not_found(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.get_dashboard(ctx, {"DashboardId": "missing"})
    assert exc.value.code == "ResourceNotFoundException"


def test_list_dashboards_items_have_required_shape(ctx):
    native.create_dashboard(ctx, {"Name": "a"})
    native.create_dashboard(ctx, {"Name": "b"})
    listed = native.list_dashboards(ctx, {})["Dashboards"]
    assert len(listed) == 2
    for item in listed:
        assert set(item.keys()) == {"DashboardArn", "Type"}


def test_update_dashboard_mutates_widgets_and_bumps_timestamp(ctx):
    created = native.create_dashboard(ctx, {"Name": "d1", "Widgets": []})
    orig_updated = created.get("UpdatedTimestamp")
    resp = native.update_dashboard(
        ctx,
        {
            "DashboardId": "d1",
            "Widgets": _basic_widgets(),
            "TerminationProtectionEnabled": True,
        },
    )
    assert resp["Widgets"] == _basic_widgets()
    assert resp["TerminationProtectionEnabled"] is True
    assert resp["UpdatedTimestamp"] is not None
    # UpdatedTimestamp moved forward or is at minimum set
    if orig_updated is not None:
        assert resp["UpdatedTimestamp"] >= orig_updated


def test_start_dashboard_refresh_stores_refresh_id(ctx):
    native.create_dashboard(ctx, {"Name": "d1"})
    resp = native.start_dashboard_refresh(ctx, {"DashboardId": "d1"})
    assert "RefreshId" in resp
    assert len(resp["RefreshId"]) > 0
    got = native.get_dashboard(ctx, {"DashboardId": "d1"})
    assert got["LastRefreshId"] == resp["RefreshId"]


def test_delete_dashboard_removes(ctx):
    native.create_dashboard(ctx, {"Name": "d1"})
    native.delete_dashboard(ctx, {"DashboardId": "d1"})
    assert native.list_dashboards(ctx, {})["Dashboards"] == []


def test_delete_dashboard_blocked_by_termination_protection(ctx):
    native.create_dashboard(ctx, {"Name": "protected", "TerminationProtectionEnabled": True})
    with pytest.raises(CommonServiceException) as exc:
        native.delete_dashboard(ctx, {"DashboardId": "protected"})
    assert exc.value.code == "ConflictException"
    # Then allow deletion by first disabling protection.
    native.update_dashboard(ctx, {"DashboardId": "protected", "TerminationProtectionEnabled": False})
    native.delete_dashboard(ctx, {"DashboardId": "protected"})
