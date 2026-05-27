"""Regression tests for the native CloudTrail Lake EventDataStore APIs.

Covered APIs (all intercepted in ``cloudtrail.provider``, backed by the
in-memory ``_EVENT_DATA_STORES`` registry):

* ``CreateEventDataStore``
* ``GetEventDataStore``
* ``UpdateEventDataStore``
* ``DeleteEventDataStore``
* ``RestoreEventDataStore``
* ``ListEventDataStores``
* ``StartEventDataStoreIngestion``
* ``StopEventDataStoreIngestion``

These tests exercise the handlers directly (unit level) rather than via
the HTTP gateway — the AWS shape is asserted on the returned response
dicts.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.services.cloudtrail.provider import (
    _handle_create_event_data_store,
    _handle_delete_event_data_store,
    _handle_get_event_data_store,
    _handle_list_event_data_stores,
    _handle_restore_event_data_store,
    _handle_start_event_data_store_ingestion,
    _handle_stop_event_data_store_ingestion,
    _handle_update_event_data_store,
    reset_event_data_stores,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_event_data_stores()
    yield
    reset_event_data_stores()


def _ctx(account: str = "000000000000", region: str = "us-east-1") -> RequestContext:
    from localemu.http.request import Request

    c = RequestContext(Request(method="POST", path="/", body=b""))
    c.account_id = account
    c.region = region
    return c


def _create(
    name: str = "my-eds",
    *,
    ctx: RequestContext | None = None,
    termination_protected: bool = False,
    **overrides,
) -> dict:
    """Convenience: create a store with termination protection off (so
    tests can delete it cleanly). Callers can override any field."""
    req: dict = {
        "Name": name,
        "RetentionPeriod": 30,
        "TerminationProtectionEnabled": termination_protected,
    }
    req.update(overrides)
    return _handle_create_event_data_store(ctx or _ctx(), req)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateShape:
    """CreateEventDataStore response must match the AWS CreateEventDataStoreResponse shape."""

    def test_required_fields_present(self):
        resp = _create("probe")
        required = {
            "EventDataStoreArn",
            "Name",
            "Status",
            "RetentionPeriod",
            "AdvancedEventSelectors",
            "TerminationProtectionEnabled",
            "CreatedTimestamp",
            "UpdatedTimestamp",
            "BillingMode",
        }
        missing = required - resp.keys()
        assert not missing, f"missing fields: {missing}"

    def test_arn_shape_and_region_and_account(self):
        resp = _create("probe", ctx=_ctx(account="111122223333", region="eu-west-1"))
        arn = resp["EventDataStoreArn"]
        assert arn.startswith("arn:aws:cloudtrail:eu-west-1:111122223333:eventdatastore/")

    def test_default_status_is_enabled(self):
        resp = _create("probe")
        assert resp["Status"] == "ENABLED"

    def test_start_ingestion_false_yields_stopped_ingestion(self):
        resp = _create("probe", StartIngestion=False)
        assert resp["Status"] == "STOPPED_INGESTION"

    def test_default_billing_mode(self):
        resp = _create("probe")
        assert resp["BillingMode"] == "EXTENDABLE_RETENTION_PRICING"

    def test_timestamps_are_datetimes(self):
        resp = _create("probe")
        assert isinstance(resp["CreatedTimestamp"], datetime)
        assert isinstance(resp["UpdatedTimestamp"], datetime)
        assert resp["CreatedTimestamp"] == resp["UpdatedTimestamp"]

    def test_default_advanced_event_selectors(self):
        resp = _create("probe")
        selectors = resp["AdvancedEventSelectors"]
        assert len(selectors) == 1
        fs = selectors[0]["FieldSelectors"]
        assert fs[0]["Field"] == "eventCategory"
        assert "Management" in fs[0]["Equals"]

    def test_tags_list_echoed(self):
        tags = [{"Key": "env", "Value": "test"}]
        resp = _create("probe", TagsList=tags)
        assert resp["TagsList"] == tags


class TestDuplicateName:
    def test_duplicate_active_name_raises_already_exists(self):
        _create("dup")
        with pytest.raises(CommonServiceException) as ei:
            _create("dup")
        assert ei.value.code == "EventDataStoreAlreadyExistsException"

    def test_duplicate_name_allowed_if_other_store_pending_deletion(self):
        first = _create("dup")
        _handle_delete_event_data_store(
            _ctx(), {"EventDataStore": first["EventDataStoreArn"]}
        )
        # Now creating with the same name should succeed.
        _create("dup")


class TestGet:
    def test_get_returns_full_shape(self):
        created = _create("probe")
        got = _handle_get_event_data_store(
            _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
        )
        assert got["EventDataStoreArn"] == created["EventDataStoreArn"]
        assert got["Name"] == "probe"
        assert got["FederationStatus"] == "DISABLED"
        assert "PartitionKeys" in got

    def test_get_accepts_id_suffix(self):
        created = _create("probe")
        suffix = created["EventDataStoreArn"].rsplit("/", 1)[-1]
        got = _handle_get_event_data_store(
            _ctx(), {"EventDataStore": suffix}
        )
        assert got["EventDataStoreArn"] == created["EventDataStoreArn"]

    def test_get_unknown_raises_not_found(self):
        with pytest.raises(CommonServiceException) as ei:
            _handle_get_event_data_store(
                _ctx(),
                {
                    "EventDataStore": "arn:aws:cloudtrail:us-east-1:000000000000:"
                    "eventdatastore/00000000-0000-0000-0000-000000000000"
                },
            )
        assert ei.value.code == "EventDataStoreNotFoundException"

    def test_get_with_malformed_arn_raises_invalid_arn(self):
        with pytest.raises(CommonServiceException) as ei:
            _handle_get_event_data_store(
                _ctx(), {"EventDataStore": "arn:aws:s3:::not-a-cloudtrail-arn"}
            )
        assert ei.value.code == "EventDataStoreARNInvalidException"


class TestUpdate:
    def test_update_retention_and_name(self):
        created = _create("probe")
        resp = _handle_update_event_data_store(
            _ctx(),
            {
                "EventDataStore": created["EventDataStoreArn"],
                "Name": "renamed",
                "RetentionPeriod": 90,
            },
        )
        assert resp["Name"] == "renamed"
        assert resp["RetentionPeriod"] == 90
        assert resp["UpdatedTimestamp"] >= created["UpdatedTimestamp"]

    def test_update_cannot_downgrade_billing_mode(self):
        created = _create("probe")
        with pytest.raises(CommonServiceException) as ei:
            _handle_update_event_data_store(
                _ctx(),
                {
                    "EventDataStore": created["EventDataStoreArn"],
                    "BillingMode": "FIXED_RETENTION_PRICING",
                },
            )
        assert ei.value.code == "InvalidParameterException"


class TestDelete:
    def test_delete_soft_deletes_to_pending_deletion(self):
        created = _create("probe")
        _handle_delete_event_data_store(
            _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
        )
        got = _handle_get_event_data_store(
            _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
        )
        assert got["Status"] == "PENDING_DELETION"

    def test_delete_unknown_raises_not_found(self):
        bogus = (
            "arn:aws:cloudtrail:us-east-1:000000000000:"
            "eventdatastore/deadbeef-dead-beef-dead-beefdeadbeef"
        )
        with pytest.raises(CommonServiceException) as ei:
            _handle_delete_event_data_store(_ctx(), {"EventDataStore": bogus})
        assert ei.value.code == "EventDataStoreNotFoundException"

    def test_termination_protection_blocks_delete(self):
        created = _create("probe", termination_protected=True)
        with pytest.raises(CommonServiceException) as ei:
            _handle_delete_event_data_store(
                _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
            )
        assert ei.value.code == "EventDataStoreTerminationProtectedException"

    def test_double_delete_raises_invalid_status(self):
        created = _create("probe")
        arn = created["EventDataStoreArn"]
        _handle_delete_event_data_store(_ctx(), {"EventDataStore": arn})
        with pytest.raises(CommonServiceException) as ei:
            _handle_delete_event_data_store(_ctx(), {"EventDataStore": arn})
        assert ei.value.code == "InvalidEventDataStoreStatusException"


class TestRestore:
    def test_restore_returns_to_enabled(self):
        created = _create("probe")
        arn = created["EventDataStoreArn"]
        _handle_delete_event_data_store(_ctx(), {"EventDataStore": arn})
        resp = _handle_restore_event_data_store(
            _ctx(), {"EventDataStore": arn}
        )
        assert resp["Status"] == "ENABLED"
        # Confirm via Get.
        assert (
            _handle_get_event_data_store(_ctx(), {"EventDataStore": arn})["Status"]
            == "ENABLED"
        )

    def test_restore_of_active_store_raises_invalid_status(self):
        created = _create("probe")
        with pytest.raises(CommonServiceException) as ei:
            _handle_restore_event_data_store(
                _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
            )
        assert ei.value.code == "InvalidEventDataStoreStatusException"


class TestList:
    def test_list_returns_created_stores(self):
        a = _create("alpha")
        b = _create("beta")
        resp = _handle_list_event_data_stores(_ctx(), {})
        arns = {e["EventDataStoreArn"] for e in resp["EventDataStores"]}
        assert a["EventDataStoreArn"] in arns
        assert b["EventDataStoreArn"] in arns

    def test_list_includes_pending_deletion_stores(self):
        """AWS's ListEventDataStores includes stores pending deletion
        (so customers can find them to restore)."""
        a = _create("alpha")
        _handle_delete_event_data_store(
            _ctx(), {"EventDataStore": a["EventDataStoreArn"]}
        )
        resp = _handle_list_event_data_stores(_ctx(), {})
        arns = {e["EventDataStoreArn"] for e in resp["EventDataStores"]}
        assert a["EventDataStoreArn"] in arns

    def test_list_respects_account_and_region_scoping(self):
        _create("alpha", ctx=_ctx(region="us-east-1"))
        _create("beta", ctx=_ctx(region="eu-west-1"))
        us = _handle_list_event_data_stores(_ctx(region="us-east-1"), {})
        eu = _handle_list_event_data_stores(_ctx(region="eu-west-1"), {})
        us_names = {e["Name"] for e in us["EventDataStores"]}
        eu_names = {e["Name"] for e in eu["EventDataStores"]}
        assert us_names == {"alpha"}
        assert eu_names == {"beta"}

    def test_list_pagination(self):
        for i in range(5):
            _create(f"store-{i}")
        page1 = _handle_list_event_data_stores(_ctx(), {"MaxResults": 2})
        assert len(page1["EventDataStores"]) == 2
        assert "NextToken" in page1
        page2 = _handle_list_event_data_stores(
            _ctx(), {"MaxResults": 2, "NextToken": page1["NextToken"]}
        )
        assert len(page2["EventDataStores"]) == 2
        assert page2["NextToken"] != page1["NextToken"]


class TestIngestion:
    def test_stop_ingestion_moves_to_stopped(self):
        created = _create("probe")
        arn = created["EventDataStoreArn"]
        _handle_stop_event_data_store_ingestion(_ctx(), {"EventDataStore": arn})
        got = _handle_get_event_data_store(_ctx(), {"EventDataStore": arn})
        assert got["Status"] == "STOPPED_INGESTION"

    def test_start_ingestion_returns_to_enabled(self):
        created = _create("probe", StartIngestion=False)
        arn = created["EventDataStoreArn"]
        assert created["Status"] == "STOPPED_INGESTION"
        _handle_start_event_data_store_ingestion(_ctx(), {"EventDataStore": arn})
        got = _handle_get_event_data_store(_ctx(), {"EventDataStore": arn})
        assert got["Status"] == "ENABLED"

    def test_start_when_already_enabled_raises(self):
        created = _create("probe")
        with pytest.raises(CommonServiceException) as ei:
            _handle_start_event_data_store_ingestion(
                _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
            )
        assert ei.value.code == "InvalidEventDataStoreStatusException"

    def test_stop_when_already_stopped_raises(self):
        created = _create("probe", StartIngestion=False)
        with pytest.raises(CommonServiceException) as ei:
            _handle_stop_event_data_store_ingestion(
                _ctx(), {"EventDataStore": created["EventDataStoreArn"]}
            )
        assert ei.value.code == "InvalidEventDataStoreStatusException"


class TestFullLifecycle:
    def test_create_get_update_stop_start_delete_restore(self):
        ctx = _ctx()
        # Create
        created = _create("lifecycle")
        arn = created["EventDataStoreArn"]
        # Get
        got = _handle_get_event_data_store(ctx, {"EventDataStore": arn})
        assert got["Name"] == "lifecycle"
        # Update
        updated = _handle_update_event_data_store(
            ctx, {"EventDataStore": arn, "RetentionPeriod": 60}
        )
        assert updated["RetentionPeriod"] == 60
        # Stop ingestion
        _handle_stop_event_data_store_ingestion(ctx, {"EventDataStore": arn})
        assert (
            _handle_get_event_data_store(ctx, {"EventDataStore": arn})["Status"]
            == "STOPPED_INGESTION"
        )
        # Start ingestion
        _handle_start_event_data_store_ingestion(ctx, {"EventDataStore": arn})
        assert (
            _handle_get_event_data_store(ctx, {"EventDataStore": arn})["Status"]
            == "ENABLED"
        )
        # Delete (soft)
        _handle_delete_event_data_store(ctx, {"EventDataStore": arn})
        assert (
            _handle_get_event_data_store(ctx, {"EventDataStore": arn})["Status"]
            == "PENDING_DELETION"
        )
        # Restore
        _handle_restore_event_data_store(ctx, {"EventDataStore": arn})
        assert (
            _handle_get_event_data_store(ctx, {"EventDataStore": arn})["Status"]
            == "ENABLED"
        )
