"""Regression tests for the native CloudTrail Imports API.

These APIs track metadata only — LocalEmu does NOT read CloudTrail log
files from the configured S3 source. The test suite locks in the state
machine and response shape, not the (absent) ingestion behavior.
"""

from __future__ import annotations

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


def _start(ctx, **overrides):
    req = {
        "Destinations": ["arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/eds1"],
        "ImportSource": {
            "S3": {
                "S3LocationUri": "s3://my-bucket/path",
                "S3BucketRegion": "us-east-1",
                "S3BucketAccessRoleArn": "arn:aws:iam::000000000000:role/r",
            }
        },
    }
    req.update(overrides)
    return native.start_import(ctx, req)


def test_start_import_assigns_id_and_initializing_status(ctx):
    resp = _start(ctx)
    assert "ImportId" in resp
    assert resp["ImportStatus"] == "INITIALIZING"
    assert resp["Destinations"][0].endswith("eds1")
    assert resp["CreatedTimestamp"] is not None


def test_get_import_advances_state_machine(ctx):
    resp = _start(ctx)
    iid = resp["ImportId"]
    # INITIALIZING -> IN_PROGRESS
    g1 = native.get_import(ctx, {"ImportId": iid})
    assert g1["ImportStatus"] == "IN_PROGRESS"
    # IN_PROGRESS -> COMPLETED
    g2 = native.get_import(ctx, {"ImportId": iid})
    assert g2["ImportStatus"] == "COMPLETED"
    # Subsequent polls remain COMPLETED (terminal)
    g3 = native.get_import(ctx, {"ImportId": iid})
    assert g3["ImportStatus"] == "COMPLETED"
    # Statistics present on COMPLETED
    assert g2["ImportStatistics"]["PrefixesFound"] == 1


def test_get_import_not_found(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.get_import(ctx, {"ImportId": "nope"})
    assert exc.value.code == "ImportNotFoundException"


def test_stop_import_marks_stopped(ctx):
    iid = _start(ctx)["ImportId"]
    resp = native.stop_import(ctx, {"ImportId": iid})
    assert resp["ImportStatus"] == "STOPPED"
    # Polling Get after Stop does NOT advance beyond STOPPED
    again = native.get_import(ctx, {"ImportId": iid})
    assert again["ImportStatus"] == "STOPPED"


def test_stop_import_not_found(ctx):
    with pytest.raises(CommonServiceException):
        native.stop_import(ctx, {"ImportId": "nope"})


def test_list_imports_returns_tracked_items(ctx):
    a = _start(ctx)["ImportId"]
    b = _start(ctx)["ImportId"]
    items = native.list_imports(ctx, {})["Imports"]
    ids = {i["ImportId"] for i in items}
    assert {a, b}.issubset(ids)
    # Shape check per spec
    for item in items:
        assert set(item.keys()) >= {"ImportId", "ImportStatus", "Destinations", "CreatedTimestamp", "UpdatedTimestamp"}


def test_list_imports_filter_by_status(ctx):
    _start(ctx)
    stopped = _start(ctx)["ImportId"]
    native.stop_import(ctx, {"ImportId": stopped})
    only_stopped = native.list_imports(ctx, {"ImportStatus": "STOPPED"})["Imports"]
    assert [i["ImportId"] for i in only_stopped] == [stopped]


def test_list_import_failures_empty_for_fake_import(ctx):
    iid = _start(ctx)["ImportId"]
    resp = native.list_import_failures(ctx, {"ImportId": iid})
    assert resp == {"Failures": []}


def test_list_import_failures_unknown_import(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.list_import_failures(ctx, {"ImportId": "nope"})
    assert exc.value.code == "ImportNotFoundException"
