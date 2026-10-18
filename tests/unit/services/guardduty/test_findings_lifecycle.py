"""Finding lifecycle on the native GuardDuty store: archive state, feedback,
generic criteria, sorting, statistics, and per-detector cleanup."""
from __future__ import annotations

import pytest

from localemu.services.guardduty import findings_store as fs

ACC, REG, DET = "000000000000", "us-east-1", "det1"
TYPES = [
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Recon:EC2/PortProbeUnprotectedPort",
    "Policy:IAMUser/RootCredentialUsage",
]


@pytest.fixture(autouse=True)
def _clean():
    fs.reset()
    yield
    fs.reset()


def _seed():
    return fs.create_sample_findings(
        account_id=ACC, region=REG, detector_id=DET, finding_types=TYPES,
    )


def _list(**kw):
    ids, _ = fs.list_findings(account_id=ACC, region=REG, detector_id=DET, **kw)
    return ids


def test_archive_and_unarchive_toggle_the_flag_and_bump_updated_at():
    created = _seed()
    target = created[0]["Id"]
    before = created[0]["UpdatedAt"]
    fs.set_archived(account_id=ACC, region=REG, detector_id=DET, finding_ids=[target], archived=True)
    got = fs.get_findings(account_id=ACC, region=REG, detector_id=DET, finding_ids=[target])[0]
    assert got["Service"]["Archived"] is True
    assert got["UpdatedAt"] >= before
    fs.set_archived(account_id=ACC, region=REG, detector_id=DET, finding_ids=[target], archived=False)
    assert fs.get_findings(account_id=ACC, region=REG, detector_id=DET, finding_ids=[target])[0][
        "Service"]["Archived"] is False


def test_archive_ignores_unknown_ids():
    _seed()
    fs.set_archived(account_id=ACC, region=REG, detector_id=DET, finding_ids=["nope"], archived=True)


def test_criteria_on_archived_flag_uses_true_false_text():
    created = _seed()
    fs.set_archived(account_id=ACC, region=REG, detector_id=DET,
                    finding_ids=[created[0]["Id"]], archived=True)
    live = _list(finding_criteria={"Criterion": {"service.archived": {"Eq": ["false"]}}})
    assert set(live) == {f["Id"] for f in created[1:]}
    assert _list(finding_criteria={"Criterion": {"service.archived": {"Eq": ["true"]}}}) == [created[0]["Id"]]


def test_feedback_is_stored_on_the_service_block():
    created = _seed()
    fs.set_feedback(account_id=ACC, region=REG, detector_id=DET,
                    finding_ids=[created[1]["Id"]], feedback="USEFUL")
    got = fs.get_findings(account_id=ACC, region=REG, detector_id=DET, finding_ids=[created[1]["Id"]])[0]
    assert got["Service"]["UserFeedback"] == "USEFUL"


@pytest.mark.parametrize("condition,expected", [
    ({"Neq": [TYPES[0]]}, {TYPES[1], TYPES[2]}),
    ({"Matches": ["Recon:*"]}, {TYPES[1]}),
    ({"NotMatches": ["Recon:*"]}, {TYPES[0], TYPES[2]}),
    ({"Equals": [TYPES[2]]}, {TYPES[2]}),
])
def test_string_conditions_on_type(condition, expected):
    created = {f["Id"]: f["Type"] for f in _seed()}
    ids = _list(finding_criteria={"Criterion": {"type": condition}})
    assert {created[i] for i in ids} == expected


def test_numeric_conditions_on_severity():
    created = {f["Id"]: f["Severity"] for f in _seed()}
    low = _list(finding_criteria={"Criterion": {"severity": {"Lt": 3}}})
    assert set(low) == {i for i, s in created.items() if s < 3}
    high = _list(finding_criteria={"Criterion": {"severity": {"Gte": 3}}})
    assert set(high) == {i for i, s in created.items() if s >= 3}


def test_time_conditions_use_epoch_milliseconds():
    created = _seed()
    assert len(_list(finding_criteria={"Criterion": {"updatedAt": {"GreaterThanOrEqual": 0}}})) == len(created)
    assert _list(finding_criteria={"Criterion": {"updatedAt": {"LessThan": 1}}}) == []


def test_field_the_finding_lacks_never_matches_a_positive_condition():
    _seed()
    assert _list(finding_criteria={"Criterion": {"no.such.field": {"Eq": ["x"]}}}) == []
    assert len(_list(finding_criteria={"Criterion": {"no.such.field": {"Neq": ["x"]}}})) == 3


def test_all_criteria_must_hold():
    created = _seed()
    ids = _list(finding_criteria={"Criterion": {
        "type": {"Matches": ["Recon:*"]}, "severity": {"Gte": 1000},
    }})
    assert ids == []
    assert len(created) == 3


@pytest.mark.parametrize("attribute", ["severity", "type", "createdAt"])
@pytest.mark.parametrize("order", ["ASC", "DESC"])
def test_sort_orders_by_attribute(attribute, order):
    created = {f["Id"]: f for f in _seed()}
    ids = _list(sort_criteria={"AttributeName": attribute, "OrderBy": order})
    keys = [created[i][{"severity": "Severity", "type": "Type", "createdAt": "CreatedAt"}[attribute]] for i in ids]
    assert keys == sorted(keys, reverse=order == "DESC")


def test_get_findings_applies_sort_criteria():
    created = _seed()
    got = fs.get_findings(account_id=ACC, region=REG, detector_id=DET,
                          finding_ids=[f["Id"] for f in created],
                          sort_criteria={"AttributeName": "severity", "OrderBy": "DESC"})
    sev = [f["Severity"] for f in got]
    assert sev == sorted(sev, reverse=True)


def test_statistics_count_by_severity_and_grouping():
    created = _seed()
    stats, _ = fs.get_statistics(account_id=ACC, region=REG, detector_id=DET,
                                 statistic_types=["COUNT_BY_SEVERITY"], group_by="FINDING_TYPE")
    assert sum(stats["CountBySeverity"].values()) == len(created)
    assert {r["FindingType"] for r in stats["GroupedByFindingType"]} == set(TYPES)
    assert all(r["TotalFindings"] == 1 for r in stats["GroupedByFindingType"])


def test_statistics_paginate_groups():
    _seed()
    first, token = fs.get_statistics(account_id=ACC, region=REG, detector_id=DET, group_by="FINDING_TYPE", max_results=2)
    assert len(first["GroupedByFindingType"]) == 2 and token == "2"
    rest, token = fs.get_statistics(account_id=ACC, region=REG, detector_id=DET, group_by="FINDING_TYPE",
                                    max_results=2, next_token="2")
    assert len(rest["GroupedByFindingType"]) == 1 and token is None


def test_deleting_a_detector_drops_its_findings():
    _seed()
    fs.delete_detector_findings(ACC, REG, DET)
    assert _list() == []


def test_findings_live_in_the_persisted_store():
    """The registry entry persistence loads/saves must point at the bundle
    the store writes to."""
    from localemu.services.guardduty.models import guardduty_stores
    from localemu.state.registry import LOAD_ORDER, NATIVE_STORES

    _seed()
    assert guardduty_stores[ACC][REG].findings[DET]
    assert NATIVE_STORES["guardduty_findings"] == ("localemu.services.guardduty.models", "guardduty_stores")
    assert any("guardduty_findings" in tier for tier in LOAD_ORDER)
