"""Unit tests for localemu.services.guardduty.findings_store and the
wire-detail conversion used by provider.py's EventBridge forwarding.

Moto's vendored GuardDuty backend has no route at all for
CreateSampleFindings/ListFindings/GetFindings. These tests cover the
native replacement directly, without needing a running server.
"""
from __future__ import annotations

from localemu.services.guardduty import findings_store
from localemu.services.guardduty.provider import _to_wire_detail

ACCOUNT = "000000000000"
REGION = "us-east-1"
DETECTOR = "d" * 32


def setup_function(_fn):
    findings_store.reset()


def test_create_sample_findings_returns_one_per_type():
    created = findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=[
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "Recon:IAMUser/MaliciousIPCaller",
        ],
    )
    assert len(created) == 2
    types = {f["Type"] for f in created}
    assert types == {
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "Recon:IAMUser/MaliciousIPCaller",
    }
    # Known type: curated severity/title, not the generic fallback.
    cred_finding = next(f for f in created if f["Type"].startswith("UnauthorizedAccess"))
    assert cred_finding["Severity"] == 8.5
    assert cred_finding["Resource"]["ResourceType"] == "AccessKey"
    assert cred_finding["AccountId"] == ACCOUNT
    assert cred_finding["Id"] in cred_finding["Arn"]


def test_create_sample_findings_unknown_type_still_schema_valid():
    created = findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=["Impact:S3Object/SomeFutureFindingTypeNotInOurTable"],
    )
    [finding] = created
    assert finding["Type"] == "Impact:S3Object/SomeFutureFindingTypeNotInOurTable"
    # Category-level default severity (Impact == 7.0), not a crash.
    assert finding["Severity"] == 7.0
    assert "Title" in finding and "Description" in finding


def test_list_and_get_findings_round_trip():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=["Recon:IAMUser/MaliciousIPCaller"],
    )
    ids, next_token = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
    )
    assert len(ids) == 1
    assert next_token is None

    [finding] = findings_store.get_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR, finding_ids=ids,
    )
    assert finding["Id"] == ids[0]


def test_get_findings_skips_unknown_ids():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=["Recon:IAMUser/MaliciousIPCaller"],
    )
    real_id = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
    )[0][0]
    results = findings_store.get_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_ids=[real_id, "does-not-exist"],
    )
    assert [f["Id"] for f in results] == [real_id]


def test_list_findings_filters_by_type_criterion():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=[
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "Recon:IAMUser/MaliciousIPCaller",
        ],
    )
    ids, _ = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_criteria={"Criterion": {"type": {"Eq": ["Recon:IAMUser/MaliciousIPCaller"]}}},
    )
    findings = findings_store.get_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR, finding_ids=ids,
    )
    assert len(findings) == 1
    assert findings[0]["Type"] == "Recon:IAMUser/MaliciousIPCaller"


def test_list_findings_filters_by_severity_criterion():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=[
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",  # 8.5
            "PenTest:IAMUser/KaliLinux",  # 2.0
        ],
    )
    ids, _ = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_criteria={"Criterion": {"severity": {"Gte": 5.0}}},
    )
    findings = findings_store.get_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR, finding_ids=ids,
    )
    assert len(findings) == 1
    assert findings[0]["Severity"] == 8.5


def test_list_findings_pagination():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=[f"PenTest:IAMUser/Type{i}" for i in range(5)],
    )
    first_page, token = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR, max_results=2,
    )
    assert len(first_page) == 2
    assert token is not None

    second_page, token2 = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        max_results=2, next_token=token,
    )
    assert len(second_page) == 2
    assert not set(first_page) & set(second_page)
    assert token2 is not None


def test_detectors_are_isolated():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id="detector-a",
        finding_types=["Recon:IAMUser/MaliciousIPCaller"],
    )
    ids, _ = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id="detector-b",
    )
    assert ids == []


def test_to_wire_detail_lowercases_first_letter_of_every_key_recursively():
    pascal = {
        "SchemaVersion": "2.0",
        "AccessKeyDetails": {"UserName": "sample-user", "UserType": "IAMUser"},
        "Tags": [{"Key": "Env"}],
    }
    wire = _to_wire_detail(pascal)
    assert wire == {
        "schemaVersion": "2.0",
        "accessKeyDetails": {"userName": "sample-user", "userType": "IAMUser"},
        "tags": [{"key": "Env"}],
    }


def test_reset_clears_all_detectors():
    findings_store.create_sample_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
        finding_types=["Recon:IAMUser/MaliciousIPCaller"],
    )
    findings_store.reset()
    ids, _ = findings_store.list_findings(
        account_id=ACCOUNT, region=REGION, detector_id=DETECTOR,
    )
    assert ids == []
