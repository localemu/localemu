"""Unit tests for the EC2 VPC Block Public Access metadata side.

Covers ``DescribeVpcBlockPublicAccessOptions`` / ``Modify*`` for the account-
region options, and the four ``*VpcBlockPublicAccessExclusion`` ops (create,
modify, delete, describe).

Data-plane enforcement (iptables) is tested separately under
``tests/unit/services/ec2/docker/``.
"""

from __future__ import annotations

from unittest import mock

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.ec2 import provider as ec2_provider_module
from localemu.services.ec2.account_settings import ec2_account_settings_stores


ACCT = "000000000000"
REGION = "us-east-1"


def _store():
    bundle = ec2_account_settings_stores
    if ACCT in bundle:
        bundle[ACCT].pop(REGION, None)
    return bundle[ACCT][REGION]


def _ctx(account=ACCT, region=REGION):
    ctx = mock.MagicMock()
    ctx.account_id = account
    ctx.region = region
    return ctx


def _provider():
    return ec2_provider_module.Ec2Provider()


# ---------- options: describe + modify ----------


def test_describe_options_default_state_for_new_account():
    _store()
    p = _provider()
    out = p.describe_vpc_block_public_access_options(_ctx(), {})
    opts = out["VpcBlockPublicAccessOptions"]
    assert opts["AwsAccountId"] == ACCT
    assert opts["AwsRegion"] == REGION
    assert opts["InternetGatewayBlockMode"] == "off"
    # Note: ``State`` is the management-transition state, NOT the block mode.
    assert opts["State"] == "default-state"
    assert opts["ExclusionsAllowed"] == "allowed"
    assert opts["ManagedBy"] == "account"
    # LastUpdateTimestamp is omitted until the first Modify call.
    assert "LastUpdateTimestamp" not in opts


def test_modify_options_sets_block_bidirectional():
    _store()
    p = _provider()
    out = p.modify_vpc_block_public_access_options(
        _ctx(), {"InternetGatewayBlockMode": "block-bidirectional"}
    )
    opts = out["VpcBlockPublicAccessOptions"]
    assert opts["InternetGatewayBlockMode"] == "block-bidirectional"
    assert opts["State"] == "update-complete"
    assert "LastUpdateTimestamp" in opts  # set on first Modify


def test_modify_options_sets_block_ingress():
    _store()
    p = _provider()
    p.modify_vpc_block_public_access_options(
        _ctx(), {"InternetGatewayBlockMode": "block-ingress"}
    )
    opts = p.describe_vpc_block_public_access_options(_ctx(), {})[
        "VpcBlockPublicAccessOptions"
    ]
    assert opts["InternetGatewayBlockMode"] == "block-ingress"
    assert opts["State"] == "update-complete"


def test_modify_options_rejects_invalid_mode():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.modify_vpc_block_public_access_options(
            _ctx(), {"InternetGatewayBlockMode": "make-it-go-away"}
        )
    assert exc.value.code == "InvalidParameterValue"


def test_modify_options_rejects_missing_mode():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException):
        p.modify_vpc_block_public_access_options(_ctx(), {})


# ---------- exclusions: create ----------


def test_create_exclusion_for_subnet():
    _store()
    p = _provider()
    out = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-abc123",
        },
    )
    rec = out["VpcBlockPublicAccessExclusion"]
    assert rec["ExclusionId"].startswith("vpcbpa-excl-")
    assert len(rec["ExclusionId"]) == len("vpcbpa-excl-") + 17
    assert rec["InternetGatewayExclusionMode"] == "allow-bidirectional"
    assert rec["ResourceArn"] == f"arn:aws:ec2:{REGION}:{ACCT}:subnet/subnet-abc123"
    assert rec["State"] == "create-complete"
    assert rec["TagSet"] == []


def test_create_exclusion_for_vpc():
    _store()
    p = _provider()
    out = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-egress",
            "VpcId": "vpc-xyz789",
        },
    )
    rec = out["VpcBlockPublicAccessExclusion"]
    assert rec["ResourceArn"] == f"arn:aws:ec2:{REGION}:{ACCT}:vpc/vpc-xyz789"


def test_create_exclusion_with_tag_specifications_passes_them_through():
    _store()
    p = _provider()
    out = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-tags",
            "TagSpecifications": [
                {
                    "ResourceType": "vpc-block-public-access-exclusion",
                    "Tags": [
                        {"Key": "env", "Value": "prod"},
                        {"Key": "team", "Value": "platform"},
                    ],
                }
            ],
        },
    )
    tags = {t["Key"]: t["Value"] for t in out["VpcBlockPublicAccessExclusion"]["TagSet"]}
    assert tags == {"env": "prod", "team": "platform"}


def test_create_exclusion_rejects_both_subnet_and_vpc():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": "subnet-a",
                "VpcId": "vpc-b",
            },
        )
    assert exc.value.code == "InvalidParameterCombination"


def test_create_exclusion_rejects_neither_subnet_nor_vpc():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_vpc_block_public_access_exclusion(
            _ctx(), {"InternetGatewayExclusionMode": "allow-bidirectional"}
        )
    assert exc.value.code == "InvalidParameterCombination"


def test_create_exclusion_rejects_invalid_mode():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "wide-open",
                "SubnetId": "subnet-a",
            },
        )
    assert exc.value.code == "InvalidParameterValue"


def test_create_exclusion_enforces_quota_per_region():
    """Default quota is 50 per account per region; the 51st create fails."""
    s = _store()
    # Pre-populate up to the limit.
    for i in range(50):
        s.vpc_bpa_exclusions[f"vpcbpa-excl-{i:017x}"] = {
            "ExclusionId": f"vpcbpa-excl-{i:017x}",
            "State": "create-complete",
        }
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": "subnet-overflow",
            },
        )
    assert exc.value.code == "ResourceLimitExceeded"


# ---------- exclusions: modify ----------


def test_modify_exclusion_updates_mode_and_state():
    _store()
    p = _provider()
    eid = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-1",
        },
    )["VpcBlockPublicAccessExclusion"]["ExclusionId"]

    out = p.modify_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "ExclusionId": eid,
            "InternetGatewayExclusionMode": "allow-egress",
        },
    )
    rec = out["VpcBlockPublicAccessExclusion"]
    assert rec["InternetGatewayExclusionMode"] == "allow-egress"
    assert rec["State"] == "update-complete"


def test_modify_exclusion_unknown_id_raises_not_found():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.modify_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "ExclusionId": "vpcbpa-excl-deadbeef00000000",
                "InternetGatewayExclusionMode": "allow-egress",
            },
        )
    assert exc.value.code == "InvalidVpcBlockPublicAccessExclusionId.NotFound"


def test_modify_exclusion_rejects_invalid_mode():
    _store()
    p = _provider()
    eid = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-mode",
        },
    )["VpcBlockPublicAccessExclusion"]["ExclusionId"]
    with pytest.raises(CommonServiceException) as exc:
        p.modify_vpc_block_public_access_exclusion(
            _ctx(),
            {"ExclusionId": eid, "InternetGatewayExclusionMode": "yolo"},
        )
    assert exc.value.code == "InvalidParameterValue"


# ---------- exclusions: delete ----------


def test_delete_exclusion_returns_terminal_record():
    _store()
    p = _provider()
    eid = p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-del",
        },
    )["VpcBlockPublicAccessExclusion"]["ExclusionId"]

    out = p.delete_vpc_block_public_access_exclusion(_ctx(), {"ExclusionId": eid})
    rec = out["VpcBlockPublicAccessExclusion"]
    assert rec["State"] == "delete-complete"
    assert "DeletionTimestamp" in rec

    # Describing now should not surface the deleted record.
    listing = p.describe_vpc_block_public_access_exclusions(_ctx(), {})[
        "VpcBlockPublicAccessExclusions"
    ]
    assert eid not in {r["ExclusionId"] for r in listing}


def test_delete_unknown_id_raises_not_found():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.delete_vpc_block_public_access_exclusion(
            _ctx(), {"ExclusionId": "vpcbpa-excl-doesnotexist00"}
        )
    assert exc.value.code == "InvalidVpcBlockPublicAccessExclusionId.NotFound"


# ---------- exclusions: describe + filters ----------


def test_describe_exclusions_empty_for_new_account():
    _store()
    p = _provider()
    out = p.describe_vpc_block_public_access_exclusions(_ctx(), {})
    assert out == {"VpcBlockPublicAccessExclusions": []}


def test_describe_exclusions_returns_all_when_no_filter():
    _store()
    p = _provider()
    for i in range(3):
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": f"subnet-{i}",
            },
        )
    out = p.describe_vpc_block_public_access_exclusions(_ctx(), {})
    assert len(out["VpcBlockPublicAccessExclusions"]) == 3


def test_describe_exclusions_filters_by_resource_arn():
    _store()
    p = _provider()
    target_subnet = "subnet-target"
    target_arn = f"arn:aws:ec2:{REGION}:{ACCT}:subnet/{target_subnet}"
    for i in range(3):
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": f"subnet-other-{i}",
            },
        )
    p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-egress",
            "SubnetId": target_subnet,
        },
    )
    out = p.describe_vpc_block_public_access_exclusions(
        _ctx(),
        {"Filters": [{"Name": "resource-arn", "Values": [target_arn]}]},
    )
    recs = out["VpcBlockPublicAccessExclusions"]
    assert len(recs) == 1
    assert recs[0]["ResourceArn"] == target_arn


def test_describe_exclusions_filters_by_tag_key_value_pair():
    _store()
    p = _provider()
    p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-prod",
            "TagSpecifications": [
                {"Tags": [{"Key": "env", "Value": "prod"}]}
            ],
        },
    )
    p.create_vpc_block_public_access_exclusion(
        _ctx(),
        {
            "InternetGatewayExclusionMode": "allow-bidirectional",
            "SubnetId": "subnet-dev",
            "TagSpecifications": [
                {"Tags": [{"Key": "env", "Value": "dev"}]}
            ],
        },
    )
    out = p.describe_vpc_block_public_access_exclusions(
        _ctx(), {"Filters": [{"Name": "tag:env", "Values": ["prod"]}]}
    )
    recs = out["VpcBlockPublicAccessExclusions"]
    assert len(recs) == 1
    assert any(
        t["Key"] == "env" and t["Value"] == "prod" for t in recs[0]["TagSet"]
    )


def test_describe_exclusions_by_explicit_id_list():
    _store()
    p = _provider()
    eids = [
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": f"subnet-x{i}",
            },
        )["VpcBlockPublicAccessExclusion"]["ExclusionId"]
        for i in range(3)
    ]
    out = p.describe_vpc_block_public_access_exclusions(
        _ctx(), {"ExclusionIds": [eids[0], eids[2]]}
    )
    recs = out["VpcBlockPublicAccessExclusions"]
    assert {r["ExclusionId"] for r in recs} == {eids[0], eids[2]}


def test_describe_exclusions_rejects_invalid_max_results():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException):
        p.describe_vpc_block_public_access_exclusions(_ctx(), {"MaxResults": 3})
    with pytest.raises(CommonServiceException):
        p.describe_vpc_block_public_access_exclusions(_ctx(), {"MaxResults": 5000})


def test_describe_exclusions_respects_max_results():
    _store()
    p = _provider()
    for i in range(10):
        p.create_vpc_block_public_access_exclusion(
            _ctx(),
            {
                "InternetGatewayExclusionMode": "allow-bidirectional",
                "SubnetId": f"subnet-mr-{i}",
            },
        )
    out = p.describe_vpc_block_public_access_exclusions(_ctx(), {"MaxResults": 5})
    assert len(out["VpcBlockPublicAccessExclusions"]) == 5
