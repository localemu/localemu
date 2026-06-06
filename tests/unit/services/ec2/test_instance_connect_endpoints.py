"""Unit tests for EC2 Instance Connect Endpoints (EICE) metadata side."""

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


def _ctx():
    ctx = mock.MagicMock()
    ctx.account_id = ACCT
    ctx.region = REGION
    return ctx


def _provider():
    return ec2_provider_module.Ec2Provider()


def test_describe_empty_for_new_account():
    _store()
    p = _provider()
    out = p.describe_instance_connect_endpoints(_ctx(), {})
    assert out == {"InstanceConnectEndpoints": []}


def test_create_returns_correct_shape():
    _store()
    p = _provider()
    out = p.create_instance_connect_endpoint(
        _ctx(),
        {"SubnetId": "subnet-1", "PreserveClientIp": False},
    )
    rec = out["InstanceConnectEndpoint"]
    assert rec["InstanceConnectEndpointId"].startswith("eice-")
    assert len(rec["InstanceConnectEndpointId"]) == len("eice-") + 17
    assert rec["SubnetId"] == "subnet-1"
    # State is create-complete, NOT "available" — AWS quirk.
    assert rec["State"] == "create-complete"
    assert rec["IpAddressType"] == "ipv4"  # default
    assert rec["PreserveClientIp"] is False
    assert rec["InstanceConnectEndpointArn"].endswith(rec["InstanceConnectEndpointId"])


def test_create_rejects_missing_subnet_id():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException):
        p.create_instance_connect_endpoint(_ctx(), {})


def test_create_rejects_invalid_ip_type():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_instance_connect_endpoint(
            _ctx(), {"SubnetId": "subnet-x", "IpAddressType": "yolo"}
        )
    assert exc.value.code == "InvalidParameterValue"


def test_preserve_client_ip_requires_ipv4():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.create_instance_connect_endpoint(
            _ctx(),
            {
                "SubnetId": "subnet-x",
                "IpAddressType": "dualstack",
                "PreserveClientIp": True,
            },
        )
    assert exc.value.code == "InvalidParameterCombination"


def test_delete_returns_terminal_state_and_removes():
    _store()
    p = _provider()
    eid = p.create_instance_connect_endpoint(
        _ctx(), {"SubnetId": "subnet-d"}
    )["InstanceConnectEndpoint"]["InstanceConnectEndpointId"]
    rec = p.delete_instance_connect_endpoint(
        _ctx(), {"InstanceConnectEndpointId": eid}
    )["InstanceConnectEndpoint"]
    assert rec["State"] == "delete-complete"
    assert "DeletedAt" in rec
    listing = p.describe_instance_connect_endpoints(_ctx(), {})[
        "InstanceConnectEndpoints"
    ]
    assert eid not in {r["InstanceConnectEndpointId"] for r in listing}


def test_delete_unknown_id_raises_not_found():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.delete_instance_connect_endpoint(
            _ctx(), {"InstanceConnectEndpointId": "eice-deadbeefdeadbeef0"}
        )
    assert exc.value.code == "InvalidInstanceConnectEndpointId.NotFound"


def test_describe_filters_by_subnet_id():
    _store()
    p = _provider()
    for i in range(3):
        p.create_instance_connect_endpoint(_ctx(), {"SubnetId": f"subnet-{i}"})
    p.create_instance_connect_endpoint(_ctx(), {"SubnetId": "subnet-target"})
    out = p.describe_instance_connect_endpoints(
        _ctx(),
        {"Filters": [{"Name": "subnet-id", "Values": ["subnet-target"]}]},
    )
    recs = out["InstanceConnectEndpoints"]
    assert len(recs) == 1
    assert recs[0]["SubnetId"] == "subnet-target"


def test_describe_rejects_invalid_max_results():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException):
        p.describe_instance_connect_endpoints(_ctx(), {"MaxResults": 99})
