"""A trust policy may only name IAM users and roles that exist (enforcement mode)."""
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from localemu.services.iam.iam_patches import apply_iam_patches

TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def _trust_for(arn):
    return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": arn}, "Action": "sts:AssumeRole"}]})


@pytest.fixture(autouse=True)
def enforcement(monkeypatch):
    monkeypatch.setenv("IAM_ENFORCEMENT", "1")
    apply_iam_patches()


@mock_aws
def test_missing_role_principal_is_rejected():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="probe", AssumeRolePolicyDocument=json.dumps(TRUST))
    with pytest.raises(ClientError) as err:
        iam.update_assume_role_policy(RoleName="probe", PolicyDocument=_trust_for("arn:aws:iam::123456789012:role/nope"))
    assert err.value.response["Error"]["Code"] == "MalformedPolicyDocument"


@mock_aws
def test_existing_principals_and_account_root_are_accepted():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="probe", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.create_user(UserName="alice")
    for arn in ("arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:role/probe"):
        iam.update_assume_role_policy(RoleName="probe", PolicyDocument=_trust_for(arn))


@mock_aws
def test_not_enforced_without_enforcement_mode(monkeypatch):
    monkeypatch.delenv("IAM_ENFORCEMENT")
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="probe", AssumeRolePolicyDocument=_trust_for("arn:aws:iam::123456789012:role/nope"))
