"""Re-setting a managed policy's default version to the version that is
already the default must be a no-op, matching real AWS."""
import json

import boto3
import pytest
from moto import mock_aws

from localemu.services.iam.iam_patches import apply_iam_patches

POLICY_DOC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})


@pytest.fixture(autouse=True)
def patched():
    apply_iam_patches()


@mock_aws
def test_set_default_to_current_default_keeps_is_default_true():
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_policy(PolicyName="p", PolicyDocument=POLICY_DOC)
    arn = created["Policy"]["Arn"]
    default_version = created["Policy"]["DefaultVersionId"]

    iam.set_default_policy_version(PolicyArn=arn, VersionId=default_version)

    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    defaults = [v["IsDefaultVersion"] for v in versions]
    assert defaults.count(True) == 1
    assert versions[0]["VersionId"] == default_version
    assert versions[0]["IsDefaultVersion"] is True


@mock_aws
def test_default_version_still_cannot_be_deleted_after_a_same_version_reset():
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_policy(PolicyName="p", PolicyDocument=POLICY_DOC)
    arn = created["Policy"]["Arn"]
    default_version = created["Policy"]["DefaultVersionId"]

    iam.set_default_policy_version(PolicyArn=arn, VersionId=default_version)

    with pytest.raises(iam.exceptions.ClientError) as err:
        iam.delete_policy_version(PolicyArn=arn, VersionId=default_version)
    assert err.value.response["Error"]["Code"] == "DeleteConflict"


@mock_aws
def test_switching_to_a_genuinely_new_version_still_moves_the_default():
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_policy(PolicyName="p", PolicyDocument=POLICY_DOC)
    arn = created["Policy"]["Arn"]
    v1 = created["Policy"]["DefaultVersionId"]

    v2 = iam.create_policy_version(
        PolicyArn=arn,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}),
        SetAsDefault=True,
    )["PolicyVersion"]["VersionId"]

    by_version = {
        v["VersionId"]: v["IsDefaultVersion"]
        for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]
    }
    assert by_version[v1] is False
    assert by_version[v2] is True
