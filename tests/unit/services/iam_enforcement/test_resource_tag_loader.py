"""``aws:ResourceTag/*`` tag loading for the services the ABAC labs use."""
import boto3
from moto import mock_aws

from localemu.services.iam_enforcement.resource_tag_loader import load_resource_tags

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@mock_aws
def test_secretsmanager_secret_tags_resolve():
    sm = boto3.client("secretsmanager", region_name=REGION)
    created = sm.create_secret(
        Name="goat-secret",
        SecretString="shh",
        Tags=[{"Key": "Department", "Value": "ZeroTrustVault"}],
    )
    assert load_resource_tags(created["ARN"], ACCOUNT_ID, REGION) == {
        "Department": "ZeroTrustVault"
    }

    sm.tag_resource(SecretId=created["ARN"], Tags=[{"Key": "Department", "Value": "Other"}])
    assert load_resource_tags(created["ARN"], ACCOUNT_ID, REGION) == {"Department": "Other"}


@mock_aws
def test_ssm_parameter_tags_resolve_including_leading_slash_in_the_name():
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.put_parameter(
        Name="/goat/s17/param",
        Value="v",
        Type="String",
        Tags=[{"Key": "Department", "Value": "ZeroTrustVault"}],
    )
    arn = f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter/goat/s17/param"
    assert load_resource_tags(arn, ACCOUNT_ID, REGION) == {"Department": "ZeroTrustVault"}


@mock_aws
def test_unknown_service_and_unknown_resource_return_empty_not_raise():
    assert load_resource_tags("arn:aws:secretsmanager:us-east-1:123456789012:secret:nope", ACCOUNT_ID, REGION) == {}
    assert load_resource_tags("arn:aws:ssm:us-east-1:123456789012:parameter/nope", ACCOUNT_ID, REGION) == {}
    assert load_resource_tags("arn:aws:ecr:us-east-1:123456789012:repository/nope", ACCOUNT_ID, REGION) == {}
    assert load_resource_tags("not-an-arn", ACCOUNT_ID, REGION) == {}
