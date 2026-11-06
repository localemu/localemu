"""``_get_resource_policy`` must actually find the stored policy for every
service it claims to support. ECR and Secrets Manager resource policies
were stored (via moto's native backends) but the dispatcher either had no
case for the service at all (ECR) or looked the policy up fine once the
ARN was correct (Secrets Manager was already right; ECR's ARN builder was
the missing piece - see test_arn_builder.py)."""
import json

import boto3
from moto import mock_aws

from localemu.services.iam_enforcement.enforcer import _get_resource_policy

REGION = "us-east-1"
ACCOUNT = "123456789012"


@mock_aws
def test_ecr_repository_policy_is_found():
    ecr = boto3.client("ecr", region_name=REGION)
    repo = ecr.create_repository(repositoryName="my-repo")["repository"]
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "ecr:GetDownloadUrlForLayer", "Resource": "*"}]}
    ecr.set_repository_policy(repositoryName="my-repo", policyText=json.dumps(policy_doc))

    found = _get_resource_policy("ecr", repo["repositoryArn"], ACCOUNT, REGION)
    assert found == policy_doc


def test_ecr_repository_without_a_policy_returns_none():
    assert _get_resource_policy("ecr", "arn:aws:ecr:us-east-1:123456789012:repository/nope", ACCOUNT, REGION) is None


@mock_aws
def test_secretsmanager_resource_policy_is_found():
    sm = boto3.client("secretsmanager", region_name=REGION)
    secret = sm.create_secret(Name="my-secret", SecretString="x")
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
    sm.put_resource_policy(SecretId=secret["ARN"], ResourcePolicy=json.dumps(policy_doc))

    found = _get_resource_policy("secretsmanager", secret["ARN"], ACCOUNT, REGION)
    assert found == policy_doc


def test_secretsmanager_secret_without_a_policy_returns_none():
    assert _get_resource_policy(
        "secretsmanager", "arn:aws:secretsmanager:us-east-1:123456789012:secret:nope", ACCOUNT, REGION
    ) is None
