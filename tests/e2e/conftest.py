"""E2E test fixtures.

Provides boto3 clients pointing at a running LocalEmu instance.
Run with: pytest tests/e2e/ -v

Requires LocalEmu running on localhost:4566 (start with: localemu start)
"""

import json
import os
import urllib.request

import boto3
import pytest
from botocore.config import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"

_CLIENT_CONFIG = Config(retries={"max_attempts": 0})


def _make_client(service: str):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=_CLIENT_CONFIG,
    )


@pytest.fixture(scope="session", autouse=True)
def _check_localemu_running():
    """Skip all E2E tests if LocalEmu is not running."""
    try:
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/health", timeout=5)
        data = json.loads(resp.read())
        running = sum(1 for s in data.get("services", {}).values() if s == "running")
        print(f"\nLocalEmu v{data.get('version', '?')} detected ({running} services running)")
    except Exception as e:
        pytest.skip(f"LocalEmu not reachable at {ENDPOINT}: {e}")


@pytest.fixture(scope="session")
def localemu_endpoint():
    return ENDPOINT


# --- Service client fixtures ---


@pytest.fixture
def s3_client():
    return _make_client("s3")


@pytest.fixture
def sqs_client():
    return _make_client("sqs")


@pytest.fixture
def sns_client():
    return _make_client("sns")


@pytest.fixture
def lambda_client():
    return _make_client("lambda")


@pytest.fixture
def iam_client():
    return _make_client("iam")


@pytest.fixture
def dynamodb_client():
    return _make_client("dynamodb")


@pytest.fixture
def kinesis_client():
    return _make_client("kinesis")


@pytest.fixture
def secretsmanager_client():
    return _make_client("secretsmanager")


@pytest.fixture
def stepfunctions_client():
    return _make_client("stepfunctions")


@pytest.fixture
def events_client():
    return _make_client("events")


@pytest.fixture
def ecs_client():
    return _make_client("ecs")


@pytest.fixture
def eks_client():
    return _make_client("eks")


@pytest.fixture
def rds_client():
    return _make_client("rds")


@pytest.fixture
def logs_client():
    return _make_client("logs")


@pytest.fixture
def cloudwatch_client():
    return _make_client("cloudwatch")


@pytest.fixture
def cloudtrail_client():
    return _make_client("cloudtrail")


@pytest.fixture
def sts_client():
    return _make_client("sts")


@pytest.fixture
def apigateway_client():
    return _make_client("apigateway")


@pytest.fixture
def apigatewayv2_client():
    return _make_client("apigatewayv2")


@pytest.fixture
def cognito_client():
    return _make_client("cognito-idp")


# --- Helper fixtures ---


@pytest.fixture
def lambda_role(iam_client):
    """Create or get a Lambda execution role."""
    role_name = "e2e-pytest-lambda-role"
    try:
        resp = iam_client.get_role(RoleName=role_name)
        return resp["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        resp = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust,
            Path="/",
        )
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        return resp["Role"]["Arn"]


def poll_until(condition, timeout=30, interval=1):
    """Poll a condition until it returns truthy or timeout is reached."""
    import time
    deadline = time.time() + timeout
    last_result = None
    while time.time() < deadline:
        last_result = condition()
        if last_result:
            return last_result
        time.sleep(interval)
    return last_result
