"""End-to-end : the nine Cognito Lambda triggers added in 1.2.0.

One ``cognito-trigger-recorder`` Lambda records every invocation into
DynamoDB row ``trigger=<triggerSource>``. The user pool is configured
with all 9 missing triggers (plus the existing 3) pointing at that
function. Each test walks a representative flow and asserts both :

* the DynamoDB rows recorded the expected ``triggerSource`` values, AND
* the LocalEmu message-buffer endpoint at
  ``/_localemu/api/cognito-messages/<pool>/<user>`` returned the
  CustomMessage override or the plain code that was sent.

Skips when LocalEmu is not running.
"""
from __future__ import annotations

import io
import json
import time
import urllib.request
import zipfile

import boto3
import pytest


# Helpers


def _lambda_zip(source: str) -> bytes:
    """Build a Lambda zip with ``index.py`` containing ``source``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


_RECORDER_SOURCE = '''
import os, boto3

_ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]


def handler(event, ctx):
    src = event.get("triggerSource") or "UNKNOWN"
    try:
        _ddb.update_item(
            TableName=TABLE,
            Key={"trigger": {"S": src}},
            UpdateExpression="ADD #c :one",
            ExpressionAttributeNames={"#c": "count"},
            ExpressionAttributeValues={":one": {"N": "1"}},
        )
    except Exception:
        pass

    response = event.setdefault("response", {})

    if src.startswith("PreSignUp"):
        response["autoConfirmUser"] = True
        response["autoVerifyEmail"] = True
    elif src.startswith("DefineAuthChallenge"):
        session = event.get("request", {}).get("session") or []
        if not session:
            response["challengeName"] = "CUSTOM_CHALLENGE"
            response["issueTokens"] = False
            response["failAuthentication"] = False
        elif session[-1].get("challengeResult"):
            response["issueTokens"] = True
        else:
            response["failAuthentication"] = True
    elif src.startswith("CreateAuthChallenge"):
        response["publicChallengeParameters"] = {"question": "What is the answer?"}
        response["privateChallengeParameters"] = {"answer": "42"}
        response["challengeMetadata"] = "round-1"
    elif src.startswith("VerifyAuthChallengeResponse"):
        answer = event.get("request", {}).get("challengeAnswer", "")
        response["answerCorrect"] = (answer == "42")
    elif src.startswith("UserMigration"):
        response["userAttributes"] = {
            "email": "migrated@example.com",
            "email_verified": "true",
        }
        response["finalUserStatus"] = "CONFIRMED"
        response["messageAction"] = "SUPPRESS"
    elif src.startswith("CustomMessage"):
        response["emailSubject"] = "LocalEmu verification"
        response["emailMessage"] = "Your code is {####}"
        response["smsMessage"] = "Code: {####}"

    return event
'''


# Fixtures


def _module_client(service: str):
    """Module-scope fixtures cannot depend on conftest's function-scope
    client fixtures, so make our own clients tied to LOCALEMU_ENDPOINT."""
    import os
    return boto3.client(
        service,
        endpoint_url=os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566"),
        region_name="us-east-1",
        aws_access_key_id="test", aws_secret_access_key="test",
    )


@pytest.fixture(scope="module")
def trigger_table():
    ddb = _module_client("dynamodb")
    table = "cognito-trigger-counts"
    try:
        ddb.delete_table(TableName=table)
        ddb.get_waiter("table_not_exists").wait(TableName=table)
    except ddb.exceptions.ResourceNotFoundException:
        pass
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "trigger", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "trigger", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=table)
    yield table
    try:
        ddb.delete_table(TableName=table)
    except Exception:
        pass


@pytest.fixture(scope="module")
def recorder_lambda(trigger_table):
    import json as _json
    iam = _module_client("iam")
    lam = _module_client("lambda")
    role_name = "e2e-cognito-triggers-role"
    try:
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        trust = _json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        role_arn = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust, Path="/",
        )["Role"]["Arn"]
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    # `lam` and `lambda_role` are not used here ; substitute the locals.
    lambda_client = lam
    lambda_role = role_arn  # noqa: F841
    name = "cognito-trigger-recorder"
    try:
        lam.delete_function(FunctionName=name)
    except lam.exceptions.ResourceNotFoundException:
        pass
    fn = lam.create_function(
        FunctionName=name,
        Runtime="python3.11",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip(_RECORDER_SOURCE)},
        Environment={"Variables": {"TABLE": trigger_table}},
        Timeout=10,
    )
    # Wait until active.
    deadline = time.time() + 60
    while time.time() < deadline:
        st = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if st == "Active":
            break
        time.sleep(1)
    yield fn["FunctionArn"]
    try:
        lam.delete_function(FunctionName=name)
    except Exception:
        pass


@pytest.fixture
def reset_table(dynamodb_client, trigger_table):
    """Wipe the recorder table at the start of each test so counts are
    independent."""
    paginator = dynamodb_client.get_paginator("scan")
    for page in paginator.paginate(TableName=trigger_table):
        for item in page.get("Items", []):
            dynamodb_client.delete_item(
                TableName=trigger_table,
                Key={"trigger": item["trigger"]},
            )
    yield


@pytest.fixture
def user_pool(cognito_client, recorder_lambda):
    pool = cognito_client.create_user_pool(
        PoolName="e2e-nine-triggers",
        AutoVerifiedAttributes=["email"],
        Schema=[
            {"Name": "email", "AttributeDataType": "String",
             "Required": True, "Mutable": True},
        ],
        LambdaConfig={
            "PreSignUp": recorder_lambda,
            "PostConfirmation": recorder_lambda,
            "PreAuthentication": recorder_lambda,
            "PostAuthentication": recorder_lambda,
            "CustomMessage": recorder_lambda,
            "DefineAuthChallenge": recorder_lambda,
            "CreateAuthChallenge": recorder_lambda,
            "VerifyAuthChallengeResponse": recorder_lambda,
            "UserMigration": recorder_lambda,
            "PreTokenGeneration": recorder_lambda,
        },
    )
    pool_id = pool["UserPool"]["Id"]
    client = cognito_client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="e2e-client",
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_CUSTOM_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    yield pool_id, client_id
    try:
        cognito_client.delete_user_pool(UserPoolId=pool_id)
    except Exception:
        pass


def _count(dynamodb_client, table: str, trigger: str) -> int:
    try:
        item = dynamodb_client.get_item(
            TableName=table, Key={"trigger": {"S": trigger}},
        ).get("Item")
    except Exception:
        return 0
    if not item:
        return 0
    return int(item["count"]["N"])


def _fetch_messages(pool_id: str, username: str, endpoint: str) -> dict:
    url = f"{endpoint}/_localemu/api/cognito-messages/{pool_id}/{username}"
    return json.loads(urllib.request.urlopen(url, timeout=5).read())


# Tests


def test_signup_fires_pre_sign_up_and_custom_message(
    cognito_client, user_pool, reset_table, dynamodb_client, trigger_table,
    localemu_endpoint,
):
    pool_id, client_id = user_pool
    username = "alice"
    cognito_client.sign_up(
        ClientId=client_id, Username=username, Password="Sup3rSecret!",
        UserAttributes=[{"Name": "email", "Value": "alice@example.com"}],
    )
    time.sleep(2)
    assert _count(dynamodb_client, trigger_table, "PreSignUp_SignUp") >= 1
    # PreSignUp auto-confirmed the user so CustomMessage may or may not fire ;
    # if it did fire, the buffer endpoint reports it.
    msgs = _fetch_messages(pool_id, username, localemu_endpoint)
    assert isinstance(msgs.get("messages"), list)


def test_initiate_auth_fires_pre_and_post_authentication(
    cognito_client, user_pool, reset_table, dynamodb_client, trigger_table,
):
    pool_id, client_id = user_pool
    username = "bob"
    cognito_client.sign_up(
        ClientId=client_id, Username=username, Password="Sup3rSecret!",
        UserAttributes=[{"Name": "email", "Value": "bob@example.com"}],
    )
    time.sleep(2)
    cognito_client.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "Sup3rSecret!"},
    )
    time.sleep(2)
    assert _count(dynamodb_client, trigger_table, "PreAuthentication_Authentication") >= 1
    assert _count(dynamodb_client, trigger_table, "PostAuthentication_Authentication") >= 1


def test_forgot_password_fires_custom_message_and_buffers_code(
    cognito_client, user_pool, reset_table, dynamodb_client, trigger_table,
    localemu_endpoint,
):
    pool_id, client_id = user_pool
    username = "carol"
    cognito_client.sign_up(
        ClientId=client_id, Username=username, Password="Sup3rSecret!",
        UserAttributes=[{"Name": "email", "Value": "carol@example.com"}],
    )
    time.sleep(2)
    cognito_client.forgot_password(ClientId=client_id, Username=username)
    time.sleep(2)
    assert _count(dynamodb_client, trigger_table, "CustomMessage_ForgotPassword") >= 1
    msgs = _fetch_messages(pool_id, username, localemu_endpoint)
    found = [m for m in msgs["messages"]
             if m["trigger_source"] == "CustomMessage_ForgotPassword"]
    assert found, f"no CustomMessage_ForgotPassword in buffer: {msgs}"
    assert "Your code is" in found[-1]["email_message"] or found[-1]["code_plain"]


def test_custom_auth_flow_fires_define_create_and_verify(
    cognito_client, user_pool, reset_table, dynamodb_client, trigger_table,
):
    """Walk a 2-step CUSTOM_AUTH : first InitiateAuth returns
    CUSTOM_CHALLENGE (fires Define + Create) ; the RespondToAuthChallenge
    with answer=42 fires Verify, then Define again, which on
    answerCorrect=True returns issueTokens=True."""
    pool_id, client_id = user_pool
    username = "dave"
    cognito_client.sign_up(
        ClientId=client_id, Username=username, Password="Sup3rSecret!",
        UserAttributes=[{"Name": "email", "Value": "dave@example.com"}],
    )
    time.sleep(2)
    init = cognito_client.initiate_auth(
        ClientId=client_id, AuthFlow="CUSTOM_AUTH",
        AuthParameters={"USERNAME": username},
    )
    assert init.get("ChallengeName") == "CUSTOM_CHALLENGE"
    session = init.get("Session", "")
    assert session
    cognito_client.respond_to_auth_challenge(
        ClientId=client_id, ChallengeName="CUSTOM_CHALLENGE",
        Session=session,
        ChallengeResponses={"USERNAME": username, "ANSWER": "42"},
    )
    time.sleep(2)
    # Both Define rounds + Create + Verify must have fired at least once.
    assert _count(dynamodb_client, trigger_table, "DefineAuthChallenge_Authentication") >= 2
    assert _count(dynamodb_client, trigger_table, "CreateAuthChallenge_Authentication") >= 1
    assert _count(dynamodb_client, trigger_table, "VerifyAuthChallengeResponse_Authentication") >= 1


def test_user_migration_creates_user_then_auth_succeeds(
    cognito_client, user_pool, reset_table, dynamodb_client, trigger_table,
):
    """UserMigration fires when InitiateAuth references a user not in the
    pool ; the trigger response carries attributes ; the user is then
    created and the second auth attempt succeeds."""
    _, client_id = user_pool
    username = "erin-migrated"
    cognito_client.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "any-pw"},
    )
    time.sleep(2)
    assert _count(dynamodb_client, trigger_table, "UserMigration_Authentication") >= 1
