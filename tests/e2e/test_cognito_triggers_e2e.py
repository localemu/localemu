"""E2E: Cognito Lambda triggers (#2b).

Requires LocalEmu running on localhost:4566 with Docker available (Lambda runs
in containers). Run with: pytest tests/e2e/test_cognito_triggers_e2e.py -v

Proves:
  * PreSignUp trigger auto-confirms + auto-verifies a user at SignUp.
  * PreTokenGeneration trigger injects a custom claim into the minted tokens.
"""

import io
import uuid
import zipfile

import jwt as pyjwt

PRE_SIGN_UP = (
    "def handler(event, context):\n"
    "    event['response']['autoConfirmUser'] = True\n"
    "    event['response']['autoVerifyEmail'] = True\n"
    "    return event\n"
)
PRE_TOKEN_GEN = (
    "def handler(event, context):\n"
    "    event.setdefault('response', {})['claimsOverrideDetails'] = "
    "{'claimsToAddOrOverride': {'custom:tenant': 'acme'}}\n"
    "    return event\n"
)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _deploy_trigger(lambda_client, role_arn, name, code) -> str:
    lambda_client.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip(code)},
    )
    lambda_client.get_waiter("function_active_v2").wait(FunctionName=name)
    return lambda_client.get_function(FunctionName=name)["Configuration"]["FunctionArn"]


class TestCognitoLambdaTriggers:
    def test_pre_sign_up_auto_confirms(self, cognito_client, lambda_client, lambda_role):
        arn = _deploy_trigger(
            lambda_client, lambda_role, f"presignup-{uuid.uuid4().hex[:8]}", PRE_SIGN_UP
        )
        pool_id = cognito_client.create_user_pool(
            PoolName=f"trig-{uuid.uuid4().hex[:8]}", LambdaConfig={"PreSignUp": arn}
        )["UserPool"]["Id"]
        client_id = cognito_client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName="app",
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )["UserPoolClient"]["ClientId"]

        resp = cognito_client.sign_up(
            ClientId=client_id,
            Username="bob",
            Password="Sign-Up-1!",
            UserAttributes=[{"Name": "email", "Value": "bob@example.com"}],
        )
        assert resp["UserConfirmed"] is True, resp
        user = cognito_client.admin_get_user(UserPoolId=pool_id, Username="bob")
        assert user["UserStatus"] == "CONFIRMED", user["UserStatus"]
        cognito_client.delete_user_pool(UserPoolId=pool_id)

    def test_pre_token_generation_adds_claim(
        self, cognito_client, lambda_client, lambda_role
    ):
        arn = _deploy_trigger(
            lambda_client, lambda_role, f"pretoken-{uuid.uuid4().hex[:8]}", PRE_TOKEN_GEN
        )
        pool_id = cognito_client.create_user_pool(
            PoolName=f"trig-{uuid.uuid4().hex[:8]}",
            LambdaConfig={"PreTokenGeneration": arn},
        )["UserPool"]["Id"]
        client_id = cognito_client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName="app",
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )["UserPoolClient"]["ClientId"]
        cognito_client.admin_create_user(
            UserPoolId=pool_id,
            Username="carol",
            TemporaryPassword="Temp-Pass-1!",
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": "carol@example.com"}],
        )
        cognito_client.admin_set_user_password(
            UserPoolId=pool_id, Username="carol", Password="New-Pass-1!", Permanent=True
        )
        auth = cognito_client.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": "carol", "PASSWORD": "New-Pass-1!"},
        )
        claims = pyjwt.decode(
            auth["AuthenticationResult"]["IdToken"], options={"verify_signature": False}
        )
        assert claims.get("custom:tenant") == "acme", claims
        cognito_client.delete_user_pool(UserPoolId=pool_id)
