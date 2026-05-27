"""E2E: Cognito hosted-UI / OAuth2 authorization-code flow (#2c).

Requires LocalEmu running on localhost:4566. Run with:
    pytest tests/e2e/test_cognito_oauth2_e2e.py -v

Proves the full hosted-UI flow over HTTP:
  GET  /oauth2/authorize   -> login page
  POST /oauth2/authorize   -> 302 redirect to the client callback with ?code=
  POST /oauth2/token       -> real id/access/refresh tokens for the code
  GET  /oauth2/userInfo    -> the user's claims for the access token
plus the issued id_token verifying against the pool JWKS.
"""

import uuid
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest
import requests
from jwt import PyJWKClient

REDIRECT = "https://example.com/cb"


@pytest.fixture
def hosted_ui_pool(cognito_client):
    pool_id = cognito_client.create_user_pool(
        PoolName=f"oauth2-{uuid.uuid4().hex[:8]}"
    )["UserPool"]["Id"]
    client_id = cognito_client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="hosted",
        CallbackURLs=[REDIRECT],
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["openid", "email"],
        AllowedOAuthFlowsUserPoolClient=True,
        SupportedIdentityProviders=["COGNITO"],
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    cognito_client.admin_create_user(
        UserPoolId=pool_id,
        Username="alice",
        TemporaryPassword="Temp-Pass-1!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": "alice@example.com"}],
    )
    cognito_client.admin_set_user_password(
        UserPoolId=pool_id, Username="alice", Password="New-Pass-1!", Permanent=True
    )
    yield {"pool_id": pool_id, "client_id": client_id}
    try:
        cognito_client.delete_user_pool(UserPoolId=pool_id)
    except Exception:
        pass


class TestCognitoOAuth2HostedUI:
    def test_authorization_code_flow(self, hosted_ui_pool, localemu_endpoint):
        client_id = hosted_ui_pool["client_id"]
        pool_id = hosted_ui_pool["pool_id"]
        authorize = f"{localemu_endpoint}/oauth2/authorize"
        common = {
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "scope": "openid email",
            "state": "st-123",
        }

        # 1. GET authorize -> hosted login page
        r = requests.get(authorize, params=common, timeout=10)
        assert r.status_code == 200 and "<form" in r.text, r.status_code

        # 2. POST credentials -> 302 redirect to callback with ?code= & state
        r = requests.post(
            authorize, data={**common, "username": "alice", "password": "New-Pass-1!"},
            allow_redirects=False, timeout=10,
        )
        assert r.status_code == 302, (r.status_code, r.text)
        location = r.headers["Location"]
        assert location.startswith(REDIRECT), location
        qs = parse_qs(urlparse(location).query)
        assert qs["state"][0] == "st-123"
        code = qs["code"][0]

        # 3. Exchange the code for tokens
        r = requests.post(
            f"{localemu_endpoint}/oauth2/token",
            data={"grant_type": "authorization_code", "code": code,
                  "client_id": client_id, "redirect_uri": REDIRECT},
            timeout=10,
        )
        assert r.status_code == 200, (r.status_code, r.text)
        tokens = r.json()
        assert tokens["token_type"] == "Bearer"
        assert "id_token" in tokens and "access_token" in tokens

        # 4. The id_token verifies against the pool JWKS (real RS256)
        jwks = f"{localemu_endpoint}/{pool_id}/.well-known/jwks.json"
        signing_key = PyJWKClient(jwks).get_signing_key_from_jwt(tokens["id_token"])
        claims = pyjwt.decode(
            tokens["id_token"], signing_key.key, algorithms=["RS256"], audience=client_id
        )
        assert claims["cognito:username"] == "alice"

        # 5. userInfo returns the user's claims for the access token
        r = requests.get(
            f"{localemu_endpoint}/oauth2/userInfo",
            headers={"Authorization": "Bearer " + tokens["access_token"]}, timeout=10,
        )
        assert r.status_code == 200, (r.status_code, r.text)
        info = r.json()
        assert info["username"] == "alice"
        assert info.get("email") == "alice@example.com"

        # 6. The code is single-use
        r = requests.post(
            f"{localemu_endpoint}/oauth2/token",
            data={"grant_type": "authorization_code", "code": code,
                  "client_id": client_id, "redirect_uri": REDIRECT},
            timeout=10,
        )
        assert r.status_code == 400, (r.status_code, r.text)

    def test_authorize_rejects_bad_password(self, hosted_ui_pool, localemu_endpoint):
        r = requests.post(
            f"{localemu_endpoint}/oauth2/authorize",
            data={
                "client_id": hosted_ui_pool["client_id"], "redirect_uri": REDIRECT,
                "response_type": "code", "scope": "openid", "state": "s",
                "username": "alice", "password": "WRONG",
            },
            allow_redirects=False, timeout=10,
        )
        # Bad credentials re-render the login page (no redirect, no code).
        assert r.status_code == 200
        assert "Incorrect" in r.text

    def test_userinfo_rejects_invalid_token(self, localemu_endpoint):
        r = requests.get(
            f"{localemu_endpoint}/oauth2/userInfo",
            headers={"Authorization": "Bearer not-a-real-token"}, timeout=10,
        )
        assert r.status_code == 401, (r.status_code, r.text)
