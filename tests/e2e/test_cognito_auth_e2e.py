"""E2E auth tests: real JWT verification through Cognito + API Gateway authorizers.

Requires LocalEmu running on localhost:4566 (start with: localemu start).
Run with: pytest tests/e2e/test_cognito_auth_e2e.py -v

Proves end to end:
  * RespondToAuthChallenge (NEW_PASSWORD_REQUIRED) mints a real RS256 token that
    verifies against the pool's JWKS endpoint (a moto kid:"dummy" token would not).
  * The REST COGNITO_USER_POOLS authorizer accepts a valid token and rejects a
    forged or absent one.
  * The HTTP API JWT authorizer rejects a forged token whose issuer points at a
    real pool, and rejects an absent token.
"""

import uuid

import jwt as pyjwt
import pytest
import requests
from jwt import PyJWKClient


@pytest.fixture
def user_pool(cognito_client):
    """Create a user pool + app client; clean up afterwards."""
    created = cognito_client.create_user_pool(PoolName=f"e2e-auth-{uuid.uuid4().hex[:8]}")
    pool_id = created["UserPool"]["Id"]
    pool_arn = created["UserPool"]["Arn"]
    client = cognito_client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="app",
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    yield {"pool_id": pool_id, "client_id": client_id, "pool_arn": pool_arn}
    try:
        cognito_client.delete_user_pool(UserPoolId=pool_id)
    except Exception:
        pass


def _login_via_new_password_challenge(cognito, pool_id, client_id):
    """AdminCreateUser -> NEW_PASSWORD_REQUIRED -> AdminRespondToAuthChallenge.

    Returns (AuthenticationResult, username). The token comes out of the
    challenge-completion path, which is what task 2a makes mint real JWTs.
    """
    username = f"user-{uuid.uuid4().hex[:8]}"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp-Pass-1!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    init = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "Temp-Pass-1!"},
    )
    assert init.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", init
    resp = cognito.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=init["Session"],
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": "New-Pass-1!"},
    )
    return resp["AuthenticationResult"], username


class TestCognitoRealJwt:
    def test_challenge_flow_mints_verifiable_jwt(
        self, cognito_client, user_pool, localemu_endpoint
    ):
        auth, username = _login_via_new_password_challenge(
            cognito_client, user_pool["pool_id"], user_pool["client_id"]
        )
        jwks_url = f"{localemu_endpoint}/{user_pool['pool_id']}/.well-known/jwks.json"
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(auth["IdToken"])

        id_claims = pyjwt.decode(
            auth["IdToken"],
            signing_key.key,
            algorithms=["RS256"],
            audience=user_pool["client_id"],
        )
        assert id_claims["token_use"] == "id"
        assert id_claims["cognito:username"] == username

        access_claims = pyjwt.decode(
            auth["AccessToken"],
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        assert access_claims["token_use"] == "access"

    def test_tampered_token_fails_verification(
        self, cognito_client, user_pool, localemu_endpoint
    ):
        auth, _ = _login_via_new_password_challenge(
            cognito_client, user_pool["pool_id"], user_pool["client_id"]
        )
        head, payload, sig = auth["IdToken"].split(".")
        tampered = f"{head}.{payload}.{sig[:-4]}AAAA"
        jwks_url = f"{localemu_endpoint}/{user_pool['pool_id']}/.well-known/jwks.json"
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(auth["IdToken"])
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(
                tampered,
                signing_key.key,
                algorithms=["RS256"],
                audience=user_pool["client_id"],
            )


def _build_rest_api_with_cognito_authorizer(apigw, pool_arn):
    """GET /secure guarded by a COGNITO_USER_POOLS authorizer, MOCK 200 backend."""
    api = apigw.create_rest_api(name=f"e2e-auth-{uuid.uuid4().hex[:8]}")
    api_id = api["id"]
    root = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    res_id = apigw.create_resource(restApiId=api_id, parentId=root, pathPart="secure")["id"]
    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name="cognito-auth",
        type="COGNITO_USER_POOLS",
        providerARNs=[pool_arn],
        identitySource="method.request.header.Authorization",
    )
    apigw.put_method(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        authorizationType="COGNITO_USER_POOLS",
        authorizerId=authorizer["id"],
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=res_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=res_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"ok": true}'},
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")
    return api_id


class TestRestCognitoAuthorizer:
    def _invoke(self, endpoint, api_id, token=None):
        url = f"{endpoint}/restapis/{api_id}/test/_user_request_/secure"
        headers = {"Authorization": token} if token else {}
        return requests.get(url, headers=headers, timeout=10)

    def test_accepts_valid_token(
        self, cognito_client, apigateway_client, user_pool, localemu_endpoint
    ):
        auth, _ = _login_via_new_password_challenge(
            cognito_client, user_pool["pool_id"], user_pool["client_id"]
        )
        api_id = _build_rest_api_with_cognito_authorizer(
            apigateway_client, user_pool["pool_arn"]
        )
        r = self._invoke(localemu_endpoint, api_id, token=auth["IdToken"])
        assert r.status_code == 200, (r.status_code, r.text)

    def test_rejects_forged_and_missing(
        self, apigateway_client, user_pool, localemu_endpoint
    ):
        api_id = _build_rest_api_with_cognito_authorizer(
            apigateway_client, user_pool["pool_arn"]
        )
        r_forged = self._invoke(localemu_endpoint, api_id, token="not-a-real-jwt")
        assert r_forged.status_code in (401, 403), (r_forged.status_code, r_forged.text)
        r_missing = self._invoke(localemu_endpoint, api_id, token=None)
        assert r_missing.status_code in (401, 403), (r_missing.status_code, r_missing.text)


def _build_v2_http_api_with_jwt_authorizer(apigw2, endpoint, issuer, audience):
    """HTTP API with a JWT authorizer on $default, proxying to the health endpoint.
    Returns (api_id, invoke_url)."""
    api = apigw2.create_api(
        Name=f"e2e-auth-{uuid.uuid4().hex[:8]}",
        ProtocolType="HTTP",
        Target=f"{endpoint}/_localemu/health",
    )
    api_id = api["ApiId"]
    authorizer = apigw2.create_authorizer(
        ApiId=api_id,
        Name="jwt-auth",
        AuthorizerType="JWT",
        IdentitySource=["$request.header.Authorization"],
        JwtConfiguration={"Issuer": issuer, "Audience": [audience]},
    )
    for route in apigw2.get_routes(ApiId=api_id)["Items"]:
        apigw2.update_route(
            ApiId=api_id,
            RouteId=route["RouteId"],
            AuthorizationType="JWT",
            AuthorizerId=authorizer["AuthorizerId"],
        )
    return api_id, f"{endpoint}/_aws/execute-api-v2/{api_id}/"


class TestV2JwtAuthorizer:
    def test_accepts_valid_token(
        self, cognito_client, apigatewayv2_client, user_pool, localemu_endpoint
    ):
        auth, _ = _login_via_new_password_challenge(
            cognito_client, user_pool["pool_id"], user_pool["client_id"]
        )
        issuer = f"{localemu_endpoint}/{user_pool['pool_id']}"
        _, url = _build_v2_http_api_with_jwt_authorizer(
            apigatewayv2_client, localemu_endpoint, issuer, user_pool["client_id"]
        )
        r = requests.get(url, headers={"Authorization": auth["IdToken"]}, timeout=10)
        # The authorizer must ACCEPT a valid token: the request gets past auth
        # (no 401/403) and reaches the integration. The exact downstream status
        # depends on the proxy backend and is out of scope for the authorizer.
        assert r.status_code not in (401, 403), (r.status_code, r.text)

    def test_rejects_forged_and_missing(
        self, apigatewayv2_client, user_pool, localemu_endpoint
    ):
        issuer = f"{localemu_endpoint}/{user_pool['pool_id']}"
        _, url = _build_v2_http_api_with_jwt_authorizer(
            apigatewayv2_client, localemu_endpoint, issuer, user_pool["client_id"]
        )
        # Real issuer (a pool we hold the key for) but signed with a junk key:
        # is_known_pool_token() is True, so signature verification must reject it.
        forged = pyjwt.encode(
            {
                "iss": issuer,
                "aud": user_pool["client_id"],
                "token_use": "id",
                "exp": 9999999999,
            },
            "junk-secret-not-the-pool-key",
            algorithm="HS256",
        )
        r_forged = requests.get(url, headers={"Authorization": forged}, timeout=10)
        assert r_forged.status_code == 401, (r_forged.status_code, r_forged.text)
        r_missing = requests.get(url, timeout=10)
        assert r_missing.status_code == 401, (r_missing.status_code, r_missing.text)
