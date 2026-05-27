"""JWT token generation for Cognito.

Generates real, verifiable ID tokens, access tokens, and opaque refresh tokens.
Tokens are signed with the user pool's RSA private key and can be verified
using the JWKS endpoint.
"""

import time
import uuid

import jwt as pyjwt

from localemu import config as _lemu_config

from .keys import private_key_to_pem


def _pool_issuer(pool_id: str) -> str:
    """Build the JWT ``iss`` claim for a Cognito user pool.

    Must match the OIDC issuer advertised by ``oidc._handle_openid_configuration``
    and resolve to a URL the verifier can fetch the JWKS from. Threading
    :func:`config.external_service_url` honours ``LOCALEMU_HOST`` /
    ``USE_SSL`` so JWTs issued by LocalEmu validate from clients that aren't
    on the same loopback interface (e.g. a containerized API that reaches
    LocalEmu through a published port or compose network name).
    """
    return f"{_lemu_config.external_service_url()}/{pool_id}"


def generate_id_token(
    pool_id: str,
    region: str,
    client_id: str,
    username: str,
    sub: str,
    private_key,
    kid: str,
    email: str | None = None,
    email_verified: bool = False,
    phone_number: str | None = None,
    phone_number_verified: bool = False,
    groups: list[str] | None = None,
    custom_attributes: dict | None = None,
    extra_claims: dict | None = None,
    suppress_claims: list[str] | None = None,
    token_validity: int = 3600,
) -> str:
    """Generate a Cognito ID token (JWT).

    The ID token contains user identity claims. Applications use it to
    identify the authenticated user.
    """
    now = int(time.time())

    payload = {
        "sub": sub,
        "aud": client_id,
        "email_verified": email_verified,
        "event_id": str(uuid.uuid4()),
        "token_use": "id",
        "auth_time": now,
        "iss": _pool_issuer(pool_id),
        "cognito:username": username,
        "exp": now + token_validity,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }

    if email:
        payload["email"] = email
    if phone_number:
        payload["phone_number"] = phone_number
        payload["phone_number_verified"] = phone_number_verified
    if groups:
        payload["cognito:groups"] = groups
    if custom_attributes:
        for key, value in custom_attributes.items():
            if key.startswith("custom:"):
                payload[key] = value

    if extra_claims:
        payload.update(extra_claims)
    for claim in suppress_claims or []:
        payload.pop(claim, None)

    return pyjwt.encode(
        payload,
        private_key_to_pem(private_key),
        algorithm="RS256",
        headers={"kid": kid},
    )


def generate_access_token(
    pool_id: str,
    region: str,
    client_id: str,
    username: str,
    sub: str,
    private_key,
    kid: str,
    groups: list[str] | None = None,
    scopes: list[str] | None = None,
    extra_claims: dict | None = None,
    suppress_claims: list[str] | None = None,
    token_validity: int = 3600,
) -> str:
    """Generate a Cognito access token (JWT).

    The access token authorizes API calls. It contains scopes and groups.
    """
    now = int(time.time())

    payload = {
        "sub": sub,
        "event_id": str(uuid.uuid4()),
        "token_use": "access",
        "scope": " ".join(scopes) if scopes else "aws.cognito.signin.user.admin",
        "auth_time": now,
        "iss": _pool_issuer(pool_id),
        "exp": now + token_validity,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
        "username": username,
    }

    if groups:
        payload["cognito:groups"] = groups

    if extra_claims:
        payload.update(extra_claims)
    for claim in suppress_claims or []:
        payload.pop(claim, None)

    return pyjwt.encode(
        payload,
        private_key_to_pem(private_key),
        algorithm="RS256",
        headers={"kid": kid},
    )


def generate_refresh_token() -> str:
    """Generate an opaque refresh token."""
    return f"{uuid.uuid4()}-{uuid.uuid4()}"
