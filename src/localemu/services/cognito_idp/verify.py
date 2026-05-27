"""Cryptographic verification of LocalEmu Cognito-issued JWTs.

Used by the API Gateway authorizers (REST ``COGNITO_USER_POOLS`` and HTTP API
``JWT`` authorizers) to actually verify token signatures, expiry, issuer/pool
membership and audience, instead of trusting tokens structurally.

The authorizers run in the same process as the Cognito provider, so
verification reads the pool's public key directly from the in-process key
store (the same key served at the ``/.well-known/jwks.json`` endpoint). This
avoids an HTTP round-trip and any host/URL mismatch between the issuer in the
token and the gateway address a client used to reach LocalEmu.
"""

from __future__ import annotations

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization

from .oidc import get_pool_keys


class TokenVerificationError(Exception):
    """Raised when a Cognito JWT fails verification."""


def pool_id_from_issuer(issuer: str | None) -> str | None:
    """Extract the user-pool id from a Cognito ``iss`` URL (``{base}/{pool_id}``)."""
    if not issuer:
        return None
    return issuer.rstrip("/").rsplit("/", 1)[-1] or None


def _public_pem_for_pool(pool_id: str) -> bytes | None:
    keys = get_pool_keys(pool_id)
    if not keys:
        return None
    private_key, _kid = keys
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def strip_bearer(raw: str | None) -> str:
    """Return the bare token, dropping an optional ``Bearer `` prefix."""
    raw = (raw or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def is_known_pool_token(token: str) -> bool:
    """True if the token's issuer resolves to a pool LocalEmu holds the key for.

    Lets callers (e.g. the HTTP API JWT authorizer) decide whether to perform
    full cryptographic verification (tokens we issued) or fall back to
    structural checks (tokens from an external IdP whose key we do not have).
    """
    try:
        unverified = pyjwt.decode(strip_bearer(token), options={"verify_signature": False})
    except Exception:
        return False
    pool_id = pool_id_from_issuer(unverified.get("iss"))
    return bool(pool_id and get_pool_keys(pool_id))


def verify_cognito_token(
    token: str,
    *,
    allowed_pool_ids: list[str] | None = None,
    allowed_audiences: list[str] | None = None,
    allowed_token_uses: tuple[str, ...] = ("id", "access"),
) -> dict:
    """Verify a LocalEmu Cognito JWT and return its claims.

    Verifies the RS256 signature against the issuing pool's key plus expiry,
    issuer/pool membership, ``token_use`` and (optionally) audience. Raises
    :class:`TokenVerificationError` on any failure.
    """
    token = strip_bearer(token)
    if not token:
        raise TokenVerificationError("missing token")

    try:
        unverified = pyjwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        raise TokenVerificationError(f"malformed token: {exc}") from exc

    pool_id = pool_id_from_issuer(unverified.get("iss"))
    if not pool_id:
        raise TokenVerificationError("token has no Cognito issuer")
    if allowed_pool_ids and pool_id not in allowed_pool_ids:
        raise TokenVerificationError(
            "token was issued by a user pool this authorizer does not trust"
        )

    pem = _public_pem_for_pool(pool_id)
    if not pem:
        raise TokenVerificationError(f"unknown user pool {pool_id}")

    try:
        claims = pyjwt.decode(
            token,
            pem,
            algorithms=["RS256"],
            options={"verify_aud": False, "require": ["exp", "iss"]},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenVerificationError("token has expired") from exc
    except Exception as exc:
        raise TokenVerificationError(f"invalid signature or claims: {exc}") from exc

    token_use = claims.get("token_use")
    if allowed_token_uses and token_use not in allowed_token_uses:
        raise TokenVerificationError(f"token_use {token_use!r} is not allowed here")

    if allowed_audiences:
        # ID tokens carry ``aud``; Cognito access tokens carry ``client_id``.
        token_aud = claims.get("aud") or claims.get("client_id")
        auds = [token_aud] if isinstance(token_aud, str) else list(token_aud or [])
        if not any(a in allowed_audiences for a in auds):
            raise TokenVerificationError("token audience is not allowed")

    return claims
