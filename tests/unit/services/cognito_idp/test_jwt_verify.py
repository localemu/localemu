"""Unit tests for Cognito JWT verification used by the API Gateway authorizers.

These are fast, isolated tests: they register pool keys in-process and exercise
``verify.verify_cognito_token`` / ``is_known_pool_token`` directly, with no
running server. They pin the failure modes the authorizers rely on: tampered
signature, expiry, wrong/unknown pool, audience, and token_use.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

import localemu.config as cfg
from localemu.services.cognito_idp import oidc, tokens
from localemu.services.cognito_idp.keys import generate_key_pair
from localemu.services.cognito_idp.verify import (
    TokenVerificationError,
    is_known_pool_token,
    pool_id_from_issuer,
    verify_cognito_token,
)

POOL_A = "us-east-1_poolAAAA"
POOL_B = "us-east-1_poolBBBB"
POOL_UNKNOWN = "us-east-1_unknownXX"
CLIENT_ID = "client-1234567890"


@pytest.fixture
def pools(monkeypatch):
    """Register two pools with their own keys; stable issuer base."""
    monkeypatch.setattr(cfg, "external_service_url", lambda *a, **k: "http://localhost:4566")
    pk_a, kid_a = generate_key_pair()
    pk_b, kid_b = generate_key_pair()
    oidc.register_pool_keys(POOL_A, pk_a, kid_a)
    oidc.register_pool_keys(POOL_B, pk_b, kid_b)
    try:
        yield {"A": (pk_a, kid_a), "B": (pk_b, kid_b)}
    finally:
        oidc._pool_keys.pop(POOL_A, None)
        oidc._pool_keys.pop(POOL_B, None)


def _id_token(pool_id, pk, kid, *, client_id=CLIENT_ID, username="alice", validity=3600):
    return tokens.generate_id_token(
        pool_id=pool_id,
        region="us-east-1",
        client_id=client_id,
        username=username,
        sub="sub-1",
        private_key=pk,
        kid=kid,
        token_validity=validity,
    )


def _access_token(pool_id, pk, kid, *, client_id=CLIENT_ID, validity=3600):
    return tokens.generate_access_token(
        pool_id=pool_id,
        region="us-east-1",
        client_id=client_id,
        username="alice",
        sub="sub-1",
        private_key=pk,
        kid=kid,
        token_validity=validity,
    )


def test_pool_id_from_issuer():
    assert pool_id_from_issuer("http://localhost:4566/us-east-1_abc") == "us-east-1_abc"
    assert pool_id_from_issuer("https://x.example.com:8443/us-east-1_xyz/") == "us-east-1_xyz"
    assert pool_id_from_issuer("") is None
    assert pool_id_from_issuer(None) is None


def test_valid_id_token_verifies(pools):
    pk, kid = pools["A"]
    claims = verify_cognito_token(_id_token(POOL_A, pk, kid))
    assert claims["token_use"] == "id"
    assert claims["cognito:username"] == "alice"
    assert claims["aud"] == CLIENT_ID


def test_valid_access_token_verifies(pools):
    pk, kid = pools["A"]
    claims = verify_cognito_token(_access_token(POOL_A, pk, kid))
    assert claims["token_use"] == "access"
    assert claims["client_id"] == CLIENT_ID


def test_bearer_prefix_is_stripped(pools):
    pk, kid = pools["A"]
    claims = verify_cognito_token("Bearer " + _id_token(POOL_A, pk, kid))
    assert claims["token_use"] == "id"


def test_is_known_pool_token(pools):
    pk, kid = pools["A"]
    assert is_known_pool_token(_id_token(POOL_A, pk, kid)) is True
    # token from a pool we hold no key for
    other_pk, other_kid = generate_key_pair()
    assert is_known_pool_token(_id_token(POOL_UNKNOWN, other_pk, other_kid)) is False
    assert is_known_pool_token("not-a-jwt") is False


def test_tampered_signature_rejected(pools):
    pk, kid = pools["A"]
    token = _id_token(POOL_A, pk, kid)
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload}.{sig[:-4]}AAAA"
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(tampered)


def test_token_signed_by_other_pool_key_rejected(pools):
    """A token claiming pool A but signed with pool B's key must fail."""
    pk_b, kid_b = pools["B"]
    forged = _id_token(POOL_A, pk_b, kid_b)  # issuer says A, signed by B
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(forged)


def test_expired_token_rejected(pools):
    pk, kid = pools["A"]
    expired = _id_token(POOL_A, pk, kid, validity=-10)
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(expired)


def test_wrong_pool_not_allowed(pools):
    pk, kid = pools["A"]
    token = _id_token(POOL_A, pk, kid)
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(token, allowed_pool_ids=[POOL_B])
    # allowed when its own pool is listed
    assert verify_cognito_token(token, allowed_pool_ids=[POOL_A, POOL_B])


def test_unknown_pool_rejected(pools):
    other_pk, other_kid = generate_key_pair()
    token = _id_token(POOL_UNKNOWN, other_pk, other_kid)
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(token)


def test_audience_enforced(pools):
    pk, kid = pools["A"]
    token = _id_token(POOL_A, pk, kid, client_id="the-right-client")
    assert verify_cognito_token(token, allowed_audiences=["the-right-client"])
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(token, allowed_audiences=["some-other-client"])


def test_access_token_audience_matches_client_id(pools):
    pk, kid = pools["A"]
    token = _access_token(POOL_A, pk, kid, client_id="acc-client")
    # Access tokens carry client_id (no aud); audience check must accept it.
    assert verify_cognito_token(token, allowed_audiences=["acc-client"])


def test_token_use_restriction(pools):
    pk, kid = pools["A"]
    id_tok = _id_token(POOL_A, pk, kid)
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(id_tok, allowed_token_uses=("access",))


def test_garbage_and_empty_rejected(pools):
    with pytest.raises(TokenVerificationError):
        verify_cognito_token("")
    with pytest.raises(TokenVerificationError):
        verify_cognito_token("garbage.token.value")


def test_non_cognito_issuer_rejected(pools):
    """A well-formed JWT with no Cognito-style issuer is rejected by verify()."""
    pk, kid = pools["A"]
    from localemu.services.cognito_idp.keys import private_key_to_pem

    token = pyjwt.encode(
        {"iss": "https://accounts.google.com", "exp": 9999999999, "token_use": "id"},
        private_key_to_pem(pk),
        algorithm="RS256",
        headers={"kid": kid},
    )
    # issuer resolves to pool_id "accounts.google.com"-ish last segment -> unknown pool
    with pytest.raises(TokenVerificationError):
        verify_cognito_token(token)
