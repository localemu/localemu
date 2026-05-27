"""Unit tests for Cognito Lambda trigger plumbing.

Fast and isolated: the actual Lambda invoke (``triggers._invoke``) is monkeypatched,
and a fake moto pool/user stands in for the backend. These pin the trigger event
shape, the PreSignUp auto-confirm/verify application, and the PreTokenGeneration
claim overrides, plus the token-generator extra/suppress-claim behaviour.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from localemu.services.cognito_idp import tokens, triggers
from localemu.services.cognito_idp.keys import generate_key_pair

POOL = "us-east-1_pool1"


class FakeUser:
    def __init__(self, attributes=None, status="UNCONFIRMED"):
        self.attributes = attributes or [{"Name": "email", "Value": "u@example.com"}]
        self.status = status


class FakePool:
    def __init__(self, lambda_config=None, user=None):
        self.extended_config = {"LambdaConfig": lambda_config or {}}
        self.users = {"alice": user or FakeUser()}


@pytest.fixture
def fake_pool(monkeypatch):
    pool = FakePool()

    def _get_pool(account_id, region, pool_id):
        return pool

    monkeypatch.setattr(triggers, "_get_pool", _get_pool)
    return pool


def _set_trigger(pool, name, arn="arn:aws:lambda:us-east-1:000000000000:function:t"):
    pool.extended_config["LambdaConfig"][name] = arn


def test_get_lambda_config(fake_pool):
    _set_trigger(fake_pool, "PreSignUp", "arn:func")
    cfg = triggers.get_lambda_config("0", "us-east-1", POOL)
    assert cfg["PreSignUp"] == "arn:func"


def test_no_trigger_is_noop(fake_pool, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(triggers, "_invoke", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    assert triggers.run_pre_sign_up(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="c", trigger_source="PreSignUp_SignUp",
    ) is None
    assert called["n"] == 0  # no function configured -> never invoked


def test_pre_sign_up_auto_confirm_and_verify(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PreSignUp")
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {
            "response": {"autoConfirmUser": True, "autoVerifyEmail": True}
        },
    )
    resp = triggers.run_pre_sign_up(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="c", trigger_source="PreSignUp_SignUp",
    )
    assert resp["autoConfirmUser"] is True
    user = fake_pool.users["alice"]
    assert user.status == "CONFIRMED"
    attrs = {a["Name"]: a["Value"] for a in user.attributes}
    assert attrs["email_verified"] == "true"


def test_pre_sign_up_event_shape(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PreSignUp")
    captured = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: captured.update(event) or {"response": {}},
    )
    triggers.run_pre_sign_up(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="cli", trigger_source="PreSignUp_SignUp",
    )
    assert captured["triggerSource"] == "PreSignUp_SignUp"
    assert captured["userPoolId"] == POOL
    assert captured["userName"] == "alice"
    assert captured["callerContext"]["clientId"] == "cli"
    assert "userAttributes" in captured["request"]
    assert captured["request"]["userAttributes"]["email"] == "u@example.com"


def test_post_confirmation_invoked(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PostConfirmation")
    seen = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: seen.update({"src": event["triggerSource"]}),
    )
    triggers.run_post_confirmation(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="c", trigger_source="PostConfirmation_ConfirmSignUp",
    )
    assert seen["src"] == "PostConfirmation_ConfirmSignUp"


def test_pre_token_generation_returns_overrides(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PreTokenGeneration")
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {
            "response": {
                "claimsOverrideDetails": {
                    "claimsToAddOrOverride": {"custom:tenant": "acme"},
                    "claimsToSuppress": ["email"],
                }
            }
        },
    )
    add, suppress = triggers.run_pre_token_generation(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="c", groups=["admins"],
    )
    assert add == {"custom:tenant": "acme"}
    assert suppress == ["email"]


def test_pre_token_generation_no_trigger(fake_pool):
    add, suppress = triggers.run_pre_token_generation(
        account_id="0", region="us-east-1", pool_id=POOL,
        username="alice", client_id="c", groups=[],
    )
    assert add == {} and suppress == []


# --- token generator extra/suppress claims (pure, no mocks) ---


def test_id_token_extra_and_suppress_claims():
    pk, kid = generate_key_pair()
    token = tokens.generate_id_token(
        pool_id=POOL, region="us-east-1", client_id="c", username="alice",
        sub="s", private_key=pk, kid=kid, email="u@example.com",
        extra_claims={"custom:tenant": "acme"}, suppress_claims=["email"],
    )
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["custom:tenant"] == "acme"
    assert "email" not in claims


def test_access_token_extra_claims():
    pk, kid = generate_key_pair()
    token = tokens.generate_access_token(
        pool_id=POOL, region="us-east-1", client_id="c", username="alice",
        sub="s", private_key=pk, kid=kid, extra_claims={"custom:role": "ops"},
    )
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["custom:role"] == "ops"
