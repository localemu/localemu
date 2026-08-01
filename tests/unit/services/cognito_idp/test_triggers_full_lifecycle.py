"""Unit tests for the 9 Cognito Lambda triggers added in 1.2.0.

One test per missing trigger : ``PreAuthentication``, ``PostAuthentication``,
``CustomMessage``, ``DefineAuthChallenge``, ``CreateAuthChallenge``,
``VerifyAuthChallengeResponse``, ``UserMigration``, plus the
``CustomEmailSender`` / ``CustomSMSSender`` routing through
``messages.send_code``.

Only ``triggers._invoke`` (the Lambda call) is mocked. No flag patching.
The buffer in ``messages.py`` is cleared between tests so assertions
on ``get_messages(...)`` are independent.
"""
from __future__ import annotations

import pytest

from localemu.services.cognito_idp import messages, triggers


POOL = "us-east-1_pool1"
ACC = "000000000000"
REGION = "us-east-1"


class FakeUser:
    def __init__(self, attributes=None, status="UNCONFIRMED"):
        self.attributes = attributes or [
            {"Name": "email", "Value": "u@example.com"},
        ]
        self.status = status
        self.confirmation_code = None


class FakePool:
    def __init__(self, lambda_config=None, user=None):
        self.id = POOL
        self.extended_config = {"LambdaConfig": lambda_config or {}}
        self.users = {"alice": user or FakeUser()}


@pytest.fixture
def fake_pool(monkeypatch):
    pool = FakePool()
    monkeypatch.setattr(triggers, "_get_pool", lambda *a, **k: pool)
    return pool


@pytest.fixture(autouse=True)
def _clear_message_buffer():
    messages.clear()
    yield
    messages.clear()


def _set_trigger(pool, name, arn="arn:aws:lambda:us-east-1:000000000000:function:t"):
    pool.extended_config["LambdaConfig"][name] = arn


# ---------------------------------------------------------------------------
# PreAuthentication
# ---------------------------------------------------------------------------


def test_pre_authentication_invokes_with_correct_trigger_source(
    fake_pool, monkeypatch,
):
    _set_trigger(fake_pool, "PreAuthentication")
    captured = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: captured.update(event) or {"response": {}},
    )
    triggers.run_pre_authentication(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
    )
    assert captured["triggerSource"] == "PreAuthentication_Authentication"
    assert captured["request"]["userNotFound"] is False


def test_pre_authentication_raises_block_auth(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PreAuthentication")
    def _boom(region, arn, event):
        raise RuntimeError("trigger returned FunctionError: Unhandled")
    monkeypatch.setattr(triggers, "_invoke", _boom)
    with pytest.raises(RuntimeError, match="FunctionError"):
        triggers.run_pre_authentication(
            account_id=ACC, region=REGION, pool_id=POOL,
            username="alice", client_id="c",
        )


# ---------------------------------------------------------------------------
# PostAuthentication
# ---------------------------------------------------------------------------


def test_post_authentication_is_noop_without_trigger(fake_pool, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    triggers.run_post_authentication(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
    )
    assert called["n"] == 0


def test_post_authentication_invoked_when_configured(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "PostAuthentication")
    captured = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: captured.update(event) or {"response": {}},
    )
    triggers.run_post_authentication(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
    )
    assert captured["triggerSource"] == "PostAuthentication_Authentication"


# ---------------------------------------------------------------------------
# CustomMessage substitutes the code placeholder
# ---------------------------------------------------------------------------


def test_custom_message_substitutes_code_placeholder(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "CustomMessage")
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {
            "response": {
                "smsMessage": "Your code is {####}",
                "emailMessage": "Welcome alice, {####}",
                "emailSubject": "Verify",
            },
        },
    )
    out = triggers.run_custom_message(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
        trigger_source="CustomMessage_SignUp",
        code_parameter="123456",
    )
    assert out["smsMessage"] == "Your code is 123456"
    assert out["emailMessage"] == "Welcome alice, 123456"
    assert out["emailSubject"] == "Verify"


# ---------------------------------------------------------------------------
# DefineAuthChallenge tokens / deny / continue
# ---------------------------------------------------------------------------


def test_define_auth_challenge_returns_lambda_response(fake_pool, monkeypatch):
    _set_trigger(fake_pool, "DefineAuthChallenge")
    canned = {"challengeName": "CUSTOM_CHALLENGE",
              "issueTokens": False, "failAuthentication": False}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {"response": canned},
    )
    out = triggers.run_define_auth_challenge(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c", session_history=[],
    )
    assert out == canned


# ---------------------------------------------------------------------------
# CreateAuthChallenge returns public + private params
# ---------------------------------------------------------------------------


def test_create_auth_challenge_returns_public_and_private_params(
    fake_pool, monkeypatch,
):
    _set_trigger(fake_pool, "CreateAuthChallenge")
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {
            "response": {
                "publicChallengeParameters": {"question": "What is 2+2?"},
                "privateChallengeParameters": {"answer": "4"},
                "challengeMetadata": "math-round-1",
            },
        },
    )
    out = triggers.run_create_auth_challenge(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
        challenge_name="CUSTOM_CHALLENGE", session_history=[],
    )
    assert out["publicChallengeParameters"]["question"] == "What is 2+2?"
    assert out["privateChallengeParameters"]["answer"] == "4"
    assert out["challengeMetadata"] == "math-round-1"


# ---------------------------------------------------------------------------
# VerifyAuthChallengeResponse returns answer correctness
# ---------------------------------------------------------------------------


def test_verify_auth_challenge_response_returns_answer_correct(
    fake_pool, monkeypatch,
):
    _set_trigger(fake_pool, "VerifyAuthChallengeResponse")
    captured = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: (
            captured.update(event) or {"response": {"answerCorrect": True}}
        ),
    )
    out = triggers.run_verify_auth_challenge_response(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c",
        private_challenge_parameters={"answer": "4"},
        challenge_answer="4",
    )
    assert out["answerCorrect"] is True
    assert captured["request"]["privateChallengeParameters"]["answer"] == "4"
    assert captured["request"]["challengeAnswer"] == "4"


# ---------------------------------------------------------------------------
# UserMigration synthesises the user in the pool
# ---------------------------------------------------------------------------


def test_user_migration_synthesises_user_with_attributes(
    fake_pool, monkeypatch,
):
    """The Lambda response carries user attributes ; the helper must
    insert a moto-shaped user into the pool keyed on the username."""
    _set_trigger(fake_pool, "UserMigration")
    # Remove the default user so the synthesised one is the only entry.
    fake_pool.users.clear()
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: {
            "response": {
                "userAttributes": {
                    "email": "alice@example.com",
                    "email_verified": "true",
                },
                "finalUserStatus": "CONFIRMED",
                "messageAction": "SUPPRESS",
            },
        },
    )
    # Patch moto's user constructor with a stand-in so the helper
    # writes an object that mimics the shape : the synthesised entry
    # should land in ``pool.users["alice"]``.
    from moto.cognitoidp import models as _moto_models

    captured = {}

    class _FakeUserModel:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.username = kwargs.get("username")
            self.attributes = kwargs.get("attributes") or []
            self.status = kwargs.get("status")

    monkeypatch.setattr(_moto_models, "CognitoIdpUser", _FakeUserModel)

    response = triggers.run_user_migration(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice", client_id="c", password="hunter2",
        trigger_source="UserMigration_Authentication",
    )
    ok = triggers.synthesise_user_from_migration_response(
        ACC, REGION, POOL, "alice", response,
    )
    assert ok is True
    assert "alice" in fake_pool.users
    synth = fake_pool.users["alice"]
    attrs = {a["Name"]: a["Value"] for a in synth.attributes}
    assert attrs == {
        "email": "alice@example.com",
        "email_verified": "true",
    }
    assert synth.status == "CONFIRMED"
    assert captured["username"] == "alice"


# ---------------------------------------------------------------------------
# Sender Lambdas via messages.send_code
# ---------------------------------------------------------------------------


def test_custom_email_sender_invoked_and_message_buffered(
    fake_pool, monkeypatch,
):
    """CustomEmailSender is configured as a structure ; ``send_code``
    must extract the LambdaArn and call _invoke with the encrypted
    code, then store a message marked ``sent_via_sender_lambda``."""
    fake_pool.extended_config["LambdaConfig"]["CustomEmailSender"] = {
        "LambdaArn": "arn:aws:lambda:us-east-1:000000000000:function:sender",
        "LambdaVersion": "V1_0",
    }
    seen = {}
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: seen.update({
            "arn": arn,
            "code_b64": event["request"]["code"],
            "trigger_source": event["triggerSource"],
        }) or {"response": {}},
    )
    stored = messages.send_code(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice",
        trigger_source="CustomMessage_SignUp",
        delivery_medium="EMAIL",
        code_plain="987654",
    )
    assert seen["arn"] == "arn:aws:lambda:us-east-1:000000000000:function:sender"
    import base64
    assert base64.b64decode(seen["code_b64"]).decode() == "987654"
    assert "CustomEmailSender" in seen["trigger_source"]
    assert stored.sent_via_sender_lambda is True
    # Buffer is populated regardless so tests can read it.
    assert messages.get_messages(ACC, REGION, POOL, "alice")[0].code_plain == "987654"


def test_custom_sms_sender_invoked_for_sms_medium(fake_pool, monkeypatch):
    fake_pool.extended_config["LambdaConfig"]["CustomSMSSender"] = {
        "LambdaArn": "arn:aws:lambda:us-east-1:000000000000:function:sms",
        "LambdaVersion": "V1_0",
    }
    calls = []
    monkeypatch.setattr(
        triggers, "_invoke",
        lambda region, arn, event: calls.append({
            "arn": arn,
            "trigger_source": event["triggerSource"],
        }) or {"response": {}},
    )
    stored = messages.send_code(
        account_id=ACC, region=REGION, pool_id=POOL,
        username="alice",
        trigger_source="CustomMessage_ForgotPassword",
        delivery_medium="SMS",
        code_plain="112233",
    )
    assert any(
        "CustomSMSSender" in c["trigger_source"] for c in calls
    )
    assert stored.sent_via_sender_lambda is True
