"""Regression tests for awsemu's credential normalization.

Context: Pre-IAM-enforcement, awsemu set AWS_ACCESS_KEY_ID="test" via
``os.environ.setdefault``. Two problems with that:

  1. ``"test"`` is not in ``ROOT_ACCESS_KEYS`` (which defaults to
     ``{AKIAIOSFODNN7EXAMPLE, 000000000000}``), so any awsemu call against
     ``IAM_ENFORCEMENT=1`` returned ``AccessDenied`` with the cryptic
     "security token included in the request is invalid" message — even
     though the awsemu docs told users awsemu would set the credentials
     for them.

  2. ``setdefault`` does nothing if the env var is already set, so users
     whose shells had ``AWS_ACCESS_KEY_ID=test`` (from following older
     docs) silently sent that broken key to LocalEmu's IAM enforcer.

The fix in ``localemu.cli.awsemu``: default to the AWS-published canonical
``AKIAIOSFODNN7EXAMPLE`` (which IS a root access key by default), and
treat a literal ``"test"`` in the env as the foot-gun it is — replace it
and tell the user via stderr. Any other env value is respected verbatim,
which preserves intentional impersonation flows like
``AWS_ACCESS_KEY_ID=AKIA_DEV_KEY awsemu s3 ls`` for IAM policy testing.
"""

from __future__ import annotations

import os

import pytest

from localemu.cli.awsemu import (
    _LOCALEMU_DEFAULT_AK,
    _LOCALEMU_DEFAULT_SK,
    _normalize_localemu_credentials,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip AWS_* env vars so each test starts from a known-empty state."""
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
    ):
        monkeypatch.delenv(var, raising=False)


def test_unset_env_gets_localemu_defaults():
    _normalize_localemu_credentials()
    assert os.environ["AWS_ACCESS_KEY_ID"] == _LOCALEMU_DEFAULT_AK
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == _LOCALEMU_DEFAULT_SK


def test_legacy_test_value_is_replaced(monkeypatch, capsys):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")

    _normalize_localemu_credentials()

    assert os.environ["AWS_ACCESS_KEY_ID"] == _LOCALEMU_DEFAULT_AK
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == _LOCALEMU_DEFAULT_SK
    err = capsys.readouterr().err
    assert "AWS_ACCESS_KEY_ID" in err
    assert "'test'" in err
    assert _LOCALEMU_DEFAULT_AK in err
    assert "AWS_SECRET_ACCESS_KEY" in err


def test_empty_string_is_replaced(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "")

    _normalize_localemu_credentials()

    assert os.environ["AWS_ACCESS_KEY_ID"] == _LOCALEMU_DEFAULT_AK
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == _LOCALEMU_DEFAULT_SK


def test_deliberate_custom_key_is_respected(monkeypatch, capsys):
    """IAM impersonation flows must keep working — don't override AKIA*-style keys."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_DEV_KEY")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "dev_secret_key")

    _normalize_localemu_credentials()

    assert os.environ["AWS_ACCESS_KEY_ID"] == "AKIA_DEV_KEY"
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == "dev_secret_key"
    assert capsys.readouterr().err == ""


def test_canonical_value_already_set_is_silent(monkeypatch, capsys):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _LOCALEMU_DEFAULT_AK)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _LOCALEMU_DEFAULT_SK)

    _normalize_localemu_credentials()

    assert os.environ["AWS_ACCESS_KEY_ID"] == _LOCALEMU_DEFAULT_AK
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == _LOCALEMU_DEFAULT_SK
    assert capsys.readouterr().err == ""


def test_mixed_one_legacy_one_custom(monkeypatch, capsys):
    """If only one var is the foot-gun, only that one gets fixed and notified."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "real_secret_from_their_shell")

    _normalize_localemu_credentials()

    assert os.environ["AWS_ACCESS_KEY_ID"] == _LOCALEMU_DEFAULT_AK
    assert os.environ["AWS_SECRET_ACCESS_KEY"] == "real_secret_from_their_shell"
    err = capsys.readouterr().err
    assert "AWS_ACCESS_KEY_ID" in err
    assert "AWS_SECRET_ACCESS_KEY" not in err


def test_default_ak_is_a_root_key():
    """The defaults must match the ROOT_ACCESS_KEYS set so IAM enforcement permits them."""
    from localemu.services.iam_enforcement.identity import _get_root_access_keys

    assert _LOCALEMU_DEFAULT_AK in _get_root_access_keys()
