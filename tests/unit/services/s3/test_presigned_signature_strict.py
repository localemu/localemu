"""Pin the strict-by-default S3 presigned-URL signature validator.

Before this fix, ``S3_SKIP_SIGNATURE_VALIDATION`` defaulted to True via
``is_env_not_false(...)``. The consequence in production: a separately-
running LocalEmu server accepted every presigned URL — including ones
where a caller had stripped query parameters after the URL was signed
— with HTTP 200, because the server skipped the signature recomputation
entirely. Real S3 always validates; the loose default was a real
security gap.

These tests pin three things:

  1. The default is now strict (False).
  2. The validator can re-sign for the canonical demo Root key
     (``AKIAIOSFODNN7EXAMPLE`` / ``wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY``)
     without needing the secret to be registered in moto. Without this
     map, the validator falls back to ``"test"`` as the secret and
     every well-formed presigned URL signed with the published example
     pair fails as ``SignatureDoesNotMatch``.
  3. The opt-out is still wired (env-set ``S3_SKIP_SIGNATURE_VALIDATION=1``
     restores the loose mode).
"""
from __future__ import annotations

import os
import importlib

from localemu.services.s3.presigned_url import (
    _DEMO_ACCESS_KEY_SECRETS,
    get_secret_access_key_from_access_key_id,
)


def test_signature_validation_is_strict_by_default(monkeypatch):
    """Without ``S3_SKIP_SIGNATURE_VALIDATION`` in the environment the
    validator runs in strict mode. Anything else would let a tampered
    presigned URL serve with HTTP 200 — the exact production gap
    flagged on 2026-06-10 (BUG ad-hoc / task #40)."""
    monkeypatch.delenv("S3_SKIP_SIGNATURE_VALIDATION", raising=False)
    from localemu import config
    importlib.reload(config)
    assert config.S3_SKIP_SIGNATURE_VALIDATION is False


def test_signature_validation_can_be_opted_back_in(monkeypatch):
    """``S3_SKIP_SIGNATURE_VALIDATION=1`` restores the historical
    loose-mode behaviour for the rare developer who needs to iterate
    against unregistered access keys without re-signing every step."""
    monkeypatch.setenv("S3_SKIP_SIGNATURE_VALIDATION", "1")
    from localemu import config
    importlib.reload(config)
    assert config.S3_SKIP_SIGNATURE_VALIDATION is True


def test_demo_root_key_has_canonical_aws_published_secret():
    """The pair must round-trip the AWS-published example secret —
    anything else means a presigned URL signed with the canonical demo
    credential pair (the one our IAM enforcement recognises as the
    demo Root key) won't validate strictly."""
    expected = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert _DEMO_ACCESS_KEY_SECRETS["AKIAIOSFODNN7EXAMPLE"] == expected


def test_get_secret_returns_demo_secret_for_canonical_root_key():
    """The lookup short-circuits to the demo map before any moto IAM
    walk. moto's IAM backend has never seen ``AKIAIOSFODNN7EXAMPLE``
    so the legacy fallback would return ``"test"`` and the signature
    recomputation would diverge from any well-formed client signature."""
    # ``get_secret_access_key_from_access_key_id`` is ``@cache``-decorated;
    # for the cache to not poison this test across runs we look up the
    # key by both the region we care about and a second region to make
    # sure the value is the demo secret regardless.
    for region in ("us-east-1", "eu-west-1"):
        secret = get_secret_access_key_from_access_key_id(
            "AKIAIOSFODNN7EXAMPLE", region,
        )
        assert secret == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", (
            f"region {region}: expected demo secret, got {secret!r}"
        )


def test_get_secret_falls_through_to_moto_for_other_keys():
    """The demo-map shortcut must NOT mask a real moto-registered key.
    For any access key that isn't the canonical demo pair, the lookup
    walks moto's IAM backend as before."""
    # An access key we know is not in the demo map and is not in moto's
    # IAM. The fallback path returns ``None``; the caller (validator)
    # then defaults to ``DEFAULT_PRE_SIGNED_SECRET_ACCESS_KEY``.
    secret = get_secret_access_key_from_access_key_id(
        "AKIAJDEFINITELYNOTREALXYZ", "us-east-1",
    )
    # Either None (unregistered) or a string returned by moto — both
    # are acceptable; what matters is the demo-map didn't masquerade.
    assert secret != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
