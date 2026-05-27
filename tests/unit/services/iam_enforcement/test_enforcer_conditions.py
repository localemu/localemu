"""Unit tests for the request-context building in enforcer._build_conditions.

Covers the invariants we rely on elsewhere:
  - aws:MultiFactorAuthPresent is ABSENT for non-MFA callers (not "false").
  - aws:MultiFactorAuthPresent is "true" only for AssumedRole sessions whose
    sts_stores entry has mfa_authenticated=True.
  - Request-scoped keys like aws:RequestTag/* / aws:TagKeys are populated.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu.services.iam_enforcement.enforcer import _build_conditions
from localemu.services.iam_enforcement.identity import CallerIdentity


def _ctx(service_request=None, headers=None, remote_addr="127.0.0.1",
         region="us-east-1", is_secure=False, url=None):
    """Build a minimal RequestContext-like object for _build_conditions."""
    request = SimpleNamespace(
        headers=(headers or {}),
        remote_addr=remote_addr,
        is_secure=is_secure,
        url=url or ("https://localhost:4566/" if is_secure else "http://localhost:4566/"),
    )
    return SimpleNamespace(
        request=request,
        service_request=service_request,
        region=region,
    )


class TestMfaPresentSemantics:
    def test_non_mfa_iam_user_key_absent(self):
        caller = CallerIdentity(
            principal_type="User",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice",
            username="alice",
            access_key_id="AKIAIOSFODNN7EXAMPLE",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds, (
            "Long-term IAM-user credentials must not include the MFA key in "
            "the request context — AWS leaves it absent."
        )

    def test_root_key_absent(self):
        caller = CallerIdentity(
            principal_type="Root",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:root",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds

    def test_assumed_role_without_mfa_key_absent(self, monkeypatch):
        """AssumedRole whose session has mfa_authenticated=False -> key absent."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {
            "ASIAFAKE": {"mfa_authenticated": False},
        }
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAFAKE",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds

    def test_assumed_role_with_mfa_key_true(self, monkeypatch):
        """AssumedRole whose session has mfa_authenticated=True -> "true"."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {
            "ASIAMFA": {"mfa_authenticated": True},
        }
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAMFA",
        )
        conds = _build_conditions(_ctx(), caller)
        assert conds.get("aws:MultiFactorAuthPresent") == "true"

    def test_assumed_role_missing_session_key_absent(self, monkeypatch):
        """AssumedRole whose session isn't tracked — fail-safe: absent."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {}
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAUNKNOWN",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds


class TestRequestTagKeys:
    """aws:RequestTag/* and aws:TagKeys are built from the request params."""

    def test_request_tags_populated_from_list_shape(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(service_request={"Tags": [
            {"Key": "env", "Value": "prod"},
            {"Key": "team", "Value": "sre"},
        ]})
        conds = _build_conditions(ctx, caller)
        assert conds["aws:RequestTag/env"] == "prod"
        assert conds["aws:RequestTag/team"] == "sre"
        assert sorted(conds["aws:TagKeys"]) == ["env", "team"]

    def test_request_tags_populated_from_dict_shape(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(service_request={"Tags": {"env": "prod"}})
        conds = _build_conditions(ctx, caller)
        assert conds["aws:RequestTag/env"] == "prod"
        assert conds["aws:TagKeys"] == ["env"]


class TestStandardContextKeys:
    def test_principal_and_request_keys_present(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(headers={"User-Agent": "boto3/1.x"}, remote_addr="203.0.113.5",
                   region="eu-west-1")
        conds = _build_conditions(ctx, caller)
        assert conds["aws:PrincipalArn"] == "arn:aws:iam::000000000000:user/alice"
        assert conds["aws:PrincipalAccount"] == "000000000000"
        assert conds["aws:PrincipalType"] == "User"
        assert conds["aws:SourceIp"] == "203.0.113.5"
        assert conds["aws:UserAgent"] == "boto3/1.x"
        assert conds["aws:RequestedRegion"] == "eu-west-1"
        assert conds["aws:username"] == "alice"


class TestSecureTransport:
    """aws:SecureTransport reflects the request scheme, not a hard-coded value."""

    def _caller(self):
        return CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )

    def test_http_is_false(self):
        conds = _build_conditions(_ctx(is_secure=False), self._caller())
        assert conds["aws:SecureTransport"] == "false"

    def test_https_is_true(self):
        conds = _build_conditions(_ctx(is_secure=True), self._caller())
        assert conds["aws:SecureTransport"] == "true"

    def test_fallback_on_url_prefix(self):
        """If is_secure raises, fall back to URL prefix sniff."""
        class FailingRequest:
            headers: dict = {}
            remote_addr = "127.0.0.1"
            url = "https://localhost:4566/_something"

            @property
            def is_secure(self):
                raise RuntimeError("wsgi env missing")

        ctx = SimpleNamespace(
            request=FailingRequest(),
            service_request=None,
            region="us-east-1",
        )
        conds = _build_conditions(ctx, self._caller())
        assert conds["aws:SecureTransport"] == "true"

    def test_fallback_on_all_failure_is_false(self):
        """If both is_secure and url sniff fail, default to false (fail-safe)."""
        class FailingRequest:
            headers: dict = {}
            remote_addr = "127.0.0.1"

            @property
            def is_secure(self):
                raise RuntimeError("wsgi env missing")

            @property
            def url(self):
                raise RuntimeError("url unavailable")

        ctx = SimpleNamespace(
            request=FailingRequest(),
            service_request=None,
            region="us-east-1",
        )
        conds = _build_conditions(ctx, self._caller())
        assert conds["aws:SecureTransport"] == "false"
