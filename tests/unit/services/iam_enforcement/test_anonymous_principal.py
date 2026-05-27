"""Unit tests for the anonymous principal in IAM enforcement.

An unauthenticated request (no Authorization header, no presigned query
credential) is stamped with ANONYMOUS_ACCESS_KEY_ID by MissingAuthHeaderInjector
and must resolve to the anonymous principal: access is granted only by a
resource policy naming Principal "*" (public), and denied otherwise — matching
AWS's behaviour for unsigned requests.
"""

from __future__ import annotations

import pytest

from localemu.aws.handlers.auth import _has_presigned_credentials
from localemu.constants import ANONYMOUS_ACCESS_KEY_ID
from localemu.services.iam_enforcement.evaluator import Decision, PolicyEvaluator
from localemu.services.iam_enforcement.identity import (
    CallerIdentity,
    get_identity_policies,
    resolve_caller,
)


def _anon(account="000000000000") -> CallerIdentity:
    return CallerIdentity(
        principal_type="Anonymous",
        account_id=account,
        arn="*",
        access_key_id=ANONYMOUS_ACCESS_KEY_ID,
    )


@pytest.fixture
def ev(monkeypatch):
    """PolicyEvaluator with identity/boundary/session sources stubbed empty
    (anonymous callers have none of these)."""
    import localemu.services.iam_enforcement.evaluator as mod

    monkeypatch.setattr(mod, "get_identity_policies", lambda c: [])
    monkeypatch.setattr(mod, "get_permission_boundary", lambda c: None)
    monkeypatch.setattr(mod, "get_session_policies", lambda c: [])
    return PolicyEvaluator()


class TestResolveAnonymous:
    def test_sentinel_resolves_to_anonymous(self):
        caller = resolve_caller(ANONYMOUS_ACCESS_KEY_ID, "000000000000", "us-east-1")
        assert caller is not None
        assert caller.principal_type == "Anonymous"
        assert caller.arn == "*"
        assert caller.access_key_id == ANONYMOUS_ACCESS_KEY_ID

    def test_unknown_key_still_unresolved(self):
        # A genuinely unknown key (e.g. boto3 default 'test') stays None so the
        # operator still gets the "unknown caller / create an IAM user" hint.
        assert resolve_caller("totallyboguskey", "000000000000", "us-east-1") is None

    def test_anonymous_has_no_identity_policies(self):
        assert get_identity_policies(_anon()) == []


class TestEvaluatorAnonymous:
    def test_no_resource_policy_is_implicit_deny(self, ev):
        # Private resource, unsigned request -> denied.
        assert ev.evaluate(_anon(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.IMPLICIT_DENY

    def test_public_star_principal_allows(self, ev):
        pol = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
        }]}
        assert ev.evaluate(_anon(), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy=pol) == Decision.ALLOW

    def test_public_aws_star_principal_allows(self, ev):
        # {"AWS": "*"} is equivalent to "*" for anonymous callers per AWS.
        pol = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "*"},
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
        }]}
        assert ev.evaluate(_anon(), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy=pol) == Decision.ALLOW

    def test_explicit_deny_on_star_overrides(self, ev):
        pol = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
            {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"},
        ]}
        assert ev.evaluate(_anon(), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy=pol) == Decision.EXPLICIT_DENY

    def test_named_principal_does_not_match_anonymous(self, ev):
        # A bucket policy that grants a specific user must NOT let an anonymous
        # request through.
        pol = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
        }]}
        assert ev.evaluate(_anon(), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy=pol) == Decision.IMPLICIT_DENY

    def test_public_read_but_action_not_granted_is_denied(self, ev):
        # Public for GetObject only; an anonymous PutObject is still denied.
        pol = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*",
        }]}
        assert ev.evaluate(_anon(), "s3:PutObject", "arn:aws:s3:::b/k", {}, resource_policy=pol) == Decision.IMPLICIT_DENY


class _FakeReq:
    def __init__(self, url):
        self.url = url


class _FakeCtx:
    def __init__(self, url):
        self.request = _FakeReq(url)


class TestPresignedGuard:
    def test_sigv4_presigned_detected(self):
        url = "http://localhost:4566/b/k?X-Amz-Credential=AKIA%2F20260101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=abc"
        assert _has_presigned_credentials(_FakeCtx(url)) is True

    def test_sigv4_signature_only_detected(self):
        url = "http://localhost:4566/b/k?X-Amz-Signature=abc"
        assert _has_presigned_credentials(_FakeCtx(url)) is True

    def test_sigv2_presigned_detected(self):
        url = "http://localhost:4566/b/k?AWSAccessKeyId=AKIA&Signature=xyz&Expires=999"
        assert _has_presigned_credentials(_FakeCtx(url)) is True

    def test_plain_url_is_not_presigned(self):
        url = "http://localhost:4566/b/k?versionId=1"
        assert _has_presigned_credentials(_FakeCtx(url)) is False

    def test_no_query_is_not_presigned(self):
        assert _has_presigned_credentials(_FakeCtx("http://localhost:4566/b/k")) is False
