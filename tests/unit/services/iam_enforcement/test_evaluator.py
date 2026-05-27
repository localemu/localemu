"""Unit tests for localemu.services.iam_enforcement.evaluator.

Covers the AWS evaluation algorithm end-to-end without hitting Moto or the
HTTP chain:
  - Deny-override across identity + resource + boundary policies
  - Implicit-vs-explicit deny
  - Permission-boundary intersection (allow required in BOTH identity and
    boundary)
  - Session-policy intersection for assumed roles
  - Resource-policy Principal semantics (Bug #2)
"""

from __future__ import annotations

import pytest

from localemu.services.iam_enforcement.evaluator import (
    Decision,
    PolicyEvaluator,
    _matches_principal,
)
from localemu.services.iam_enforcement.identity import CallerIdentity


def _user(name="alice", account="000000000000") -> CallerIdentity:
    return CallerIdentity(
        principal_type="User",
        account_id=account,
        arn=f"arn:aws:iam::{account}:user/{name}",
        username=name,
    )


@pytest.fixture
def ev(monkeypatch):
    """PolicyEvaluator with identity/boundary/session sources stubbed out."""
    import localemu.services.iam_enforcement.evaluator as mod

    fixtures = {"identity": [], "boundary": None, "session": []}
    monkeypatch.setattr(mod, "get_identity_policies", lambda c: fixtures["identity"])
    monkeypatch.setattr(mod, "get_permission_boundary", lambda c: fixtures["boundary"])
    monkeypatch.setattr(mod, "get_session_policies", lambda c: fixtures["session"])

    evaluator = PolicyEvaluator()
    evaluator._fixtures = fixtures
    return evaluator


class TestDenyOverride:
    def test_allow_only(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        assert ev.evaluate(_user(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW

    def test_explicit_deny_on_identity_overrides_allow(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
            ]},
        ]
        assert ev.evaluate(_user(), "s3:DeleteObject", "arn:aws:s3:::b/k", {}) == Decision.EXPLICIT_DENY
        assert ev.evaluate(_user(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW

    def test_implicit_deny_with_no_allow(self, ev):
        ev._fixtures["identity"] = []
        assert ev.evaluate(_user(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.IMPLICIT_DENY

    def test_explicit_deny_on_boundary(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        ]
        ev._fixtures["boundary"] = {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ]}
        assert ev.evaluate(_user(), "s3:DeleteObject", "arn:aws:s3:::b/k", {}) == Decision.EXPLICIT_DENY

    def test_explicit_deny_on_resource_policy(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        resource_policy = {"Statement": [{
            "Effect": "Deny", "Principal": "*",
            "Action": "s3:DeleteObject", "Resource": "*",
        }]}
        assert ev.evaluate(
            _user(), "s3:DeleteObject", "arn:aws:s3:::b/k", {}, resource_policy
        ) == Decision.EXPLICIT_DENY


class TestPermissionBoundary:
    """Identity Allow + Boundary Allow required (intersection)."""

    def test_boundary_must_also_allow(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        ev._fixtures["boundary"] = {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        ]}
        # Identity allows PutObject, boundary doesn't -> IMPLICIT_DENY
        assert ev.evaluate(_user(), "s3:PutObject", "arn:aws:s3:::b/k", {}) == Decision.IMPLICIT_DENY
        # Both allow GetObject -> ALLOW
        assert ev.evaluate(_user(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW


class TestSessionPolicy:
    def test_session_policy_narrows_allow(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        ev._fixtures["session"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
        ]
        caller = CallerIdentity(
            principal_type="AssumedRole", account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R", session_name="s",
        )
        assert ev.evaluate(caller, "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW
        assert ev.evaluate(caller, "s3:DeleteObject", "arn:aws:s3:::b/k", {}) == Decision.IMPLICIT_DENY


class TestResourcePolicyPrincipal:
    """Bug #2: Principal semantics on resource-based policy statements."""

    def test_missing_principal_on_resource_policy_does_not_match(self):
        """No Principal and no NotPrincipal — statement matches no one."""
        stmt = {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        assert _matches_principal(stmt, _user()) is False

    def test_star_principal_matches_everyone(self):
        stmt = {"Principal": "*"}
        assert _matches_principal(stmt, _user()) is True

    def test_explicit_aws_arn_match(self):
        stmt = {"Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"}}
        assert _matches_principal(stmt, _user("alice")) is True
        assert _matches_principal(stmt, _user("bob")) is False

    def test_root_arn_matches_any_caller_in_account(self):
        """Principal 'arn:aws:iam::ACCT:root' means any identity in that account."""
        stmt = {"Principal": {"AWS": "arn:aws:iam::000000000000:root"}}
        assert _matches_principal(stmt, _user("alice")) is True
        assert _matches_principal(stmt, _user("bob")) is True

    def test_not_principal_excludes(self):
        stmt = {"NotPrincipal": {"AWS": "arn:aws:iam::000000000000:user/alice"}}
        assert _matches_principal(stmt, _user("alice")) is False
        assert _matches_principal(stmt, _user("bob")) is True

    def test_both_principal_and_not_principal_is_malformed(self):
        stmt = {
            "Principal": "*",
            "NotPrincipal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
        }
        assert _matches_principal(stmt, _user("alice")) is False
        assert _matches_principal(stmt, _user("bob")) is False


class TestResourcePolicyStandaloneAllowSameAccount:
    """AWS: for same-account calls, resource-policy Allow alone is sufficient.

    Quote: "If either the identity-based policy or the resource-based policy
    within the same account allows the request and the other doesn't, the
    request is still allowed."
    Ref: reference_policies_evaluation-logic_policy-eval-basics.html
    """

    def test_resource_policy_alone_grants(self, ev):
        ev._fixtures["identity"] = []  # no identity policy at all
        resource_policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "s3:*", "Resource": "arn:aws:s3:::b/*",
        }]}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy
        ) == Decision.ALLOW

    def test_identity_policy_alone_grants(self, ev):
        ev._fixtures["identity"] = [{"Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        ]}]
        # No resource policy — identity policy alone grants.
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {},
        ) == Decision.ALLOW

    def test_neither_policy_grants_implicit_deny(self, ev):
        ev._fixtures["identity"] = []
        resource_policy = {"Statement": []}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy
        ) == Decision.IMPLICIT_DENY


class TestResourcePolicyAllowWithPrincipalBug:
    """Bug #2 integration test: a resource policy WITHOUT Principal must not
    auto-allow the caller just because Action + Resource match."""

    def test_unprincipaled_allow_does_not_grant(self, ev):
        ev._fixtures["identity"] = []  # no identity allow
        resource_policy = {"Statement": [
            # Missing Principal — malformed, must not grant.
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        ]}
        assert ev.evaluate(
            _user(), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy
        ) == Decision.IMPLICIT_DENY

    def test_unprincipaled_deny_does_not_block(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        resource_policy = {"Statement": [
            # Missing Principal on a Deny — must not explicit-deny.
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ]}
        assert ev.evaluate(
            _user(), "s3:DeleteObject", "arn:aws:s3:::b/k", {}, resource_policy
        ) == Decision.ALLOW
