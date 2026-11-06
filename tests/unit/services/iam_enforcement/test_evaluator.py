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


class TestKmsKeyPolicyRootGrantRequiresIdentityPolicyToo:
    """AWS documents KMS key policies as a named exception to the general
    "resource policy Allow alone is sufficient for same-account calls" rule:
    a key-policy statement granting only the account ROOT means "IAM
    policies in the account govern this", not "everyone in the account gets
    the action regardless of their own permissions." A key policy granting
    a SPECIFIC principal directly still works like every other resource
    policy (sufficient on its own)."""

    _root_grant_policy = {"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
        "Action": "kms:*", "Resource": "*",
    }]}

    def test_root_only_grant_is_not_sufficient_without_an_identity_policy(self, ev):
        ev._fixtures["identity"] = []  # no identity policy at all
        assert ev.evaluate(
            _user("alice"), "kms:Decrypt", "arn:aws:kms:us-east-1:000000000000:key/k",
            {}, self._root_grant_policy,
        ) == Decision.IMPLICIT_DENY

    def test_root_only_grant_plus_identity_allow_does_grant(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]},
        ]
        assert ev.evaluate(
            _user("alice"), "kms:Decrypt", "arn:aws:kms:us-east-1:000000000000:key/k",
            {}, self._root_grant_policy,
        ) == Decision.ALLOW

    def test_key_policy_granting_a_specific_principal_is_still_sufficient_alone(self, ev):
        ev._fixtures["identity"] = []  # no identity policy at all
        specific_policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "kms:Decrypt", "Resource": "*",
        }]}
        assert ev.evaluate(
            _user("alice"), "kms:Decrypt", "arn:aws:kms:us-east-1:000000000000:key/k",
            {}, specific_policy,
        ) == Decision.ALLOW

    def test_non_kms_services_are_unaffected_by_the_exception(self, ev):
        """Same root-only grant shape, but for S3 - must keep using the
        general OR-logic (this is a KMS-specific exception, not a general
        tightening)."""
        ev._fixtures["identity"] = []
        s3_root_grant = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {}, s3_root_grant,
        ) == Decision.ALLOW


class TestDecisionLogIncludesTheMatchingStatement:
    """The DEBUG-gated decision log showed caller/action/resource/reason
    but never the actual statement that decided it."""

    def test_identity_allow_logs_the_matching_statement(self, ev, caplog):
        import logging

        caplog.set_level(logging.DEBUG, logger="localemu.services.iam_enforcement.evaluator")
        ev._fixtures["identity"] = [{"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        ]}]
        assert ev.evaluate(_user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW
        joined = "\n".join(caplog.messages)
        assert '"Action":"s3:GetObject"' in joined

    def test_explicit_deny_logs_the_matching_statement(self, ev, caplog):
        import logging

        caplog.set_level(logging.DEBUG, logger="localemu.services.iam_enforcement.evaluator")
        ev._fixtures["identity"] = [{"Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ]}]
        assert ev.evaluate(_user("alice"), "s3:DeleteObject", "arn:aws:s3:::b/k", {}) == Decision.EXPLICIT_DENY
        joined = "\n".join(caplog.messages)
        assert '"Effect":"Deny"' in joined
        assert '"Action":"s3:DeleteObject"' in joined

    def test_resource_policy_allow_logs_the_matching_statement(self, ev, caplog):
        import logging

        caplog.set_level(logging.DEBUG, logger="localemu.services.iam_enforcement.evaluator")
        ev._fixtures["identity"] = []
        resource_policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {}, resource_policy,
        ) == Decision.ALLOW
        joined = "\n".join(caplog.messages)
        assert '"Action":"s3:GetObject"' in joined


class TestVpcEndpointPolicy:
    """VPC endpoint policies are an independent AND-gate (lab s22 / goat-bugs
    item 5): the endpoint's own policy must separately allow the action, on
    top of (never instead of) identity/resource-policy allow, and an
    explicit Deny in it must behave exactly like any other explicit Deny -
    not fall through to a bypassable implicit deny."""

    _default_allow_policy = {
        "Version": "2008-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
    }

    def test_default_allow_policy_is_a_no_op_when_identity_allows(self, ev):
        """Regression guard: moto defaults every endpoint to this policy, so
        the overwhelming majority of existing endpoint traffic (every
        endpoint without a custom policy attached) must behave exactly as
        if endpoint_policy had never been passed at all."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        assert ev.evaluate(
            _user(), "s3:GetObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=self._default_allow_policy,
        ) == Decision.ALLOW

    def test_default_allow_policy_does_not_rescue_an_identity_deny(self, ev):
        ev._fixtures["identity"] = []  # no identity allow
        assert ev.evaluate(
            _user(), "s3:GetObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=self._default_allow_policy,
        ) == Decision.IMPLICIT_DENY

    def test_endpoint_policy_allow_required_even_when_identity_and_resource_allow(self, ev):
        """The AND-gate: identity allows, resource policy (same-account OR
        logic) would normally short-circuit to ALLOW on its own - but the
        endpoint policy only allows a different action, so the overall
        decision must still be denied."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        resource_policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        endpoint_policy = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:ListBucket", "Resource": "*"},
        ]}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {},
            resource_policy=resource_policy, endpoint_policy=endpoint_policy,
        ) == Decision.IMPLICIT_DENY

    def test_endpoint_policy_explicit_deny_overrides_identity_allow(self, ev):
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        endpoint_policy = {"Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteObject", "Resource": "*"},
        ]}
        assert ev.evaluate(
            _user(), "s3:DeleteObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=endpoint_policy,
        ) == Decision.EXPLICIT_DENY

    def test_endpoint_policy_explicit_deny_is_not_a_bypassable_implicit_deny(self, ev):
        """The bug three independent reviews converged on: treating the
        endpoint policy as only a standalone "must separately Allow" check
        (and never folding it into the Step-1 Deny sweep) makes its explicit
        Deny indistinguishable from IMPLICIT_DENY - and IMPLICIT_DENY, unlike
        EXPLICIT_DENY, can be overridden downstream by the KMS-grant
        fallback in enforcer.py. Asserting the Decision enum value directly
        (not just "is denied") is the point of this test."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "kms:*", "Resource": "*"}]},
        ]
        endpoint_policy = {"Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"},
        ]}
        decision = ev.evaluate(
            _user(), "kms:Decrypt", "arn:aws:kms:us-east-1:000000000000:key/k", {},
            endpoint_policy=endpoint_policy,
        )
        assert decision == Decision.EXPLICIT_DENY
        assert decision != Decision.IMPLICIT_DENY

    def test_endpoint_policy_can_restrict_to_a_specific_principal(self, ev):
        """A common real-world shape: the endpoint policy scopes access to
        one specific role/account, narrower than what identity+resource
        policy would otherwise allow - e.g. a data-exfiltration lab where
        the endpoint should only ever be usable by the intended service
        role, not any caller with a broad identity policy."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        endpoint_policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:user/bob"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert ev.evaluate(
            _user("alice"), "s3:GetObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=endpoint_policy,
        ) == Decision.IMPLICIT_DENY
        assert ev.evaluate(
            _user("bob"), "s3:GetObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=endpoint_policy,
        ) == Decision.ALLOW

    def test_endpoint_policy_missing_principal_on_allow_does_not_grant(self, ev):
        """Same fail-closed Principal semantics as resource policies (Bug
        #2) apply to endpoint policies - they're resource-shaped too."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        endpoint_policy = {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},  # no Principal
        ]}
        assert ev.evaluate(
            _user(), "s3:GetObject", "arn:aws:s3:::b/k", {},
            endpoint_policy=endpoint_policy,
        ) == Decision.IMPLICIT_DENY

    def test_no_endpoint_policy_is_unaffected(self, ev):
        """endpoint_policy=None (the default - a request that didn't arrive
        through a VPC endpoint) must behave identically to before this
        feature existed."""
        ev._fixtures["identity"] = [
            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        ]
        assert ev.evaluate(_user(), "s3:GetObject", "arn:aws:s3:::b/k", {}) == Decision.ALLOW
