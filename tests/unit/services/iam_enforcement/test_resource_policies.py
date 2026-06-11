"""Unit tests for the cross-account resource-policy evaluator.

The evaluator powers cross-account decisions for S3 / SQS / SNS / KMS /
Lambda / EventBridge : when the caller is in a different account than
the target resource, the target's resource policy is loaded and walked
to produce ALLOW / EXPLICIT_DENY / NEUTRAL. The new S3-specific
condition keys (``s3:DataAccessPointArn`` etc.) and the AWS-global
condition keys (``aws:PrincipalAccount``, ``aws:ResourceAccount``,
``aws:PrincipalOrgID`` …) are honored.
"""

from __future__ import annotations

import pytest

from localemu.services.iam_enforcement.resource_policies import (
    Decision, ResourceTarget,
    evaluate_resource_policy, evaluate_cross_account,
)


def _target(*, service: str = "s3", name: str = "bucket-x",
            account: str = "222222222222", region: str = "us-east-1",
            key: str | None = None) -> ResourceTarget:
    arn = (f"arn:aws:s3:::{name}/{key}" if key
           else f"arn:aws:s3:::{name}")
    if service != "s3":
        arn = f"arn:aws:{service}:{region}:{account}:{name}"
    return ResourceTarget(
        service=service, arn=arn, account_id=account,
        region=region, name=name,
    )


# --------------------------------------------------------------------------
# Principal matching
# --------------------------------------------------------------------------


class TestPrincipalMatching:
    def test_wildcard_principal_matches_anyone(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "*",
            "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_aws_wildcard_matches_anyone(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "*"},
            "Action": "*", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_aws_root_arn_matches_account_caller(self):
        policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_aws_12_digit_matches_account_caller(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "111111111111"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_aws_specific_arn_matches_caller_arn(self):
        policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111111111111:user/alice"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_aws_arn_list_matches_caller(self):
        policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": [
                "arn:aws:iam::222222222222:root",
                "arn:aws:iam::111111111111:root",
            ]},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_principal_mismatch_no_allow(self):
        policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::555555555555:root"},
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.NEUTRAL


# --------------------------------------------------------------------------
# Action matching
# --------------------------------------------------------------------------


class TestActionMatching:
    def test_action_wildcard_matches_anything(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "*", "Resource": "*",
        }]}
        for action in ("s3:GetObject", "s3:PutObject", "kms:Decrypt"):
            assert evaluate_resource_policy(
                policy, _target(), caller_account="111111111111",
                caller_arn="arn:aws:iam::111111111111:user/alice",
                action=action,
            ) == Decision.ALLOW

    def test_action_exact_match_case_insensitive(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "S3:GETOBJECT", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_action_service_wildcard(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:*", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW
        # Different service -> no match
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="kms:Decrypt",
        ) == Decision.NEUTRAL

    def test_action_list(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*",
        }]}
        for action in ("s3:GetObject", "s3:PutObject"):
            assert evaluate_resource_policy(
                policy, _target(), caller_account="111111111111",
                caller_arn="arn:aws:iam::111111111111:user/alice",
                action=action,
            ) == Decision.ALLOW

    def test_action_no_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:DeleteObject",
        ) == Decision.NEUTRAL


# --------------------------------------------------------------------------
# Resource matching
# --------------------------------------------------------------------------


class TestResourceMatching:
    def test_resource_wildcard(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "*", "Resource": "*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_resource_exact_arn_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "*",
            "Resource": "arn:aws:s3:::x/k",
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_resource_glob_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "*",
            "Resource": "arn:aws:s3:::x/*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="path/to/k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_resource_no_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "*", "Resource": "arn:aws:s3:::other/*",
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.NEUTRAL


# --------------------------------------------------------------------------
# Effect ordering : explicit Deny beats Allow
# --------------------------------------------------------------------------


class TestEffectOrdering:
    def test_explicit_deny_wins_over_allow(self):
        policy = {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
            {"Effect": "Deny",  "Principal": "*", "Action": "*", "Resource": "*"},
        ]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.EXPLICIT_DENY

    def test_explicit_deny_wins_regardless_of_order(self):
        policy = {"Statement": [
            {"Effect": "Deny",  "Principal": "*", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
        ]}
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.EXPLICIT_DENY

    def test_no_matching_statement_is_neutral(self):
        policy = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::555555555555:root"},
            "Action": "*", "Resource": "*",
        }]}
        # Caller is not the principal -> no Allow, no Deny -> NEUTRAL
        assert evaluate_resource_policy(
            policy, _target(), caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.NEUTRAL


# --------------------------------------------------------------------------
# Condition keys (focus on the new org / account keys)
# --------------------------------------------------------------------------


class TestConditionKeys:
    def test_principal_org_id_match_allows(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::x/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-acme"}},
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject", caller_org_id="o-acme",
        ) == Decision.ALLOW

    def test_principal_org_id_mismatch_does_not_allow(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-acme"}},
        }]}
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject", caller_org_id="o-different",
        ) == Decision.NEUTRAL

    def test_principal_account_condition_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*",
            "Condition": {"StringEquals": {"aws:PrincipalAccount": "111111111111"}},
        }]}
        # The evaluator's default condition_context populates
        # aws:PrincipalAccount from the caller; we don't pass it
        # explicitly to confirm the auto-population path.
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_resource_account_condition_match(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*",
            "Condition": {"StringEquals": {"aws:ResourceAccount": "222222222222"}},
        }]}
        # aws:ResourceAccount auto-populated from target.account_id
        assert evaluate_resource_policy(
            policy, _target(name="x", key="k", account="222222222222"),
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW


# --------------------------------------------------------------------------
# evaluate_cross_account top-level entry
# --------------------------------------------------------------------------


class TestEvaluateCrossAccount:
    def test_same_account_returns_neutral_immediately(self):
        # Same account -> evaluator must not attempt a resource policy load
        # (which could otherwise raise on a missing backend).
        assert evaluate_cross_account(
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            target=_target(account="111111111111"),
            action="s3:GetObject",
        ) == Decision.NEUTRAL

    def test_unknown_service_returns_neutral(self):
        # A service not in the loader map (e.g. "foo") -> NEUTRAL,
        # never crash.
        target = ResourceTarget(
            service="foo", arn="arn:aws:foo:::r",
            account_id="222222222222", region="us-east-1", name="r",
        )
        assert evaluate_cross_account(
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            target=target, action="foo:DoThing",
        ) == Decision.NEUTRAL
