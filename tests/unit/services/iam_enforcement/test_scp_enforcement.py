"""Organizations Service Control Policies (SCPs) were previously stored
(moto's native backend) but never consulted during authorization - a Deny
SCP attached to the root/OU/account had zero effect, so any identity with
a permissive IAM policy could still perform the "restricted" action."""
import json

import boto3
from moto import mock_aws

from localemu.services.iam_enforcement.evaluator import Decision, _scp_denies

DENY_DELETE_USER_UNLESS_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "iam:DeleteUser",
        "Resource": "*",
        "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Admin*"}},
    }],
}


def _attach_scp(org_client, root_id: str, doc: dict) -> None:
    policy = org_client.create_policy(
        Content=json.dumps(doc), Description="d", Name="scp", Type="SERVICE_CONTROL_POLICY",
    )
    org_client.attach_policy(
        PolicyId=policy["Policy"]["PolicySummary"]["Id"], TargetId=root_id,
    )


@mock_aws
def test_scp_deny_blocks_the_covered_action_for_a_non_exempt_principal():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]
    _attach_scp(org, root_id, DENY_DELETE_USER_UNLESS_ADMIN)

    assert _scp_denies(
        "123456789012", "iam:DeleteUser", "*",
        {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/attacker"},
    ) is True


@mock_aws
def test_scp_arn_not_like_exemption_lets_the_matching_principal_through():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]
    _attach_scp(org, root_id, DENY_DELETE_USER_UNLESS_ADMIN)

    assert _scp_denies(
        "123456789012", "iam:DeleteUser", "*",
        {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/AdminRole"},
    ) is False


@mock_aws
def test_scp_does_not_cover_unrelated_actions():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]
    _attach_scp(org, root_id, DENY_DELETE_USER_UNLESS_ADMIN)

    assert _scp_denies(
        "123456789012", "iam:ListUsers", "*",
        {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/attacker"},
    ) is False


def test_no_organization_at_all_never_denies():
    """The common case: no org was created. Must be a fast, safe no-op,
    not an exception."""
    assert _scp_denies("000000000000", "iam:DeleteUser", "*", {}) is False


@mock_aws
def test_account_outside_this_org_is_unaffected():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]
    _attach_scp(org, root_id, DENY_DELETE_USER_UNLESS_ADMIN)

    assert _scp_denies(
        "999999999999", "iam:DeleteUser", "*",
        {"aws:PrincipalArn": "arn:aws:iam::999999999999:user/attacker"},
    ) is False


@mock_aws
def test_evaluate_integration_scp_deny_overrides_a_broad_identity_allow(monkeypatch):
    import localemu.services.iam_enforcement.evaluator as mod
    from localemu.services.iam_enforcement.evaluator import PolicyEvaluator
    from localemu.services.iam_enforcement.identity import CallerIdentity

    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]
    _attach_scp(org, root_id, DENY_DELETE_USER_UNLESS_ADMIN)

    monkeypatch.setattr(mod, "get_identity_policies", lambda c: [
        {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]},
    ])
    monkeypatch.setattr(mod, "get_permission_boundary", lambda c: None)
    monkeypatch.setattr(mod, "get_session_policies", lambda c: [])

    caller = CallerIdentity(
        principal_type="User", account_id="123456789012",
        arn="arn:aws:iam::123456789012:user/attacker", username="attacker",
    )
    decision = PolicyEvaluator().evaluate(
        caller, "iam:DeleteUser", "arn:aws:iam::123456789012:user/victim",
        {"aws:PrincipalArn": caller.arn},
    )
    assert decision == Decision.EXPLICIT_DENY
