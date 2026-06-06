"""Unit tests for the managed-policy and permission-boundary document
resolution in the IAM enforcement gather step (BUG-001).

Before the fix, ``_get_managed_policy_doc`` read a non-existent attribute
(``policy.default_version``) on moto's ``ManagedPolicy``, silently returning
``None`` for every attached managed policy and every managed permission
boundary. That dropped all of:

* user-attached managed policies
* role-attached managed policies
* group-attached managed policies (user-in-group inheritance)
* managed permission boundaries on users and roles
* AWS-managed policies (``arn:aws:iam::aws:policy/...``)

from the principal's effective policy set, so enforcement was effectively
inline-only.

These tests exercise the real moto backend (no monkey-patching of the gather
functions) to make sure the bug stays fixed.
"""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from localemu.services.iam_enforcement.identity import (
    CallerIdentity,
    _extract_boundary_arn,
    _get_managed_policy_doc,
    get_identity_policies,
    get_permission_boundary,
)

NARROW_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::demo-bucket/*",
        }
    ],
}


def _backend_for(arn: str):
    """Return the moto iam backend that owns the given ARN."""
    from moto.iam.models import iam_backends

    account = arn.split(":")[4] or "123456789012"
    return iam_backends[account]["global"]


def _iam():
    return boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


# ---------- _get_managed_policy_doc (the function the bug lives in) ----------


@mock_aws
def test_get_managed_policy_doc_returns_default_version_document():
    """The bug: this used to return None for every managed policy."""
    iam = _iam()
    arn = iam.create_policy(
        PolicyName="t1", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]

    doc = _get_managed_policy_doc(_backend_for(arn), arn)

    assert doc is not None, "_get_managed_policy_doc returned None for a known policy"
    assert doc["Version"] == "2012-10-17"
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


@mock_aws
def test_get_managed_policy_doc_returns_none_for_unknown_arn():
    iam = _iam()
    # Force the backend into existence for this account so the lookup runs.
    iam.list_policies(Scope="Local")
    arn = "arn:aws:iam::123456789012:policy/does-not-exist"
    assert _get_managed_policy_doc(_backend_for(arn), arn) is None


@mock_aws
def test_get_managed_policy_doc_returns_latest_when_default_id_missing():
    """Defensive fallback: if the default_version_id does not match any
    version (e.g. a stale id), return the most recent version's document
    instead of crashing or returning None."""
    iam = _iam()
    arn = iam.create_policy(
        PolicyName="t2", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]

    backend = _backend_for(arn)
    policy = backend.managed_policies[arn]
    # Sabotage the default version id so no version matches.
    policy.default_version_id = "vSTALE"

    doc = _get_managed_policy_doc(backend, arn)
    assert doc is not None
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


# ---------- get_identity_policies: full gather through real attachments ----------


@mock_aws
def test_get_identity_policies_includes_user_attached_managed_policy():
    iam = _iam()
    iam.create_user(UserName="alice")
    arn = iam.create_policy(
        PolicyName="p-user", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]
    iam.attach_user_policy(UserName="alice", PolicyArn=arn)

    caller = CallerIdentity(
        principal_type="User",
        account_id=arn.split(":")[4],
        arn=f"arn:aws:iam::{arn.split(':')[4]}:user/alice",
        username="alice",
    )
    docs = get_identity_policies(caller)
    assert any(
        d.get("Statement", [{}])[0].get("Action") == ["s3:GetObject"] for d in docs
    ), f"attached managed policy missing from gathered docs: {docs!r}"


@mock_aws
def test_get_identity_policies_includes_role_attached_managed_policy():
    iam = _iam()
    iam.create_role(
        RoleName="bot",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    arn = iam.create_policy(
        PolicyName="p-role", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="bot", PolicyArn=arn)

    account = arn.split(":")[4]
    caller = CallerIdentity(
        principal_type="AssumedRole",
        account_id=account,
        arn=f"arn:aws:sts::{account}:assumed-role/bot/sess",
        role_name="bot",
        session_name="sess",
    )
    docs = get_identity_policies(caller)
    assert any(
        d.get("Statement", [{}])[0].get("Action") == ["s3:GetObject"] for d in docs
    )


@mock_aws
def test_get_identity_policies_includes_group_attached_managed_policy():
    iam = _iam()
    iam.create_group(GroupName="devs")
    arn = iam.create_policy(
        PolicyName="p-group", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]
    iam.attach_group_policy(GroupName="devs", PolicyArn=arn)
    iam.create_user(UserName="bob")
    iam.add_user_to_group(UserName="bob", GroupName="devs")

    caller = CallerIdentity(
        principal_type="User",
        account_id=arn.split(":")[4],
        arn=f"arn:aws:iam::{arn.split(':')[4]}:user/bob",
        username="bob",
    )
    docs = get_identity_policies(caller)
    assert any(
        d.get("Statement", [{}])[0].get("Action") == ["s3:GetObject"] for d in docs
    ), f"group-attached managed policy missing: {docs!r}"


@mock_aws
def test_get_identity_policies_still_includes_inline_regression():
    """Inline policies were the only working path before the fix. They must
    still work after it."""
    iam = _iam()
    iam.create_user(UserName="carol")
    iam.put_user_policy(
        UserName="carol",
        PolicyName="inline",
        PolicyDocument=json.dumps(NARROW_DOC),
    )

    from moto.iam.models import iam_backends

    accounts = [a for a, regions in iam_backends.items() if "global" in regions]
    account = accounts[0] if accounts else "123456789012"
    caller = CallerIdentity(
        principal_type="User",
        account_id=account,
        arn=f"arn:aws:iam::{account}:user/carol",
        username="carol",
    )
    docs = get_identity_policies(caller)
    assert any(
        d.get("Statement", [{}])[0].get("Action") == ["s3:GetObject"] for d in docs
    )


# ---------- get_permission_boundary: managed-boundary resolution ----------


@mock_aws
def test_get_permission_boundary_returns_user_boundary_document():
    iam = _iam()
    iam.create_user(UserName="dave")
    arn = iam.create_policy(
        PolicyName="bnd-u", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]
    try:
        iam.put_user_permissions_boundary(UserName="dave", PermissionsBoundary=arn)
    except Exception as e:
        if "not been implemented" in str(e):
            pytest.skip("moto does not implement put_user_permissions_boundary yet")
        raise

    caller = CallerIdentity(
        principal_type="User",
        account_id=arn.split(":")[4],
        arn=f"arn:aws:iam::{arn.split(':')[4]}:user/dave",
        username="dave",
    )
    doc = get_permission_boundary(caller)
    assert doc is not None
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


@mock_aws
def test_get_permission_boundary_returns_role_boundary_document():
    iam = _iam()
    iam.create_role(
        RoleName="bnd-role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    arn = iam.create_policy(
        PolicyName="bnd-r", PolicyDocument=json.dumps(NARROW_DOC)
    )["Policy"]["Arn"]
    iam.put_role_permissions_boundary(RoleName="bnd-role", PermissionsBoundary=arn)

    account = arn.split(":")[4]
    caller = CallerIdentity(
        principal_type="AssumedRole",
        account_id=account,
        arn=f"arn:aws:sts::{account}:assumed-role/bnd-role/sess",
        role_name="bnd-role",
        session_name="sess",
    )
    doc = get_permission_boundary(caller)
    assert doc is not None
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


@mock_aws
def test_get_permission_boundary_returns_none_when_no_boundary_set():
    iam = _iam()
    iam.create_user(UserName="eve")
    caller = CallerIdentity(
        principal_type="User",
        account_id="123456789012",
        arn="arn:aws:iam::123456789012:user/eve",
        username="eve",
    )
    assert get_permission_boundary(caller) is None


# ---------- _extract_boundary_arn: shape-tolerance ----------


def test_extract_boundary_arn_from_string():
    assert (
        _extract_boundary_arn("arn:aws:iam::000000000000:policy/p")
        == "arn:aws:iam::000000000000:policy/p"
    )


def test_extract_boundary_arn_from_api_dict():
    """Moto's ``permissions_boundary`` @property returns this shape."""
    raw = {
        "PermissionsBoundaryArn": "arn:aws:iam::000000000000:policy/p",
        "PermissionsBoundaryType": "Policy",
    }
    assert _extract_boundary_arn(raw) == "arn:aws:iam::000000000000:policy/p"


def test_extract_boundary_arn_returns_none_for_unknown_shape():
    assert _extract_boundary_arn(None) is None
    assert _extract_boundary_arn("") is None
    assert _extract_boundary_arn({}) is None
    assert _extract_boundary_arn({"NotAnArn": "x"}) is None
    assert _extract_boundary_arn(object()) is None
