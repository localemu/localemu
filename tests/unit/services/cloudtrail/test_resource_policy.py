"""Regression tests for Put/Get/DeleteResourcePolicy.

The native implementation validates that the policy is a JSON object with
a non-empty ``Statement`` array. It does NOT evaluate the policy — that's
consistent with AWS's first-pass syntactic validation at Put time.
"""

from __future__ import annotations

import json

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


RESOURCE_ARN = "arn:aws:cloudtrail:us-east-1:000000000000:trail/audit"


def _policy(sid: str = "s1") -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "cloudtrail:LookupEvents",
                "Resource": "*",
            }
        ],
    })


def test_put_and_get_round_trip(ctx):
    native.put_resource_policy(
        ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": _policy()}
    )
    resp = native.get_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})
    assert resp["ResourceArn"] == RESOURCE_ARN
    assert json.loads(resp["ResourcePolicy"])["Statement"][0]["Sid"] == "s1"


def test_put_overwrites_previous(ctx):
    native.put_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": _policy("old")})
    native.put_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": _policy("new")})
    resp = native.get_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})
    assert json.loads(resp["ResourcePolicy"])["Statement"][0]["Sid"] == "new"


def test_get_missing_policy(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.get_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})
    assert exc.value.code == "ResourcePolicyNotFoundException"


def test_delete_removes_policy(ctx):
    native.put_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": _policy()})
    native.delete_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})
    with pytest.raises(CommonServiceException):
        native.get_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})


def test_delete_missing_policy(ctx):
    with pytest.raises(CommonServiceException) as exc:
        native.delete_resource_policy(ctx, {"ResourceArn": RESOURCE_ARN})
    assert exc.value.code == "ResourcePolicyNotFoundException"


@pytest.mark.parametrize(
    "bad_policy",
    [
        "not json at all",
        "[]",  # list, not object
        "null",
        json.dumps({"Version": "2012-10-17"}),  # no Statement
        json.dumps({"Version": "2012-10-17", "Statement": []}),  # empty Statement
        json.dumps({"Version": "2012-10-17", "Statement": "not-a-list"}),
    ],
)
def test_put_rejects_malformed_policy(ctx, bad_policy):
    with pytest.raises(CommonServiceException) as exc:
        native.put_resource_policy(
            ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": bad_policy}
        )
    assert exc.value.code == "ResourcePolicyNotValidException"


def test_put_rejects_empty_policy(ctx):
    # Empty string is rejected earlier by the required-field validator.
    with pytest.raises(CommonServiceException) as exc:
        native.put_resource_policy(
            ctx, {"ResourceArn": RESOURCE_ARN, "ResourcePolicy": ""}
        )
    assert exc.value.code in {"InvalidParameterCombination", "ResourcePolicyNotValidException"}
