"""Unit tests for the account/region rewrite phase."""

from __future__ import annotations

from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.rewrite import LOCALEMU_DEFAULT_ACCOUNT, rewrite_snapshot


def _snap(*resources: Resource) -> Snapshot:
    return Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=list(resources),
    )


def test_rewrites_account_id_in_arn() -> None:
    r = Resource(
        service="iam",
        resource_type="role",
        resource_id="r",
        account_id=LOCALEMU_DEFAULT_ACCOUNT,
        region="us-east-1",
        attributes={"arn": f"arn:aws:iam::{LOCALEMU_DEFAULT_ACCOUNT}:role/r"},
    )
    out = rewrite_snapshot(_snap(r), "123456789012", "us-east-1")
    assert out.resources[0].attributes["arn"] == "arn:aws:iam::123456789012:role/r"
    assert out.resources[0].account_id == "123456789012"


def test_preserves_empty_account_segment_in_s3_arn() -> None:
    # S3 ARNs carry an empty account segment; rewriting it to a real
    # account would break every consumer.
    r = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="b",
        account_id=LOCALEMU_DEFAULT_ACCOUNT,
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::b"},
    )
    out = rewrite_snapshot(_snap(r), "123456789012", "us-east-1")
    assert out.resources[0].attributes["arn"] == "arn:aws:s3:::b"


def test_rewrites_region_in_matching_arns_only() -> None:
    r = Resource(
        service="lambda",
        resource_type="function",
        resource_id="f",
        account_id=LOCALEMU_DEFAULT_ACCOUNT,
        region="us-east-1",
        attributes={
            "arn": f"arn:aws:lambda:us-east-1:{LOCALEMU_DEFAULT_ACCOUNT}:function:f",
            "cross_region": (
                f"arn:aws:lambda:eu-west-1:{LOCALEMU_DEFAULT_ACCOUNT}:function:g"
            ),
        },
    )
    out = rewrite_snapshot(_snap(r), "123456789012", "ap-south-1")
    # The resource's home-region ARN gets rewritten.
    assert out.resources[0].attributes["arn"] == (
        "arn:aws:lambda:ap-south-1:123456789012:function:f"
    )
    # Cross-region ARNs keep their own region.
    assert out.resources[0].attributes["cross_region"] == (
        "arn:aws:lambda:eu-west-1:123456789012:function:g"
    )


def test_rewrites_bare_account_id_exact_match_only() -> None:
    r = Resource(
        service="iam",
        resource_type="policy",
        resource_id="p",
        account_id=LOCALEMU_DEFAULT_ACCOUNT,
        region="us-east-1",
        attributes={
            "principal_exact": LOCALEMU_DEFAULT_ACCOUNT,
            "substring": f"prefix-{LOCALEMU_DEFAULT_ACCOUNT}-suffix",
        },
    )
    out = rewrite_snapshot(_snap(r), "123456789012", "us-east-1")
    assert out.resources[0].attributes["principal_exact"] == "123456789012"
    # A substring is NOT an account id; rewriting it would corrupt data.
    assert (
        out.resources[0].attributes["substring"]
        == f"prefix-{LOCALEMU_DEFAULT_ACCOUNT}-suffix"
    )
