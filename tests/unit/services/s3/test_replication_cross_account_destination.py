"""Pin BUG-006: PutBucketReplication's destination-versioning check must
walk the cross-account bucket resolver, not just the source account's
local bucket dict.

Before the fix, ``put_bucket_replication`` did
``store.buckets.get(dest_bucket_name)`` on the SOURCE account's S3
store. When the destination bucket lived in a different account and
the request named that owner via ``Destination.Account``, the lookup
returned None and the validator raised
``InvalidRequest("Destination bucket must have versioning enabled.")``
even when the destination was genuinely versioned (and
``GetBucketVersioning`` on it returned ``Enabled``).

The fix routes through ``_get_cross_account_bucket`` — the same
resolver every other cross-account read path uses — which walks
``global_bucket_map`` (a ``CrossAccountAttribute`` shared across every
account's S3 store) to find the owning account's store. This pin
ensures the two layers stay aligned.
"""
from __future__ import annotations

import boto3
import pytest
from moto.core.models import DEFAULT_ACCOUNT_ID


_AK_ROOT = "AKIAIOSFODNN7EXAMPLE"
_SK_ROOT = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_AK_B = "999999999999"  # 12-digit access key → account id "999999999999"
_REGION = "us-east-1"


def _client(svc: str, ak: str, sk: str = "any"):
    """Build a boto3 client against the in-process moto layer. We use
    moto's ``mock_aws`` decorator in each test instead of a module-level
    server — the S3Provider helpers we exercise need a live store
    backing the access keys, but moto's in-process intercept is enough.
    """
    return boto3.client(
        svc, endpoint_url="http://localhost:4566",  # not used under mock_aws
        region_name=_REGION,
        aws_access_key_id=ak, aws_secret_access_key=sk,
    )


def _reset_s3_stores():
    """Wipe LocalEmu's S3 stores so each test starts from a clean
    cross-account state."""
    from localemu.services.s3.models import s3_stores
    s3_stores.reset()


@pytest.fixture(autouse=True)
def _isolation():
    _reset_s3_stores()
    yield
    _reset_s3_stores()


def _make_rule(dest_bucket_arn: str, dest_account: str | None = None) -> dict:
    dest: dict = {"Bucket": dest_bucket_arn}
    if dest_account:
        dest["Account"] = dest_account
    return {
        "Role": f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:role/r",
        "Rules": [{
            "ID": "r", "Status": "Enabled", "Priority": 1, "Filter": {},
            "DeleteMarkerReplication": {"Status": "Disabled"},
            "Destination": dest,
        }],
    }


# ---------------------------------------------------------------------------
# Tests use the in-process S3Provider directly with a live moto store —
# the wire layer (HTTP) is not what's being pinned; the validator's
# bucket resolution is.
# ---------------------------------------------------------------------------


class _FakeContext:
    """Minimal RequestContext stand-in for the provider's helpers.
    Provides only ``account_id`` and ``region`` — the two fields
    ``_get_cross_account_bucket`` reads."""
    def __init__(self, account_id: str, region: str = _REGION):
        self.account_id = account_id
        self.region = region


def _make_bucket(account_id: str, name: str, *, versioning: bool):
    """Create a bucket directly in the moto store under ``account_id``,
    optionally with versioning enabled. Returns the resulting
    ``S3Bucket`` so tests can inspect attributes."""
    from localemu.services.s3.models import S3Bucket, s3_stores
    from localemu.aws.api.s3 import BucketVersioningStatus

    store = s3_stores[account_id][_REGION]
    # The ``owner`` field is required by S3Bucket.__init__ and used for
    # display-only purposes (Owner.ID + Owner.DisplayName in ListBuckets
    # responses). Synthesise a minimal one — the validator never reads
    # it, so a fixed placeholder keeps the test reproducible.
    owner = {"ID": account_id, "DisplayName": f"acct-{account_id}"}
    bucket = S3Bucket(
        name=name, account_id=account_id, bucket_region=_REGION,
        owner=owner,
    )
    if versioning:
        bucket.versioning_status = BucketVersioningStatus.Enabled
    store.buckets[name] = bucket
    store.global_bucket_map[name] = account_id
    return bucket


# ---------------------------------------------------------------------------
# The bug repro and its inverse
# ---------------------------------------------------------------------------


def test_cross_account_versioned_destination_is_accepted():
    """The exact shape of BUG-006: source in account A, destination in
    account B with versioning enabled, and ``Destination.Account``
    names B. After the fix this must succeed without raising."""
    from localemu.services.s3.provider import S3Provider
    from localemu.aws.api.s3 import BucketVersioningStatus

    src = _make_bucket(DEFAULT_ACCOUNT_ID, "src-real", versioning=True)
    _make_bucket("999999999999", "b-dst-real", versioning=True)

    provider = S3Provider()
    rule_cfg = _make_rule(
        "arn:aws:s3:::b-dst-real", dest_account="999999999999",
    )
    ctx = _FakeContext(DEFAULT_ACCOUNT_ID)

    # Must not raise InvalidRequest("Destination bucket must have versioning enabled.")
    provider.put_bucket_replication(
        context=ctx, bucket="src-real",
        replication_configuration=rule_cfg,
    )
    # And the rule was persisted on the source bucket
    assert src.replication == rule_cfg


def test_same_account_versioned_destination_still_accepted():
    """Control case from the bug doc — the pre-fix path that worked
    must keep working. Source and versioned destination both in
    account A."""
    from localemu.services.s3.provider import S3Provider

    _make_bucket(DEFAULT_ACCOUNT_ID, "src-real", versioning=True)
    _make_bucket(DEFAULT_ACCOUNT_ID, "a-dst-versioned", versioning=True)

    rule_cfg = _make_rule("arn:aws:s3:::a-dst-versioned")
    S3Provider().put_bucket_replication(
        context=_FakeContext(DEFAULT_ACCOUNT_ID), bucket="src-real",
        replication_configuration=rule_cfg,
    )


def test_cross_account_unversioned_destination_is_rejected():
    """The fix must not loosen the AWS rule. Destination owned by
    account B but versioning OFF — same InvalidRequest as before."""
    from localemu.services.s3.provider import S3Provider
    from localemu.aws.api import CommonServiceException

    _make_bucket(DEFAULT_ACCOUNT_ID, "src-real", versioning=True)
    _make_bucket("999999999999", "b-dst-unversioned", versioning=False)

    rule_cfg = _make_rule(
        "arn:aws:s3:::b-dst-unversioned", dest_account="999999999999",
    )
    with pytest.raises(
        Exception, match="Destination bucket must have versioning enabled",
    ):
        S3Provider().put_bucket_replication(
            context=_FakeContext(DEFAULT_ACCOUNT_ID), bucket="src-real",
            replication_configuration=rule_cfg,
        )


def test_missing_destination_bucket_is_rejected_with_aws_shaped_error():
    """AWS collapses 'destination does not exist' and 'destination
    unversioned' into the same ``InvalidRequest`` — we preserve that
    parity even when the resolution path was widened to cross-account."""
    from localemu.services.s3.provider import S3Provider

    _make_bucket(DEFAULT_ACCOUNT_ID, "src-real", versioning=True)

    rule_cfg = _make_rule("arn:aws:s3:::ghost-bucket")
    with pytest.raises(
        Exception, match="Destination bucket must have versioning enabled",
    ):
        S3Provider().put_bucket_replication(
            context=_FakeContext(DEFAULT_ACCOUNT_ID), bucket="src-real",
            replication_configuration=rule_cfg,
        )


def test_same_account_unversioned_destination_is_rejected():
    """The original pre-fix rejection case for completeness — source
    and destination in account A, destination unversioned."""
    from localemu.services.s3.provider import S3Provider

    _make_bucket(DEFAULT_ACCOUNT_ID, "src-real", versioning=True)
    _make_bucket(DEFAULT_ACCOUNT_ID, "a-dst-unversioned", versioning=False)

    rule_cfg = _make_rule("arn:aws:s3:::a-dst-unversioned")
    with pytest.raises(
        Exception, match="Destination bucket must have versioning enabled",
    ):
        S3Provider().put_bucket_replication(
            context=_FakeContext(DEFAULT_ACCOUNT_ID), bucket="src-real",
            replication_configuration=rule_cfg,
        )


# ---------------------------------------------------------------------------
# Sanity pin for the resolver itself — the layer the validator relies on
# ---------------------------------------------------------------------------


def test_get_cross_account_bucket_walks_global_bucket_map():
    """The resolver walks ``global_bucket_map`` (CrossAccountAttribute,
    truly shared across every account-region store) to find a bucket
    owned by another account. If THIS test ever flips, the fix's
    foundation is gone and put_bucket_replication will silently
    regress."""
    from localemu.services.s3.provider import S3Provider
    from localemu.aws.api.s3 import BucketVersioningStatus

    _make_bucket("999999999999", "b-dst-real", versioning=True)

    provider = S3Provider()
    ctx = _FakeContext(DEFAULT_ACCOUNT_ID)
    _, b = provider._get_cross_account_bucket(ctx, "b-dst-real")

    assert b.bucket_account_id == "999999999999"
    assert b.versioning_status == BucketVersioningStatus.Enabled
