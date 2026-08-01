"""``DescribeSnapshots`` must honour ``OwnerIds``.

moto's own response handler for ``DescribeSnapshots`` never reads the
``OwnerIds`` request field, so any inventory-style caller passing
``OwnerIds=['self']`` or ``OwnerIds=['<caller-account-id>']`` gets the
whole seeded AMI catalog back (~1177 snapshots in ``us-east-1``,
generated because every seeded AMI auto-creates a backing snapshot
owned by the AMI's own owner). Tools like ``awsmap`` report ~19,821
phantom snapshot rows on empty accounts across 17 regions.

LocalEmu's patch resolves ``self`` to the caller account id, matches
raw account ids against ``snapshot.owner_id``, and matches
``"amazon"`` / ``"aws-marketplace"`` aliases via the AMI's
``owner_alias`` (snapshot ``from_ami`` -> AMI in the backend). If
``OwnerIds`` is absent the filter is not applied - regression-safe
for callers that intentionally want the full catalog.
"""
from __future__ import annotations

import boto3
import pytest

# Applies the LocalEmu patches, including the DescribeSnapshots filter.
import localemu.services.ec2.patches as _ec2_patches  # noqa: F401

# Patch registration happens as a side effect of importing apply_patches
# BODY (which is what @patch decorates inside). We must actually call it.
_ec2_patches.apply_patches()

# moto's default account under ``@mock_aws`` (matches
# ``moto.core.DEFAULT_ACCOUNT_ID``). LocalEmu itself defaults to
# "000000000000", but these tests exercise the patched moto handler
# directly through the moto mock; account resolution therefore happens
# inside moto and uses its default.
_CALLER_ACCOUNT = "123456789012"


@pytest.fixture(autouse=True)
def _mock_aws_context():
    """Wrap each test in ``@mock_aws`` - the mock spins up a fresh moto
    backend so the seeded AMI catalog is present and consistent across
    tests.
    """
    from moto import mock_aws

    with mock_aws():
        yield


def _ec2_client():
    return boto3.client("ec2", region_name="us-east-1")


def _count(resp) -> int:
    return len(resp.get("Snapshots", []))


def test_no_owner_filter_returns_full_seeded_catalog():
    """Regression check : without ``OwnerIds`` the caller still gets the
    entire seeded catalog. Prior behaviour must be preserved.
    """
    resp = _ec2_client().describe_snapshots()
    # moto's us-east-1 seeded catalog is ~1177 snapshots. Assert lower
    # bound to stay robust across moto version bumps.
    assert _count(resp) >= 100


def test_owner_ids_fresh_account_gets_zero_seeded_snapshots():
    """The whole point : an empty account filtering by
    ``OwnerIds=['000000000000']`` (or any account id that owns nothing
    in the seeded catalog) gets 0 snapshots back. Not 1177.
    """
    resp = _ec2_client().describe_snapshots(OwnerIds=["000000000000"])
    assert _count(resp) == 0


def test_owner_ids_self_alias_returns_zero_on_fresh_account():
    """``self`` resolves to the caller's account. On a fresh account
    (nothing created yet) that yields 0 - none of the seeded 1177
    are owned by the caller.
    """
    resp = _ec2_client().describe_snapshots(OwnerIds=["self"])
    assert _count(resp) == 0


def test_owner_ids_amazon_alias_returns_seeded_catalog_slice():
    """AWS-seeded AMIs carry ``owner_alias='amazon'``. Their auto-created
    snapshots must be reachable via ``OwnerIds=['amazon']``.
    """
    resp = _ec2_client().describe_snapshots(OwnerIds=["amazon"])
    # amazon-owned slice varies with moto version; assert non-zero to
    # prove the alias resolution works, without over-fitting the count.
    assert _count(resp) >= 1


def test_own_snapshot_visible_via_caller_owner_id():
    """A snapshot the caller creates must be returned by
    ``OwnerIds=[<caller>]`` and by ``OwnerIds=['self']``.
    """
    ec2 = _ec2_client()
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"])

    resp_self = ec2.describe_snapshots(OwnerIds=["self"])
    ids_self = {s["SnapshotId"] for s in resp_self["Snapshots"]}
    assert snap["SnapshotId"] in ids_self, sorted(ids_self)

    resp_by_acct = ec2.describe_snapshots(OwnerIds=[_CALLER_ACCOUNT])
    ids_by_acct = {s["SnapshotId"] for s in resp_by_acct["Snapshots"]}
    assert snap["SnapshotId"] in ids_by_acct


def test_owner_ids_unknown_account_returns_empty():
    """A random account id that owns no seeded snapshots yields 0."""
    resp = _ec2_client().describe_snapshots(OwnerIds=["999999999999"])
    assert _count(resp) == 0


def test_snapshot_ids_filter_still_works_alongside_owner_ids():
    """``SnapshotIds`` scoping must still work when combined with
    ``OwnerIds``. We create our own snapshot then ask for it by id +
    by caller account.
    """
    ec2 = _ec2_client()
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=8)
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"])

    resp = ec2.describe_snapshots(
        SnapshotIds=[snap["SnapshotId"]],
        OwnerIds=["self"],
    )
    assert _count(resp) == 1
    assert resp["Snapshots"][0]["SnapshotId"] == snap["SnapshotId"]
