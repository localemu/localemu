"""End-to-end tests for the EBS direct API.

These tests run against a live LocalEmu instance and cover:

* The full direct-API write/read path
  (``StartSnapshot`` -> ``PutSnapshotBlock`` -> ``CompleteSnapshot`` ->
  ``GetSnapshotBlock`` -> ``ListSnapshotBlocks``).
* The reproduction: ``ebs:ListSnapshotBlocks`` on a snapshot
  created via ``ec2:CreateSnapshot`` no longer raises ``InternalError``.
* The "Snapshot Heist" data path: PutSnapshotBlock -> CreateVolume from
  snapshot -> take another snapshot of the restored volume -> blocks
  survive.
* ``ListChangedBlocks`` returns the right diff between two snapshots.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _read_block_payload(resp) -> bytes:
    """``GetSnapshotBlock`` returns ``BlockData`` as a StreamingBody."""
    body = resp.get("BlockData")
    if body is None:
        return b""
    if hasattr(body, "read"):
        return body.read()
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return body.encode("utf-8") if isinstance(body, str) else b""


# ---------------------------------------------------------------------------
# Full direct-API round trip
# ---------------------------------------------------------------------------


def test_direct_api_round_trip_via_start_put_complete_get(ebs_client):
    """The canonical direct-API workflow: open snapshot, write a block,
    complete, read it back."""
    desc = f"e2e-{uuid.uuid4().hex[:8]}"
    start = ebs_client.start_snapshot(VolumeSize=1, Description=desc)
    snapshot_id = start["SnapshotId"]
    assert start.get("Status") == "pending"

    raw = b"first-block-of-bytes" * 16
    put = ebs_client.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=raw,
        DataLength=len(raw),
        Checksum=_sha256_b64(raw),
        ChecksumAlgorithm="SHA256",
    )
    assert put["Checksum"] == _sha256_b64(raw)

    done = ebs_client.complete_snapshot(SnapshotId=snapshot_id)
    assert done["Status"] == "completed"

    got = ebs_client.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken="any",
    )
    assert _read_block_payload(got) == raw
    assert got["Checksum"] == _sha256_b64(raw)


def test_list_snapshot_blocks_returns_all_indexes(ebs_client):
    start = ebs_client.start_snapshot(VolumeSize=1)
    snap = start["SnapshotId"]
    raw = b"x"
    for idx in [0, 5, 3]:
        ebs_client.put_snapshot_block(
            SnapshotId=snap, BlockIndex=idx,
            BlockData=raw, DataLength=len(raw),
            Checksum=_sha256_b64(raw), ChecksumAlgorithm="SHA256",
        )
    ebs_client.complete_snapshot(SnapshotId=snap)
    listed = ebs_client.list_snapshot_blocks(SnapshotId=snap)
    indexes = sorted(b["BlockIndex"] for b in listed["Blocks"])
    assert indexes == [0, 3, 5]


# ---------------------------------------------------------------------------
# reproduction: list_snapshot_blocks on an ec2:CreateSnapshot snapshot
# ---------------------------------------------------------------------------


def test_pr005_reproduction_ec2_created_snapshot_is_visible_to_ebs_api(
    ebs_client, ec2_client,
):
    """``ListSnapshotBlocks`` raised ``InternalError``
    because the snapshot wasn't in the EBS backend's dict. After the
    fix the bridge registers a mirror entry, so the direct API can
    list it (empty if the source volume had no blocks)."""
    vol = ec2_client.create_volume(
        AvailabilityZone="us-east-1a", Size=1,
    )["VolumeId"]
    try:
        snap = ec2_client.create_snapshot(
            VolumeId=vol, Description="e2e-bridge",
        )["SnapshotId"]
        try:
            # The exact line that used to raise InternalError.
            listed = ebs_client.list_snapshot_blocks(SnapshotId=snap)
            assert "Blocks" in listed  # may be empty for an empty source volume
        finally:
            ec2_client.delete_snapshot(SnapshotId=snap)
    finally:
        ec2_client.delete_volume(VolumeId=vol)


# ---------------------------------------------------------------------------
# Snapshot Heist: PutSnapshotBlock -> CreateVolume from snapshot ->
# re-snapshot -> data inherits
# ---------------------------------------------------------------------------


def test_snapshot_heist_data_survives_restore_and_resnapshot(
    ebs_client, ec2_client,
):
    """The full attack path: an attacker puts a block via the
    direct API, restores it via CreateVolume, then takes a new
    snapshot of the restored volume and reads the same bytes back."""
    secret = b"victims-disk-bytes" + uuid.uuid4().bytes

    # 1. Build a snapshot via the direct API and write a secret block.
    src_snap = ebs_client.start_snapshot(VolumeSize=1)["SnapshotId"]
    ebs_client.put_snapshot_block(
        SnapshotId=src_snap,
        BlockIndex=0, BlockData=secret, DataLength=len(secret),
        Checksum=_sha256_b64(secret), ChecksumAlgorithm="SHA256",
    )
    ebs_client.complete_snapshot(SnapshotId=src_snap)

    # 2. Restore the snapshot as a new volume.
    restored_vol = ec2_client.create_volume(
        AvailabilityZone="us-east-1a", Size=1, SnapshotId=src_snap,
    )["VolumeId"]

    try:
        # 3. Take a new snapshot of the restored volume.
        new_snap = ec2_client.create_snapshot(
            VolumeId=restored_vol, Description="heist",
        )["SnapshotId"]
        try:
            # 4. Read block 0 from the new snapshot - must be the secret.
            got = ebs_client.get_snapshot_block(
                SnapshotId=new_snap, BlockIndex=0, BlockToken="any",
            )
            assert _read_block_payload(got) == secret, (
                "blocks did not survive the snapshot -> restore -> snapshot "
                "round trip; the Snapshot Heist scenario is still blocked"
            )
        finally:
            ec2_client.delete_snapshot(SnapshotId=new_snap)
    finally:
        ec2_client.delete_volume(VolumeId=restored_vol)
        # Cleanup the upstream snapshot too - ec2:CreateVolume(SnapshotId=)
        # creates a moto-side mirror, but the direct-API snapshot we
        # started with also needs an ec2:DeleteSnapshot to fully tear down.
        try:
            ec2_client.delete_snapshot(SnapshotId=src_snap)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ListChangedBlocks
# ---------------------------------------------------------------------------


def test_list_changed_blocks_reports_added_and_modified_blocks(ebs_client):
    """A diff between two snapshots reports the right shape."""
    a = ebs_client.start_snapshot(VolumeSize=1)["SnapshotId"]
    ebs_client.put_snapshot_block(
        SnapshotId=a, BlockIndex=0, BlockData=b"X", DataLength=1,
        Checksum=_sha256_b64(b"X"), ChecksumAlgorithm="SHA256",
    )
    ebs_client.put_snapshot_block(
        SnapshotId=a, BlockIndex=1, BlockData=b"Y", DataLength=1,
        Checksum=_sha256_b64(b"Y"), ChecksumAlgorithm="SHA256",
    )
    ebs_client.complete_snapshot(SnapshotId=a)

    b = ebs_client.start_snapshot(VolumeSize=1)["SnapshotId"]
    ebs_client.put_snapshot_block(
        SnapshotId=b, BlockIndex=0, BlockData=b"Z", DataLength=1,  # changed
        Checksum=_sha256_b64(b"Z"), ChecksumAlgorithm="SHA256",
    )
    ebs_client.put_snapshot_block(
        SnapshotId=b, BlockIndex=2, BlockData=b"N", DataLength=1,  # new
        Checksum=_sha256_b64(b"N"), ChecksumAlgorithm="SHA256",
    )
    ebs_client.complete_snapshot(SnapshotId=b)

    resp = ebs_client.list_changed_blocks(
        FirstSnapshotId=a, SecondSnapshotId=b,
    )
    changed_indexes = sorted(c["BlockIndex"] for c in resp["ChangedBlocks"])
    # block 0 changed (in both), block 1 in a only (added-or-removed)
    assert 0 in changed_indexes
    assert 1 in changed_indexes
