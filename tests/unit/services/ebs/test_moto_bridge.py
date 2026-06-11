"""Unit tests for the moto-ec2 → LocalEmu-block-store bridge.

These run against a fresh ``moto.ec2.models.EC2Backend`` so we can
exercise the patched ``create_snapshot`` / ``create_volume`` /
``delete_snapshot`` / ``delete_volume`` directly without spinning up
boto, the gateway, or a LocalEmu service runtime.
"""
from __future__ import annotations

import pytest

from localemu.services.ebs import block_store
from localemu.services.ebs.moto_bridge import apply_patches


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path):
    """Re-root the block store per test."""
    block_store.set_root(tmp_path / "ebs")
    block_store._locks.clear()
    yield
    block_store.reset_for_tests()


@pytest.fixture(autouse=True)
def _apply_bridge_patches():
    apply_patches()


@pytest.fixture
def ec2_backend():
    """A fresh moto EC2 backend for each test.

    moto's ``ec2_backends`` is a global ``BackendDict``; we use a
    distinct (account, region) per test invocation so state from one
    test never bleeds into another.
    """
    import uuid as _uuid
    from moto.ec2.models import ec2_backends

    region = "us-east-1"
    account_id = str(int(_uuid.uuid4().int % 10_000_000_000)).zfill(12)
    return ec2_backends[account_id][region]


# ---------------------------------------------------------------------------
# ec2:CreateSnapshot → block-store entry
# ---------------------------------------------------------------------------


def test_ec2_create_snapshot_registers_block_store_entry(ec2_backend):
    vol = ec2_backend.create_volume(size=4, zone_name="us-east-1a")
    snap = ec2_backend.create_snapshot(
        volume_id=vol.id, description="test",
    )
    meta = block_store.read_snapshot_meta(snap.id)
    assert meta.snapshot_id == snap.id
    assert meta.volume_size_gib == 4
    assert meta.status == "completed"  # ec2:CreateSnapshot is one-shot
    assert meta.description == "test"


def test_ec2_create_snapshot_copies_volume_blocks(ec2_backend):
    """When the source volume already has blocks (e.g. from a prior
    ``CreateVolume --snapshot-id``), the new snapshot inherits them."""
    vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    block_store.put_volume_block(
        volume_id=vol.id, block_index=0, block_data=b"hello",
    )
    block_store.put_volume_block(
        volume_id=vol.id, block_index=1, block_data=b"world",
    )

    snap = ec2_backend.create_snapshot(volume_id=vol.id, description="")
    listed = block_store.list_snapshot_blocks(snap.id)
    assert [r.block_index for r in listed] == [0, 1]
    data, _ = block_store.get_snapshot_block(
        snapshot_id=snap.id, block_index=0,
    )
    assert data == b"hello"


def test_ec2_create_snapshot_with_empty_volume_makes_empty_snapshot(ec2_backend):
    vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    snap = ec2_backend.create_snapshot(volume_id=vol.id, description="")
    assert block_store.list_snapshot_blocks(snap.id) == []


# ---------------------------------------------------------------------------
# ec2:CreateVolume --snapshot-id → inherits blocks
# ---------------------------------------------------------------------------


def test_ec2_create_volume_from_snapshot_inherits_blocks(ec2_backend):
    """The full Snapshot Heist data path: write blocks via the EBS
    direct API into a source snapshot, restore it via CreateVolume,
    and the restored volume's backing store must mirror the blocks."""
    # Build a snapshot the EBS direct API way: create a fresh snapshot
    # via the block store (we don't have a Python-level start_snapshot
    # in this test scope) and populate it.
    src_vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    src_snap = ec2_backend.create_snapshot(volume_id=src_vol.id, description="")

    block_store.put_snapshot_block(
        snapshot_id=src_snap.id, block_index=0,
        block_data=b"secret-data",
    )

    # Restore the snapshot as a new volume.
    new_vol = ec2_backend.create_volume(
        size=1, zone_name="us-east-1a", snapshot_id=src_snap.id,
    )

    listed = block_store.list_volume_blocks(new_vol.id)
    assert [r.block_index for r in listed] == [0]
    assert (
        block_store.read_volume_meta(new_vol.id).source_snapshot_id
        == src_snap.id
    )


def test_ec2_create_volume_without_snapshot_id_still_registers_blank(ec2_backend):
    """No SnapshotId -> no blocks copied, but the volume's block-store
    entry is still created so future ``PutSnapshotBlock`` /
    ``CreateSnapshot`` can find it."""
    vol = ec2_backend.create_volume(size=2, zone_name="us-east-1a")
    assert block_store.volume_exists(vol.id)
    assert block_store.list_volume_blocks(vol.id) == []
    assert block_store.read_volume_meta(vol.id).source_snapshot_id is None


# ---------------------------------------------------------------------------
# ec2:DeleteSnapshot / ec2:DeleteVolume → block-store cleanup
# ---------------------------------------------------------------------------


def test_ec2_delete_snapshot_removes_block_store_entry(ec2_backend):
    vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    snap = ec2_backend.create_snapshot(volume_id=vol.id, description="")
    assert block_store.snapshot_exists(snap.id)
    ec2_backend.delete_snapshot(snap.id)
    assert not block_store.snapshot_exists(snap.id)


def test_ec2_delete_volume_removes_block_store_entry(ec2_backend):
    vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    assert block_store.volume_exists(vol.id)
    ec2_backend.delete_volume(vol.id)
    assert not block_store.volume_exists(vol.id)


# ---------------------------------------------------------------------------
# Patch idempotency
# ---------------------------------------------------------------------------


def test_apply_patches_is_idempotent(ec2_backend):
    """Calling apply_patches a second time must not re-wrap or break."""
    apply_patches()
    apply_patches()
    vol = ec2_backend.create_volume(size=1, zone_name="us-east-1a")
    snap = ec2_backend.create_snapshot(volume_id=vol.id, description="")
    # The bridge still works after the second apply.
    assert block_store.snapshot_exists(snap.id)
