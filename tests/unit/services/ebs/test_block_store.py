"""Unit tests for ``localemu.services.ebs.block_store``.

The store is pure-Python file I/O — these tests run against a
per-test temp directory, so they're instant and independent of any
running LocalEmu / moto / Docker.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from pathlib import Path

import pytest

from localemu.services.ebs import block_store
from localemu.services.ebs.block_store import (
    BLOCK_SIZE_BYTES,
    BlockNotFoundError,
    BlockRecord,
    SnapshotMeta,
    SnapshotNotFoundError,
    VolumeMeta,
    VolumeNotFoundError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path, monkeypatch):
    """Re-root the block store at a fresh tmp dir per test.

    Also clears the per-id lock dict so stale locks don't bleed across
    tests.
    """
    block_store.set_root(tmp_path / "ebs")
    block_store._locks.clear()
    yield
    block_store.reset_for_tests()


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


# ---------------------------------------------------------------------------
# Snapshot CRUD
# ---------------------------------------------------------------------------


def test_create_snapshot_lays_out_directory_and_meta():
    meta = block_store.create_snapshot(
        snapshot_id="snap-aaa",
        owner_id="000000000000",
        volume_size_gib=8,
        description="test",
    )
    assert meta.snapshot_id == "snap-aaa"
    assert meta.status == "pending"
    assert meta.block_size == BLOCK_SIZE_BYTES
    assert meta.volume_size_gib == 8
    snap_dir = block_store.snapshot_dir("snap-aaa")
    assert (snap_dir / "meta.json").is_file()
    assert (snap_dir / "blocks").is_dir()
    assert (snap_dir / "tokens.json").read_text() == "{}"


def test_create_snapshot_is_idempotent():
    a = block_store.create_snapshot(
        snapshot_id="snap-i", owner_id="o", volume_size_gib=1,
    )
    b = block_store.create_snapshot(
        snapshot_id="snap-i", owner_id="o", volume_size_gib=1,
    )
    assert a == b


def test_snapshot_exists_returns_false_for_unknown_id():
    assert block_store.snapshot_exists("snap-nope") is False


def test_delete_snapshot_removes_directory():
    block_store.create_snapshot(
        snapshot_id="snap-del", owner_id="o", volume_size_gib=1,
    )
    block_store.delete_snapshot("snap-del")
    assert not block_store.snapshot_exists("snap-del")


def test_delete_snapshot_unknown_id_is_noop():
    block_store.delete_snapshot("snap-nope")  # must not raise


def test_update_snapshot_status_persists():
    block_store.create_snapshot(
        snapshot_id="snap-s", owner_id="o", volume_size_gib=1,
    )
    meta = block_store.update_snapshot_status("snap-s", "completed")
    assert meta.status == "completed"
    # Reload from disk to verify the write was persisted, not just in-memory.
    on_disk = block_store.read_snapshot_meta("snap-s")
    assert on_disk.status == "completed"


# ---------------------------------------------------------------------------
# Block put / get / list
# ---------------------------------------------------------------------------


def test_put_and_get_snapshot_block_round_trip():
    block_store.create_snapshot(
        snapshot_id="snap-rt", owner_id="o", volume_size_gib=1,
    )
    raw = b"hello-world" * 100
    record = block_store.put_snapshot_block(
        snapshot_id="snap-rt", block_index=0, block_data=raw,
    )
    assert record.block_index == 0
    assert record.block_token
    assert record.data_length == len(raw)
    assert record.checksum == _sha256_b64(raw)

    data, rec2 = block_store.get_snapshot_block(
        snapshot_id="snap-rt", block_index=0,
    )
    assert data == raw
    assert rec2.block_token == record.block_token
    assert rec2.checksum == record.checksum


def test_put_block_into_unknown_snapshot_raises():
    with pytest.raises(SnapshotNotFoundError):
        block_store.put_snapshot_block(
            snapshot_id="snap-nope", block_index=0, block_data=b"x",
        )


def test_get_unknown_block_raises_block_not_found():
    block_store.create_snapshot(
        snapshot_id="snap-empty", owner_id="o", volume_size_gib=1,
    )
    with pytest.raises(BlockNotFoundError):
        block_store.get_snapshot_block(
            snapshot_id="snap-empty", block_index=42,
        )


def test_list_snapshot_blocks_sorted_by_index():
    block_store.create_snapshot(
        snapshot_id="snap-l", owner_id="o", volume_size_gib=1,
    )
    for idx in [3, 1, 7, 0]:
        block_store.put_snapshot_block(
            snapshot_id="snap-l",
            block_index=idx,
            block_data=f"block-{idx}".encode(),
        )
    listed = block_store.list_snapshot_blocks("snap-l")
    assert [r.block_index for r in listed] == [0, 1, 3, 7]


def test_list_snapshot_blocks_on_empty_snapshot_returns_empty():
    block_store.create_snapshot(
        snapshot_id="snap-e", owner_id="o", volume_size_gib=1,
    )
    assert block_store.list_snapshot_blocks("snap-e") == []


def test_put_block_with_mismatched_caller_checksum_raises():
    block_store.create_snapshot(
        snapshot_id="snap-cs", owner_id="o", volume_size_gib=1,
    )
    with pytest.raises(ValueError, match="checksum mismatch"):
        block_store.put_snapshot_block(
            snapshot_id="snap-cs",
            block_index=0,
            block_data=b"abc",
            checksum="wrong-checksum",
        )


def test_put_block_with_matching_caller_checksum_succeeds():
    block_store.create_snapshot(
        snapshot_id="snap-csok", owner_id="o", volume_size_gib=1,
    )
    raw = b"abc"
    correct = _sha256_b64(raw)
    record = block_store.put_snapshot_block(
        snapshot_id="snap-csok",
        block_index=0, block_data=raw,
        checksum=correct,
    )
    assert record.checksum == correct


# ---------------------------------------------------------------------------
# Volume CRUD + blocks
# ---------------------------------------------------------------------------


def test_create_volume_and_put_block():
    block_store.create_volume(
        volume_id="vol-a", owner_id="o", size_gib=8,
    )
    record = block_store.put_volume_block(
        volume_id="vol-a", block_index=5, block_data=b"v",
    )
    assert record.block_index == 5
    assert block_store.list_volume_blocks("vol-a")[0].block_index == 5


def test_put_block_into_unknown_volume_raises():
    with pytest.raises(VolumeNotFoundError):
        block_store.put_volume_block(
            volume_id="vol-nope", block_index=0, block_data=b"x",
        )


# ---------------------------------------------------------------------------
# Cross-entity copy: volume -> snapshot, snapshot -> volume
# ---------------------------------------------------------------------------


def test_copy_volume_to_snapshot_carries_blocks_and_tokens():
    block_store.create_volume(
        volume_id="vol-src", owner_id="o", size_gib=1,
    )
    block_store.put_volume_block(
        volume_id="vol-src", block_index=0, block_data=b"V0",
    )
    block_store.put_volume_block(
        volume_id="vol-src", block_index=1, block_data=b"V1",
    )
    block_store.create_snapshot(
        snapshot_id="snap-dst", owner_id="o", volume_size_gib=1,
    )
    n = block_store.copy_volume_to_snapshot(
        volume_id="vol-src", snapshot_id="snap-dst",
    )
    assert n == 2
    listed = block_store.list_snapshot_blocks("snap-dst")
    assert [r.block_index for r in listed] == [0, 1]
    data, _ = block_store.get_snapshot_block(
        snapshot_id="snap-dst", block_index=0,
    )
    assert data == b"V0"


def test_copy_snapshot_to_volume_carries_blocks():
    block_store.create_snapshot(
        snapshot_id="snap-src", owner_id="o", volume_size_gib=1,
    )
    block_store.put_snapshot_block(
        snapshot_id="snap-src", block_index=2, block_data=b"S2",
    )
    block_store.create_volume(
        volume_id="vol-dst", owner_id="o", size_gib=1,
    )
    n = block_store.copy_snapshot_to_volume(
        snapshot_id="snap-src", volume_id="vol-dst",
    )
    assert n == 1
    listed = block_store.list_volume_blocks("vol-dst")
    assert [r.block_index for r in listed] == [2]


def test_copy_volume_to_snapshot_on_empty_volume_is_zero():
    block_store.create_volume(
        volume_id="vol-empty", owner_id="o", size_gib=1,
    )
    block_store.create_snapshot(
        snapshot_id="snap-from-empty", owner_id="o", volume_size_gib=1,
    )
    assert block_store.copy_volume_to_snapshot(
        volume_id="vol-empty", snapshot_id="snap-from-empty",
    ) == 0


def test_copy_into_unknown_snapshot_raises():
    block_store.create_volume(
        volume_id="vol-x", owner_id="o", size_gib=1,
    )
    with pytest.raises(SnapshotNotFoundError):
        block_store.copy_volume_to_snapshot(
            volume_id="vol-x", snapshot_id="snap-nope",
        )


# ---------------------------------------------------------------------------
# diff_snapshots
# ---------------------------------------------------------------------------


def test_diff_snapshots_detects_added_and_changed_blocks():
    block_store.create_snapshot(
        snapshot_id="snap-a", owner_id="o", volume_size_gib=1,
    )
    block_store.create_snapshot(
        snapshot_id="snap-b", owner_id="o", volume_size_gib=1,
    )
    # snap-a has blocks 0 (data X), 1 (data Y).
    block_store.put_snapshot_block(
        snapshot_id="snap-a", block_index=0, block_data=b"X",
    )
    block_store.put_snapshot_block(
        snapshot_id="snap-a", block_index=1, block_data=b"Y",
    )
    # snap-b has block 0 (CHANGED data X2) and a new block 2 (only in b).
    block_store.put_snapshot_block(
        snapshot_id="snap-b", block_index=0, block_data=b"X2",
    )
    block_store.put_snapshot_block(
        snapshot_id="snap-b", block_index=2, block_data=b"Z",
    )

    diff = block_store.diff_snapshots("snap-a", "snap-b")
    # block 0 changed: token_a, token_b.
    # block 1 in a but missing in b -> token_a, None.
    indexes = [d[0] for d in diff]
    assert indexes == [0, 1]
    assert diff[0][1] != "" and diff[0][2] is not None
    assert diff[1][2] is None


# ---------------------------------------------------------------------------
# Thread safety: per-snapshot serialisation
# ---------------------------------------------------------------------------


def test_parallel_put_blocks_serialise_within_one_snapshot():
    """Concurrent puts on the SAME snapshot must not corrupt tokens.json.

    The file-rename pattern + per-snap lock together make this safe;
    this test exercises both.
    """
    block_store.create_snapshot(
        snapshot_id="snap-p", owner_id="o", volume_size_gib=1,
    )

    errors: list[BaseException] = []

    def worker(idx: int) -> None:
        try:
            block_store.put_snapshot_block(
                snapshot_id="snap-p", block_index=idx,
                block_data=f"d{idx}".encode(),
            )
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    listed = block_store.list_snapshot_blocks("snap-p")
    assert sorted(r.block_index for r in listed) == list(range(16))
