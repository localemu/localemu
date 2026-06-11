"""Disk-backed block store for EBS direct API + volume/snapshot data plane.

Real AWS EBS exposes a block-level read/write API on snapshots
(``ebs:StartSnapshot`` / ``PutSnapshotBlock`` / ``CompleteSnapshot``
/ ``GetSnapshotBlock`` / ``ListSnapshotBlocks`` / ``ListChangedBlocks``).
Moto's in-memory ``EBSSnapshot`` model holds blocks in a dict keyed on
``block_index``, which evaporates on process restart and isn't visible
to snapshots created via ``ec2:CreateSnapshot``.

This module provides the persistent backing store that the LocalEmu
EBS provider (:mod:`localemu.services.ebs.provider`) and the moto
bridge (:mod:`localemu.services.ebs.moto_bridge`) operate over.

Layout::

    <root>/
      snapshots/
        snap-<id>/
          meta.json    # { "status": ..., "volume_size_gib": ..., "block_size": ..., "owner_id": ..., "created": ... }
          blocks/      # raw block files
            000000.bin
            000001.bin
            ...
          tokens.json  # { "<block_index_str>": { "token", "checksum", "checksum_algorithm", "data_length" } }
      volumes/
        vol-<id>/
          meta.json
          blocks/
          tokens.json

Block size: 524 288 bytes (512 KiB) — matches AWS's documented default.

Thread-safety: ``BlockStore`` uses one :class:`threading.Lock` per
snapshot/volume id (lazily allocated) so concurrent
``put_snapshot_block`` calls on the SAME snapshot serialise but
unrelated snapshots run in parallel.

Persistence: the root is under ``/var/lib/localemu/ebs`` by default
(falling back to ``$TMPDIR/localemu/ebs`` when ``/var/lib`` isn't
writable, e.g. on a non-root dev box). Override via ``set_root()`` for
tests.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: AWS EBS direct-API default block size.
BLOCK_SIZE_BYTES = 524_288

#: How many block files we keep per snapshot/volume in a single directory
#: before pagination breaks down. AWS uses up to ~10 000 block indexes for
#: a 5 TiB volume at 512 KiB blocks; flat layout keeps the file-system
#: friendly for the local labs.
_DEFAULT_BLOCKS_DIR_NAME = "blocks"
_META_FILE_NAME = "meta.json"
_TOKENS_FILE_NAME = "tokens.json"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SnapshotMeta:
    """Metadata for a snapshot's block store entry."""
    snapshot_id: str
    owner_id: str
    volume_size_gib: int
    block_size: int = BLOCK_SIZE_BYTES
    status: str = "pending"  # "pending" | "completed" | "error"
    parent_snapshot_id: str | None = None
    description: str = ""
    created: float = field(default_factory=time.time)


@dataclass
class VolumeMeta:
    """Metadata for a volume's block store entry."""
    volume_id: str
    owner_id: str
    size_gib: int
    block_size: int = BLOCK_SIZE_BYTES
    source_snapshot_id: str | None = None
    created: float = field(default_factory=time.time)


@dataclass
class BlockRecord:
    """A single block's bookkeeping (size, checksum, opaque token)."""
    block_index: int
    block_token: str
    checksum: str = ""
    checksum_algorithm: str = "SHA256"
    data_length: int = 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


_root_lock = threading.Lock()
_root: Path | None = None


def _default_root() -> Path:
    """Pick the persistence root.

    ``/var/lib/localemu/ebs`` when writable, else ``$TMPDIR/localemu/ebs``.
    The latter is what most dev boxes will see.
    """
    primary = Path("/var/lib/localemu/ebs")
    try:
        primary.mkdir(parents=True, exist_ok=True)
        # writability check — touching a probe file is cheap and exact.
        probe = primary / ".writable"
        probe.write_bytes(b"")
        probe.unlink()
        return primary
    except (OSError, PermissionError):
        fallback = Path(tempfile.gettempdir()) / "localemu" / "ebs"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def get_root() -> Path:
    """Return the current block-store root, creating it on first use."""
    global _root
    with _root_lock:
        if _root is None:
            _root = _default_root()
            (_root / "snapshots").mkdir(parents=True, exist_ok=True)
            (_root / "volumes").mkdir(parents=True, exist_ok=True)
        return _root


def set_root(path: Path) -> None:
    """Re-root the store. Used by tests; resets the cached locks too."""
    global _root
    with _root_lock:
        _root = Path(path)
        (_root / "snapshots").mkdir(parents=True, exist_ok=True)
        (_root / "volumes").mkdir(parents=True, exist_ok=True)
    _locks.clear()


def reset_for_tests() -> None:
    """Reset module state. Used by test fixtures."""
    global _root
    with _root_lock:
        _root = None
    _locks.clear()


# ---------------------------------------------------------------------------
# Per-id locking
# ---------------------------------------------------------------------------


_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


def _lock_for(scope: str, identifier: str) -> threading.Lock:
    """Return a stable :class:`threading.Lock` per (scope, id) pair."""
    key = f"{scope}:{identifier}"
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _locks[key] = lock
        return lock


# ---------------------------------------------------------------------------
# Public API — snapshots
# ---------------------------------------------------------------------------


def snapshot_dir(snapshot_id: str) -> Path:
    return get_root() / "snapshots" / snapshot_id


def volume_dir(volume_id: str) -> Path:
    return get_root() / "volumes" / volume_id


def snapshot_exists(snapshot_id: str) -> bool:
    return (snapshot_dir(snapshot_id) / _META_FILE_NAME).is_file()


def volume_exists(volume_id: str) -> bool:
    return (volume_dir(volume_id) / _META_FILE_NAME).is_file()


def create_snapshot(
    *,
    snapshot_id: str,
    owner_id: str,
    volume_size_gib: int,
    parent_snapshot_id: str | None = None,
    description: str = "",
    status: str = "pending",
) -> SnapshotMeta:
    """Create the on-disk skeleton for a snapshot. Idempotent.

    Calling this on an already-existing snapshot returns its existing
    meta unchanged. Mirrors AWS's idempotency for ``StartSnapshot``
    with a stable ``ClientToken``.
    """
    with _lock_for("snap", snapshot_id):
        target = snapshot_dir(snapshot_id)
        if (target / _META_FILE_NAME).is_file():
            return read_snapshot_meta(snapshot_id)
        (target / _DEFAULT_BLOCKS_DIR_NAME).mkdir(parents=True, exist_ok=True)
        meta = SnapshotMeta(
            snapshot_id=snapshot_id,
            owner_id=owner_id,
            volume_size_gib=int(volume_size_gib),
            parent_snapshot_id=parent_snapshot_id,
            description=description,
            status=status,
        )
        _write_meta(target / _META_FILE_NAME, meta)
        (target / _TOKENS_FILE_NAME).write_text("{}", encoding="utf-8")
        return meta


def read_snapshot_meta(snapshot_id: str) -> SnapshotMeta:
    path = snapshot_dir(snapshot_id) / _META_FILE_NAME
    raw = json.loads(path.read_text(encoding="utf-8"))
    return SnapshotMeta(**raw)


def update_snapshot_status(snapshot_id: str, status: str) -> SnapshotMeta:
    """Set the snapshot's status (``pending`` / ``completed`` / ``error``)."""
    with _lock_for("snap", snapshot_id):
        meta = read_snapshot_meta(snapshot_id)
        meta.status = status
        _write_meta(snapshot_dir(snapshot_id) / _META_FILE_NAME, meta)
        return meta


def put_snapshot_block(
    *,
    snapshot_id: str,
    block_index: int,
    block_data: bytes,
    checksum: str | None = None,
    checksum_algorithm: str = "SHA256",
) -> BlockRecord:
    """Write a single block. Generates the block token + checksum.

    ``block_data`` is the raw bytes (caller is responsible for
    base64-decoding the wire-format ``BlockData`` parameter before
    handing it here).

    If ``checksum`` is None we compute it from the data with
    ``checksum_algorithm`` (only ``SHA256`` is supported per AWS spec).
    """
    if not snapshot_exists(snapshot_id):
        raise SnapshotNotFoundError(snapshot_id)
    with _lock_for("snap", snapshot_id):
        record = _write_block(
            base_dir=snapshot_dir(snapshot_id),
            block_index=int(block_index),
            block_data=block_data,
            checksum=checksum,
            checksum_algorithm=checksum_algorithm,
        )
        return record


def get_snapshot_block(
    *,
    snapshot_id: str,
    block_index: int,
) -> tuple[bytes, BlockRecord]:
    """Read a block back. Returns ``(data, record)``.

    Raises :class:`SnapshotNotFoundError` or :class:`BlockNotFoundError`.
    """
    if not snapshot_exists(snapshot_id):
        raise SnapshotNotFoundError(snapshot_id)
    return _read_block(
        base_dir=snapshot_dir(snapshot_id),
        block_index=int(block_index),
    )


def list_snapshot_blocks(snapshot_id: str) -> list[BlockRecord]:
    """Return the block records for a snapshot, sorted by block_index."""
    if not snapshot_exists(snapshot_id):
        raise SnapshotNotFoundError(snapshot_id)
    return _list_blocks(snapshot_dir(snapshot_id))


def delete_snapshot(snapshot_id: str) -> None:
    """Best-effort: remove the snapshot directory. No-op if missing."""
    with _lock_for("snap", snapshot_id):
        path = snapshot_dir(snapshot_id)
        if path.is_dir():
            shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Public API — volumes
# ---------------------------------------------------------------------------


def create_volume(
    *,
    volume_id: str,
    owner_id: str,
    size_gib: int,
    source_snapshot_id: str | None = None,
) -> VolumeMeta:
    """Create the on-disk skeleton for a volume."""
    with _lock_for("vol", volume_id):
        target = volume_dir(volume_id)
        if (target / _META_FILE_NAME).is_file():
            return read_volume_meta(volume_id)
        (target / _DEFAULT_BLOCKS_DIR_NAME).mkdir(parents=True, exist_ok=True)
        meta = VolumeMeta(
            volume_id=volume_id,
            owner_id=owner_id,
            size_gib=int(size_gib),
            source_snapshot_id=source_snapshot_id,
        )
        _write_meta(target / _META_FILE_NAME, meta)
        (target / _TOKENS_FILE_NAME).write_text("{}", encoding="utf-8")
        return meta


def read_volume_meta(volume_id: str) -> VolumeMeta:
    path = volume_dir(volume_id) / _META_FILE_NAME
    raw = json.loads(path.read_text(encoding="utf-8"))
    return VolumeMeta(**raw)


def put_volume_block(
    *,
    volume_id: str,
    block_index: int,
    block_data: bytes,
    checksum: str | None = None,
    checksum_algorithm: str = "SHA256",
) -> BlockRecord:
    if not volume_exists(volume_id):
        raise VolumeNotFoundError(volume_id)
    with _lock_for("vol", volume_id):
        return _write_block(
            base_dir=volume_dir(volume_id),
            block_index=int(block_index),
            block_data=block_data,
            checksum=checksum,
            checksum_algorithm=checksum_algorithm,
        )


def list_volume_blocks(volume_id: str) -> list[BlockRecord]:
    if not volume_exists(volume_id):
        raise VolumeNotFoundError(volume_id)
    return _list_blocks(volume_dir(volume_id))


def delete_volume(volume_id: str) -> None:
    with _lock_for("vol", volume_id):
        path = volume_dir(volume_id)
        if path.is_dir():
            shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Cross-entity copy: volume -> snapshot, snapshot -> volume
# ---------------------------------------------------------------------------


def copy_volume_to_snapshot(*, volume_id: str, snapshot_id: str) -> int:
    """Copy a volume's blocks into a snapshot. Returns block count copied.

    Called from the EC2 ``CreateSnapshot`` bridge: a snapshot taken from
    a volume that had block data must produce that same data via the
    EBS direct API. If the source volume has no blocks (typical for
    instance-attached volumes whose data was never written through the
    LocalEmu data plane), the snapshot is left empty — the EBS direct
    API will return an empty block list, which matches what real AWS
    would do for a volume that was never written to.
    """
    if not volume_exists(volume_id):
        return 0
    if not snapshot_exists(snapshot_id):
        raise SnapshotNotFoundError(snapshot_id)
    return _copy_blocks_between(
        src=volume_dir(volume_id),
        dst=snapshot_dir(snapshot_id),
        src_lock_scope="vol",
        src_lock_id=volume_id,
        dst_lock_scope="snap",
        dst_lock_id=snapshot_id,
    )


def copy_snapshot_to_volume(*, snapshot_id: str, volume_id: str) -> int:
    """Copy a snapshot's blocks into a volume's backing store."""
    if not snapshot_exists(snapshot_id):
        return 0
    if not volume_exists(volume_id):
        raise VolumeNotFoundError(volume_id)
    return _copy_blocks_between(
        src=snapshot_dir(snapshot_id),
        dst=volume_dir(volume_id),
        src_lock_scope="snap",
        src_lock_id=snapshot_id,
        dst_lock_scope="vol",
        dst_lock_id=volume_id,
    )


def diff_snapshots(
    first_snapshot_id: str,
    second_snapshot_id: str,
) -> list[tuple[int, str, str | None]]:
    """Return changed blocks between two snapshots.

    Each element is ``(block_index, first_token, second_token_or_None)``.
    Matches the AWS ``ListChangedBlocks`` shape.
    """
    if not snapshot_exists(first_snapshot_id):
        raise SnapshotNotFoundError(first_snapshot_id)
    if not snapshot_exists(second_snapshot_id):
        raise SnapshotNotFoundError(second_snapshot_id)
    a = {r.block_index: r for r in list_snapshot_blocks(first_snapshot_id)}
    b = {r.block_index: r for r in list_snapshot_blocks(second_snapshot_id)}
    changed: list[tuple[int, str, str | None]] = []
    for idx in sorted(a):
        if idx not in b:
            changed.append((idx, a[idx].block_token, None))
        elif a[idx].checksum != b[idx].checksum:
            changed.append((idx, a[idx].block_token, b[idx].block_token))
    return changed


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SnapshotNotFoundError(Exception):
    def __init__(self, snapshot_id: str):
        super().__init__(f"EBS snapshot {snapshot_id!r} not found in block store")
        self.snapshot_id = snapshot_id


class VolumeNotFoundError(Exception):
    def __init__(self, volume_id: str):
        super().__init__(f"EBS volume {volume_id!r} not found in block store")
        self.volume_id = volume_id


class BlockNotFoundError(Exception):
    def __init__(self, scope_id: str, block_index: int):
        super().__init__(f"block {block_index} not found for {scope_id!r}")
        self.scope_id = scope_id
        self.block_index = block_index


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _write_meta(path: Path, meta) -> None:
    """Atomically write a JSON meta file (rename within same dir)."""
    payload = json.dumps(asdict(meta), indent=2, sort_keys=True).encode("utf-8")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)


def _load_tokens(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        LOG.warning("tokens file %s was corrupted; resetting", path)
        return {}


def _save_tokens(path: Path, data: dict[str, dict]) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)


def _block_file(blocks_dir: Path, block_index: int) -> Path:
    # AWS lets indexes go up to 1.8M for the largest volumes. 7-digit
    # zero-padding sorts lexicographically up to 9,999,999 indexes —
    # more than enough.
    return blocks_dir / f"{int(block_index):07d}.bin"


def _compute_checksum(data: bytes, algorithm: str) -> str:
    if algorithm.upper() == "SHA256":
        return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
    raise ValueError(f"unsupported checksum algorithm: {algorithm}")


def _write_block(
    *,
    base_dir: Path,
    block_index: int,
    block_data: bytes,
    checksum: str | None,
    checksum_algorithm: str,
) -> BlockRecord:
    blocks_dir = base_dir / _DEFAULT_BLOCKS_DIR_NAME
    blocks_dir.mkdir(parents=True, exist_ok=True)
    target = _block_file(blocks_dir, block_index)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(block_data)
    os.replace(tmp, target)

    computed = _compute_checksum(block_data, checksum_algorithm)
    if checksum is not None and checksum != computed:
        # Real AWS rejects a mismatched checksum with InvalidParameterValue.
        # We surface that as the same exception type the provider layer
        # already maps to a clean 4xx — keep raising the value error here.
        target.unlink(missing_ok=True)
        raise ValueError(
            f"checksum mismatch for block {block_index}: caller={checksum!r} computed={computed!r}"
        )

    record = BlockRecord(
        block_index=int(block_index),
        block_token=str(uuid.uuid4()),
        checksum=computed,
        checksum_algorithm=checksum_algorithm.upper(),
        data_length=len(block_data),
    )
    tokens_path = base_dir / _TOKENS_FILE_NAME
    tokens = _load_tokens(tokens_path)
    tokens[str(block_index)] = {
        "token": record.block_token,
        "checksum": record.checksum,
        "checksum_algorithm": record.checksum_algorithm,
        "data_length": record.data_length,
    }
    _save_tokens(tokens_path, tokens)
    return record


def _read_block(*, base_dir: Path, block_index: int) -> tuple[bytes, BlockRecord]:
    target = _block_file(base_dir / _DEFAULT_BLOCKS_DIR_NAME, block_index)
    if not target.is_file():
        raise BlockNotFoundError(str(base_dir.name), block_index)
    data = target.read_bytes()
    tokens = _load_tokens(base_dir / _TOKENS_FILE_NAME)
    rec = tokens.get(str(block_index), {})
    record = BlockRecord(
        block_index=int(block_index),
        block_token=rec.get("token", str(uuid.uuid4())),
        checksum=rec.get("checksum", ""),
        checksum_algorithm=rec.get("checksum_algorithm", "SHA256"),
        data_length=rec.get("data_length", len(data)),
    )
    return data, record


def _list_blocks(base_dir: Path) -> list[BlockRecord]:
    tokens = _load_tokens(base_dir / _TOKENS_FILE_NAME)
    blocks: list[BlockRecord] = []
    for idx_str, rec in sorted(tokens.items(), key=lambda kv: int(kv[0])):
        blocks.append(BlockRecord(
            block_index=int(idx_str),
            block_token=rec.get("token", ""),
            checksum=rec.get("checksum", ""),
            checksum_algorithm=rec.get("checksum_algorithm", "SHA256"),
            data_length=rec.get("data_length", 0),
        ))
    return blocks


def _copy_blocks_between(
    *,
    src: Path,
    dst: Path,
    src_lock_scope: str,
    src_lock_id: str,
    dst_lock_scope: str,
    dst_lock_id: str,
) -> int:
    """Copy block files + tokens from ``src`` to ``dst``. Idempotent.

    Acquires both locks in a stable order to avoid AB/BA deadlocks
    when two threads happen to copy between overlapping snapshots and
    volumes at the same time.
    """
    a = (src_lock_scope, src_lock_id)
    b = (dst_lock_scope, dst_lock_id)
    first, second = sorted([a, b])
    with _lock_for(*first), _lock_for(*second):
        src_blocks = src / _DEFAULT_BLOCKS_DIR_NAME
        dst_blocks = dst / _DEFAULT_BLOCKS_DIR_NAME
        if not src_blocks.is_dir():
            return 0
        dst_blocks.mkdir(parents=True, exist_ok=True)
        count = 0
        for entry in sorted(src_blocks.iterdir()):
            if entry.is_file() and entry.name.endswith(".bin"):
                shutil.copy2(entry, dst_blocks / entry.name)
                count += 1
        # Copy tokens too — the receiver inherits source token metadata
        # so checksums and block_token uniqueness flow forwards.
        src_tokens = _load_tokens(src / _TOKENS_FILE_NAME)
        if src_tokens:
            existing = _load_tokens(dst / _TOKENS_FILE_NAME)
            existing.update(src_tokens)
            _save_tokens(dst / _TOKENS_FILE_NAME, existing)
        return count
