"""On-disk store for RDS snapshot dumps.

Closes the "RestoreDBInstanceFromDBSnapshot spawns a fresh empty
container with no data" hole. Each snapshot lives in:

    ${VOLUME_DIR}/rds/snapshots/<snapshot-id>/
        manifest.json   metadata + engine + sha256
        dump.sql.gz     gzipped pg_dump -Fc / mysqldump output

The manifest is written LAST so a partial dump never confuses the
restore path — readers treat ``manifest.json`` as the completion
signal.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger(__name__)


def _default_root() -> Path:
    """Snapshot storage root. Honours ``LOCALEMU_RDS_SNAPSHOT_DIR``,
    falls back to ``~/.localemu/rds/snapshots`` so unit tests and
    rootless dev installs work without LOCALEMU_VOLUME_DIR set."""
    override = os.environ.get("LOCALEMU_RDS_SNAPSHOT_DIR")
    if override:
        return Path(override)
    return Path.home() / ".localemu" / "rds" / "snapshots"


@dataclass
class SnapshotManifest:
    """Everything we need to restore an instance from this snapshot
    without any cross-reference to moto state.

    ``source_origin`` distinguishes dumps written by this code path
    (``localemu-engine-dump``) from older metadata-only snapshots
    that pre-date this feature (``localemu-moto-only``) so a future
    upgrade can tell them apart."""
    schema_version: int
    snapshot_id: str
    source_db_instance_id: str
    engine: str
    engine_version: str | None
    db_name: str | None
    master_username: str
    db_instance_class: str | None
    dump_format: str  # "pg_custom" | "mysql_sql"
    dump_size_bytes: int
    dump_sha256: str
    created_at: str  # ISO 8601 UTC
    source_origin: str  # "localemu-engine-dump" | "localemu-moto-only"


class SnapshotStore:
    """File-backed store. Single-process for now (no cross-process
    locking) — the same process owns RDS state. Thread-safe via a
    coarse lock around dir creation / rename."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = Path(root) if root is not None else _default_root()
        self._lock = threading.RLock()

    @property
    def root(self) -> Path:
        return self._root

    # -- path helpers ---------------------------------------------------

    def dir_for(self, snapshot_id: str) -> Path:
        return self._root / snapshot_id

    def dump_path(self, snapshot_id: str) -> Path:
        return self.dir_for(snapshot_id) / "dump.sql.gz"

    def manifest_path(self, snapshot_id: str) -> Path:
        return self.dir_for(snapshot_id) / "manifest.json"

    # -- write path -----------------------------------------------------

    def write(
        self,
        snapshot_id: str,
        engine: str,
        dump_bytes: bytes,
        *,
        source_db_instance_id: str,
        master_username: str,
        engine_version: str | None = None,
        db_name: str | None = None,
        db_instance_class: str | None = None,
    ) -> SnapshotManifest:
        """Persist ``dump_bytes`` (already gzipped) and the matching
        manifest. The manifest write is the atomic "this snapshot
        exists" signal — readers tolerate a snapshot dir with no
        manifest as "partial / failed mid-create"."""
        with self._lock:
            d = self.dir_for(snapshot_id)
            d.mkdir(parents=True, exist_ok=True)
            tmp = self.dump_path(snapshot_id).with_suffix(".gz.tmp")
            tmp.write_bytes(dump_bytes)
            os.replace(tmp, self.dump_path(snapshot_id))
            manifest = SnapshotManifest(
                schema_version=1,
                snapshot_id=snapshot_id,
                source_db_instance_id=source_db_instance_id,
                engine=engine,
                engine_version=engine_version,
                db_name=db_name,
                master_username=master_username,
                db_instance_class=db_instance_class,
                dump_format=_dump_format_for(engine),
                dump_size_bytes=len(dump_bytes),
                dump_sha256=hashlib.sha256(dump_bytes).hexdigest(),
                created_at=datetime.now(timezone.utc).isoformat(),
                source_origin="localemu-engine-dump",
            )
            mf_tmp = self.manifest_path(snapshot_id).with_suffix(".json.tmp")
            mf_tmp.write_text(json.dumps(asdict(manifest), indent=2))
            os.replace(mf_tmp, self.manifest_path(snapshot_id))
            LOG.info(
                "snapshot %s persisted (%d bytes, engine=%s)",
                snapshot_id, len(dump_bytes), engine,
            )
            return manifest

    def delete(self, snapshot_id: str) -> bool:
        """Remove the snapshot's directory. Idempotent — returns False
        when nothing was there to remove."""
        with self._lock:
            d = self.dir_for(snapshot_id)
            if not d.exists():
                return False
            shutil.rmtree(d, ignore_errors=True)
            return True

    # -- read path ------------------------------------------------------

    def has(self, snapshot_id: str) -> bool:
        return self.manifest_path(snapshot_id).exists()

    def read_manifest(self, snapshot_id: str) -> SnapshotManifest | None:
        p = self.manifest_path(snapshot_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text())
            return SnapshotManifest(**data)
        except Exception:
            LOG.warning("snapshot %s: manifest unreadable", snapshot_id, exc_info=True)
            return None

    def read_dump(self, snapshot_id: str) -> bytes | None:
        p = self.dump_path(snapshot_id)
        if not p.exists():
            return None
        return p.read_bytes()

    def list_ids(self) -> list[str]:
        if not self._root.exists():
            return []
        out: list[str] = []
        for child in self._root.iterdir():
            if child.is_dir() and (child / "manifest.json").exists():
                out.append(child.name)
        return sorted(out)


def _dump_format_for(engine: str) -> str:
    e = (engine or "").lower()
    if e.startswith("postgres") or e.startswith("aurora-postgresql"):
        return "pg_custom"
    return "mysql_sql"


# ---------------------------------------------------------------------------
# Pure helpers — what to exec inside the container for each engine
# ---------------------------------------------------------------------------


def is_postgres_family(engine: str) -> bool:
    e = (engine or "").lower()
    return e.startswith("postgres") or e.startswith("aurora-postgresql")


def is_mysql_family(engine: str) -> bool:
    e = (engine or "").lower()
    return (
        e.startswith("mysql")
        or e.startswith("mariadb")
        or e.startswith("aurora-mysql")
        or e == "aurora"
    )


def pg_dump_command(master_username: str, db_name: str | None) -> list[str]:
    """``pg_dump -Fc`` (custom format) so ``pg_restore`` can drive the
    restore with ``--clean --if-exists`` for idempotency. The dump
    excludes ownership/ACLs so it's portable across master usernames
    (``-O -x``). When ``db_name`` is None we default to the database
    the docker-entrypoint creates for the master user."""
    db = db_name or master_username
    return [
        "pg_dump",
        "-U", master_username,
        "-h", "127.0.0.1",
        "-d", db,
        "-Fc",
        "-O", "-x",
        "-Z", "0",  # leave compression to our gzip layer
    ]


def pg_restore_command(master_username: str, db_name: str | None) -> list[str]:
    db = db_name or master_username
    return [
        "pg_restore",
        "-U", master_username,
        "-h", "127.0.0.1",
        "-d", db,
        "--clean", "--if-exists",
        "-O", "-x",
        "--no-comments",
    ]


def mysqldump_command(master_username: str, db_name: str | None) -> list[str]:
    """``mysqldump`` for mysql/mariadb. ``--single-transaction`` for
    InnoDB consistency, ``--routines --triggers --events`` to capture
    procedural objects, ``--set-gtid-purged=OFF`` so the dump is safe
    to load into a new instance without GTID drama."""
    db = db_name or master_username
    return [
        "mysqldump",
        "-u", master_username,
        "-h", "127.0.0.1",
        "--single-transaction",
        "--routines", "--triggers", "--events",
        "--set-gtid-purged=OFF",
        db,
    ]


def mysql_restore_command(master_username: str, db_name: str | None) -> list[str]:
    db = db_name or master_username
    return ["mysql", "-u", master_username, "-h", "127.0.0.1", db]


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_store: SnapshotStore | None = None
_lock = threading.Lock()


def get_snapshot_store() -> SnapshotStore:
    global _store
    if _store is None:
        with _lock:
            if _store is None:
                _store = SnapshotStore()
    return _store


def reset_for_tests(root: Path | None = None) -> None:
    """Tests-only — point the singleton at a tmp dir (or drop it)."""
    global _store
    with _lock:
        _store = SnapshotStore(root) if root is not None else None
