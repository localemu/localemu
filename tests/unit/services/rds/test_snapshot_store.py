"""Tests for the on-disk RDS snapshot store + dump-command builders.

Closes audit bug #9 (RestoreDBInstanceFromDBSnapshot spawned a fresh
empty container with no data). The store is the durable layer the
provider's CreateDBSnapshot writes to and RestoreDBInstanceFromDBSnapshot
reads from.
"""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from localemu.services.rds.snapshot_store import (
    SnapshotStore,
    is_mysql_family, is_postgres_family,
    mysql_restore_command, mysqldump_command,
    pg_dump_command, pg_restore_command,
)


@pytest.fixture
def store(tmp_path):
    return SnapshotStore(root=tmp_path / "snapshots")


def _gz(payload: bytes) -> bytes:
    return gzip.compress(payload)


# ---------------------------------------------------------------------------
# Engine sniffing
# ---------------------------------------------------------------------------


class TestEngineFamily:
    @pytest.mark.parametrize("engine", [
        "postgres", "POSTGRES", "aurora-postgresql",
        "aurora-postgresql-15.4",
    ])
    def test_postgres_family(self, engine):
        assert is_postgres_family(engine) is True
        assert is_mysql_family(engine) is False

    @pytest.mark.parametrize("engine", [
        "mysql", "MYSQL", "mariadb", "aurora-mysql", "aurora",
    ])
    def test_mysql_family(self, engine):
        assert is_mysql_family(engine) is True
        assert is_postgres_family(engine) is False


# ---------------------------------------------------------------------------
# Command builders — what gets exec'd inside the container
# ---------------------------------------------------------------------------


class TestPgCommands:
    def test_pg_dump_uses_custom_format(self):
        cmd = pg_dump_command("admin", "myapp")
        assert cmd[0] == "pg_dump"
        assert "-Fc" in cmd
        # Ownership + ACL stripped for portability
        assert "-O" in cmd
        assert "-x" in cmd
        # No engine-side compression — we gzip in Python
        assert "-Z" in cmd and cmd[cmd.index("-Z") + 1] == "0"
        # Picked db_name
        assert "myapp" in cmd

    def test_pg_dump_defaults_db_to_master_user(self):
        cmd = pg_dump_command("admin", None)
        assert "admin" in cmd[cmd.index("-d") + 1: cmd.index("-d") + 2]

    def test_pg_restore_is_idempotent(self):
        cmd = pg_restore_command("admin", "myapp")
        assert cmd[0] == "pg_restore"
        assert "--clean" in cmd
        assert "--if-exists" in cmd


class TestMysqlCommands:
    def test_mysqldump_is_transactionally_consistent(self):
        cmd = mysqldump_command("root", "myapp")
        assert cmd[0] == "mysqldump"
        assert "--single-transaction" in cmd
        assert "--routines" in cmd
        assert "--triggers" in cmd
        assert "--events" in cmd
        assert "--set-gtid-purged=OFF" in cmd
        assert "myapp" in cmd

    def test_mysql_restore_reads_stdin(self):
        cmd = mysql_restore_command("root", "myapp")
        assert cmd[0] == "mysql"
        # No -e or input file — stdin is the dump source
        assert "-e" not in cmd
        assert "myapp" in cmd


# ---------------------------------------------------------------------------
# Store round-trip
# ---------------------------------------------------------------------------


class TestSnapshotStore:
    def test_write_then_read_roundtrip(self, store):
        payload = _gz(b"-- CREATE TABLE users (id int);\n")
        manifest = store.write(
            "snap-1", engine="postgres", dump_bytes=payload,
            source_db_instance_id="db-1", master_username="admin",
            db_name="myapp", db_instance_class="db.t3.micro",
        )
        assert store.has("snap-1")
        assert manifest.snapshot_id == "snap-1"
        assert manifest.source_db_instance_id == "db-1"
        assert manifest.engine == "postgres"
        assert manifest.dump_format == "pg_custom"
        assert manifest.dump_sha256 == hashlib.sha256(payload).hexdigest()
        assert manifest.dump_size_bytes == len(payload)
        assert manifest.schema_version == 1
        assert manifest.source_origin == "localemu-engine-dump"

        read = store.read_manifest("snap-1")
        assert read is not None
        assert read.dump_sha256 == manifest.dump_sha256

        bytes_back = store.read_dump("snap-1")
        assert bytes_back == payload

    def test_mysql_dump_format_label(self, store):
        store.write(
            "snap-m", engine="mariadb", dump_bytes=_gz(b"-- mysql\n"),
            source_db_instance_id="db-m", master_username="root",
        )
        m = store.read_manifest("snap-m")
        assert m.dump_format == "mysql_sql"

    def test_missing_snapshot_returns_none(self, store):
        assert store.has("nope") is False
        assert store.read_manifest("nope") is None
        assert store.read_dump("nope") is None

    def test_delete_removes_dir(self, store):
        store.write(
            "snap-d", engine="postgres", dump_bytes=_gz(b"."),
            source_db_instance_id="db", master_username="u",
        )
        assert store.has("snap-d")
        assert store.delete("snap-d") is True
        assert store.has("snap-d") is False

    def test_delete_missing_is_idempotent(self, store):
        assert store.delete("never-existed") is False

    def test_list_ids_skips_partial_dirs(self, store, tmp_path):
        # Complete snapshot
        store.write(
            "snap-ok", engine="postgres", dump_bytes=_gz(b"."),
            source_db_instance_id="db", master_username="u",
        )
        # Manually create a partial dir (dump but no manifest)
        partial = store.dir_for("snap-partial")
        partial.mkdir(parents=True)
        (partial / "dump.sql.gz").write_bytes(b"junk")
        ids = store.list_ids()
        assert "snap-ok" in ids
        assert "snap-partial" not in ids

    def test_manifest_last_so_partial_writes_dont_confuse_readers(self, store):
        """The manifest is the completion signal — if a crash kills
        the dump write, the dir exists but ``has()`` must return
        False so a restore doesn't replay garbage."""
        d = store.dir_for("snap-partial")
        d.mkdir(parents=True)
        (d / "dump.sql.gz").write_bytes(b"truncated")
        assert store.has("snap-partial") is False
