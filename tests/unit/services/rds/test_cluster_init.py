"""Tests for the Aurora-Postgres streaming replication init helpers.

Pure helpers (engine sniffing, password derivation, command builders,
SQL rendering) get full coverage. The side-effecting
``apply_writer_init`` is tested with a mocked ``DOCKER_CLIENT`` so the
exec sequence is verified without needing Docker.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.rds.docker import cluster_init as ci


# ---------------------------------------------------------------------------
# Engine sniffing
# ---------------------------------------------------------------------------

class TestIsPostgresEngine:
    @pytest.mark.parametrize("engine", [
        "postgres", "POSTGRES", "aurora-postgresql",
        "aurora-postgresql-15.4",
    ])
    def test_postgres_family_returns_true(self, engine):
        assert ci.is_postgres_engine(engine) is True

    @pytest.mark.parametrize("engine", [
        "", "mysql", "mariadb", "aurora-mysql", "aurora", "redis",
    ])
    def test_non_postgres_returns_false(self, engine):
        assert ci.is_postgres_engine(engine) is False


# ---------------------------------------------------------------------------
# Password derivation — stable + isolated per cluster
# ---------------------------------------------------------------------------

class TestReplicationPasswordDerivation:
    def test_is_stable_for_same_inputs(self):
        a = ci.replication_password_for_cluster("c1", "pw")
        b = ci.replication_password_for_cluster("c1", "pw")
        assert a == b

    def test_changes_with_cluster_id(self):
        a = ci.replication_password_for_cluster("c1", "pw")
        b = ci.replication_password_for_cluster("c2", "pw")
        assert a != b

    def test_changes_with_master_password(self):
        a = ci.replication_password_for_cluster("c1", "pw1")
        b = ci.replication_password_for_cluster("c1", "pw2")
        assert a != b

    def test_is_hex_no_quotes(self):
        """The derived password must contain only chars that are safe
        to drop into a single-quoted SQL string and a libpq
        primary_conninfo without escaping."""
        pw = ci.replication_password_for_cluster("c1", "any")
        assert pw.isalnum()
        assert "'" not in pw
        assert '"' not in pw
        assert " " not in pw


# ---------------------------------------------------------------------------
# Writer CMD
# ---------------------------------------------------------------------------

class TestWriterPostgresCommand:
    def test_starts_with_postgres(self):
        cmd = ci.writer_postgres_command()
        assert cmd[0] == "postgres"

    def test_contains_replication_directives(self):
        cmd = ci.writer_postgres_command()
        flat = " ".join(cmd)
        assert "wal_level=replica" in flat
        assert "max_wal_senders=" in flat
        assert "max_replication_slots=" in flat
        assert "hot_standby=on" in flat
        assert "listen_addresses=*" in flat

    def test_floors_wal_senders_at_four(self):
        cmd = ci.writer_postgres_command(max_readers=0)
        flat = " ".join(cmd)
        assert "max_wal_senders=4" in flat

    def test_scales_wal_senders_with_max_readers(self):
        cmd = ci.writer_postgres_command(max_readers=20)
        flat = " ".join(cmd)
        # 20 + 1 = 21
        assert "max_wal_senders=21" in flat


# ---------------------------------------------------------------------------
# Reader init shell
# ---------------------------------------------------------------------------

class TestReaderInheritsWriterFlags:
    """Postgres aborts standby recovery if the reader's
    ``max_wal_senders`` / ``max_replication_slots`` is below the
    writer's. The reader's exec'd postgres MUST therefore use the
    same ``-c`` args the writer was built with."""

    def test_reader_command_includes_writer_replication_flags(self):
        cmd = ci.reader_container_command(
            "c1-writer", 5432, "u", "p", max_readers=16,
        )
        script = cmd[2]
        for arg in ci.replication_postgres_args(max_readers=16):
            # Each ``-c key=value`` token should appear in the
            # shell-quoted exec line at the end of the reader script.
            assert arg in script, f"missing replication arg {arg!r}"

    def test_reader_and_writer_use_same_sender_count(self):
        readers = 8
        w = ci.writer_postgres_command(max_readers=readers)
        r = ci.reader_container_command("a", 1, "u", "p", max_readers=readers)
        # Extract the max_wal_senders= value from each
        def extract(seq, key):
            for s in seq:
                if isinstance(s, str) and s.startswith(f"{key}="):
                    return s.split("=", 1)[1]
            return None
        w_val = extract(w, "max_wal_senders")
        # Reader is a bash script — pull the value out of the script body
        assert w_val in r[2]


class TestReaderInitShell:
    def test_waits_then_basebackups_then_execs(self):
        script = ci.reader_init_shell(
            writer_alias="c1-writer", port=5432,
            repl_user="localemu_repl", repl_password="abc123",
        )
        assert "pg_isready" in script
        assert "c1-writer" in script
        assert "pg_basebackup" in script
        # -R writes standby.signal + primary_conninfo automatically.
        assert " -R" in script
        assert "exec gosu postgres postgres" in script
        # Must propagate the replication password to libpq via PGPASSWORD.
        assert "PGPASSWORD=abc123" in script

    def test_safely_quotes_alias_and_user(self):
        """Aliases/users we control should still pass through
        shlex.quote so a future change can't inject shell."""
        script = ci.reader_init_shell(
            writer_alias="weird name", port=5432,
            repl_user="user;rm -rf /", repl_password="pw",
        )
        # The dangerous substring must NOT appear unquoted as a
        # standalone token; shlex.quote will wrap it in single quotes.
        assert "'user;rm -rf /'" in script
        assert "'weird name'" in script

    def test_returns_list_for_container_cmd(self):
        cmd = ci.reader_container_command(
            "c1-writer", 5432, "u", "p",
        )
        assert cmd[0] == "bash"
        assert cmd[1] == "-c"
        assert isinstance(cmd[2], str)


# ---------------------------------------------------------------------------
# CREATE USER SQL — idempotent + injection-safe
# ---------------------------------------------------------------------------

class TestRenderCreateReplicationUserSql:
    def test_uses_do_block_for_idempotency(self):
        sql = ci.render_create_replication_user_sql("repl", "pw")
        assert "DO $$" in sql
        assert "pg_roles" in sql
        assert "CREATE ROLE repl WITH REPLICATION LOGIN" in sql
        assert "ALTER ROLE repl WITH PASSWORD" in sql

    def test_escapes_single_quote_in_password(self):
        sql = ci.render_create_replication_user_sql("repl", "a'b")
        # Doubled quote inside the SQL literal.
        assert "PASSWORD 'a''b'" in sql

    @pytest.mark.parametrize("bad_name", [
        "1bad", "bad-name", "bad name", "bad;drop", "", "a" * 100,
    ])
    def test_rejects_unsafe_role_name(self, bad_name):
        with pytest.raises(ValueError):
            ci.render_create_replication_user_sql(bad_name, "pw")

    @pytest.mark.parametrize("ok_name", [
        "repl", "localemu_repl", "_x", "R", "abc123",
    ])
    def test_accepts_safe_role_names(self, ok_name):
        ci.render_create_replication_user_sql(ok_name, "pw")  # no raise


# ---------------------------------------------------------------------------
# apply_writer_init — the post-boot exec sequence
# ---------------------------------------------------------------------------

class TestApplyWriterInit:
    def _patch_docker(self):
        return mock.patch.object(ci, "DOCKER_CLIENT")

    def test_runs_four_exec_calls_in_order(self):
        with self._patch_docker() as dc:
            dc.exec_in_container.return_value = (b"", b"")
            ci.apply_writer_init(
                container_name="localemu-rds-c1",
                master_username="admin",
                repl_user="localemu_repl",
                repl_password="secret123",
            )
        # Four execs: pg_isready (probe), CREATE USER, append pg_hba,
        # SIGHUP reload of pg_hba.
        assert dc.exec_in_container.call_count == 4
        ready, first, second, third = [
            c.args for c in dc.exec_in_container.call_args_list
        ]
        # 0th: pg_isready probe — must precede every SQL/file edit so
        # docker-entrypoint's initdb has fully finished.
        assert ready[1][0] == "pg_isready"
        # 1st: psql CREATE/ALTER ROLE
        assert first[0] == "localemu-rds-c1"
        assert first[1][0] == "psql"
        assert any("DO $$" in s for s in first[1] if isinstance(s, str))
        # 2nd: bash -c appending pg_hba.conf
        assert second[1][0] == "bash"
        assert "pg_hba.conf" in second[1][2]
        assert "grep -F -q" in second[1][2]
        # 3rd: bash -c SIGHUP-to-PID-1 (postgres reloads pg_hba
        # without disconnecting); falls back to pg_ctl reload.
        assert third[1][0] == "bash"
        assert "kill -HUP 1" in third[1][2]
        assert "pg_ctl" in third[1][2]

    def test_returns_early_when_create_role_fails(self):
        """If CREATE ROLE fails (DB unreachable, etc.) we don't push
        the pg_hba line either — it'd be inconsistent without the
        role. The container is left running so the issue is visible.

        First call (pg_isready) succeeds; second call (psql CREATE)
        raises — execution must stop without reaching exec #3."""
        with self._patch_docker() as dc:
            dc.exec_in_container.side_effect = [
                (b"", b""),  # pg_isready
                RuntimeError("psql down"),  # psql CREATE ROLE
            ]
            ci.apply_writer_init(
                "ctr", "admin", "localemu_repl", "pw",
            )
        assert dc.exec_in_container.call_count == 2

    def test_pg_hba_append_uses_idempotent_grep_guard(self):
        with self._patch_docker() as dc:
            dc.exec_in_container.return_value = (b"", b"")
            ci.apply_writer_init(
                "ctr", "admin", "localemu_repl", "pw",
            )
        # Exec calls: [0]=pg_isready, [1]=psql CREATE, [2]=bash, [3]=psql reload
        bash_call = dc.exec_in_container.call_args_list[2].args[1]
        script = bash_call[2]
        # ``grep -F -q ... || echo ... >> pg_hba.conf`` pattern.
        assert "grep -F -q" in script
        assert ">> /var/lib/postgresql/data/pg_hba.conf" in script


class TestRenderAlterPrimaryConninfo:
    def test_includes_all_parts(self):
        sql = ci.render_alter_primary_conninfo_sql(
            "c1-writer", 5432, "localemu_repl", "abc123",
        )
        assert "ALTER SYSTEM SET primary_conninfo" in sql
        assert "host=c1-writer" in sql
        assert "port=5432" in sql
        assert "user=localemu_repl" in sql
        assert "password=abc123" in sql
        assert "application_name=standby" in sql

    def test_escapes_single_quote_in_password(self):
        sql = ci.render_alter_primary_conninfo_sql(
            "c1-writer", 5432, "localemu_repl", "a'b",
        )
        assert "password=a''b" in sql

    def test_rejects_unsafe_repl_user(self):
        with pytest.raises(ValueError):
            ci.render_alter_primary_conninfo_sql(
                "c1-writer", 5432, "bad;user", "pw",
            )


class TestDockerClusterOps:
    """The real DockerOps the orchestrator uses for FailoverDBCluster.
    All assertions are against a mocked ``DOCKER_CLIENT``."""

    def _build(self, password_for=None):
        return ci.DockerClusterOps(
            cluster_network_name_fn=lambda c: f"localemu-aurora-{c}",
            repl_user="localemu_repl",
            repl_password_fn=password_for or (lambda c: "pw-" + c),
        )

    def test_promote_to_writer_runs_pg_ctl_promote(self):
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            dc.exec_in_container.return_value = (b"", b"")
            self._build().promote_to_writer("r1")
        args = dc.exec_in_container.call_args.args
        assert args[0] == "localemu-rds-r1"
        assert args[1][:4] == ["gosu", "postgres", "pg_ctl", "-D"]
        assert "promote" in args[1]

    def test_promote_failure_raises(self):
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            dc.exec_in_container.side_effect = RuntimeError("docker down")
            with pytest.raises(RuntimeError):
                self._build().promote_to_writer("r1")

    def test_repoint_reader_restarts_container(self):
        """After a failover, the new writer is on a new timeline that
        forked BEFORE the standby's current LSN. Postgres can't
        reconcile this — the only safe fix is to re-basebackup the
        standby from the new writer. Since the reader container's CMD
        already does ``wipe PGDATA → pg_basebackup → exec postgres``
        on every start, ``docker stop && docker start`` re-runs the
        whole init."""
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            self._build().repoint_reader_to_writer(
                "r-old", "c1-writer", 5432,
            )
        dc.stop_container.assert_called_once_with(
            "localemu-rds-r-old", timeout=10,
        )
        dc.start_container.assert_called_once_with("localemu-rds-r-old")

    def test_repoint_reader_continues_when_stop_fails(self):
        """Stop is best-effort — if the standby's container already
        crashed (e.g. because the writer died and it gave up), we
        still need to start it back up."""
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            dc.stop_container.side_effect = RuntimeError("not running")
            self._build().repoint_reader_to_writer(
                "r-old", "c1-writer", 5432,
            )
        dc.start_container.assert_called_once_with("localemu-rds-r-old")

    def test_set_writer_network_alias_disconnects_then_reconnects(self):
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            self._build().set_writer_network_alias("c1", "r1")
        dc.disconnect_container_from_network.assert_called_once_with(
            network_name="localemu-aurora-c1",
            container_name_or_id="localemu-rds-r1",
        )
        dc.connect_container_to_network.assert_called_once()
        kwargs = dc.connect_container_to_network.call_args.kwargs
        assert kwargs["network_name"] == "localemu-aurora-c1"
        assert kwargs["container_name_or_id"] == "localemu-rds-r1"
        assert "c1-writer" in kwargs["aliases"]
        assert "r1" in kwargs["aliases"]

    def test_set_writer_alias_swallows_disconnect_failure(self):
        """Cluster network might already be disconnected from this
        container (race or partial state). Disconnect failure must not
        block the reconnect; otherwise the cluster is stuck with no
        writer alias."""
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            dc.disconnect_container_from_network.side_effect = (
                RuntimeError("not connected")
            )
            self._build().set_writer_network_alias("c1", "r1")
        dc.connect_container_to_network.assert_called_once()

    def test_stop_instance_container_best_effort(self):
        with mock.patch.object(ci, "DOCKER_CLIENT") as dc:
            dc.stop_container.side_effect = RuntimeError("not running")
            # Must NOT raise — failover already promoted; killing the
            # old writer is best-effort.
            self._build().stop_instance_container("w-old")
        dc.stop_container.assert_called_once_with(
            "localemu-rds-w-old", timeout=10,
        )


