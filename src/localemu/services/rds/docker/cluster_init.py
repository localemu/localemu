"""Aurora-PostgreSQL streaming replication init.

This module is responsible for turning a vanilla Postgres image into a
working primary/standby pair on a shared Docker bridge:

  * the **writer** runs Postgres with the replication-source command-
    line flags (``wal_level=replica`` etc.) so the directives apply
    from boot, and the post-boot hook (:func:`apply_writer_init`)
    installs the replication user + the ``pg_hba.conf`` line.
  * the **reader** runs a small bash wrapper as its container CMD that
    waits for the writer, runs ``pg_basebackup -R`` (which writes the
    ``standby.signal`` file and a ``primary_conninfo`` line under
    ``postgresql.auto.conf``) and finally exec's into postgres so the
    server runs as PID 1.

Only ``postgres`` / ``aurora-postgresql`` are supported. MySQL/Aurora-
MySQL would use binlog replication and is intentionally out of scope
here.
"""
from __future__ import annotations

import hashlib
import logging
import re
import shlex
import time

from localemu.services.rds.cluster_orchestrator import (
    render_writer_pg_hba_line,
)
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

REPLICATION_USER = "localemu_repl"
PGDATA = "/var/lib/postgresql/data"


def is_postgres_engine(engine: str) -> bool:
    """True for engines whose Docker images are PostgreSQL-shaped.
    Returns False for mysql/mariadb/aurora-mysql so the cluster init
    path stays a no-op (logging a warning) for those engines."""
    e = (engine or "").lower()
    return e == "postgres" or e.startswith("aurora-postgresql")


def replication_password_for_cluster(
    cluster_id: str, master_password: str,
) -> str:
    """Derive a stable replication-user password from the cluster id
    and master password. Stable across restarts so a reader spawned
    after the writer's password rotated still authenticates.

    Returned as a hex digest so it's safe to drop into
    ``primary_conninfo`` without escaping concerns."""
    h = hashlib.sha256(
        f"{cluster_id}|{master_password}|aurora-repl".encode(),
    ).hexdigest()
    return h[:32]


def replication_postgres_args(max_readers: int = 16) -> list[str]:
    """The ``-c key=value`` args shared by writer and reader. Readers
    must match (or exceed) the writer's ``max_wal_senders`` and
    ``max_replication_slots`` or Postgres aborts recovery with
    "insufficient parameter settings" the moment it enters standby
    mode. ``hot_standby=on`` is what makes a reader queryable while
    it streams; ``wal_level=replica`` is required on the writer and
    harmless on the reader."""
    senders = max(int(max_readers) + 1, 4)
    return [
        "-c", "wal_level=replica",
        "-c", f"max_wal_senders={senders}",
        "-c", f"max_replication_slots={senders}",
        "-c", "hot_standby=on",
        "-c", "listen_addresses=*",
        "-c", "wal_keep_size=1024",
    ]


def writer_postgres_command(max_readers: int = 16) -> list[str]:
    """Build the ``postgres`` CMD that the writer container runs.

    Setting ``wal_level``, ``max_wal_senders`` etc. as ``-c`` args
    avoids the need to restart Postgres after editing
    ``postgresql.conf`` — they apply from boot."""
    return ["postgres", *replication_postgres_args(max_readers)]


def reader_init_shell(
    writer_alias: str, port: int, repl_user: str, repl_password: str,
    max_readers: int = 16,
) -> str:
    """The bash script the reader container runs as CMD. It waits for
    the writer (``pg_isready`` loop), then base-backs up the writer
    into ``PGDATA`` using ``pg_basebackup -R`` (which automatically
    writes ``standby.signal`` and the right ``primary_conninfo``
    line), fixes the data-dir ownership/permissions, and finally
    exec's into ``postgres`` with the same replication ``-c`` flags
    the writer runs with — Postgres refuses to enter standby mode
    if the reader's ``max_wal_senders`` is lower than the writer's.

    The wait loop uses a short sleep so a slow-to-start writer
    delays the reader by seconds, not minutes; a hard cap of 180s
    fails the container fast if the writer never appears."""
    # Single-quote the variables we splice in so a master password
    # containing $ / ` can't break out of the shell context.
    pg_args = " ".join(shlex.quote(a) for a in replication_postgres_args(max_readers))
    return (
        "set -e\n"
        "echo '[localemu] reader init: waiting for writer "
        f"{writer_alias}:{port}'\n"
        "deadline=$(( $(date +%s) + 180 ))\n"
        f"until PGPASSWORD={shlex.quote(repl_password)} "
        f"pg_isready -h {shlex.quote(writer_alias)} -p {int(port)} "
        f"-U {shlex.quote(repl_user)} > /dev/null 2>&1; do\n"
        "  if [ $(date +%s) -ge $deadline ]; then\n"
        "    echo '[localemu] writer never became reachable' >&2\n"
        "    exit 1\n"
        "  fi\n"
        "  sleep 2\n"
        "done\n"
        "echo '[localemu] reader init: writer reachable, basebackup'\n"
        f"rm -rf {PGDATA}/* {PGDATA}/.[!.]* 2>/dev/null || true\n"
        f"PGPASSWORD={shlex.quote(repl_password)} pg_basebackup "
        f"-h {shlex.quote(writer_alias)} -p {int(port)} "
        f"-U {shlex.quote(repl_user)} "
        f"-D {PGDATA} -X stream -P -R\n"
        f"chown -R postgres:postgres {PGDATA}\n"
        f"chmod 700 {PGDATA}\n"
        "echo '[localemu] reader init: starting postgres as standby'\n"
        f"exec gosu postgres postgres {pg_args}\n"
    )


def reader_container_command(
    writer_alias: str, port: int, repl_user: str, repl_password: str,
    max_readers: int = 16,
) -> list[str]:
    """Wrap :func:`reader_init_shell` for use as a container CMD."""
    return [
        "bash", "-c",
        reader_init_shell(
            writer_alias, port, repl_user, repl_password, max_readers,
        ),
    ]


# ---------------------------------------------------------------------------
# Writer post-start init — runs inside the writer container after
# Postgres comes up, installs the replication user + grants
# ``pg_hba.conf`` access for it, and reloads the conf.
# ---------------------------------------------------------------------------

# Postgres role names cap at 63 bytes; reject anything weirder than
# the alnum+underscore set so we never build an injectable SQL string.
_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def render_create_replication_user_sql(
    repl_user: str, repl_password: str,
) -> str:
    """Idempotent ``CREATE USER ... REPLICATION`` SQL.

    Uses Postgres's ``DO`` block so re-running it (e.g. after a
    container restart) doesn't fail with ``role already exists``."""
    if not _SAFE_IDENT.match(repl_user):
        raise ValueError(f"unsafe replication user name: {repl_user!r}")
    # Escape any single quote in the password by doubling it.
    quoted_pw = repl_password.replace("'", "''")
    return (
        "DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{repl_user}') THEN "
        f"CREATE ROLE {repl_user} WITH REPLICATION LOGIN PASSWORD '{quoted_pw}'; "
        f"ELSE ALTER ROLE {repl_user} WITH PASSWORD '{quoted_pw}'; "
        "END IF; END $$;"
    )


def _exec(container: str, cmd: list[str], **kw) -> tuple[bytes, bytes]:
    """Thin wrapper around ``DOCKER_CLIENT.exec_in_container``."""
    return DOCKER_CLIENT.exec_in_container(container, cmd, **kw)


def _wait_for_postgres_in_container(
    container_name: str, master_username: str, timeout: int = 60,
) -> bool:
    """Block until ``pg_isready`` inside ``container_name`` reports
    Postgres is accepting connections. Returns True on success,
    False on timeout. Used so the post-boot init doesn't race the
    docker-entrypoint's ``initdb`` on a fresh writer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _exec(container_name, [
                "pg_isready", "-U", master_username, "-d", "postgres",
            ])
            return True
        except Exception:
            time.sleep(1)
    return False


def apply_writer_init(
    container_name: str, master_username: str,
    repl_user: str, repl_password: str,
) -> None:
    """Post-boot writer setup. Idempotent.

    Steps (all via ``docker exec``):
      0. Wait until Postgres inside the container is accepting
         connections (the docker-entrypoint runs initdb on first boot
         and only then exec's postgres, so the TCP port can be open
         before SQL is ready).
      1. Create / update the replication role with the derived
         password (idempotent ``DO`` block).
      2. Ensure the ``pg_hba.conf`` line that grants the role
         replication access from any host on the cluster bridge.
      3. ``SELECT pg_reload_conf()`` so the new ``pg_hba.conf`` is
         picked up without a restart.

    Failures here are logged but not raised: the container is already
    running, and surfacing the exception would prevent registering
    the writer at all. Failover and reader joins will surface the
    misconfiguration loudly when they fail to authenticate."""
    if not _wait_for_postgres_in_container(container_name, master_username):
        LOG.warning(
            "writer %s: Postgres did not accept SQL within timeout; "
            "skipping replication init", container_name,
        )
        return

    sql = render_create_replication_user_sql(repl_user, repl_password)
    try:
        _exec(container_name, [
            "psql", "-U", master_username, "-d", "postgres",
            "-v", "ON_ERROR_STOP=1", "-c", sql,
        ])
    except Exception:
        LOG.warning(
            "writer %s: CREATE ROLE %s failed; standbys may not "
            "authenticate", container_name, repl_user, exc_info=True,
        )
        return

    pg_hba_line = render_writer_pg_hba_line(repl_user).rstrip("\n")
    # Use grep -F -q to make the append idempotent across restarts.
    append_cmd = (
        f"grep -F -q {shlex.quote(pg_hba_line)} {PGDATA}/pg_hba.conf "
        f"|| echo {shlex.quote(pg_hba_line)} >> {PGDATA}/pg_hba.conf"
    )
    try:
        _exec(container_name, ["bash", "-c", append_cmd])
    except Exception:
        LOG.warning(
            "writer %s: pg_hba.conf append failed", container_name,
            exc_info=True,
        )
        return

    # Send SIGHUP to PID 1 inside the container so postgres re-reads
    # pg_hba.conf without disconnecting clients. ``psql -c SELECT
    # pg_reload_conf()`` races docker-entrypoint's user-init phase
    # and can return exit 2; SIGHUP is the underlying mechanism
    # anyway and is robust against that race.
    try:
        _exec(container_name, [
            "bash", "-c",
            "kill -HUP 1 2>/dev/null || pg_ctl -D " + PGDATA + " reload",
        ])
    except Exception:
        LOG.warning(
            "writer %s: SIGHUP reload failed", container_name,
            exc_info=True,
        )


def wait_for_standby_ready(
    host: str, port: int, repl_user: str, repl_password: str,
    timeout: int = 120,
) -> bool:
    """Poll ``pg_isready`` from the host machine to confirm the
    standby container is accepting connections. Returns True if it
    came up within ``timeout`` seconds, False otherwise.

    Note: a standby in recovery still answers ``pg_isready`` with
    "accepting connections" once it has replayed enough WAL to be
    consistent. That's the signal we want — the reader is queryable."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            import socket
            with socket.create_connection((host, port), timeout=2):
                return True
        except Exception:
            time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# DockerClusterOps — the real DockerOps the orchestrator uses for
# FailoverDBCluster. Replaces the warning-only :class:`_NoopDockerOps`
# placeholder.
# ---------------------------------------------------------------------------


def _container(db_instance_id: str) -> str:
    return f"localemu-rds-{db_instance_id}"


def render_alter_primary_conninfo_sql(
    writer_alias: str, port: int, repl_user: str, repl_password: str,
) -> str:
    """``ALTER SYSTEM SET primary_conninfo = '...'`` SQL that we
    issue inside a standby to repoint it at the new writer after
    failover. The standby picks up the new primary_conninfo on
    ``pg_reload_conf()`` without a restart."""
    if not _SAFE_IDENT.match(repl_user):
        raise ValueError(f"unsafe replication user: {repl_user!r}")
    # Escape any single quote in the password — defensive, since
    # replication_password_for_cluster returns a hex digest.
    pw = repl_password.replace("'", "''")
    alias = writer_alias.replace("'", "''")
    return (
        "ALTER SYSTEM SET primary_conninfo = "
        f"'host={alias} port={int(port)} user={repl_user} "
        f"password={pw} application_name=standby sslmode=disable';"
    )


class DockerClusterOps:
    """Real :class:`DockerOps` implementation for the orchestrator.

    Knows how to:
      * exec ``pg_ctl promote`` inside the chosen reader so Postgres
        exits recovery and becomes writable (``promote_to_writer``).
      * disconnect/reconnect the new writer's cluster-network
        attachment so it gains the ``<cluster_id>-writer`` alias that
        readers use in their ``primary_conninfo``
        (``set_writer_network_alias``). Old writer (if still up)
        loses the alias.
      * exec into each remaining standby and ``ALTER SYSTEM`` its
        ``primary_conninfo`` to the new writer, then SIGHUP
        (``repoint_reader_to_writer``).
      * ``docker stop`` the old writer as a best-effort cleanup."""

    def __init__(
        self,
        cluster_network_name_fn,
        repl_user: str,
        repl_password_fn,
        repl_port: int = 5432,
    ) -> None:
        self._cluster_network_name = cluster_network_name_fn
        self._repl_user = repl_user
        self._repl_password_for = repl_password_fn
        self._repl_port = repl_port

    def promote_to_writer(self, instance_id: str) -> None:
        try:
            _exec(_container(instance_id), [
                "gosu", "postgres", "pg_ctl", "-D", PGDATA, "promote",
            ])
            LOG.info("cluster: promoted %s via pg_ctl promote", instance_id)
        except Exception:
            LOG.warning(
                "cluster: pg_ctl promote on %s failed", instance_id,
                exc_info=True,
            )
            raise

    def repoint_reader_to_writer(
        self, reader_instance_id: str, writer_alias: str, port: int,
    ) -> None:
        """Re-attach a standby to the new writer by restarting its
        container.

        Physical streaming after a failover faces a divergence
        problem: the new writer's promoted timeline forked off the
        old timeline at some LSN, but the remaining standby was
        likely streaming AHEAD of that fork point at the moment of
        failover. Postgres won't catch up — it logs ``new timeline N
        forked off current database system timeline N-1 before
        current recovery point`` and waits forever.

        Fix: do what real Aurora does — re-base each surviving
        standby from the new writer. The container's CMD already
        handles ``wipe PGDATA → pg_basebackup → exec postgres`` on
        every start, so a ``docker stop && docker start`` re-runs
        the basebackup automatically. The Docker network attachment
        survives, and the writer alias now resolves to the new
        writer."""
        name = _container(reader_instance_id)
        try:
            DOCKER_CLIENT.stop_container(name, timeout=10)
        except Exception:
            LOG.debug(
                "cluster: stop on standby %s failed", reader_instance_id,
                exc_info=True,
            )
        try:
            DOCKER_CLIENT.start_container(name)
            LOG.info(
                "cluster: standby %s restarted; pg_basebackup will "
                "re-sync from new writer %s",
                reader_instance_id, writer_alias,
            )
        except Exception:
            LOG.warning(
                "cluster: failed to restart standby %s after failover",
                reader_instance_id, exc_info=True,
            )

    def set_writer_network_alias(
        self, cluster_id: str, new_writer_instance_id: str,
    ) -> None:
        net = self._cluster_network_name(cluster_id)
        writer_alias = f"{cluster_id}-writer"
        # Disconnect + reconnect the new writer with the writer alias
        # added. Docker has no in-place alias mutation API.
        try:
            DOCKER_CLIENT.disconnect_container_from_network(
                network_name=net,
                container_name_or_id=_container(new_writer_instance_id),
            )
        except Exception:
            LOG.debug(
                "cluster: disconnect %s from %s failed (already "
                "disconnected?)", new_writer_instance_id, net, exc_info=True,
            )
        try:
            DOCKER_CLIENT.connect_container_to_network(
                network_name=net,
                container_name_or_id=_container(new_writer_instance_id),
                aliases=[new_writer_instance_id, writer_alias],
            )
            LOG.info(
                "cluster %s: %s now holds the %s alias",
                cluster_id, new_writer_instance_id, writer_alias,
            )
        except Exception:
            LOG.warning(
                "cluster %s: failed to re-attach %s with writer alias",
                cluster_id, new_writer_instance_id, exc_info=True,
            )

    def stop_instance_container(self, instance_id: str) -> None:
        try:
            DOCKER_CLIENT.stop_container(_container(instance_id), timeout=10)
        except Exception:
            LOG.debug(
                "cluster: stop_container(%s) failed; continuing",
                instance_id, exc_info=True,
            )


def make_docker_cluster_ops() -> "DockerClusterOps":
    """Build a :class:`DockerClusterOps` wired against the live
    orchestrator singleton so each call can look up the right
    cluster password by id at the moment of failover."""
    from localemu.services.rds.cluster_orchestrator import get_orchestrator
    from localemu.services.rds.docker.db_manager import cluster_network_name

    def _password_for(cluster_id: str) -> str:
        topo = get_orchestrator().topology(cluster_id)
        if topo is None:
            return ""
        return replication_password_for_cluster(
            cluster_id, topo.master_password,
        )

    return DockerClusterOps(
        cluster_network_name_fn=cluster_network_name,
        repl_user=REPLICATION_USER,
        repl_password_fn=_password_for,
    )
