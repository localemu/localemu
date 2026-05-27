"""Pure orchestration for Aurora cluster topology.

This module is the brain behind real writer/reader topology + failover.
It is intentionally pure-Python with a small injection seam
(:class:`DockerOps`) so the heavy Docker-side work can be mocked in
tests. Provider + DockerDbManager call into here; nothing here imports
provider or db_manager (one-way dependency).

Responsibilities:

  * Track per-cluster membership (writer + readers, ports, promotion
    tiers, network name).
  * Render the Postgres config strings that initialize a writer for
    replication and a reader for streaming standby.
  * Pick the right failover target given an explicit
    ``TargetDBInstanceIdentifier`` or a tier-based default.
  * Drive the failover sequence (promote target → repoint siblings →
    stop old writer → update endpoint map + moto state). The actual
    Docker exec calls are delegated to an injected :class:`DockerOps`.

See ``DESIGN_aurora_topology.md`` for full architecture.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from itertools import count
from typing import Protocol

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass
class ClusterMember:
    """One container's role within a cluster."""
    instance_id: str
    is_writer: bool
    promotion_tier: int = 1
    host_port: int = 0  # the port exposed on the host (updated at start)


@dataclass
class ClusterTopology:
    """In-memory view of an Aurora cluster's membership.

    The orchestrator owns one of these per cluster. Membership is
    re-derivable from container labels (``localemu.cluster-id`` etc.)
    on a cold start; ``ClusterOrchestrator.recover_from_labels``
    re-hydrates this from the running Docker world.
    """
    cluster_id: str
    engine: str
    network_name: str
    master_username: str
    master_password: str
    members: dict[str, ClusterMember] = field(default_factory=dict)

    @property
    def writer(self) -> ClusterMember | None:
        for m in self.members.values():
            if m.is_writer:
                return m
        return None

    @property
    def readers(self) -> list[ClusterMember]:
        return [m for m in self.members.values() if not m.is_writer]

    def writer_alias(self) -> str:
        """Docker network alias the readers use in primary_conninfo."""
        return f"{self.cluster_id}-writer"


# ---------------------------------------------------------------------------
# Pure helpers — pg config + target picking
# ---------------------------------------------------------------------------

def render_writer_postgres_conf(max_readers: int = 16) -> str:
    """The minimal postgresql.conf delta that turns a vanilla
    Postgres image into a replication source. The image's stock
    conf is left intact; these directives are appended."""
    return (
        "wal_level = replica\n"
        f"max_wal_senders = {max(int(max_readers) + 1, 4)}\n"
        f"max_replication_slots = {max(int(max_readers) + 1, 4)}\n"
        "hot_standby = on\n"
        "listen_addresses = '*'\n"
        "wal_keep_size = 1024\n"
    )


def render_writer_pg_hba_line(replication_user: str) -> str:
    """A pg_hba.conf line that lets ``replication_user`` connect for
    physical streaming replication from any host on the cluster's
    Docker bridge."""
    return f"host replication {replication_user} 0.0.0.0/0 md5\n"


def render_primary_conninfo(
    writer_alias: str, port: int, replication_user: str, password: str,
) -> str:
    """The ``primary_conninfo`` string a standby writes to its
    ``postgresql.auto.conf`` so it can stream from the writer.
    Used both for initial standby setup and on failover (when the
    standby's primary_conninfo gets ALTER SYSTEM-ed to the new
    writer)."""
    return (
        f"host={writer_alias} port={port} "
        f"user={replication_user} password={password} "
        "application_name=standby sslmode=disable"
    )


class NoFailoverTargetError(Exception):
    """Raised when FailoverDBCluster cannot find a promotable
    reader (no readers at all, or the only readers are the
    requested target which == current writer)."""


def pick_failover_target(
    topology: ClusterTopology,
    target_instance_id: str | None = None,
) -> ClusterMember:
    """Resolve the reader to promote.

    Explicit ``target_instance_id`` wins if it's a valid reader.
    Otherwise: lowest ``promotion_tier`` reader; ties broken by
    instance_id ascending. Real AWS uses replication-lag as the
    final tie-break; MVP defers that.

    Raises :class:`NoFailoverTargetError` when no eligible reader
    exists.
    """
    readers = topology.readers
    if not readers:
        raise NoFailoverTargetError(
            f"cluster {topology.cluster_id} has no readers to promote",
        )
    if target_instance_id:
        # Caller-specified target must be a current reader.
        match = topology.members.get(target_instance_id)
        if match is None or match.is_writer:
            raise NoFailoverTargetError(
                f"target {target_instance_id} is not a reader in "
                f"cluster {topology.cluster_id}",
            )
        return match
    return sorted(
        readers, key=lambda m: (m.promotion_tier, m.instance_id),
    )[0]


# ---------------------------------------------------------------------------
# Endpoint map — cluster_id → writer port + rotating reader port
# ---------------------------------------------------------------------------

@dataclass
class _ClusterEndpoints:
    writer_port: int = 0
    reader_ports: list[int] = field(default_factory=list)
    _rr: count = field(default_factory=lambda: count(0))


class EndpointMap:
    """Per-cluster host-port resolution for the writer + reader
    endpoints. ``DescribeDBClusters`` reads from here so the response
    reflects the CURRENT topology even after failover."""

    def __init__(self) -> None:
        self._map: dict[str, _ClusterEndpoints] = {}
        self._lock = threading.Lock()

    def set_writer_port(self, cluster_id: str, port: int) -> None:
        with self._lock:
            entry = self._map.setdefault(cluster_id, _ClusterEndpoints())
            entry.writer_port = int(port)

    def add_reader_port(self, cluster_id: str, port: int) -> None:
        with self._lock:
            entry = self._map.setdefault(cluster_id, _ClusterEndpoints())
            if int(port) not in entry.reader_ports:
                entry.reader_ports.append(int(port))

    def drop_reader_port(self, cluster_id: str, port: int) -> None:
        with self._lock:
            entry = self._map.get(cluster_id)
            if entry is None:
                return
            try:
                entry.reader_ports.remove(int(port))
            except ValueError:
                pass

    def writer_port(self, cluster_id: str) -> int:
        with self._lock:
            entry = self._map.get(cluster_id)
            return entry.writer_port if entry else 0

    def next_reader_port(self, cluster_id: str) -> int:
        """Round-robin across registered reader ports. Returns 0 when
        the cluster has no readers (caller falls back to writer)."""
        with self._lock:
            entry = self._map.get(cluster_id)
            if entry is None or not entry.reader_ports:
                return 0
            idx = next(entry._rr) % len(entry.reader_ports)
            return entry.reader_ports[idx]

    def forget_cluster(self, cluster_id: str) -> None:
        with self._lock:
            self._map.pop(cluster_id, None)


# ---------------------------------------------------------------------------
# Injection seam — the Docker-side ops the orchestrator calls
# ---------------------------------------------------------------------------

class DockerOps(Protocol):
    """Methods on the live DockerDbManager that the orchestrator
    needs. Defined as a Protocol so tests can pass a Mock without
    importing the heavyweight db_manager."""

    def promote_to_writer(self, instance_id: str) -> None: ...
    def repoint_reader_to_writer(
        self, reader_instance_id: str, writer_alias: str, port: int,
    ) -> None: ...
    def stop_instance_container(self, instance_id: str) -> None: ...
    def set_writer_network_alias(
        self, cluster_id: str, new_writer_instance_id: str,
    ) -> None: ...


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------

class ClusterOrchestrator:
    """Owns per-cluster topology + endpoint state, drives failover.

    Constructed once per process; the RDS provider holds the singleton.
    All state is in-memory but reconstructable from Docker labels via
    :meth:`recover_from_labels` on cold start.
    """

    def __init__(self, docker_ops: DockerOps) -> None:
        self._docker = docker_ops
        self._topologies: dict[str, ClusterTopology] = {}
        self._endpoints = EndpointMap()
        self._cluster_locks: dict[str, threading.RLock] = {}
        self._registry_lock = threading.RLock()

    # ----- topology mutation -----

    def register_cluster(
        self, cluster_id: str, engine: str, network_name: str,
        master_username: str, master_password: str,
    ) -> ClusterTopology:
        with self._registry_lock:
            topology = self._topologies.get(cluster_id)
            if topology is None:
                topology = ClusterTopology(
                    cluster_id=cluster_id,
                    engine=engine,
                    network_name=network_name,
                    master_username=master_username,
                    master_password=master_password,
                )
                self._topologies[cluster_id] = topology
                self._cluster_locks[cluster_id] = threading.RLock()
            return topology

    def register_member(
        self, cluster_id: str, instance_id: str, is_writer: bool,
        promotion_tier: int, host_port: int,
    ) -> None:
        topology = self._topologies.get(cluster_id)
        if topology is None:
            raise KeyError(f"cluster {cluster_id} not registered")
        with self._cluster_lock(cluster_id):
            topology.members[instance_id] = ClusterMember(
                instance_id=instance_id, is_writer=is_writer,
                promotion_tier=promotion_tier, host_port=host_port,
            )
            if is_writer:
                self._endpoints.set_writer_port(cluster_id, host_port)
            else:
                self._endpoints.add_reader_port(cluster_id, host_port)

    def deregister_member(
        self, cluster_id: str, instance_id: str,
    ) -> None:
        topology = self._topologies.get(cluster_id)
        if topology is None:
            return
        with self._cluster_lock(cluster_id):
            member = topology.members.pop(instance_id, None)
            if member is None:
                return
            if member.is_writer:
                self._endpoints.set_writer_port(cluster_id, 0)
            else:
                self._endpoints.drop_reader_port(cluster_id, member.host_port)

    def forget_cluster(self, cluster_id: str) -> None:
        with self._registry_lock:
            self._topologies.pop(cluster_id, None)
            self._cluster_locks.pop(cluster_id, None)
        self._endpoints.forget_cluster(cluster_id)

    # ----- read accessors -----

    def topology(self, cluster_id: str) -> ClusterTopology | None:
        return self._topologies.get(cluster_id)

    def writer_port(self, cluster_id: str) -> int:
        return self._endpoints.writer_port(cluster_id)

    def reader_port(self, cluster_id: str) -> int:
        """Round-robin pick across registered reader ports.
        Returns 0 when the cluster has no readers."""
        return self._endpoints.next_reader_port(cluster_id)

    # ----- failover -----

    def failover(
        self, cluster_id: str, target_instance_id: str | None = None,
    ) -> ClusterMember:
        """Promote a reader to writer; demote the current writer.

        Returns the new writer's :class:`ClusterMember`. Raises
        :class:`NoFailoverTargetError` when no eligible reader exists
        or :class:`KeyError` when the cluster is unknown.
        """
        topology = self._topologies.get(cluster_id)
        if topology is None:
            raise KeyError(f"cluster {cluster_id} not registered")
        with self._cluster_lock(cluster_id):
            target = pick_failover_target(topology, target_instance_id)
            old_writer = topology.writer
            old_writer_port = old_writer.host_port if old_writer else 0

            # 1. Promote the target reader to writer (Docker side).
            self._docker.promote_to_writer(target.instance_id)

            # 2. Update Docker network alias so siblings can reach
            #    the new writer by name on the cluster network.
            self._docker.set_writer_network_alias(
                cluster_id, target.instance_id,
            )

            # 3. Repoint every OTHER reader to the new writer.
            for member in list(topology.members.values()):
                if (
                    member.instance_id == target.instance_id
                    or member.is_writer
                ):
                    continue
                self._docker.repoint_reader_to_writer(
                    member.instance_id, topology.writer_alias(),
                    target.host_port,
                )

            # 4. Stop the old writer container. MVP behavior: it's
            #    out of the cluster until the user manually re-adds
            #    it via CreateDBInstance (real AWS rejoins it as a
            #    reader; tracked as a follow-up).
            if old_writer is not None:
                try:
                    self._docker.stop_instance_container(old_writer.instance_id)
                except Exception:
                    LOG.warning(
                        "cluster %s: failed to stop old writer %s after "
                        "failover", cluster_id, old_writer.instance_id,
                        exc_info=True,
                    )
                self._endpoints.drop_reader_port(cluster_id, old_writer_port)
                # Remove from topology — caller (provider) syncs moto.
                topology.members.pop(old_writer.instance_id, None)

            # 5. Flip flags + endpoint map.
            target.is_writer = True
            self._endpoints.drop_reader_port(cluster_id, target.host_port)
            self._endpoints.set_writer_port(cluster_id, target.host_port)
            LOG.info(
                "cluster %s: failover complete, new writer=%s (port=%s)",
                cluster_id, target.instance_id, target.host_port,
            )
            return target

    # ----- internals -----

    def _cluster_lock(self, cluster_id: str) -> threading.RLock:
        with self._registry_lock:
            lock = self._cluster_locks.get(cluster_id)
            if lock is None:
                lock = threading.RLock()
                self._cluster_locks[cluster_id] = lock
            return lock


# ---------------------------------------------------------------------------
# Process-wide singleton — the provider grabs this once and shares with the
# whole RDS subsystem. Constructed lazily so importing this module before
# the DockerDbManager exists is safe (e.g. unit tests).
# ---------------------------------------------------------------------------

_orchestrator: ClusterOrchestrator | None = None
_orchestrator_lock = threading.Lock()


def get_orchestrator(docker_ops: DockerOps | None = None) -> ClusterOrchestrator:
    """Return the process-wide :class:`ClusterOrchestrator`, creating
    it on first call. ``docker_ops`` is REQUIRED on the first call;
    subsequent calls return the cached instance and ignore the
    argument (the singleton's bindings are immutable for the
    lifetime of the process)."""
    global _orchestrator
    with _orchestrator_lock:
        if _orchestrator is None:
            if docker_ops is None:
                raise RuntimeError(
                    "cluster_orchestrator: first call must supply docker_ops",
                )
            _orchestrator = ClusterOrchestrator(docker_ops)
        return _orchestrator


def reset_orchestrator_for_tests() -> None:
    """Drop the singleton so tests can install a fresh one with
    mocked DockerOps. Tests-only."""
    global _orchestrator
    with _orchestrator_lock:
        _orchestrator = None
