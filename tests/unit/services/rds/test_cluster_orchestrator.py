"""Tests for the pure cluster orchestrator — topology, target picking,
endpoint map, and failover sequencing with a mocked DockerOps.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.rds.cluster_orchestrator import (
    ClusterOrchestrator,
    ClusterTopology,
    EndpointMap,
    NoFailoverTargetError,
    pick_failover_target,
    render_primary_conninfo,
    render_writer_pg_hba_line,
    render_writer_postgres_conf,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

class TestRenderConfigs:
    def test_writer_conf_has_replication_directives(self):
        s = render_writer_postgres_conf(max_readers=3)
        assert "wal_level = replica" in s
        assert "max_wal_senders = 4" in s
        assert "max_replication_slots = 4" in s
        assert "hot_standby = on" in s
        assert "listen_addresses = '*'" in s

    def test_writer_conf_minimum_floor(self):
        """Tiny max_readers must not yield max_wal_senders<4."""
        s = render_writer_postgres_conf(max_readers=0)
        assert "max_wal_senders = 4" in s
        assert "max_replication_slots = 4" in s

    def test_pg_hba_includes_replication_grant(self):
        line = render_writer_pg_hba_line("repl")
        assert line.startswith("host replication repl ")
        assert "0.0.0.0/0" in line
        assert line.endswith("md5\n")

    def test_primary_conninfo_shape(self):
        s = render_primary_conninfo("c1-writer", 5432, "repl", "secret")
        assert "host=c1-writer" in s
        assert "port=5432" in s
        assert "user=repl" in s
        assert "password=secret" in s
        assert "application_name=standby" in s


# ---------------------------------------------------------------------------
# Failover target picking
# ---------------------------------------------------------------------------

def _topology_with(*members):
    """``members`` is a list of (instance_id, is_writer, tier) tuples."""
    from localemu.services.rds.cluster_orchestrator import ClusterMember
    t = ClusterTopology(
        cluster_id="c1", engine="aurora-postgresql",
        network_name="localemu-aurora-c1",
        master_username="m", master_password="p",
    )
    for iid, is_writer, tier in members:
        t.members[iid] = ClusterMember(
            instance_id=iid, is_writer=is_writer,
            promotion_tier=tier, host_port=10000 + len(t.members),
        )
    return t


class TestPickFailoverTarget:
    def test_no_readers_raises(self):
        t = _topology_with(("w", True, 1))
        with pytest.raises(NoFailoverTargetError):
            pick_failover_target(t)

    def test_explicit_target_must_be_a_reader(self):
        t = _topology_with(("w", True, 1), ("r1", False, 1))
        with pytest.raises(NoFailoverTargetError):
            pick_failover_target(t, target_instance_id="w")
        with pytest.raises(NoFailoverTargetError):
            pick_failover_target(t, target_instance_id="bogus")

    def test_explicit_target_wins(self):
        t = _topology_with(
            ("w", True, 1), ("r1", False, 5), ("r2", False, 1),
        )
        # Without a target, lowest tier (r2) would win. Explicit r1
        # overrides.
        chosen = pick_failover_target(t, target_instance_id="r1")
        assert chosen.instance_id == "r1"

    def test_default_picks_lowest_tier(self):
        t = _topology_with(
            ("w", True, 1), ("r1", False, 5), ("r2", False, 2),
        )
        chosen = pick_failover_target(t)
        assert chosen.instance_id == "r2"

    def test_tier_tie_break_alphabetical(self):
        t = _topology_with(
            ("w", True, 1),
            ("z-reader", False, 1), ("a-reader", False, 1),
        )
        chosen = pick_failover_target(t)
        assert chosen.instance_id == "a-reader"


# ---------------------------------------------------------------------------
# EndpointMap
# ---------------------------------------------------------------------------

class TestEndpointMap:
    def test_empty_returns_zero(self):
        m = EndpointMap()
        assert m.writer_port("c1") == 0
        assert m.next_reader_port("c1") == 0

    def test_writer_and_readers_tracked(self):
        m = EndpointMap()
        m.set_writer_port("c1", 11000)
        m.add_reader_port("c1", 11001)
        m.add_reader_port("c1", 11002)
        assert m.writer_port("c1") == 11000
        # Round-robin across readers
        seen = {m.next_reader_port("c1") for _ in range(20)}
        assert seen == {11001, 11002}

    def test_duplicate_reader_port_is_ignored(self):
        m = EndpointMap()
        m.add_reader_port("c1", 11001)
        m.add_reader_port("c1", 11001)
        # Single reader → every pick returns it
        assert {m.next_reader_port("c1") for _ in range(5)} == {11001}

    def test_drop_reader(self):
        m = EndpointMap()
        m.add_reader_port("c1", 11001)
        m.drop_reader_port("c1", 11001)
        assert m.next_reader_port("c1") == 0

    def test_forget_cluster_clears(self):
        m = EndpointMap()
        m.set_writer_port("c1", 11000)
        m.forget_cluster("c1")
        assert m.writer_port("c1") == 0


# ---------------------------------------------------------------------------
# Orchestrator: register + failover
# ---------------------------------------------------------------------------

def _fresh_orchestrator():
    docker = mock.MagicMock()
    return ClusterOrchestrator(docker), docker


def _register_cluster(orch, *, writer="w", readers=(("r1", 2), ("r2", 1))):
    orch.register_cluster(
        "c1", "aurora-postgresql", "localemu-aurora-c1", "master", "secret",
    )
    orch.register_member("c1", writer, True, 1, host_port=12000)
    for i, (rid, tier) in enumerate(readers):
        orch.register_member("c1", rid, False, tier, host_port=12001 + i)


class TestOrchestratorRegistration:
    def test_register_cluster_then_members(self):
        orch, _ = _fresh_orchestrator()
        _register_cluster(orch)
        t = orch.topology("c1")
        assert t is not None
        assert t.writer.instance_id == "w"
        assert sorted(m.instance_id for m in t.readers) == ["r1", "r2"]
        assert orch.writer_port("c1") == 12000
        # Reader endpoint round-robins both readers
        seen = {orch.reader_port("c1") for _ in range(20)}
        assert seen == {12001, 12002}

    def test_register_member_into_unknown_cluster_raises(self):
        orch, _ = _fresh_orchestrator()
        with pytest.raises(KeyError):
            orch.register_member("c-unknown", "r1", False, 1, 5000)

    def test_deregister_writer_clears_writer_port(self):
        orch, _ = _fresh_orchestrator()
        _register_cluster(orch)
        orch.deregister_member("c1", "w")
        assert orch.writer_port("c1") == 0

    def test_deregister_reader_drops_endpoint(self):
        orch, _ = _fresh_orchestrator()
        _register_cluster(orch)
        orch.deregister_member("c1", "r1")
        # Only r2 (port 12002) remains
        assert {orch.reader_port("c1") for _ in range(5)} == {12002}


class TestOrchestratorFailover:
    def test_failover_promotes_lowest_tier_reader(self):
        orch, docker = _fresh_orchestrator()
        _register_cluster(orch)  # readers: r1 tier=2, r2 tier=1
        new_writer = orch.failover("c1")
        assert new_writer.instance_id == "r2"
        # Docker ops called in the right order with right args
        docker.promote_to_writer.assert_called_once_with("r2")
        docker.set_writer_network_alias.assert_called_once_with("c1", "r2")
        # r1 repointed; r2 (the promoted one) and the demoted old writer
        # don't get repointed
        repoint_calls = [c.args[0] for c in docker.repoint_reader_to_writer.call_args_list]
        assert repoint_calls == ["r1"]
        docker.stop_instance_container.assert_called_once_with("w")
        # Endpoint map flipped
        assert orch.writer_port("c1") == 12002
        # r2 no longer in reader rotation; r1 alone
        assert {orch.reader_port("c1") for _ in range(5)} == {12001}
        # Topology no longer carries old writer
        assert "w" not in orch.topology("c1").members

    def test_failover_with_explicit_target(self):
        orch, docker = _fresh_orchestrator()
        _register_cluster(orch)
        new_writer = orch.failover("c1", target_instance_id="r1")
        assert new_writer.instance_id == "r1"
        docker.promote_to_writer.assert_called_once_with("r1")

    def test_failover_with_no_readers_raises(self):
        orch, _ = _fresh_orchestrator()
        orch.register_cluster(
            "c1", "aurora-postgresql", "n", "m", "p",
        )
        orch.register_member("c1", "w", True, 1, 12000)
        with pytest.raises(NoFailoverTargetError):
            orch.failover("c1")

    def test_failover_with_unknown_cluster_raises(self):
        orch, _ = _fresh_orchestrator()
        with pytest.raises(KeyError):
            orch.failover("never-existed")

    def test_failover_stop_old_writer_failure_does_not_abort(self):
        """Stopping the old writer is best-effort; the new writer is
        already promoted at that point and we must not leave the
        cluster half-failed-over."""
        orch, docker = _fresh_orchestrator()
        _register_cluster(orch)
        docker.stop_instance_container.side_effect = RuntimeError("docker down")
        new_writer = orch.failover("c1")
        assert new_writer.instance_id == "r2"
        assert orch.writer_port("c1") == 12002
