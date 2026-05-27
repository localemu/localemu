"""Provider-level cluster routing: a CreateDBInstance call that
carries ``DBClusterIdentifier`` (or whose moto record is tagged with
one) routes the new container through the orchestrator as a reader and
inherits the cluster's master credentials so streaming replication can
authenticate.

These tests mock ``call_moto`` and the Docker db manager so they stay
pure: no Docker, no real moto state mutation.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.rds import provider
from localemu.services.rds.cluster_orchestrator import (
    reset_orchestrator_for_tests,
)
from localemu.services.rds.docker.db_manager import RdsContainerInfo


@pytest.fixture(autouse=True)
def _fresh_orchestrator():
    reset_orchestrator_for_tests()
    yield
    reset_orchestrator_for_tests()


def _fake_ctx(region: str = "us-east-1"):
    ctx = mock.MagicMock()
    ctx.region = region
    ctx.account_id = "000000000000"
    return ctx


def _info(db_id: str, *, host_port: int, cluster_id: str | None = None,
          is_writer: bool = False) -> RdsContainerInfo:
    return RdsContainerInfo(
        db_instance_id=db_id, container_name=f"localemu-rds-{db_id}",
        engine="aurora-postgresql", image="postgres:15",
        host_port=host_port, container_port=5432,
        master_username="admin", master_password="secret",
        cluster_id=cluster_id, is_writer=is_writer,
    )


class TestCreateDbInstanceClusterRouting:
    """``_handle_create_db_instance`` must:
      * detect cluster membership from request OR moto record
      * call ``mgr.create_db_instance`` with cluster kwargs set
      * register the new container with the orchestrator
    """

    def test_standalone_instance_unchanged(self):
        """No cluster_id anywhere → no orchestrator side effects, no
        cluster kwargs on the manager call."""
        ctx = _fake_ctx()
        request = {
            "DBInstanceIdentifier": "i-solo",
            "Engine": "postgres",
            "MasterUserPassword": "pw",
        }
        mgr = mock.MagicMock()
        mgr.create_db_instance.return_value = _info("i-solo", host_port=14000)
        with mock.patch.object(
            provider, "call_moto",
            return_value={"DBInstance": {
                "DBInstanceIdentifier": "i-solo",
                "Engine": "postgres", "MasterUsername": "admin",
            }},
        ), mock.patch.object(provider, "_init_db_manager", return_value=mgr):
            provider._handle_create_db_instance(ctx, request)
        kwargs = mgr.create_db_instance.call_args.kwargs
        assert kwargs.get("cluster_id") is None
        assert kwargs.get("is_writer") is False
        assert kwargs.get("promotion_tier") == 1

    def test_cluster_member_routes_as_reader_when_writer_exists(self):
        """The cluster already has a writer registered (from a prior
        CreateDBCluster). A subsequent CreateDBInstance must add the
        new instance as a reader."""
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c1", "aurora-postgresql", "localemu-aurora-c1",
            "cluster-master", "cluster-secret",
        )
        orch.register_member("c1", "c1", is_writer=True, promotion_tier=1,
                             host_port=15000)

        ctx = _fake_ctx()
        request = {
            "DBInstanceIdentifier": "c1-r1",
            "DBClusterIdentifier": "c1",
            "Engine": "aurora-postgresql",
        }
        mgr = mock.MagicMock()
        mgr.create_db_instance.return_value = _info(
            "c1-r1", host_port=15001, cluster_id="c1", is_writer=False,
        )
        with mock.patch.object(
            provider, "call_moto",
            return_value={"DBInstance": {
                "DBInstanceIdentifier": "c1-r1",
                "Engine": "aurora-postgresql",
                "DBClusterIdentifier": "c1",
                "MasterUsername": "admin",
            }},
        ), mock.patch.object(provider, "_init_db_manager", return_value=mgr), \
            mock.patch(
                "localemu.services.rds.docker.db_manager.ensure_cluster_network"
            ) as ens:
            provider._handle_create_db_instance(ctx, request)
        ens.assert_called_once_with("c1")
        kwargs = mgr.create_db_instance.call_args.kwargs
        assert kwargs["cluster_id"] == "c1"
        assert kwargs["is_writer"] is False
        # Member inherits cluster master credentials so replication
        # auth works.
        assert kwargs["master_username"] == "cluster-master"
        assert kwargs["master_password"] == "cluster-secret"
        # Orchestrator now knows about the reader → reader_port returns
        # the new port.
        assert orch.reader_port("c1") == 15001

    def test_cluster_id_from_moto_record_when_absent_in_request(self):
        """Some clients omit DBClusterIdentifier on the request body
        but moto tags the record post-create. Detection must use the
        record as a fallback."""
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c2", "aurora-postgresql", "localemu-aurora-c2", "m", "p",
        )
        orch.register_member("c2", "c2", is_writer=True, promotion_tier=1,
                             host_port=16000)

        ctx = _fake_ctx()
        request = {"DBInstanceIdentifier": "c2-r1"}
        mgr = mock.MagicMock()
        mgr.create_db_instance.return_value = _info(
            "c2-r1", host_port=16001, cluster_id="c2", is_writer=False,
        )
        with mock.patch.object(
            provider, "call_moto",
            return_value={"DBInstance": {
                "DBInstanceIdentifier": "c2-r1",
                "DBClusterIdentifier": "c2",
            }},
        ), mock.patch.object(provider, "_init_db_manager", return_value=mgr), \
            mock.patch(
                "localemu.services.rds.docker.db_manager.ensure_cluster_network"
            ):
            provider._handle_create_db_instance(ctx, request)
        assert mgr.create_db_instance.call_args.kwargs["cluster_id"] == "c2"
        assert orch.reader_port("c2") == 16001

    def test_first_member_becomes_writer_when_no_writer_registered(self):
        """Real AWS: CreateDBCluster only mints the cluster record;
        the user calls CreateDBInstance to add the first instance,
        which becomes the writer. If LocalEmu reaches a state where
        the cluster is registered but has no writer (e.g. the writer
        container failed to spawn during CreateDBCluster), the next
        CreateDBInstance should fill that role."""
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c3", "aurora-postgresql", "localemu-aurora-c3", "m", "p",
        )
        # No writer registered yet
        ctx = _fake_ctx()
        request = {
            "DBInstanceIdentifier": "c3-first",
            "DBClusterIdentifier": "c3",
        }
        mgr = mock.MagicMock()
        mgr.create_db_instance.return_value = _info(
            "c3-first", host_port=17000, cluster_id="c3", is_writer=True,
        )
        with mock.patch.object(
            provider, "call_moto",
            return_value={"DBInstance": {
                "DBInstanceIdentifier": "c3-first",
                "DBClusterIdentifier": "c3",
            }},
        ), mock.patch.object(provider, "_init_db_manager", return_value=mgr), \
            mock.patch(
                "localemu.services.rds.docker.db_manager.ensure_cluster_network"
            ):
            provider._handle_create_db_instance(ctx, request)
        assert mgr.create_db_instance.call_args.kwargs["is_writer"] is True
        assert orch.writer_port("c3") == 17000

    def test_promotion_tier_from_request(self):
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c4", "aurora-postgresql", "localemu-aurora-c4", "m", "p",
        )
        orch.register_member("c4", "c4", is_writer=True, promotion_tier=1,
                             host_port=18000)
        ctx = _fake_ctx()
        request = {
            "DBInstanceIdentifier": "c4-r1",
            "DBClusterIdentifier": "c4",
            "PromotionTier": "5",
        }
        mgr = mock.MagicMock()
        mgr.create_db_instance.return_value = _info(
            "c4-r1", host_port=18001, cluster_id="c4", is_writer=False,
        )
        with mock.patch.object(
            provider, "call_moto",
            return_value={"DBInstance": {
                "DBInstanceIdentifier": "c4-r1",
                "DBClusterIdentifier": "c4",
            }},
        ), mock.patch.object(provider, "_init_db_manager", return_value=mgr), \
            mock.patch(
                "localemu.services.rds.docker.db_manager.ensure_cluster_network"
            ):
            provider._handle_create_db_instance(ctx, request)
        assert mgr.create_db_instance.call_args.kwargs["promotion_tier"] == 5


class TestDeleteDbInstanceClusterDeregistration:
    def test_cluster_member_deregisters_from_orchestrator(self):
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c5", "aurora-postgresql", "localemu-aurora-c5", "m", "p",
        )
        orch.register_member("c5", "c5", is_writer=True, promotion_tier=1,
                             host_port=19000)
        orch.register_member("c5", "c5-r1", is_writer=False,
                             promotion_tier=1, host_port=19001)

        ctx = _fake_ctx()
        request = {"DBInstanceIdentifier": "c5-r1"}
        mgr = mock.MagicMock()
        mgr.get_instance_info.return_value = _info(
            "c5-r1", host_port=19001, cluster_id="c5", is_writer=False,
        )
        with mock.patch.object(provider, "call_moto", return_value={}), \
            mock.patch.object(provider, "_init_db_manager", return_value=mgr):
            provider._handle_delete_db_instance(ctx, request)
        # Reader endpoint map no longer hands out the deleted reader.
        assert orch.reader_port("c5") == 0
        mgr.delete_db_instance.assert_called_once_with("c5-r1")

    def test_standalone_instance_skips_orchestrator(self):
        ctx = _fake_ctx()
        request = {"DBInstanceIdentifier": "i-solo"}
        mgr = mock.MagicMock()
        mgr.get_instance_info.return_value = _info("i-solo", host_port=20000)
        with mock.patch.object(provider, "call_moto", return_value={}), \
            mock.patch.object(provider, "_init_db_manager", return_value=mgr):
            provider._handle_delete_db_instance(ctx, request)
        mgr.delete_db_instance.assert_called_once_with("i-solo")


class TestDeleteDbClusterTearsDownMembers:
    def test_all_members_are_deleted_and_topology_forgotten(self):
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.db_manager import _NoopDockerOps

        orch = get_orchestrator(_NoopDockerOps())
        orch.register_cluster(
            "c6", "aurora-postgresql", "localemu-aurora-c6", "m", "p",
        )
        orch.register_member("c6", "c6", is_writer=True, promotion_tier=1,
                             host_port=21000)
        orch.register_member("c6", "c6-r1", is_writer=False,
                             promotion_tier=1, host_port=21001)
        orch.register_member("c6", "c6-r2", is_writer=False,
                             promotion_tier=2, host_port=21002)

        ctx = _fake_ctx()
        request = {"DBClusterIdentifier": "c6"}
        mgr = mock.MagicMock()
        with mock.patch.object(provider, "call_moto", return_value={}), \
            mock.patch.object(provider, "_init_db_manager", return_value=mgr):
            provider._handle_delete_db_cluster(ctx, request)
        deleted = {c.args[0] for c in mgr.delete_db_instance.call_args_list}
        assert deleted == {"c6", "c6-r1", "c6-r2"}
        assert orch.topology("c6") is None
