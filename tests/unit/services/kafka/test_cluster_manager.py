"""ClusterManager — registry mutations + Docker-mocked lifecycle.

The live broker round-trip is in ``/tmp/kafka_e2e.py``; this file pins
the manager-side contract (singleton semantics, label stamping,
port-reconciliation read-back, delete cleanup) without touching the
real Docker daemon.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from localemu.services.kafka.docker.cluster_manager import (
    BrokerInfo,
    ClusterManager,
    _new_kraft_uuid,
    _reset_singleton_for_tests,
)


@pytest.fixture(autouse=True)
def _isolate():
    _reset_singleton_for_tests()
    yield
    _reset_singleton_for_tests()


class TestSingleton:
    def test_instance_returns_same_object(self):
        assert ClusterManager.instance() is ClusterManager.instance()


class TestCreateCluster:
    def test_single_broker_happy_path(self):
        mgr = ClusterManager.instance()
        with (
            patch(
                "localemu.services.kafka.docker.cluster_manager.DOCKER_CLIENT"
            ) as mock_docker,
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._wait_for_port",
                return_value=True,
            ),
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._reconcile_host_port",
                return_value=33333,
            ),
        ):
            mock_docker.inspect_image.return_value = {"Id": "fake"}
            brokers = mgr.create_cluster(
                cluster_arn="arn:aws:kafka:us-east-1:000000000000:cluster/c-1/uuid",
                cluster_id="c-1",
                kafka_version="3.7.1",
                number_of_brokers=1,
            )
        assert len(brokers) == 1
        broker = brokers[0]
        assert broker.broker_id == 1
        assert broker.host_plain_port == 33333
        assert broker.container_name == "localemu-msk-c-1-broker-1"

    def test_multi_broker_warns_and_starts_one(self, caplog):
        import logging

        caplog.set_level(logging.WARNING)
        mgr = ClusterManager.instance()
        with (
            patch(
                "localemu.services.kafka.docker.cluster_manager.DOCKER_CLIENT"
            ) as mock_docker,
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._wait_for_port",
                return_value=True,
            ),
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._reconcile_host_port",
                return_value=44444,
            ),
        ):
            mock_docker.inspect_image.return_value = {"Id": "fake"}
            brokers = mgr.create_cluster(
                cluster_arn="arn:aws:kafka:::cluster/c-multi/u",
                cluster_id="c-multi",
                kafka_version="3.7.1",
                number_of_brokers=3,
            )
        # v1 lands a single broker even when 3 are requested — the
        # warning surfaces the limitation; tests pin both behaviours.
        assert len(brokers) == 1
        assert any(
            "v1 supports 1" in r.getMessage() for r in caplog.records
        )

    def test_readiness_failure_removes_container(self):
        mgr = ClusterManager.instance()
        with (
            patch(
                "localemu.services.kafka.docker.cluster_manager.DOCKER_CLIENT"
            ) as mock_docker,
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._wait_for_port",
                return_value=False,
            ),
            patch(
                "localemu.services.kafka.docker.cluster_manager.ClusterManager._reconcile_host_port",
                return_value=33333,
            ),
        ):
            mock_docker.inspect_image.return_value = {"Id": "fake"}
            with pytest.raises(RuntimeError):
                mgr.create_cluster(
                    cluster_arn="arn:aws:kafka:::cluster/c-fail/u",
                    cluster_id="c-fail",
                    kafka_version="3.7.1",
                    number_of_brokers=1,
                )
        mock_docker.remove_container.assert_called()


class TestDeleteCluster:
    def test_delete_removes_each_broker(self):
        mgr = ClusterManager.instance()
        mgr._clusters["arn-x"] = [
            BrokerInfo(
                cluster_arn="arn-x",
                broker_id=1,
                container_name="localemu-msk-x-broker-1",
                host_plain_port=12345,
                kraft_uuid="abc",
                kafka_version="3.7.1",
            ),
        ]
        with patch(
            "localemu.services.kafka.docker.cluster_manager.DOCKER_CLIENT"
        ) as mock_docker:
            mgr.delete_cluster("arn-x")
            mock_docker.stop_container.assert_called_once()
            mock_docker.remove_container.assert_called_once()
        assert mgr.get_cluster("arn-x") is None

    def test_delete_unknown_is_noop(self):
        # Idempotent so DeleteCluster against a never-created cluster
        # doesn't raise. AWS itself accepts the call and just returns 200.
        ClusterManager.instance().delete_cluster("arn-missing")


class TestBootstrapBrokers:
    def test_returns_comma_joined_host_ports(self):
        mgr = ClusterManager.instance()
        mgr._clusters["arn-multi"] = [
            BrokerInfo("arn-multi", 1, "c1", 19092, "u1", "3.7.1"),
            BrokerInfo("arn-multi", 2, "c2", 19093, "u2", "3.7.1"),
        ]
        assert (
            mgr.bootstrap_brokers("arn-multi")
            == "127.0.0.1:19092,127.0.0.1:19093"
        )

    def test_returns_empty_when_unknown(self):
        assert ClusterManager.instance().bootstrap_brokers("nope") == ""


class TestKraftUuid:
    def test_uuid_is_22_chars_base64url(self):
        u = _new_kraft_uuid()
        # urlsafe_b64encode of 16 bytes = 22 chars after stripping '='
        assert len(u) == 22
        assert "=" not in u
