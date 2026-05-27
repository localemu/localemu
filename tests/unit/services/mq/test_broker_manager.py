"""BrokerManager — driver registry, port allocation, hydrate-from-labels.

The container side is mocked through ``DOCKER_CLIENT`` so these tests
run on machines without a Docker daemon; the live E2E
(``/tmp/mq_e2e.py``) covers the actual provisioning.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.services.mq.docker.broker_manager import (
    BrokerInstance,
    BrokerManager,
    _reset_singleton_for_tests,
)
from localemu.services.mq.docker.rabbitmq import RabbitMQDriver


@pytest.fixture(autouse=True)
def _isolate():
    _reset_singleton_for_tests()
    yield
    _reset_singleton_for_tests()


class TestDriverRegistry:
    def test_rabbitmq_driver_registered_by_default(self):
        mgr = BrokerManager.instance()
        assert "RABBITMQ" in mgr._drivers
        assert isinstance(mgr._drivers["RABBITMQ"], RabbitMQDriver)

    def test_unknown_engine_raises_not_implemented(self):
        mgr = BrokerManager.instance()
        with patch(
            "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
        ):
            with pytest.raises(NotImplementedError) as ei:
                mgr.create_broker(
                    broker_id="b-1",
                    engine_type="ACTIVEMQ",
                    engine_version="5.18",
                    admin_username="admin",
                    admin_password="secret",
                )
        assert "ACTIVEMQ" in str(ei.value)


class TestPortAllocation:
    def test_each_protocol_gets_distinct_port(self):
        """The driver declares 5 protocols; each must end up bound to a
        unique host port. Same port for two protocols would silently
        break clients that rely on the wire-protocol-specific port."""
        mgr = BrokerManager.instance()
        driver = mgr._drivers["RABBITMQ"]
        protocols = driver.protocols()
        assert len(set(protocols)) == len(protocols)

        with (
            patch(
                "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
            ) as mock_docker,
            patch(
                "localemu.services.mq.docker.broker_manager.BrokerManager._wait_for_port",
                return_value=True,
            ),
        ):
            mock_docker.inspect_image.return_value = {"Id": "fake"}
            mgr.create_broker(
                broker_id="b-distinct",
                engine_type="RABBITMQ",
                engine_version="3.13",
                admin_username="admin",
                admin_password="pw",
            )
        instance = mgr.get_broker("b-distinct")
        assert instance is not None
        assert len(set(instance.ports.values())) == len(protocols)


class TestRehydrateFromDocker:
    def test_get_broker_pulls_labels_when_dict_empty(self):
        mgr = BrokerManager.instance()
        with patch(
            "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
        ) as mock_docker:
            mock_docker.inspect_container.return_value = {
                "Config": {
                    "Labels": {
                        "localemu.mq.broker-id": "b-rehydrate",
                        "localemu.mq.engine": "RABBITMQ",
                        "localemu.mq.port.amqp": "32791",
                        "localemu.mq.port.mgmt": "32792",
                    },
                },
                "State": {"Running": True},
            }
            instance = mgr.get_broker("b-rehydrate")
        assert instance is not None
        assert instance.engine == "RABBITMQ"
        assert instance.ports["amqp"] == 32791
        assert instance.ports["mgmt"] == 32792
        assert instance.state == "RUNNING"
        # Second call hits the cache.
        with patch(
            "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
        ) as mock_docker:
            mock_docker.inspect_container.side_effect = AssertionError(
                "should not re-query Docker once cached"
            )
            same = mgr.get_broker("b-rehydrate")
        assert same is instance

    def test_get_broker_returns_none_when_no_container(self):
        mgr = BrokerManager.instance()
        with patch(
            "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
        ) as mock_docker:
            mock_docker.inspect_container.side_effect = Exception("no such container")
            assert mgr.get_broker("b-missing") is None


class TestDeleteBroker:
    def test_delete_removes_container_and_drops_from_registry(self):
        mgr = BrokerManager.instance()
        instance = BrokerInstance(
            broker_id="b-del",
            container_name="localemu-mq-b-del",
            engine="RABBITMQ",
            engine_version="3.13",
            ports={"amqp": 32791},
            admin_username="admin",
            admin_password="pw",
        )
        mgr._brokers["b-del"] = instance
        with patch(
            "localemu.services.mq.docker.broker_manager.DOCKER_CLIENT"
        ) as mock_docker:
            mgr.delete_broker("b-del")
            mock_docker.stop_container.assert_called_once_with(
                "localemu-mq-b-del", timeout=10,
            )
            mock_docker.remove_container.assert_called_once()
        assert mgr.get_broker("b-del") is None or mgr.get_broker("b-del").state == "CREATION_FAILED"


class TestRabbitMQDriver:
    def test_default_image_pattern(self):
        d = RabbitMQDriver()
        assert d.default_image("3.13") == "rabbitmq:3.13-management"
        assert d.default_image("") == "rabbitmq:3.13-management"
        assert d.default_image("3.12-management") == "rabbitmq:3.12-management"

    def test_protocols_match_declaration(self):
        d = RabbitMQDriver()
        assert set(d.protocols()) == {"amqp", "amqps", "mgmt", "mqtt", "stomp"}

    def test_readiness_port_is_amqp(self):
        d = RabbitMQDriver()
        ports = {"amqp": 32791, "mgmt": 32792, "amqps": 32793, "mqtt": 32794, "stomp": 32795}
        assert d.readiness_port(ports) == 32791
