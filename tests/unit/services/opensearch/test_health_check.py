"""The OpenSearch readiness check must work when LocalEmu runs in Docker.

In a LocalEmu container, ``localhost:<published port>`` is the LocalEmu
container itself, so only the domain container's own address is reachable.
Without probing that address the domain stayed ``creating`` forever, and
``terraform apply`` waited on ``Processing`` for the whole timeout.
"""
from __future__ import annotations

from unittest import mock

from localemu.services.opensearch.docker import cluster_manager as cm


def _manager_with_domain(name="kb", port=39929):
    manager = cm.DockerClusterManager()
    info = cm.ClusterInfo(
        domain_name=name,
        container_name=f"localemu-opensearch-{name}",
        engine="OpenSearch_2.11",
        image="opensearchproject/opensearch:2.11.1",
        host_port=port,
        endpoint=f"localhost:{port}",
    )
    manager._clusters[name] = info
    return manager, info


def test_container_address_is_probed_before_localhost():
    with mock.patch.object(cm.DOCKER_CLIENT, "get_container_ip", return_value="172.17.0.3"):
        urls = cm.DockerClusterManager._health_urls("localemu-opensearch-kb", 39929)
    assert urls == [
        "http://172.17.0.3:9200/_cluster/health",
        "http://localhost:39929/_cluster/health",
    ]


def test_localhost_is_still_probed_when_the_container_ip_is_unknown():
    with mock.patch.object(cm.DOCKER_CLIENT, "get_container_ip", side_effect=RuntimeError("no ip")):
        urls = cm.DockerClusterManager._health_urls("localemu-opensearch-kb", 39929)
    assert urls == ["http://localhost:39929/_cluster/health"]


def test_domain_becomes_active_when_only_the_container_address_answers():
    manager, info = _manager_with_domain()

    def fake_get(url, timeout):
        if url.startswith("http://172.17.0.3:9200"):
            return mock.Mock(status_code=200)
        raise ConnectionError("localhost is the LocalEmu container, not the Docker host")

    with (
        mock.patch.object(cm.DOCKER_CLIENT, "get_container_ip", return_value="172.17.0.3"),
        mock.patch("requests.get", side_effect=fake_get),
        mock.patch.object(cm.time, "sleep"),
    ):
        manager._wait_for_health("kb", 39929, "localemu-opensearch-kb", timeout=10)

    assert info.status == "active"


def test_domain_stays_creating_when_nothing_answers():
    manager, info = _manager_with_domain()
    clock = iter(range(0, 1000, 5))
    with (
        mock.patch.object(cm.DOCKER_CLIENT, "get_container_ip", return_value="172.17.0.3"),
        mock.patch("requests.get", side_effect=ConnectionError("down")),
        mock.patch.object(cm.time, "sleep"),
        mock.patch.object(cm.time, "time", side_effect=lambda: next(clock)),
    ):
        manager._wait_for_health("kb", 39929, "localemu-opensearch-kb", timeout=20)

    assert info.status == "creating"
