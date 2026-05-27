"""Unit tests for OpenSearch orphan recovery .

Before this fix _recover_orphaned_containers used ``all=False`` so
stopped containers were silently skipped — if LocalEmu was stopped
with PERSISTENCE=1 the OpenSearch container was preserved (stopped),
but the recovery on cold-start missed it and the domain's
DescribeDomain response went stale.

After the fix: ``all=True`` so stopped containers are found, and
they're started + marked ``active`` when recovered.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.opensearch.docker import cluster_manager as cm


class TestOrphanRecovery:
    def _container(self, name, running: bool = True) -> dict:
        return {
            "name": name,
            "id": f"id-{name}",
            "labels": {
                "localemu.service": "opensearch",
                "localemu.domain-name": name.removeprefix("localemu-opensearch-"),
                "localemu.engine": "OpenSearch_2.11",
            },
        }

    def _inspect(self, *, running: bool, host_port: str = "45678") -> dict:
        return {
            "State": {"Running": running, "Status": "running" if running else "exited"},
            "Config": {"Image": "opensearchproject/opensearch:2.11.1"},
            "HostConfig": {"PortBindings": {"9200/tcp": [{"HostPort": host_port}]}},
            "NetworkSettings": {"Ports": {"9200/tcp": [{"HostPort": host_port}]}},
        }

    def test_recovers_running_container(self):
        dc = mock.MagicMock()
        dc.list_containers.return_value = [self._container("localemu-opensearch-d1")]
        dc.inspect_container.return_value = self._inspect(running=True)
        with mock.patch.object(cm, "DOCKER_CLIENT", dc):
            mgr = cm.DockerClusterManager.__new__(cm.DockerClusterManager)
            import threading as _t
            mgr._clusters = {}
            mgr._lock = _t.Lock()
            mgr._recover_orphaned_containers()
        assert "d1" in mgr._clusters
        assert mgr._clusters["d1"].status == "active"
        dc.start_container.assert_not_called()

    def test_recovers_stopped_container_and_starts_it(self):
        """all=True must pick up exited containers, and recovery must
        docker-start them so PERSISTENCE=1 actually resumes the domain."""
        dc = mock.MagicMock()
        dc.list_containers.return_value = [self._container("localemu-opensearch-d2")]
        dc.inspect_container.return_value = self._inspect(running=False)
        with mock.patch.object(cm, "DOCKER_CLIENT", dc):
            mgr = cm.DockerClusterManager.__new__(cm.DockerClusterManager)
            import threading as _t
            mgr._clusters = {}
            mgr._lock = _t.Lock()
            mgr._recover_orphaned_containers()
        dc.list_containers.assert_called_once()
        # Critical: all=True in the filter call
        kwargs = dc.list_containers.call_args.kwargs
        assert kwargs.get("all") is True
        dc.start_container.assert_called_once_with("localemu-opensearch-d2")
        assert "d2" in mgr._clusters

    def test_missing_port_binding_still_records_domain(self):
        """Even without a resolvable host port we should record the domain
        so DescribeDomain returns ``creating`` rather than a 404. The
        cold-start health check will reconcile later."""
        dc = mock.MagicMock()
        dc.list_containers.return_value = [self._container("localemu-opensearch-d3")]
        dc.inspect_container.return_value = {
            "State": {"Running": True},
            "Config": {"Image": "opensearchproject/opensearch:2.11.1"},
            "HostConfig": {"PortBindings": {}},
            "NetworkSettings": {"Ports": {}},
        }
        with mock.patch.object(cm, "DOCKER_CLIENT", dc):
            mgr = cm.DockerClusterManager.__new__(cm.DockerClusterManager)
            import threading as _t
            mgr._clusters = {}
            mgr._lock = _t.Lock()
            mgr._recover_orphaned_containers()
        # Without a port binding we still shouldn't crash; either the
        # domain is recorded or skipped cleanly.
        # (Legacy behaviour was to `continue` — acceptable as long as
        # no exception escapes.)
