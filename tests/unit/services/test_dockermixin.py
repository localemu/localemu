"""Tests for the shared docker-backed-service helpers used by EC2/RDS/ECS
data-plane persistence. The helpers make dilligent use of DOCKER_CLIENT;
we replace it with a fake for every test so no daemon is required.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from localemu.services import dockermixin
from localemu.services.dockermixin import (
    ContainerSnapshot,
    ReconcileCounts,
    discover_service_containers,
    reconcile,
    stop_containers_by_label,
)


class _FakeDocker:
    def __init__(self, containers: list[dict], inspects: dict[str, dict] | None = None):
        self._containers = containers
        self._inspects = inspects or {}
        self.stopped: list[tuple[str, int]] = []

    def list_containers(self, filter=None, all=True):  # noqa: A002
        return list(self._containers)

    def inspect_container(self, name_or_id):
        if name_or_id in self._inspects:
            return self._inspects[name_or_id]
        raise LookupError(name_or_id)

    def stop_container(self, name, timeout=10):
        self.stopped.append((name, timeout))


def _make_inspect(running: bool = True, exit_code: int = 0,
                  image: str = "x:1", ports=None, networks=None) -> dict:
    return {
        "State": {
            "Running": running,
            "Status": "running" if running else "exited",
            "ExitCode": exit_code,
        },
        "Config": {"Image": image},
        "HostConfig": {"PortBindings": ports or {}},
        "NetworkSettings": {"Networks": networks or {}, "Ports": {}},
    }


class TestDiscoverServiceContainers:
    def test_returns_map_keyed_by_id_label(self):
        fake = _FakeDocker(
            containers=[
                {
                    "name": "localemu-ec2-i-abc",
                    "id": "abc123",
                    "labels": {
                        "localemu.service": "ec2",
                        "localemu.instance-id": "i-abc",
                    },
                },
            ],
            inspects={"localemu-ec2-i-abc": _make_inspect(
                running=True,
                ports={"22/tcp": [{"HostPort": "32000"}]},
                networks={"localemu-vpc-vpc-1": {"IPAddress": "172.28.0.2"}},
            )},
        )
        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            result = discover_service_containers("ec2", "localemu.instance-id")
        assert list(result) == ["i-abc"]
        snap = result["i-abc"]
        assert isinstance(snap, ContainerSnapshot)
        assert snap.name == "localemu-ec2-i-abc"
        assert snap.running
        assert snap.host_port_for("22/tcp") == 32000
        assert snap.networks["localemu-vpc-vpc-1"]["IPAddress"] == "172.28.0.2"

    def test_skips_containers_missing_id_label(self):
        fake = _FakeDocker(
            containers=[
                {
                    "name": "lost",
                    "id": "zzz",
                    "labels": {"localemu.service": "rds"},  # no id label
                },
            ],
            inspects={"lost": _make_inspect()},
        )
        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            result = discover_service_containers("rds", "localemu.db-instance-id")
        assert result == {}

    def test_returns_empty_on_docker_failure(self):
        class Broken:
            def list_containers(self, filter=None, all=True):  # noqa: A002
                raise RuntimeError("daemon down")
        with patch.object(dockermixin, "DOCKER_CLIENT", Broken()):
            assert discover_service_containers("ec2", "localemu.instance-id") == {}


class TestStopContainersByLabel:
    def test_stops_every_matching_container(self):
        fake = _FakeDocker(
            containers=[
                {"name": "localemu-ecs-foo", "id": "1",
                 "labels": {"localemu.service": "ecs"}},
                {"name": "localemu-ecs-bar", "id": "2",
                 "labels": {"localemu.service": "ecs"}},
            ],
            inspects={},
        )
        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            n = stop_containers_by_label("ecs", timeout=5)
        assert n == 2
        assert [name for name, _ in fake.stopped] == ["localemu-ecs-foo", "localemu-ecs-bar"]
        assert all(t == 5 for _, t in fake.stopped)

    def test_swallows_failures_per_container(self):
        class FlakyDocker(_FakeDocker):
            def stop_container(self, name, timeout=10):
                if name == "localemu-ecs-bad":
                    raise RuntimeError("container gone")
                super().stop_container(name, timeout)
        fake = FlakyDocker(
            containers=[
                {"name": "localemu-ecs-bad", "id": "1", "labels": {"localemu.service": "ecs"}},
                {"name": "localemu-ecs-ok", "id": "2", "labels": {"localemu.service": "ecs"}},
            ],
        )
        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            # Doesn't raise; counts only the ones that worked.
            n = stop_containers_by_label("ecs")
        assert n == 1


class TestReconcile:
    def test_resumed_recreated_orphaned_counts(self):
        fake = _FakeDocker(
            containers=[
                {"name": "localemu-rds-db-resumed", "id": "r",
                 "labels": {"localemu.service": "rds",
                            "localemu.db-instance-id": "db-resumed"}},
                {"name": "localemu-rds-db-orphan", "id": "o",
                 "labels": {"localemu.service": "rds",
                            "localemu.db-instance-id": "db-orphan"}},
            ],
            inspects={
                "localemu-rds-db-resumed": _make_inspect(running=False),
                "localemu-rds-db-orphan": _make_inspect(running=True),
            },
        )
        resumed_ids: list[str] = []
        recreated_ids: list[str] = []
        orphaned_ids: list[str] = []

        def _on_with_ctr(rid, _snap):
            resumed_ids.append(rid)
            return "resumed"

        def _on_without_ctr(rid):
            recreated_ids.append(rid)
            return "recreated"

        def _on_orphan(rid, _snap):
            orphaned_ids.append(rid)

        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            counts = reconcile(
                "rds", "localemu.db-instance-id",
                record_ids=["db-resumed", "db-missing"],
                on_record_with_container=_on_with_ctr,
                on_record_without_container=_on_without_ctr,
                on_orphan_container=_on_orphan,
            )

        assert counts == ReconcileCounts(resumed=1, recreated=1, failed=0, orphaned=1)
        assert resumed_ids == ["db-resumed"]
        assert recreated_ids == ["db-missing"]
        assert orphaned_ids == ["db-orphan"]

    def test_callback_exception_becomes_failed(self):
        fake = _FakeDocker(
            containers=[],
            inspects={},
        )

        def _on_without_ctr(rid):
            raise RuntimeError("boom")

        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            counts = reconcile(
                "ec2", "localemu.instance-id",
                record_ids=["i-bad"],
                on_record_with_container=lambda _rid, _snap: "resumed",
                on_record_without_container=_on_without_ctr,
            )
        assert counts == ReconcileCounts(resumed=0, recreated=0, failed=1, orphaned=0)

    def test_unknown_outcome_counts_as_failed(self):
        """Callback returning anything other than resumed/recreated is a failure."""
        fake = _FakeDocker(containers=[], inspects={})
        with patch.object(dockermixin, "DOCKER_CLIENT", fake):
            counts = reconcile(
                "ec2", "localemu.instance-id",
                record_ids=["i-x"],
                on_record_with_container=lambda _rid, _snap: "resumed",
                on_record_without_container=lambda _rid: "nonsense",
            )
        assert counts.failed == 1
        assert counts.recreated == 0
