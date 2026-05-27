"""Tests for the Aurora-cluster fields on RdsContainerInfo and the
per-cluster Docker-network helper. Pure: mocks DOCKER_CLIENT.

These cover commit #2 of the Aurora topology plan:
  * RdsContainerInfo carries cluster_id / is_writer / promotion_tier
  * Labels round-trip through _hydrate_from_container
  * ensure_cluster_network is idempotent and survives the
    create-and-someone-else-created-it race
"""
from __future__ import annotations

import base64
from unittest import mock

import pytest

from localemu.services.rds.docker import db_manager as dm


# ---------------------------------------------------------------------------
# RdsContainerInfo data shape
# ---------------------------------------------------------------------------

class TestRdsContainerInfoClusterFields:
    def test_defaults_are_standalone(self):
        info = dm.RdsContainerInfo(
            db_instance_id="i-a", container_name="c", engine="postgres",
            image="img", host_port=1, container_port=2,
            master_username="m", master_password="p",
        )
        assert info.cluster_id is None
        assert info.is_writer is False
        assert info.promotion_tier == 1


# ---------------------------------------------------------------------------
# cluster_network_name + ensure_cluster_network
# ---------------------------------------------------------------------------

class TestClusterNetwork:
    def test_name_shape(self):
        assert dm.cluster_network_name("my-c") == "localemu-aurora-my-c"

    def test_ensure_creates_when_missing(self):
        with mock.patch.object(dm, "DOCKER_CLIENT") as dc:
            dc.inspect_network.side_effect = Exception("not found")
            dc.create_network.return_value = "net-id"
            name = dm.ensure_cluster_network("c1")
        assert name == "localemu-aurora-c1"
        dc.create_network.assert_called_once_with("localemu-aurora-c1")

    def test_ensure_skips_when_already_exists(self):
        with mock.patch.object(dm, "DOCKER_CLIENT") as dc:
            dc.inspect_network.return_value = {"Name": "localemu-aurora-c1"}
            name = dm.ensure_cluster_network("c1")
        assert name == "localemu-aurora-c1"
        dc.create_network.assert_not_called()

    def test_ensure_handles_race(self):
        """Concurrent caller created the network between our inspect
        and our create; the second inspect-after-create-fail should
        succeed and we return the name."""
        with mock.patch.object(dm, "DOCKER_CLIENT") as dc:
            # First inspect: not found. create_network: race (raises).
            # Second inspect: now exists.
            dc.inspect_network.side_effect = [
                Exception("not found"),
                {"Name": "localemu-aurora-c1"},
            ]
            dc.create_network.side_effect = Exception("already exists")
            name = dm.ensure_cluster_network("c1")
        assert name == "localemu-aurora-c1"

    def test_ensure_raises_on_real_failure(self):
        with mock.patch.object(dm, "DOCKER_CLIENT") as dc:
            dc.inspect_network.side_effect = Exception("not found")
            dc.create_network.side_effect = Exception("docker down")
            with pytest.raises(RuntimeError):
                dm.ensure_cluster_network("c1")


# ---------------------------------------------------------------------------
# Label round-trip through _hydrate_from_container
# ---------------------------------------------------------------------------

def _inspect_payload(host_port: int = 5432) -> dict:
    """Minimal inspect_container response with the fields the hydrator
    expects so we can drive the parser in isolation."""
    return {
        "HostConfig": {
            "PortBindings": {
                "5432/tcp": [{"HostPort": str(host_port)}],
            },
        },
        "NetworkSettings": {
            "Networks": {
                "bridge": {"IPAddress": "172.17.0.5"},
            },
            "IPAddress": "172.17.0.5",
        },
        "State": {"Running": True, "Status": "running"},
        "Config": {"Image": "postgres:15"},
    }


class TestHydrateClusterRoundTrip:
    def _hydrate(self, labels: dict):
        mgr = dm.DockerDbManager.__new__(dm.DockerDbManager)
        # Bypass __init__ so _recover_orphaned_containers doesn't poke
        # real Docker; we test the parser only.
        mgr._instances = {}
        with mock.patch.object(
            dm.DOCKER_CLIENT, "inspect_container",
            return_value=_inspect_payload(),
        ):
            return mgr._hydrate_from_container("ctr", labels)

    def test_standalone_instance_has_no_cluster_fields(self):
        info = self._hydrate({
            "localemu.db-instance-id": "i-a",
            "localemu.engine": "postgres",
            "localemu.master-username": "admin",
        })
        assert info is not None
        assert info.cluster_id is None
        assert info.is_writer is False
        assert info.promotion_tier == 1

    def test_cluster_writer_round_trip(self):
        info = self._hydrate({
            "localemu.db-instance-id": "i-w",
            "localemu.engine": "aurora-postgresql",
            "localemu.master-username": "admin",
            dm.CLUSTER_ID_LABEL: "my-aurora",
            dm.IS_WRITER_LABEL: "true",
            dm.PROMOTION_TIER_LABEL: "1",
        })
        assert info.cluster_id == "my-aurora"
        assert info.is_writer is True
        assert info.promotion_tier == 1

    def test_cluster_reader_round_trip(self):
        info = self._hydrate({
            "localemu.db-instance-id": "i-r1",
            "localemu.engine": "aurora-postgresql",
            "localemu.master-username": "admin",
            dm.CLUSTER_ID_LABEL: "my-aurora",
            dm.IS_WRITER_LABEL: "false",
            dm.PROMOTION_TIER_LABEL: "3",
        })
        assert info.cluster_id == "my-aurora"
        assert info.is_writer is False
        assert info.promotion_tier == 3

    def test_malformed_promotion_tier_falls_back_to_default(self):
        info = self._hydrate({
            "localemu.db-instance-id": "i-r",
            "localemu.engine": "aurora-postgresql",
            "localemu.master-username": "admin",
            dm.CLUSTER_ID_LABEL: "c1",
            dm.IS_WRITER_LABEL: "false",
            dm.PROMOTION_TIER_LABEL: "not-an-int",
        })
        assert info.promotion_tier == 1

    def test_is_writer_label_is_case_insensitive(self):
        info = self._hydrate({
            "localemu.db-instance-id": "i-w",
            "localemu.engine": "aurora-postgresql",
            "localemu.master-username": "admin",
            dm.CLUSTER_ID_LABEL: "c1",
            dm.IS_WRITER_LABEL: "TRUE",
        })
        assert info.is_writer is True
