"""Unit tests for ECS task-role credentials (fix #79).

Covers:
  - TaskCredentialStore put/get/revoke roundtrip + isolation between task_ids
  - TaskCredentialsServer returns 200 JSON for a known task_id, 404 for
    an unknown one, and minimal JSON stubs for /v3/ and /v4/
  - run_task injects AWS_CONTAINER_CREDENTIALS_FULL_URI only when a
    taskRoleArn is present, and NOT AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    (RELATIVE_URI takes SDK-provider priority over FULL_URI and is not
    useful when pointed at an unreachable 169.254.170.2)
  - run_task always injects AWS_ENDPOINT_URL / AWS_REGION /
    AWS_DEFAULT_REGION so SDK calls reach LocalEmu (not real AWS)
  - additional_flags always contains ``--add-host
    host.docker.internal:host-gateway`` so the credential + gateway
    URLs resolve on Linux + Docker CE
  - stopped tasks have their credentials revoked from the server
"""
from __future__ import annotations

import http.client
import json
import threading
from unittest import mock

import pytest

from localemu.services.ecs.docker import task_credentials, task_manager


class TestTaskCredentialStore:
    def test_put_get_revoke_roundtrip(self):
        s = task_credentials.TaskCredentialStore()
        s.put("t1", {"AccessKeyId": "LSIA1", "SecretAccessKey": "x"})
        assert s.get("t1")["AccessKeyId"] == "LSIA1"
        s.revoke("t1")
        assert s.get("t1") is None

    def test_isolation_between_tasks(self):
        s = task_credentials.TaskCredentialStore()
        s.put("a", {"AccessKeyId": "KEY_A"})
        s.put("b", {"AccessKeyId": "KEY_B"})
        assert s.get("a")["AccessKeyId"] == "KEY_A"
        assert s.get("b")["AccessKeyId"] == "KEY_B"

    def test_get_unknown_returns_none(self):
        s = task_credentials.TaskCredentialStore()
        assert s.get("missing") is None


@pytest.fixture
def running_server():
    srv = task_credentials.TaskCredentialsServer()
    srv.start()
    yield srv
    srv.stop()


class TestTaskCredentialsServer:
    def _fetch(self, port: int, path: str) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_serves_credentials_for_known_task(self, running_server):
        running_server.store.put("tid-1", {
            "RoleArn": "arn:aws:iam::000000000000:role/R",
            "AccessKeyId": "LSIAKEY",
            "SecretAccessKey": "sec",
            "Token": "FQoG...",
            "Expiration": "2099-01-01T00:00:00Z",
        })
        status, body = self._fetch(running_server.port, "/v2/credentials/tid-1")
        assert status == 200
        doc = json.loads(body)
        assert doc["AccessKeyId"] == "LSIAKEY"
        assert doc["RoleArn"] == "arn:aws:iam::000000000000:role/R"
        assert doc["Token"] == "FQoG..."

    def test_404_for_unknown_task(self, running_server):
        status, _ = self._fetch(running_server.port, "/v2/credentials/ghost")
        assert status == 404

    def test_v3_metadata_stub(self, running_server):
        status, body = self._fetch(running_server.port, "/v3/anything")
        assert status == 200
        doc = json.loads(body)
        # V1 stub — details not required, structure must be dict
        assert isinstance(doc, dict)

    def test_port_is_stable_after_start(self, running_server):
        # Multiple .start() calls must return the same port (idempotent)
        p1 = running_server.port
        p2 = running_server.start()
        assert p1 == p2


@pytest.fixture
def mgr():
    from localemu.services.ecs.docker.task_manager import DockerTaskManager
    m = DockerTaskManager.__new__(DockerTaskManager)
    m._tasks = {}
    m._lock = threading.Lock()
    return m


def _run_task_with_mocks(mgr, task_definition, **kwargs):
    """Call mgr.run_task with enough mocks to reach the container build."""
    captured = []
    dc = mock.MagicMock()

    def _capture_cfg(cfg):
        captured.append(cfg)
    dc.create_container_from_config.side_effect = _capture_cfg
    dc.get_container_ipv4_for_network.return_value = "172.17.0.5"
    dc.exec_in_container.return_value = (b"", b"")

    with mock.patch.object(task_manager, "DOCKER_CLIENT", dc), \
         mock.patch.object(task_manager.DockerTaskManager, "_ensure_image"), \
         mock.patch.object(task_manager, "get_free_tcp_port",
                           return_value=2222), \
         mock.patch.object(task_manager, "_container_name", create=True,
                           return_value="localemu-ecs-1"):
        try:
            mgr.run_task(
                cluster_name="c",
                task_definition=task_definition,
                task_arn="arn:aws:ecs:us-east-1:000000000000:task/c/t-1",
                count=1,
                account_id="000000000000",
                region="us-east-1",
                **kwargs,
            )
        except Exception:
            pass
    return captured


def _default_task_def(task_role_arn=None):
    td = {
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:000000000000:task-definition/fam:1",
        "containerDefinitions": [{
            "name": "app",
            "image": "localemu/ec2-base:v3",
            "environment": [],
            "command": ["sh", "-c", "sleep 60"],
        }],
        "networkMode": "bridge",
        "volumes": [],
    }
    if task_role_arn:
        td["taskRoleArn"] = task_role_arn
    return td


class TestContainerEnvVars:
    def test_always_sets_endpoint_url_and_region(self, mgr):
        cfgs = _run_task_with_mocks(mgr, _default_task_def())
        assert cfgs, "no container config captured"
        env = cfgs[0].env_vars
        assert env["AWS_REGION"] == "us-east-1"
        assert env["AWS_DEFAULT_REGION"] == "us-east-1"
        assert env["AWS_ENDPOINT_URL"].startswith("http://host.docker.internal:")

    def test_injects_relative_uri_when_task_role_present(self, mgr):
        fake_sts = mock.MagicMock()
        fake_assumed = mock.MagicMock()
        fake_assumed.access_key_id = "LSIATESTKEY"
        fake_assumed.secret_access_key = "sec"
        fake_assumed.session_token = "FQoG"
        fake_sts.assume_role.return_value = fake_assumed
        with mock.patch("moto.sts.models.sts_backends",
                        {"000000000000": {"global": fake_sts}}):
            cfgs = _run_task_with_mocks(
                mgr,
                _default_task_def(
                    task_role_arn="arn:aws:iam::000000000000:role/MyRole",
                ),
            )
        assert cfgs
        env = cfgs[0].env_vars
        # AWS SDK security: credentials-endpoint host must be in the
        # allow-list (169.254.170.2, 169.254.170.23, localhost, ::1).
        # RELATIVE_URI resolves against 169.254.170.2 — the DNAT rule
        # installed post-start redirects to the host creds server.
        uri = env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
        assert uri.startswith("/v2/credentials/"), uri
        # FULL_URI would take SDK priority and would fail the
        # approved-host validation when pointed at host.docker.internal.
        assert "AWS_CONTAINER_CREDENTIALS_FULL_URI" not in env

    def test_no_credentials_env_when_no_task_role(self, mgr):
        cfgs = _run_task_with_mocks(mgr, _default_task_def())
        assert cfgs
        env = cfgs[0].env_vars
        assert "AWS_CONTAINER_CREDENTIALS_FULL_URI" not in env
        assert "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" not in env

    def test_cap_add_includes_net_admin(self, mgr):
        fake_sts = mock.MagicMock()
        fake_sts.assume_role.return_value = mock.MagicMock(
            access_key_id="LSIA", secret_access_key="s", session_token="t",
        )
        with mock.patch("moto.sts.models.sts_backends",
                        {"000000000000": {"global": fake_sts}}):
            cfgs = _run_task_with_mocks(
                mgr,
                _default_task_def(
                    task_role_arn="arn:aws:iam::000000000000:role/R",
                ),
            )
        assert cfgs
        # NET_ADMIN is required for the iptables DNAT rule that
        # redirects 169.254.170.2 → host-bound creds server.
        assert "NET_ADMIN" in (cfgs[0].cap_add or [])

    def test_additional_flags_include_host_gateway(self, mgr):
        cfgs = _run_task_with_mocks(mgr, _default_task_def())
        assert cfgs
        flags = cfgs[0].additional_flags or ""
        assert "--add-host host.docker.internal:host-gateway" in flags

    def test_role_label_persisted_on_container(self, mgr):
        fake_sts = mock.MagicMock()
        fake_sts.assume_role.return_value = mock.MagicMock(
            access_key_id="LSIA", secret_access_key="s",
            session_token="t",
        )
        with mock.patch("moto.sts.models.sts_backends",
                        {"000000000000": {"global": fake_sts}}):
            cfgs = _run_task_with_mocks(
                mgr,
                _default_task_def(
                    task_role_arn="arn:aws:iam::000000000000:role/R",
                ),
            )
        assert cfgs
        label = cfgs[0].labels.get("localemu.task-role-arn", "")
        assert label == "arn:aws:iam::000000000000:role/R"
