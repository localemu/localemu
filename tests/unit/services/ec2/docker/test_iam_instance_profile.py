"""Unit tests for IAM instance profile integration (task #78).

Covers:
  - base image carries ``awscli`` so ``aws <cmd>`` works inside the container
  - base image tag is versioned (NOT ``:latest``) so existing dev envs
    re-pull when the Dockerfile changes
  - ``create_instance`` injects ``AWS_ENDPOINT_URL`` / ``AWS_REGION`` /
    ``AWS_DEFAULT_REGION`` so unmodified SDKs inside the container
    reach LocalEmu instead of real AWS
  - failed ``assume_role`` records ``iam_credentials_error`` in metadata
    (so ``curl /iam/info`` can surface the reason) and logs at ERROR
"""
from __future__ import annotations

import threading
from unittest import mock

import pytest

from localemu.services.ec2.docker import base_image, vm_manager


class TestBaseImageAwsCli:
    def test_dockerfile_installs_awscli(self):
        assert "awscli" in base_image._DOCKERFILE

    def test_tag_is_versioned_not_latest(self):
        # :latest won't trigger a rebuild on existing hosts when the
        # Dockerfile's apt list changes — any bump like :v2, :v3 works.
        assert base_image.BASE_IMAGE_TAG != "localemu/ec2-base:latest"
        assert base_image.BASE_IMAGE_TAG.startswith("localemu/ec2-base:")


@pytest.fixture
def mgr():
    m = vm_manager.DockerVmManager.__new__(vm_manager.DockerVmManager)
    m._instances = {}
    m._lock = threading.Lock()
    imds = mock.MagicMock()
    imds.port = 1666
    imds.allocate_port_for_instance.return_value = 1700
    m._imds_server = imds
    return m


def _create_mocks_for_create_instance():
    """Return a dict of patchers that make ``create_instance`` callable
    without a live Docker daemon. Each caller applies them in an
    ``ExitStack``; the container config is captured into a list so the
    test can inspect the env vars."""
    captured: list = []
    dc = mock.MagicMock()

    def _capture(cfg):
        captured.append(cfg)
    dc.create_container_from_config.side_effect = _capture
    dc.get_container_ipv4_for_network.return_value = "172.31.0.5"
    dc.exec_in_container.return_value = (b"", b"")
    return dc, captured


class TestContainerEndpointEnvVars:
    def test_env_vars_include_aws_endpoint_url_and_region(self, mgr):
        dc, captured = _create_mocks_for_create_instance()
        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc), \
             mock.patch.object(vm_manager, "resolve_ami_to_image",
                               return_value="localemu/ec2-base:v2"), \
             mock.patch.object(vm_manager.DockerVmManager, "_ensure_image"), \
             mock.patch.object(vm_manager, "get_free_tcp_port",
                               return_value=2222), \
             mock.patch.object(vm_manager, "get_instance_resources",
                               return_value={"mem_limit": "1g",
                                             "cpu_shares": 256}), \
             mock.patch.object(vm_manager, "_resolve_container_private_ip",
                               return_value="172.31.0.5"), \
             mock.patch.object(vm_manager, "_patch_moto_instance_ip"):
            mgr.create_instance(
                instance_id="i-endpoint-1",
                ami_id="ami-ubuntu-22.04",
                region="eu-west-3",
                public_key="ssh-rsa AAA user@h",
            )
        assert captured, "create_container_from_config was never called"
        env = captured[0].env_vars
        assert env.get("AWS_REGION") == "eu-west-3"
        assert env.get("AWS_DEFAULT_REGION") == "eu-west-3"
        url = env.get("AWS_ENDPOINT_URL", "")
        assert url.startswith("http://host.docker.internal:"), url
        assert url.rsplit(":", 1)[1].isdigit()


class TestCredentialMintFailureMarksMetadata:
    def test_assume_role_exception_records_error_marker(self, mgr, caplog):
        dc, captured = _create_mocks_for_create_instance()
        # Make moto's sts assume_role raise — we want to confirm the
        # caller still gets a launched container but that IMDS metadata
        # now carries a diagnostic error string.
        fake_sts = mock.MagicMock()
        fake_sts.assume_role.side_effect = RuntimeError("role not trusted")
        fake_sts_backends = {"000000000000": {"global": fake_sts}}

        with mock.patch.object(vm_manager, "DOCKER_CLIENT", dc), \
             mock.patch.object(vm_manager, "resolve_ami_to_image",
                               return_value="localemu/ec2-base:v2"), \
             mock.patch.object(vm_manager.DockerVmManager, "_ensure_image"), \
             mock.patch.object(vm_manager, "get_free_tcp_port",
                               return_value=2222), \
             mock.patch.object(vm_manager, "get_instance_resources",
                               return_value={"mem_limit": "1g",
                                             "cpu_shares": 256}), \
             mock.patch.object(vm_manager, "_resolve_container_private_ip",
                               return_value="172.31.0.5"), \
             mock.patch.object(vm_manager, "_patch_moto_instance_ip"), \
             mock.patch("moto.sts.models.sts_backends", fake_sts_backends), \
             caplog.at_level("ERROR", logger="localemu.services.ec2.docker.vm_manager"):
            mgr.create_instance(
                instance_id="i-credfail",
                ami_id="ami-ubuntu-22.04",
                region="us-east-1",
                iam_role_name="BrokenRole",
                iam_instance_profile_arn=(
                    "arn:aws:iam::000000000000:instance-profile/BrokenProfile"
                ),
                public_key="ssh-rsa AAA user@h",
            )
        # The IMDS server must have received a metadata dict with the
        # error marker so operators can query /iam/info and diagnose.
        register_calls = mgr._imds_server.register_instance.call_args_list
        assert register_calls, "IMDS register was never called"
        _, _, metadata = register_calls[-1].args
        assert "iam_credentials" not in metadata, (
            "credentials must NOT be present when assume_role fails"
        )
        assert metadata.get("iam_credentials_error") == "role not trusted"
        # And the failure must be logged at ERROR, not WARNING — silent
        # failures here are a support nightmare (SDK sees NoCredsError).
        assert any(
            "Failed to generate IMDS credentials" in rec.message
            and rec.levelname == "ERROR"
            for rec in caplog.records
        )
