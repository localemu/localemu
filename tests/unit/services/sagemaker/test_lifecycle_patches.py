"""SageMaker has zero LocalEmu-specific implementation otherwise (plain
moto passthrough) - a notebook instance's ``OnStart`` lifecycle script was
stored but never executed. These tests pin the real-execution patch at the
unit level (mocked Docker/STS); the end-to-end behaviour (real container,
real assumed-role credentials, real enforced AWS call) was verified live."""
from __future__ import annotations

import base64
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from localemu.services.sagemaker import patches as sagemaker_patches


def _backend(on_start_content: str | None, role_arn: str | None = "arn:aws:iam::000000000000:role/r"):
    notebook_instance = SimpleNamespace(
        role_arn=role_arn,
        lifecycle_config_name="cfg" if on_start_content is not None else None,
    )
    lifecycle_config = SimpleNamespace(on_start=[{"Content": on_start_content}]) if on_start_content else None
    return SimpleNamespace(
        notebook_instances={"nb": notebook_instance},
        notebook_instance_lifecycle_configurations={"cfg": lifecycle_config} if lifecycle_config else {},
        region_name="us-east-1",
        account_id="000000000000",
    )


class TestRunOnStartScript:
    def test_no_lifecycle_config_is_a_noop(self):
        backend = _backend(on_start_content=None)
        with patch.object(sagemaker_patches.threading.Thread, "start") as mock_start:
            sagemaker_patches._run_on_start_script(backend, "nb")
        mock_start.assert_not_called()

    def test_unknown_notebook_instance_is_a_noop(self):
        backend = _backend(on_start_content=None)
        with patch.object(sagemaker_patches.threading.Thread, "start") as mock_start:
            sagemaker_patches._run_on_start_script(backend, "does-not-exist")
        mock_start.assert_not_called()

    def test_valid_lifecycle_config_spawns_a_background_thread(self):
        script_b64 = base64.b64encode(b"#!/bin/sh\necho hi\n").decode()
        backend = _backend(on_start_content=script_b64)
        with patch.object(sagemaker_patches, "_execute_script") as mock_execute:
            sagemaker_patches._run_on_start_script(backend, "nb")
            # Thread.start() runs the target in a real (daemon) thread; join
            # it so the assertion below sees the call.
            for t in threading.enumerate():
                if t.name == "sagemaker-lifecycle-onstart":
                    t.join(timeout=2)
        mock_execute.assert_called_once()
        assert mock_execute.call_args.args[0] is backend
        script_arg = mock_execute.call_args.args[1]
        # LocalEmu's base image lacks the AWS CLI - the real script is
        # wrapped with a one-time ``pip install awscli`` bootstrap.
        assert script_arg.endswith(b"#!/bin/sh\necho hi\n")
        assert b"pip install" in script_arg


class TestExecuteScript:
    def test_assumes_role_as_the_sagemaker_service_principal(self):
        with patch("localemu.aws.connect.connect_to") as mock_connect, \
             patch("localemu.utils.docker_utils.DOCKER_CLIENT") as mock_docker, \
             patch("localemu.utils.container_networking.get_main_container_network", return_value="bridge"), \
             patch("localemu.utils.container_networking.get_endpoint_for_network", return_value="1.2.3.4"):
            mock_sts = MagicMock()
            mock_connect.return_value.sts.request_metadata.return_value = mock_sts
            mock_sts.assume_role.return_value = {
                "Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "secret", "SessionToken": "tok"},
            }
            mock_docker.run_container.return_value = (b"", b"")

            sagemaker_patches._execute_script(
                _backend(None), b"#!/bin/sh\necho hi\n",
                "arn:aws:iam::000000000000:role/r", "us-east-1", "nb",
            )

        from localemu.utils.aws.client_types import ServicePrincipal
        mock_connect.return_value.sts.request_metadata.assert_called_once_with(
            service_principal=ServicePrincipal("sagemaker")
        )
        env_vars = mock_docker.run_container.call_args.kwargs["env_vars"]
        assert env_vars["AWS_ACCESS_KEY_ID"] == "AKIA"
        assert env_vars["AWS_SECRET_ACCESS_KEY"] == "secret"
        assert env_vars["AWS_SESSION_TOKEN"] == "tok"
        assert mock_docker.run_container.call_args.kwargs["interactive"] is True

    def test_assume_role_failure_still_runs_the_script_without_credentials(self):
        with patch("localemu.aws.connect.connect_to") as mock_connect, \
             patch("localemu.utils.docker_utils.DOCKER_CLIENT") as mock_docker, \
             patch("localemu.utils.container_networking.get_main_container_network", return_value="bridge"), \
             patch("localemu.utils.container_networking.get_endpoint_for_network", return_value="1.2.3.4"):
            mock_connect.return_value.sts.request_metadata.return_value.assume_role.side_effect = Exception("denied")
            mock_docker.run_container.return_value = (b"", b"")

            sagemaker_patches._execute_script(
                _backend(None), b"#!/bin/sh\necho hi\n",
                "arn:aws:iam::000000000000:role/r", "us-east-1", "nb",
            )

        mock_docker.run_container.assert_called_once()
        env_vars = mock_docker.run_container.call_args.kwargs["env_vars"]
        assert "AWS_ACCESS_KEY_ID" not in env_vars

    def test_no_role_arn_skips_assume_role_entirely(self):
        with patch("localemu.aws.connect.connect_to") as mock_connect, \
             patch("localemu.utils.docker_utils.DOCKER_CLIENT") as mock_docker, \
             patch("localemu.utils.container_networking.get_main_container_network", return_value="bridge"), \
             patch("localemu.utils.container_networking.get_endpoint_for_network", return_value="1.2.3.4"):
            mock_docker.run_container.return_value = (b"", b"")

            sagemaker_patches._execute_script(_backend(None), b"#!/bin/sh\necho hi\n", None, "us-east-1", "nb")

        mock_connect.assert_not_called()
        mock_docker.run_container.assert_called_once()


class TestOnStartFailureSurfacedOnNotebookInstance:
    """A failing OnStart script used to be a silent server-log line - the
    lab needs it visible through DescribeNotebookInstance's FailureReason
    (confirmed live: a bad command correctly produces
    'Docker process returned with exit code 127' plus the real stderr)."""

    def test_script_failure_sets_failure_reason_and_status(self):
        backend = _backend(None)
        docker_exc = Exception("Docker process returned with exit code 127")
        docker_exc.stdout = b""
        docker_exc.stderr = b"/bin/sh: 1: nope: not found\n"
        with patch("localemu.aws.connect.connect_to"), \
             patch("localemu.utils.docker_utils.DOCKER_CLIENT") as mock_docker, \
             patch("localemu.utils.container_networking.get_main_container_network", return_value="bridge"), \
             patch("localemu.utils.container_networking.get_endpoint_for_network", return_value="1.2.3.4"):
            mock_docker.run_container.side_effect = docker_exc

            sagemaker_patches._execute_script(backend, b"#!/bin/sh\nnope\n", None, "us-east-1", "nb")

        instance = backend.notebook_instances["nb"]
        assert instance.status == "Failed"
        assert "exit code 127" in instance.onstart_failure_reason
        assert "nope: not found" in instance.onstart_failure_reason

    def test_script_success_clears_failure_reason(self):
        backend = _backend(None)
        with patch("localemu.aws.connect.connect_to"), \
             patch("localemu.utils.docker_utils.DOCKER_CLIENT") as mock_docker, \
             patch("localemu.utils.container_networking.get_main_container_network", return_value="bridge"), \
             patch("localemu.utils.container_networking.get_endpoint_for_network", return_value="1.2.3.4"):
            mock_docker.run_container.return_value = (b"ok", b"")

            sagemaker_patches._execute_script(backend, b"#!/bin/sh\necho ok\n", None, "us-east-1", "nb")

        instance = backend.notebook_instances["nb"]
        assert instance.onstart_failure_reason is None

    def test_to_dict_patch_adds_failure_reason_only_when_present(self):
        """Exercises the real patched ``FakeSagemakerNotebookInstance.to_dict``
        (not a reimplementation of its logic) - applies the actual plux
        patch, then calls the real (now-patched) method."""
        from moto.sagemaker.models import FakeSagemakerNotebookInstance

        sagemaker_patches.apply_sagemaker_patches()

        instance = FakeSagemakerNotebookInstance.__new__(FakeSagemakerNotebookInstance)
        instance.arn = "arn:aws:sagemaker:us-east-1:000000000000:notebook-instance/nb"
        instance.notebook_instance_name = "nb"
        instance.status = "InService"
        instance.region_name = "us-east-1"
        instance.instance_type = "ml.t2.medium"
        instance.subnet_id = None
        instance.security_group_ids = None
        instance.role_arn = "arn:aws:iam::000000000000:role/r"
        instance.kms_key_id = None
        instance.last_modified_time = "0"
        instance.creation_time = "0"
        instance.lifecycle_config_name = None
        instance.direct_internet_access = "Enabled"
        instance.volume_size_in_gb = 5
        instance.accelerator_types = None
        instance.default_code_repository = None
        instance.additional_code_repositories = None
        instance.root_access = "Enabled"
        instance.onstart_failure_reason = None

        assert "FailureReason" not in instance.to_dict()

        instance.onstart_failure_reason = "boom"
        assert instance.to_dict()["FailureReason"] == "boom"
