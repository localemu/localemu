"""Unit tests for the SSM docker executor (fix #76).

Covers the core behaviours without needing a live LocalEmu: script
assembly, {{ssm:/path}} resolution, non-shell document stubbing,
InstanceUnreachable handling, and moto invocation mutation.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ssm import docker_executor as de


@pytest.fixture
def executor():
    return de.SsmDockerExecutor()


class TestStubbedDocuments:
    def test_run_patch_baseline_returns_success_without_docker(self, executor):
        with mock.patch.object(executor, "_update_invocation") as upd:
            executor.dispatch(
                command_id="c-1", document_name="AWS-RunPatchBaseline",
                parameters={}, instance_ids=["i-1"],
                account_id="a", region="r",
            )
        upd.assert_called_once()
        kw = upd.call_args.kwargs
        assert kw["status"] == "Success"
        assert "stubbed" in kw["status_details"].lower()
        assert kw["response_code"] == 0

    def test_update_ssm_agent_stubbed(self, executor):
        with mock.patch.object(executor, "_update_invocation") as upd:
            executor.dispatch(
                command_id="c-u", document_name="AWS-UpdateSSMAgent",
                parameters={}, instance_ids=["i-1"],
                account_id="a", region="r",
            )
        upd.assert_called_once()
        assert upd.call_args.kwargs["status"] == "Success"


class TestInstanceUnreachable:
    def test_missing_container_marks_invocation_failed(self, executor):
        with mock.patch.object(de.SsmDockerExecutor, "_resolve_container",
                               return_value=None), \
             mock.patch.object(executor, "_update_invocation") as upd:
            executor._run_one(
                command_id="c-2", instance_id="i-ghost",
                account_id="a", region="r",
                script="#!/bin/bash\necho hi\n",
                working_directory="/", exec_timeout=60,
                output_s3_bucket_name=None, output_s3_key_prefix=None,
            )
        calls = [c.kwargs for c in upd.call_args_list]
        statuses = [c.get("status") for c in calls]
        assert "Failed" in statuses
        # Final call should carry InstanceUnreachable detail
        final = [c for c in calls if c.get("status") == "Failed"][-1]
        assert final["status_details"] == "InstanceUnreachable"
        assert final["response_code"] == -1


class TestExecSuccessfulPath:
    def test_happy_path_populates_output_and_status(self, executor):
        dc = mock.MagicMock()
        # Script write → ok; run → returns b'0' as the exit code raw output;
        # stdout/stderr reads come back via separate exec_in_container calls.
        dc.exec_in_container.side_effect = [
            (b"", b""),          # prepare_cmd (mkdir + write script)
            (b"0", b""),         # run_cmd (exit code via echo -n $?)
            (b"Linux\n", b""),   # stdout read
            (b"", b""),          # stderr read
        ]
        with mock.patch(
            "localemu.services.ssm.docker_executor.DOCKER_CLIENT", dc, create=True,
        ), \
             mock.patch("localemu.utils.docker_utils.DOCKER_CLIENT", dc), \
             mock.patch.object(de.SsmDockerExecutor, "_resolve_container",
                               return_value="localemu-ec2-i-1"), \
             mock.patch.object(executor, "_update_invocation") as upd:
            executor._run_one(
                command_id="c-ok", instance_id="i-1",
                account_id="a", region="r",
                script="#!/bin/bash\nuname -s\n",
                working_directory="/", exec_timeout=60,
                output_s3_bucket_name=None, output_s3_key_prefix=None,
            )
        # Two calls: the InProgress update and the final Success one
        kinds = [c.kwargs.get("status") for c in upd.call_args_list]
        assert "InProgress" in kinds
        assert "Success" in kinds
        final = upd.call_args_list[-1].kwargs
        assert final["status"] == "Success"
        assert final["standard_output"].startswith("Linux")
        assert final["response_code"] == 0


class TestExecNonZeroStillCapturesOutput:
    def test_exit_7_still_has_stdout_and_stderr(self, executor):
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = [
            (b"", b""),
            (b"7", b""),
            (b"partial stdout\n", b""),
            (b"error msg\n", b""),
        ]
        with mock.patch("localemu.utils.docker_utils.DOCKER_CLIENT", dc), \
             mock.patch.object(de.SsmDockerExecutor, "_resolve_container",
                               return_value="localemu-ec2-i-1"), \
             mock.patch.object(executor, "_update_invocation") as upd:
            executor._run_one(
                command_id="c-fail", instance_id="i-1",
                account_id="a", region="r",
                script="#!/bin/bash\nexit 7\n",
                working_directory="/", exec_timeout=60,
                output_s3_bucket_name=None, output_s3_key_prefix=None,
            )
        final = upd.call_args_list[-1].kwargs
        assert final["status"] == "Failed"
        assert final["response_code"] == 7
        # CRITICAL: we beat LocalStack Pro's gap — stdout+stderr captured
        # even on non-zero exit.
        assert final["standard_output"] == "partial stdout\n"
        assert final["standard_error"] == "error msg\n"


class TestTimeoutDetection:
    def test_exit_124_is_timed_out(self, executor):
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = [
            (b"", b""),
            (b"124", b""),
            (b"", b""),
            (b"", b""),
        ]
        with mock.patch("localemu.utils.docker_utils.DOCKER_CLIENT", dc), \
             mock.patch.object(de.SsmDockerExecutor, "_resolve_container",
                               return_value="localemu-ec2-i-1"), \
             mock.patch.object(executor, "_update_invocation") as upd:
            executor._run_one(
                command_id="c-to", instance_id="i-1",
                account_id="a", region="r",
                script="#!/bin/bash\nsleep 99999\n",
                working_directory="/", exec_timeout=1,
                output_s3_bucket_name=None, output_s3_key_prefix=None,
            )
        final = upd.call_args_list[-1].kwargs
        assert final["status"] == "TimedOut"


class TestSsmPlaceholderResolution:
    def test_replaces_placeholder_with_parameter_value(self):
        import moto.backends as moto_backends
        param = mock.Mock()
        param.value = "resolved-value"
        fake_backend = mock.Mock()
        fake_backend.get_parameter.return_value = param
        with mock.patch.object(
            moto_backends, "get_backend",
            return_value={"a": {"r": fake_backend}},
        ):
            out = de.SsmDockerExecutor._resolve_ssm_placeholders(
                "echo {{ssm:/my/key}}", "a", "r",
            )
        assert out == "echo resolved-value"

    def test_unresolved_placeholder_preserved(self):
        import moto.backends as moto_backends
        fake_backend = mock.Mock()
        fake_backend.get_parameter.side_effect = RuntimeError("not found")
        with mock.patch.object(
            moto_backends, "get_backend",
            return_value={"a": {"r": fake_backend}},
        ):
            out = de.SsmDockerExecutor._resolve_ssm_placeholders(
                "echo {{ssm:/missing}}", "a", "r",
            )
        # Placeholder left in place so the user sees a clear failure
        # inside the executed script rather than a silent empty string.
        assert "{{ssm:/missing}}" in out


class TestNonShellDocumentPassthrough:
    def test_unknown_document_does_not_call_moto_update(self, executor):
        """A document we don't recognise at all (not in SHELL_SCRIPT_DOCUMENTS
        and not in STUBBED_DOCUMENTS) must NOT mutate the moto record —
        let moto's own passthrough own it."""
        with mock.patch.object(executor, "_update_invocation") as upd:
            executor.dispatch(
                command_id="c-x", document_name="CustomCompanyDoc",
                parameters={"commands": ["echo hi"]},
                instance_ids=["i-1"],
                account_id="a", region="r",
            )
        upd.assert_not_called()
