"""Docker-backed SSM command execution.

Intercepts ``SendCommand`` in the SSM provider and runs the command
directly against the target EC2 instance's Docker container via
``docker exec``. No guest-side SSM agent is required or installed.

Design notes (see ``LocalEmuResearch/DockerEmulation/DESIGN_SSM_EC2.md``):

- Script is written to a temp file **inside** the container with a
  POSIX ``#!/bin/sh`` shebang so the same path works on Alpine (no
  bash) and Ubuntu/Amazon-Linux alike. Shell constructs (``&&``,
  ``|``, ``>``) and user-provided shebangs both work. Executing the
  file directly (not ``sh -c "$script"``) avoids the inline-string
  limitation that strips shebangs.
- Execution is dispatched to a bounded ``ThreadPoolExecutor``; the
  calling API thread returns the CommandId within ~10 ms even for
  multi-instance fan-out.
- stdout + stderr are captured regardless of exit code (LocalStack Pro
  misses this). Each is truncated to 24 000 bytes for the inline
  ``StandardOutputContent`` / ``StandardErrorContent`` fields (AWS
  parity); full output is available in ``/var/lib/localemu/ssm/`` on
  the container and optionally spilled to S3 when the caller provides
  ``OutputS3BucketName``.
- ``executionTimeout`` is enforced by wrapping the script launcher in
  GNU ``timeout(1)``. On timeout the status is ``TimedOut``.
- ``{{ssm:/path}}`` placeholders in the script are resolved via a
  local SSM GetParameter call **before** the docker exec.
- Non-shell documents (``AWS-RunPatchBaseline`` etc.) short-circuit to
  a synthetic ``Success`` with ``StatusDetails`` explaining the stub.
"""

from __future__ import annotations

import base64
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)

# Max inline content per AWS contract — larger spills to S3 if
# OutputS3BucketName was provided.
MAX_INLINE_BYTES = 24_000
# Default execution timeout when caller does not pass one.
DEFAULT_TIMEOUT_SECONDS = 3600
# Max concurrent docker-exec calls across all in-flight commands.
_EXECUTOR_MAX_WORKERS = 16

# Documents that we run as real shell scripts inside the container.
SHELL_SCRIPT_DOCUMENTS = frozenset({
    "AWS-RunShellScript",
})

# Documents that we stub with synthetic success so IaC doesn't hard-fail.
STUBBED_DOCUMENTS = frozenset({
    "AWS-RunPatchBaseline",
    "AWS-ApplyPatchBaseline",
    "AWS-UpdateSSMAgent",
    "AWS-RunAnsiblePlaybook",
    "AWS-ConfigureAWSPackage",
    "AWS-RunPowerShellScript",  # Linux-only V1
})

# ``{{ssm:/path}}`` and ``{{ssm-secure:/path}}`` placeholders.
_SSM_PLACEHOLDER = re.compile(r"\{\{\s*ssm(?:-secure)?:([^}]+?)\s*\}\}")


class SsmDockerExecutor:
    """Owns the ThreadPoolExecutor and the ``docker exec`` machinery.

    Single instance per-process (``_singleton`` below). Per-invocation
    work: resolve container, write script, exec with timeout, capture
    stdout/stderr/exitcode, mutate the moto Invocation record.
    """

    def __init__(self) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=_EXECUTOR_MAX_WORKERS,
            thread_name_prefix="ssm-exec",
        )
        self._in_flight: dict[str, list] = {}  # command_id → list[Future]
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def dispatch(
        self,
        command_id: str,
        document_name: str,
        parameters: dict,
        instance_ids: list[str],
        account_id: str,
        region: str,
        timeout_seconds: int | None = None,
        output_s3_bucket_name: str | None = None,
        output_s3_key_prefix: str | None = None,
    ) -> None:
        """Run the command on every resolved instance, asynchronously."""
        if document_name in STUBBED_DOCUMENTS:
            # Synthesize Success immediately and return — no exec.
            for iid in instance_ids:
                self._finalize_stub(command_id, iid, account_id, region, document_name)
            return

        if document_name not in SHELL_SCRIPT_DOCUMENTS:
            # Unknown document → moto's record stays untouched; log once.
            LOG.info(
                "SSM: document %s not supported for Docker execution, "
                "leaving moto state untouched", document_name,
            )
            return

        commands = parameters.get("commands") or parameters.get("Commands") or []
        if isinstance(commands, str):
            commands = [commands]
        working_directory = (
            parameters.get("workingDirectory") or parameters.get("WorkingDirectory") or "/"
        )
        try:
            working_directory = working_directory[0] if isinstance(
                working_directory, list,
            ) else working_directory
        except Exception:
            working_directory = "/"

        # Resolve {{ssm:/path}} placeholders in every command line.
        resolved = [
            self._resolve_ssm_placeholders(cmd, account_id, region)
            for cmd in commands
        ]
        # POSIX sh, not bash: Alpine (and many minimal Linux images) ship
        # only /bin/sh. Real AWS SSM RunCommand executes the user's
        # commands verbatim with no implicit `set -e` / `set -o pipefail`,
        # so we match that — adding fail-fast would break common probe
        # patterns like `which foo; do_something_else`.
        script = "#!/bin/sh\n" + "\n".join(resolved) + "\n"

        exec_timeout = int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS)

        futures = []
        for iid in instance_ids:
            fut = self._pool.submit(
                self._run_one,
                command_id=command_id,
                instance_id=iid,
                account_id=account_id,
                region=region,
                script=script,
                working_directory=str(working_directory) if working_directory else "/",
                exec_timeout=exec_timeout,
                output_s3_bucket_name=output_s3_bucket_name,
                output_s3_key_prefix=output_s3_key_prefix,
            )
            futures.append(fut)
        with self._lock:
            self._in_flight[command_id] = futures

    def cancel_in_flight(self, command_id: str) -> None:
        """Best-effort cancel — running docker-execs will still complete."""
        with self._lock:
            futs = self._in_flight.pop(command_id, [])
        for f in futs:
            f.cancel()

    def shutdown(self, wait: bool = False) -> None:
        """Called on LocalEmu shutdown. In-flight commands get a final
        chance; any still-running are marked Cancelled on restore."""
        self._pool.shutdown(wait=wait, cancel_futures=True)

    # ------------------------------------------------------------------
    # Per-invocation work (runs in a pool thread)
    # ------------------------------------------------------------------

    def _run_one(
        self,
        command_id: str,
        instance_id: str,
        account_id: str,
        region: str,
        script: str,
        working_directory: str,
        exec_timeout: int,
        output_s3_bucket_name: str | None,
        output_s3_key_prefix: str | None,
    ) -> None:
        start = datetime.now(timezone.utc)
        self._update_invocation(
            command_id, instance_id, account_id, region,
            status="InProgress", status_details="InProgress",
            execution_start=start,
        )

        container_name = self._resolve_container(account_id, region, instance_id)
        if container_name is None:
            self._update_invocation(
                command_id, instance_id, account_id, region,
                status="Failed", status_details="InstanceUnreachable",
                standard_output="",
                standard_error=f"Instance {instance_id} has no running Docker container in LocalEmu",
                response_code=-1,
                execution_start=start,
                execution_end=datetime.now(timezone.utc),
            )
            return

        # Write the script, chmod +x, exec via timeout(1).
        from localemu.utils.docker_utils import DOCKER_CLIENT
        script_b64 = base64.b64encode(script.encode()).decode()
        script_path = f"/var/lib/localemu/ssm/{command_id}.sh"
        prepare_cmd = [
            "sh", "-c",
            f"mkdir -p /var/lib/localemu/ssm && "
            f"printf '%s' '{script_b64}' | base64 -d > {script_path} && "
            f"chmod +x {script_path}",
        ]
        try:
            DOCKER_CLIENT.exec_in_container(container_name, prepare_cmd)
        except Exception as exc:
            self._update_invocation(
                command_id, instance_id, account_id, region,
                status="Failed", status_details="ExecutionDidNotStart",
                standard_output="",
                standard_error=f"Could not write script into container: {exc}",
                response_code=-1,
                execution_start=start,
                execution_end=datetime.now(timezone.utc),
            )
            return

        # Run the script with timeout; capture stdout and stderr separately
        # via two files so we can recover both regardless of exit code.
        run_cmd = [
            "sh", "-c",
            f"cd {shlex_quote(working_directory)} && "
            f"timeout {exec_timeout}s {script_path} "
            f">/var/lib/localemu/ssm/{command_id}.out "
            f"2>/var/lib/localemu/ssm/{command_id}.err; "
            f"echo -n $?",
        ]
        try:
            rc_raw, _ = DOCKER_CLIENT.exec_in_container(container_name, run_cmd)
        except Exception as exc:
            # exec_in_container raises on non-zero exit; we wrapped with
            # ``; echo -n $?`` so the outer sh always returns 0, meaning
            # an exception here is a real Docker-level error.
            self._update_invocation(
                command_id, instance_id, account_id, region,
                status="Failed", status_details="DeliveryTimedOut",
                standard_output="",
                standard_error=f"Docker exec error: {exc}",
                response_code=-1,
                execution_start=start,
                execution_end=datetime.now(timezone.utc),
            )
            return

        try:
            exit_code = int((rc_raw or b"").decode("ascii", errors="ignore").strip() or "0")
        except (TypeError, ValueError):
            exit_code = -1

        # Read stdout + stderr files back out of the container.
        stdout = self._read_file(container_name, f"/var/lib/localemu/ssm/{command_id}.out")
        stderr = self._read_file(container_name, f"/var/lib/localemu/ssm/{command_id}.err")

        # Optional S3 spill.
        self._maybe_spill_to_s3(
            output_s3_bucket_name, output_s3_key_prefix,
            command_id, instance_id, stdout, stderr, account_id, region,
        )

        # Status mapping: 124 = coreutils timeout; otherwise 0 → Success,
        # anything else → Failed.
        if exit_code == 124:
            status, details = "TimedOut", "ExecutionTimedOut"
        elif exit_code == 0:
            status, details = "Success", "Success"
        else:
            status, details = "Failed", "Failed"

        self._update_invocation(
            command_id, instance_id, account_id, region,
            status=status, status_details=details,
            standard_output=stdout[:MAX_INLINE_BYTES],
            standard_error=stderr[:MAX_INLINE_BYTES],
            response_code=exit_code,
            execution_start=start,
            execution_end=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_container(
        account_id: str, region: str, instance_id: str,
    ) -> str | None:
        """Resolve an EC2 instance id to a running Docker container name.

        Uses the public helper on ``DockerVmManager`` when available; if
        the vm_manager has not been initialized in this process (e.g.
        EC2_VM_MANAGER is unset), returns ``None`` so the caller surfaces
        InstanceUnreachable.
        """
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_container_for_instance,
            )
        except Exception:
            return None
        try:
            return get_container_for_instance(account_id, region, instance_id)
        except Exception:
            LOG.debug(
                "resolve_container(%s, %s, %s) failed",
                account_id, region, instance_id, exc_info=True,
            )
            return None

    @staticmethod
    def _read_file(container_name: str, path: str) -> str:
        from localemu.utils.docker_utils import DOCKER_CLIENT
        try:
            out, _ = DOCKER_CLIENT.exec_in_container(
                container_name,
                ["sh", "-c", f"cat {path} 2>/dev/null || true"],
            )
        except Exception:
            return ""
        if isinstance(out, bytes):
            return out.decode("utf-8", errors="replace")
        return str(out or "")

    @staticmethod
    def _resolve_ssm_placeholders(
        script: str, account_id: str, region: str,
    ) -> str:
        """Expand ``{{ssm:/path}}`` and ``{{ssm-secure:/path}}``.

        Errors are logged and the placeholder is left in place so the
        user sees a clear failure inside the executed script rather than
        a silent substitution to empty string.
        """
        try:
            import moto.backends as moto_backends

            backend = moto_backends.get_backend("ssm")[account_id][region]
        except Exception:
            return script

        def _sub(match):
            name = match.group(1).strip()
            try:
                param = backend.get_parameter(name)
                if param is not None:
                    return str(getattr(param, "value", "") or "")
            except Exception:
                pass
            LOG.warning("SSM placeholder %s could not be resolved", name)
            return match.group(0)

        return _SSM_PLACEHOLDER.sub(_sub, script)

    @staticmethod
    def _maybe_spill_to_s3(
        bucket: str | None, prefix: str | None,
        command_id: str, instance_id: str,
        stdout: str, stderr: str,
        account_id: str, region: str,
    ) -> None:
        if not bucket:
            return
        try:
            from localemu.aws.connect import connect_to

            s3 = connect_to(region_name=region).s3
            key_base = f"{(prefix or '').rstrip('/')}/{command_id}/{instance_id}".lstrip("/")
            s3.put_object(Bucket=bucket, Key=f"{key_base}/stdout",
                          Body=stdout.encode("utf-8"))
            s3.put_object(Bucket=bucket, Key=f"{key_base}/stderr",
                          Body=stderr.encode("utf-8"))
        except Exception:
            LOG.debug(
                "SSM output S3 spill failed for %s", command_id, exc_info=True,
            )

    @staticmethod
    def _update_invocation(
        command_id: str, instance_id: str, account_id: str, region: str,
        *,
        status: str,
        status_details: str,
        standard_output: str = "",
        standard_error: str = "",
        response_code: int | None = None,
        execution_start: datetime | None = None,
        execution_end: datetime | None = None,
    ) -> None:
        """Mutate the moto ``CommandInvocation`` record in place so
        ``GetCommandInvocation`` returns our results.

        Moto stores ``Command.invocations`` as a list of **dicts**
        (not objects) with AWS-shaped keys: ``CommandId``, ``InstanceId``,
        ``Status``, ``StandardOutputContent``, ``StandardErrorContent``,
        ``ResponseCode``, ``StatusDetails``, ``ExecutionStartDateTime``,
        ``ExecutionEndDateTime``.
        """
        try:
            import moto.backends as moto_backends

            backend = moto_backends.get_backend("ssm")[account_id][region]
            commands = getattr(backend, "_commands", None) or []
            target = None
            for c in commands:
                if getattr(c, "command_id", None) == command_id:
                    target = c
                    break
            if target is None:
                return
            # Also flip the Command-level status so ListCommands is correct.
            try:
                target.status = status
                target.status_details = status_details
            except Exception:
                pass
            for inv in getattr(target, "invocations", []) or []:
                if not isinstance(inv, dict):
                    continue
                if inv.get("InstanceId") != instance_id:
                    continue
                inv["Status"] = status
                inv["StatusDetails"] = status_details
                inv["StandardOutputContent"] = standard_output
                inv["StandardErrorContent"] = standard_error
                if response_code is not None:
                    inv["ResponseCode"] = response_code
                if execution_start is not None:
                    inv["ExecutionStartDateTime"] = execution_start.isoformat()
                if execution_end is not None:
                    inv["ExecutionEndDateTime"] = execution_end.isoformat()
                return
        except Exception:
            LOG.debug(
                "SSM moto invocation update failed for %s/%s",
                command_id, instance_id, exc_info=True,
            )

    def _finalize_stub(
        self,
        command_id: str, instance_id: str,
        account_id: str, region: str, document_name: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        self._update_invocation(
            command_id, instance_id, account_id, region,
            status="Success",
            status_details=f"LocalEmu: document {document_name} is stubbed (synthetic success)",
            standard_output="",
            standard_error="",
            response_code=0,
            execution_start=now,
            execution_end=now,
        )


# Single-line shell-quote that tolerates odd working-directory values.
def shlex_quote(s: str) -> str:
    import shlex as _shlex
    return _shlex.quote(s)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_singleton: SsmDockerExecutor | None = None
_singleton_lock = threading.Lock()


def get_executor() -> SsmDockerExecutor:
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SsmDockerExecutor()
    return _singleton
