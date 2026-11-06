"""Make a SageMaker notebook instance's ``OnStart`` lifecycle script
actually run.

SageMaker has zero LocalEmu-specific implementation otherwise - it's a
plain passthrough to upstream moto (``services/providers.py``), which only
tracks in-memory metadata and never executes anything. For a security lab
that treats the lifecycle config as a privilege-escalation / RCE step (you
can attach a script that runs under the notebook's own execution role),
that means the "exploit" had nothing to actually land on.

Scope: only ``StartNotebookInstance``'s ``OnStart`` script, run once,
fire-and-forget, in a throwaway container - not a persistent Jupyter
environment. Real AWS runs this on the actual EC2 instance backing the
notebook, which LocalEmu doesn't emulate; this gives the lab a real command
execution side effect under the role's real (enforced) credentials without
pretending to emulate a whole notebook server.
"""

from __future__ import annotations

import base64
import logging
import threading

from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)

_PATCHED = False
_LOCK = threading.Lock()


def apply_sagemaker_patches() -> None:
    global _PATCHED
    with _LOCK:
        if _PATCHED:
            return
        try:
            _do_patch()
            _PATCHED = True
        except Exception:
            _PATCHED = False
            raise


def _do_patch() -> None:
    from moto.sagemaker.models import FakeSagemakerNotebookInstance, SageMakerModelBackend

    @patch(SageMakerModelBackend.start_notebook_instance)
    def start_notebook_instance(fn, self, notebook_instance_name: str):
        fn(self, notebook_instance_name)
        try:
            _run_on_start_script(self, notebook_instance_name)
        except Exception:
            LOG.warning(
                "Failed to run OnStart lifecycle script for notebook instance %s",
                notebook_instance_name, exc_info=True,
            )

    @patch(FakeSagemakerNotebookInstance.to_dict)
    def to_dict(fn, self):
        result = fn(self)
        # moto's own to_dict() never had a FailureReason field for notebook
        # instances - the lab's whole point in attaching an OnStart script
        # is to observe whether it ran, and a script that fails (bootstrap
        # network hiccup, bad command, ...) used to be a silent server-log
        # line with nothing visible through the API at all.
        failure_reason = getattr(self, "onstart_failure_reason", None)
        if failure_reason:
            result["FailureReason"] = failure_reason
        return result


def _run_on_start_script(backend, notebook_instance_name: str) -> None:
    notebook_instance = backend.notebook_instances.get(notebook_instance_name)
    if notebook_instance is None:
        return
    lifecycle_config_name = getattr(notebook_instance, "lifecycle_config_name", None)
    if not lifecycle_config_name:
        return
    lifecycle_config = backend.notebook_instance_lifecycle_configurations.get(
        lifecycle_config_name
    )
    if lifecycle_config is None:
        return
    on_start = getattr(lifecycle_config, "on_start", None) or []
    user_script = b"".join(
        base64.b64decode(entry["Content"])
        for entry in on_start
        if isinstance(entry, dict) and entry.get("Content")
    )
    if not user_script:
        return
    # LocalEmu's own base image has Python but neither the AWS CLI nor
    # boto3 - unlike a real SageMaker notebook's conda environment, where
    # both are preinstalled. Lifecycle scripts conventionally shell out to
    # `aws ...`, so bootstrap it before handing off to the real script
    # rather than silently failing on "aws: not found". Retried once: a
    # `pip install` against PyPI is a real network dependency and a
    # transient blip there must not be indistinguishable from the user's
    # own script failing - capture the bootstrap's own output too so a
    # failure here (vs. in the user's script) is visible in FailureReason
    # rather than showing up as an opaque "aws: not found" / exit 127.
    script = (
        b"#!/bin/sh\n"
        b"BOOTSTRAP_OK=0\n"
        b"for i in 1 2; do\n"
        b"  if python3 -m pip install -q awscli >/tmp/.onstart_bootstrap.log 2>&1; then\n"
        b"    BOOTSTRAP_OK=1\n"
        b"    break\n"
        b"  fi\n"
        b"done\n"
        b'if [ "$BOOTSTRAP_OK" != "1" ]; then\n'
        b'  echo "awscli bootstrap failed after 2 attempts:" >&2\n'
        b"  cat /tmp/.onstart_bootstrap.log >&2\n"
        b"  exit 97\n"
        b"fi\n"
    ) + user_script

    role_arn = getattr(notebook_instance, "role_arn", None)
    region = backend.region_name

    # Fire-and-forget, same as real AWS: StartNotebookInstance returns long
    # before the instance (and its lifecycle script) has actually finished
    # starting.
    threading.Thread(
        target=_execute_script,
        args=(backend, script, role_arn, region, notebook_instance_name),
        name="sagemaker-lifecycle-onstart",
        daemon=True,
    ).start()


_MAX_FAILURE_REASON_LEN = 1024


def _execute_script(
    backend, script: bytes, role_arn: str | None, region: str, notebook_instance_name: str,
) -> None:
    from localemu import config
    from localemu.aws.connect import connect_to
    from localemu.constants import DOCKER_IMAGE_NAME
    from localemu.utils.container_networking import (
        get_endpoint_for_network,
        get_main_container_network,
    )
    from localemu.utils.docker_utils import DOCKER_CLIENT

    env_vars = {"AWS_DEFAULT_REGION": region, "AWS_REGION": region}
    if role_arn:
        try:
            from localemu.utils.aws.client_types import ServicePrincipal

            # Matches the trust policy AWS-documented SageMaker execution
            # roles use (``Principal: {Service: "sagemaker.amazonaws.com"}``)
            # - without this, AssumeRole evaluated the caller as LocalEmu's
            # internal root identity, which that trust policy doesn't name.
            sts_client = connect_to(region_name=region).sts.request_metadata(
                service_principal=ServicePrincipal("sagemaker")
            )
            credentials = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"sagemaker-onstart-{notebook_instance_name}"[:64],
            )["Credentials"]
            env_vars.update({
                "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
                "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
                "AWS_SESSION_TOKEN": credentials["SessionToken"],
            })
        except Exception:
            LOG.warning(
                "Could not assume RoleArn %s for notebook instance %s OnStart script - "
                "running without AWS credentials",
                role_arn, notebook_instance_name, exc_info=True,
            )

    network = get_main_container_network()
    try:
        endpoint_host = get_endpoint_for_network(network=network)
        env_vars["AWS_ENDPOINT_URL"] = f"http://{endpoint_host}:{config.GATEWAY_LISTEN[0].port}"
    except Exception:
        LOG.debug("Could not resolve LocalEmu endpoint for OnStart script container", exc_info=True)

    notebook_instance = backend.notebook_instances.get(notebook_instance_name)
    try:
        stdout, stderr = DOCKER_CLIENT.run_container(
            DOCKER_IMAGE_NAME,
            stdin=script,
            interactive=True,  # without this, docker never attaches stdin at all
            entrypoint="/bin/sh",
            remove=True,
            env_vars=env_vars,
            network=network,
        )
        LOG.info(
            "SageMaker notebook instance %s OnStart script finished. stdout=%s stderr=%s",
            notebook_instance_name, stdout, stderr,
        )
        if notebook_instance is not None:
            notebook_instance.onstart_failure_reason = None
    except Exception as exc:
        LOG.warning(
            "SageMaker notebook instance %s OnStart script failed", notebook_instance_name,
            exc_info=True,
        )
        if notebook_instance is not None:
            notebook_instance.onstart_failure_reason = _format_onstart_failure(exc)
            notebook_instance.status = "Failed"


def _format_onstart_failure(exc: Exception) -> str:
    """Compact, API-visible summary of an OnStart failure - exit code plus
    the tail of stdout/stderr, so a lab can tell a bootstrap network blip
    (exit 97, see the retry loop in ``_run_on_start_script``) apart from
    its own script actually failing (e.g. exit 127, command not found),
    instead of both looking like the same opaque silence."""
    stdout = getattr(exc, "stdout", None) or b""
    stderr = getattr(exc, "stderr", None) or b""
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    message = str(exc)
    reason = f"OnStart script error: {message}"
    tail = (stderr or stdout).strip()
    if tail:
        reason += f" | output: {tail[-512:]}"
    return reason[:_MAX_FAILURE_REASON_LEN]
