"""Phase 7 — verification gate.

After the writer drops files in the output directory, we shell out to
``terraform`` (or ``aws cloudformation validate-template``) against the
target account and treat the result as the export's exit code. An export
that produces broken IaC is not a successful export.

The optional ``apply`` mode actually applies, asserts resources exist,
then destroys — gated to CI / sandbox accounts via an env var because
applying real infra has cost and side effects.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from localemu.export.realaws.preflight import AwsCredentials

LOG = logging.getLogger(__name__)


class VerifyError(RuntimeError):
    """Raised when the post-export verification step fails."""


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of the verification gate."""

    mode: str           # "plan" | "apply" | "validate" | "skipped"
    succeeded: bool
    stdout: str
    stderr: str


def _run(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int = 600,
) -> tuple[int, str, str]:
    """Run a subprocess and capture output. Never raises on non-zero exit."""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def verify_terraform(
    output_dir: Path,
    creds: AwsCredentials,
    target_region: str,
    target_account: str,
    mode: str = "plan",
) -> VerifyResult:
    """Run ``terraform init`` + ``terraform plan`` (and optionally apply/destroy).

    Args:
        output_dir: Directory containing ``main.tf`` etc.
        creds: Credentials for the target account.
        target_region: Target AWS region.
        target_account: Target AWS account id (passed as ``-var``).
        mode: ``"plan"`` (default) or ``"apply"``.

    Raises:
        VerifyError: If ``terraform`` is not installed, or if any of the
            invoked terraform steps exits non-zero.
    """
    if shutil.which("terraform") is None:
        raise VerifyError(
            "`terraform` binary not found on PATH. Install Terraform "
            ">= 1.5 to enable the export verification gate."
        )

    env = creds.env_for_subprocess(target_region)
    var_args = [
        "-var",
        f"aws_account_id={target_account}",
        "-var",
        f"aws_region={target_region}",
    ]
    if (output_dir / "terraform.tfvars").exists():
        # Picked up automatically by terraform — nothing extra needed.
        pass
    elif (output_dir / "terraform.tfvars.example").exists():
        # Use the example for the gate so secret variables have placeholder
        # values (terraform plan only validates types and graph, not the
        # semantic correctness of the secrets themselves).
        var_args += ["-var-file", "terraform.tfvars.example"]

    code, out, err = _run(["terraform", "init", "-input=false"], output_dir, env)
    if code != 0:
        raise VerifyError(
            "terraform init failed:\n"
            f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
        )

    code, out, err = _run(
        ["terraform", "plan", "-input=false", "-lock=false", *var_args],
        output_dir,
        env,
    )
    if code != 0:
        raise VerifyError(
            "terraform plan failed against the target account:\n"
            f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
        )

    if mode == "plan":
        return VerifyResult(mode="plan", succeeded=True, stdout=out, stderr=err)

    if mode == "apply":
        code, out, err = _run(
            ["terraform", "apply", "-input=false", "-auto-approve", *var_args],
            output_dir,
            env,
        )
        if code != 0:
            raise VerifyError(
                "terraform apply failed:\n"
                f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
            )
        # Always destroy after a verify-apply — this mode is for CI gates.
        d_code, d_out, d_err = _run(
            ["terraform", "destroy", "-input=false", "-auto-approve", *var_args],
            output_dir,
            env,
        )
        if d_code != 0:
            raise VerifyError(
                "terraform destroy after verify-apply failed:\n"
                f"--- stdout ---\n{d_out}\n--- stderr ---\n{d_err}"
            )
        return VerifyResult(
            mode="apply", succeeded=True, stdout=out + d_out, stderr=err + d_err
        )

    raise VerifyError(f"unknown verify mode: {mode!r}")


def verify_cloudformation(
    output_dir: Path,
    creds: AwsCredentials,
    target_region: str,
    template_filename: str = "main.yaml",
) -> VerifyResult:
    """Run ``aws cloudformation validate-template`` against the target."""
    if shutil.which("aws") is None:
        raise VerifyError(
            "`aws` CLI not found on PATH. Install AWS CLI v2 to enable the "
            "CloudFormation verification gate."
        )
    env = creds.env_for_subprocess(target_region)
    template_path = output_dir / template_filename
    if not template_path.exists():
        raise VerifyError(f"template not found: {template_path}")
    code, out, err = _run(
        [
            "aws",
            "cloudformation",
            "validate-template",
            "--template-body",
            f"file://{template_path}",
        ],
        output_dir,
        env,
    )
    if code != 0:
        raise VerifyError(
            "aws cloudformation validate-template failed:\n"
            f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
        )
    return VerifyResult(mode="validate", succeeded=True, stdout=out, stderr=err)
