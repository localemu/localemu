"""MANIFEST.md generation.

The manifest is the single source of truth the user reads after an
export. It must list:

* Every resource the export emitted (so the user can check nothing was
  silently dropped).
* Every secret that needs a value before deploy.
* Every resource the export *could not* translate, with a reason —
  silent drops were a v1 footgun.

Format is intentionally Markdown so it renders nicely on GitHub / PRs.
"""

from __future__ import annotations

from typing import Iterable

from localemu.export.ir import Snapshot
from localemu.export.realaws.secrets import SecretSlot


def build_manifest(
    snapshot: Snapshot,
    target_account: str,
    target_region: str,
    fmt: str,
    secret_slots: Iterable[SecretSlot],
    unsupported: list[tuple[str, str, str, str]],
    skipped_lambdas: list[tuple[str, str]],
    deployment_bucket: str | None,
) -> str:
    """Build the MANIFEST.md text.

    Args:
        snapshot: The snapshot that was actually written.
        target_account: AWS account id the export targets.
        target_region: AWS region the export targets.
        fmt: ``"terraform"`` or ``"cloudformation"``.
        secret_slots: Secrets the user must populate before deploy.
        unsupported: ``(service, resource_type, resource_id, reason)``
            entries for resources we collected but couldn't translate.
        skipped_lambdas: Lambda functions skipped due to missing code
            bytes.
        deployment_bucket: Name of the Lambda code deployment bucket if
            one was created; ``None`` if no Lambda functions were
            present.

    Returns:
        Markdown text.
    """
    lines: list[str] = [
        "# LocalEmu Export Manifest",
        "",
        f"- **Format:** `{fmt}`",
        f"- **Target account:** `{target_account}`",
        f"- **Target region:** `{target_region}`",
        f"- **Exported at:** `{snapshot.exported_at}`",
        f"- **LocalEmu version:** `{snapshot.localemu_version}`",
        f"- **Resources written:** {len(snapshot.resources)}",
        "",
    ]

    # ----- Inventory -----
    lines.append("## Resources")
    lines.append("")
    if snapshot.resources:
        by_service: dict[str, list[str]] = {}
        for r in snapshot.resources:
            by_service.setdefault(r.service, []).append(
                f"{r.resource_type} `{r.resource_id}`"
            )
        for svc in sorted(by_service):
            lines.append(f"### {svc}")
            for entry in sorted(by_service[svc]):
                lines.append(f"- {entry}")
            lines.append("")
    else:
        lines.append("_No resources collected._")
        lines.append("")

    # ----- Deployment bucket note -----
    if deployment_bucket:
        lines.extend(
            [
                "## Lambda code deployment bucket",
                "",
                f"`{deployment_bucket}` will be created by this plan and used to",
                "stage every Lambda function's zip. It is safe to destroy with the",
                "rest of the stack (the bucket is created with `force_destroy = true`).",
                "",
            ]
        )

    # ----- Secrets -----
    lines.append("## Secrets to populate before deploy")
    lines.append("")
    secret_list = list(secret_slots)
    if secret_list:
        lines.append(
            "The following values are intentionally NOT written into the "
            "generated Terraform / CloudFormation. Populate them in "
            "`terraform.tfvars` (copy from `terraform.tfvars.example`) before "
            "running `terraform apply`."
        )
        lines.append("")
        lines.append("| Variable | Resource | Field |")
        lines.append("|---|---|---|")
        for slot in secret_list:
            lines.append(
                f"| `{slot.variable_name}` | "
                f"`{slot.service}.{slot.resource_type}/{slot.resource_id}` | "
                f"`{slot.attribute_path}` |"
            )
        lines.append("")
    else:
        lines.append("_None._")
        lines.append("")

    # ----- Unsupported resources -----
    lines.append("## Unsupported resources")
    lines.append("")
    if unsupported or skipped_lambdas:
        lines.append(
            "These resources exist in your LocalEmu sandbox but were NOT "
            "translated into the export, with the listed reason. Please open "
            "an issue if you need any of them supported."
        )
        lines.append("")
        for service, resource_type, resource_id, reason in unsupported:
            lines.append(
                f"- `{service}.{resource_type}` `{resource_id}` — {reason}"
            )
        for fn_name, reason in skipped_lambdas:
            lines.append(f"- `lambda.function` `{fn_name}` — {reason}")
        lines.append("")
    else:
        lines.append("_None — every collected resource was translated._")
        lines.append("")

    # ----- Export-time warnings -----
    if snapshot.export_warnings:
        lines.append("## Warnings emitted during export")
        lines.append("")
        for w in snapshot.export_warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)
