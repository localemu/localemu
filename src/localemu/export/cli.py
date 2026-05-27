"""Click CLI for LocalEmu infrastructure export / import.

Exposes two commands:

* ``localemu export`` — drives :class:`localemu.export.orchestrator.Orchestrator`
  and one of the format writers (JSON / Terraform / CloudFormation) to
  produce a snapshot artifact on disk.
* ``localemu import`` — replays a previously exported snapshot against a
  live AWS-compatible endpoint (default: LocalEmu on ``localhost:4566``)
  using :class:`localemu.export.importer.ImportRunner`.

Exit codes (Unix convention):
    0 — success
    1 — runtime failure (I/O, orchestrator, importer, etc.)
    2 — usage error (Click already uses this for ``UsageError``)
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import click

LOG = logging.getLogger(__name__)


_VALID_FORMATS = ("json", "terraform", "cloudformation")
_VALID_MODES = ("skip-existing", "fail-on-existing", "replace")
_VALID_ON_ERROR = ("continue", "stop")


def _parse_csv(value: Optional[str]) -> Optional[list[str]]:
    """Parse a comma-separated CLI value into a cleaned list, or ``None``."""
    if value is None:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return parts or None


def _warn_sensitive(flag_name: str) -> None:
    """Emit a loud stderr warning for opt-in sensitive export flags."""
    banner = click.style(
        "!" * 72
        + f"\n!! WARNING: {flag_name} is enabled.\n"
        "!! The resulting snapshot may contain sensitive material\n"
        "!! (credentials, private keys, customer data).\n"
        "!! Handle and store the output accordingly.\n"
        + "!" * 72,
        fg="yellow",
        bold=True,
    )
    click.echo(banner, err=True)


@click.group(name="export-group")
def export_group() -> None:
    """Export LocalEmu infrastructure to JSON / Terraform / CloudFormation,
    and import snapshots back into a LocalEmu or AWS endpoint."""


@export_group.command("export")
@click.option(
    "--format",
    "fmt",
    required=True,
    type=click.Choice(("terraform", "cloudformation", "json"), case_sensitive=False),
    help="Output format. ``terraform`` and ``cloudformation`` produce "
    "real-AWS deployable output; ``json`` produces the legacy raw snapshot.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=True, file_okay=True, writable=True, path_type=Path),
    default=None,
    help="Output directory. Defaults to ``./localemu-export-<timestamp>/``.",
)
@click.option(
    "--aws-account-id",
    "aws_account_id",
    default=None,
    help="Target AWS account id (required for terraform/cloudformation).",
)
@click.option(
    "--aws-region",
    "aws_region",
    default="us-east-1",
    show_default=True,
    help="Target AWS region.",
)
@click.option(
    "--aws-profile",
    "aws_profile",
    default=None,
    help="Named AWS profile to use for preflight + verification.",
)
@click.option(
    "--aws-access-key-id",
    "aws_access_key_id",
    default=None,
    help="Static AWS access key id (use with --aws-secret-access-key).",
)
@click.option(
    "--aws-secret-access-key",
    "aws_secret_access_key",
    default=None,
    help="Static AWS secret access key (use with --aws-access-key-id).",
)
@click.option(
    "--aws-session-token",
    "aws_session_token",
    default=None,
    help="Optional AWS session token (for STS-issued temporary credentials).",
)
@click.option(
    "--verify",
    "verify_mode",
    type=click.Choice(("plan", "apply", "skip"), case_sensitive=False),
    default="plan",
    show_default=True,
    help="Post-export verification: terraform plan (default), apply+destroy "
    "(requires sandbox), or skip.",
)
@click.option(
    "--localemu-endpoint",
    "localemu_endpoint",
    default="http://localhost:4566",
    show_default=True,
    help="LocalEmu endpoint to read state from.",
)
# --- Legacy options retained for the JSON path -------------------------
@click.option(
    "--services",
    default=None,
    help="(json only) Comma-separated list of services to export.",
)
@click.option(
    "--regions",
    default=None,
    help="(json only) Comma-separated list of regions.",
)
@click.option(
    "--include-secrets",
    is_flag=True,
    default=False,
    help="(json only) Include sensitive attributes. USE WITH CARE.",
)
@click.option(
    "--include-data",
    is_flag=True,
    default=False,
    help="(json only) Include bulk payloads.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="(json only) Collect and render, but do not write the output file.",
)
def export_cmd(
    fmt: str,
    output: Optional[Path],
    aws_account_id: Optional[str],
    aws_region: str,
    aws_profile: Optional[str],
    aws_access_key_id: Optional[str],
    aws_secret_access_key: Optional[str],
    aws_session_token: Optional[str],
    verify_mode: str,
    localemu_endpoint: str,
    services: Optional[str],
    regions: Optional[str],
    include_secrets: bool,
    include_data: bool,
    dry_run: bool,
) -> None:
    """Export running LocalEmu state to deployable Terraform / CloudFormation.

    For ``--format terraform`` / ``--format cloudformation`` the export
    targets the real AWS account named by ``--aws-account-id`` and produces
    a directory that ``terraform apply`` / ``aws cloudformation deploy``
    can run against that account without manual editing.
    """
    fmt_lower = fmt.lower()

    # Legacy JSON path is preserved verbatim.
    if fmt_lower == "json":
        _run_legacy_json_export(
            output=output,
            services=services,
            regions=regions,
            include_secrets=include_secrets,
            include_data=include_data,
            dry_run=dry_run,
        )
        return

    if not aws_account_id:
        click.echo(
            click.style(
                "--aws-account-id is required for terraform / cloudformation output.",
                fg="red",
                bold=True,
            ),
            err=True,
        )
        sys.exit(2)

    if (aws_access_key_id and not aws_secret_access_key) or (
        aws_secret_access_key and not aws_access_key_id
    ):
        click.echo(
            "--aws-access-key-id and --aws-secret-access-key must be supplied together.",
            err=True,
        )
        sys.exit(2)

    try:
        from localemu.export.realaws import (
            RealAwsExportError,
            RealAwsExporter,
        )
        from localemu.export.realaws.preflight import AwsCredentials
    except Exception as exc:  # pragma: no cover - defensive
        click.echo(f"Failed to load real-AWS exporter: {exc}", err=True)
        sys.exit(1)

    creds = AwsCredentials(
        profile=aws_profile,
        access_key_id=aws_access_key_id,
        secret_access_key=aws_secret_access_key,
        session_token=aws_session_token,
    )

    if output is None:
        import datetime as _dt

        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = Path.cwd() / f"localemu-export-{stamp}"

    exporter = RealAwsExporter(
        creds=creds,
        target_account=aws_account_id,
        target_region=aws_region,
        localemu_endpoint=localemu_endpoint,
    )
    try:
        result = exporter.export(
            fmt=fmt_lower, output_dir=output, verify_mode=verify_mode.lower()
        )
    except RealAwsExportError as exc:
        click.echo(click.style(f"Export failed: {exc}", fg="red", bold=True), err=True)
        sys.exit(1)
    except Exception as exc:
        LOG.error("Real-AWS export failed", exc_info=True)
        click.echo(f"Unexpected error: {exc}", err=True)
        sys.exit(1)

    click.echo(click.style("Export complete.", fg="green", bold=True))
    click.echo(f"  format        : {result.fmt}")
    click.echo(f"  output dir    : {result.output_dir}")
    click.echo(f"  account/region: {result.target_account} / {result.target_region}")
    click.echo(f"  resources     : {result.resources_written}")
    if result.secret_slots:
        click.echo(
            click.style(
                f"  secrets       : {len(result.secret_slots)} value(s) "
                "needed before deploy (see MANIFEST.md)",
                fg="yellow",
            )
        )
    if result.unsupported or result.skipped_lambdas:
        click.echo(
            click.style(
                f"  unsupported   : {len(result.unsupported) + len(result.skipped_lambdas)}"
                " resource(s) skipped (see MANIFEST.md)",
                fg="yellow",
            )
        )
    if result.verify is not None:
        click.echo(f"  verify        : {result.verify.mode} (passed)")
    sys.exit(0)


def _run_legacy_json_export(
    output: Optional[Path],
    services: Optional[str],
    regions: Optional[str],
    include_secrets: bool,
    include_data: bool,
    dry_run: bool,
) -> None:
    """Original v2 JSON export path (kept for round-trip imports)."""
    if include_secrets:
        _warn_sensitive("--include-secrets")
    if include_data:
        _warn_sensitive("--include-data")

    service_list = _parse_csv(services)
    region_list = _parse_csv(regions)

    try:
        from localemu.export.orchestrator import Orchestrator
    except Exception as exc:  # pragma: no cover - defensive
        click.echo(f"Failed to load export orchestrator: {exc}", err=True)
        sys.exit(1)

    try:
        snapshot = Orchestrator().export(
            services=service_list,
            regions=region_list,
            include_data=include_data,
            include_secrets=include_secrets,
        )
    except Exception as exc:
        LOG.error("Export orchestration failed", exc_info=True)
        click.echo(f"Export failed: {exc}", err=True)
        sys.exit(1)

    writer = _resolve_writer("json")
    if writer is None:
        click.echo("JSON writer not available in this build.", err=True)
        sys.exit(1)

    if output is None:
        output = Path.cwd() / _default_output_name("json")

    if dry_run:
        click.echo(
            f"[dry-run] Would write json snapshot to {output} "
            f"(resources={len(snapshot.resources)}, "
            f"warnings={len(snapshot.export_warnings)})."
        )
        sys.exit(0)

    try:
        final_path = writer.write(snapshot, output)
    except Exception as exc:
        LOG.error("Snapshot write failed", exc_info=True)
        click.echo(f"Failed to write snapshot: {exc}", err=True)
        sys.exit(1)

    click.echo(click.style("Export complete.", fg="green", bold=True))
    click.echo(f"  format        : json")
    click.echo(f"  output        : {final_path}")
    click.echo(f"  resources     : {len(snapshot.resources)}")
    if snapshot.export_warnings:
        click.echo(
            click.style(
                f"  warnings      : {len(snapshot.export_warnings)} "
                "(see snapshot.export_warnings)",
                fg="yellow",
            )
        )
    if snapshot.redacted_secrets:
        click.echo(f"  redacted keys : {len(snapshot.redacted_secrets)}")
    sys.exit(0)


@export_group.command("import")
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--endpoint",
    default=None,
    help="AWS endpoint URL. Default: LocalEmu at http://localhost:4566.",
)
@click.option(
    "--access-key",
    default=None,
    help="AWS access key ID (default: boto3 credential chain).",
)
@click.option(
    "--secret-key",
    default=None,
    help="AWS secret access key (default: boto3 credential chain).",
)
@click.option(
    "--mode",
    type=click.Choice(_VALID_MODES, case_sensitive=False),
    default="skip-existing",
    show_default=True,
    help="Behavior when a resource already exists at the target.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Plan the import but do not call the target.",
)
@click.option(
    "--on-error",
    type=click.Choice(_VALID_ON_ERROR, case_sensitive=False),
    default="continue",
    show_default=True,
    help="Whether to continue after a per-resource failure.",
)
@click.option(
    "--yes",
    is_flag=True,
    default=False,
    help="Required confirmation for --mode replace (destructive).",
)
def import_snapshot(
    path: Path,
    endpoint: Optional[str],
    access_key: Optional[str],
    secret_key: Optional[str],
    mode: str,
    dry_run: bool,
    on_error: str,
    yes: bool,
) -> None:
    """Replay a snapshot into a LocalEmu or AWS endpoint."""
    mode_normalized = mode.lower()
    if mode_normalized == "replace" and not yes:
        click.echo(
            click.style(
                "Refusing to run --mode replace without --yes. "
                "This mode deletes existing resources before re-creating them.",
                fg="red",
                bold=True,
            ),
            err=True,
        )
        sys.exit(2)

    try:
        from localemu.export.formats import JsonReader
    except Exception as exc:  # pragma: no cover - defensive
        click.echo(f"Failed to load snapshot reader: {exc}", err=True)
        sys.exit(1)

    try:
        snapshot = JsonReader().read(path)
    except Exception as exc:
        click.echo(f"Could not read snapshot '{path}': {exc}", err=True)
        sys.exit(1)

    try:
        from localemu.export.importer import ImportMode, ImportRunner
    except ImportError as exc:
        click.echo(
            "Import runner is not available in this build "
            f"({exc}). Please upgrade LocalEmu or check your install.",
            err=True,
        )
        sys.exit(1)

    mode_map = {
        "skip-existing": getattr(ImportMode, "SKIP_EXISTING", "SKIP_EXISTING"),
        "fail-on-existing": getattr(ImportMode, "FAIL_ON_EXISTING", "FAIL_ON_EXISTING"),
        "replace": getattr(ImportMode, "REPLACE", "REPLACE"),
    }

    try:
        runner = ImportRunner(
            snapshot,
            endpoint_url=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            mode=mode_map[mode_normalized],
            on_error=on_error,
            dry_run=dry_run,
        )
        result = runner.run()
    except Exception as exc:
        LOG.error("Import failed", exc_info=True)
        click.echo(f"Import failed: {exc}", err=True)
        sys.exit(1)

    # ``ImportResult`` carries three list attributes; use their lengths as
    # the honest summary counts (the prior aggregate-by-status loop was a
    # holdover from an older per-resource result shape that no longer
    # exists).
    applied = len(getattr(result, "applied", []))
    skipped = len(getattr(result, "skipped", []))
    failed = len(getattr(result, "failed", []))

    header = "[dry-run] Import plan" if dry_run else "Import complete"
    click.echo(click.style(header, fg="green" if not failed else "yellow", bold=True))
    click.echo(f"  applied : {applied}")
    click.echo(f"  skipped : {skipped}")
    click.echo(f"  failed  : {failed}")
    sys.exit(0 if failed == 0 else 1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_writer(fmt: str):
    """Return an instance of the writer for *fmt*, or ``None``."""
    fmt = fmt.lower()
    try:
        from localemu.export.formats import CfnWriter, JsonWriter, TerraformWriter
    except Exception:
        LOG.debug("Format writers not importable", exc_info=True)
        return None

    if fmt == "json":
        return JsonWriter()
    if fmt == "terraform":
        # Not every build ships a fully-functional TerraformWriter.
        w = TerraformWriter()
        if not hasattr(w, "write"):
            return None
        return w
    if fmt == "cloudformation":
        w = CfnWriter()
        if not hasattr(w, "write"):
            return None
        return w
    return None


def _default_output_name(fmt: str) -> str:
    """Return a conventional default filename for the given format."""
    import datetime as _dt

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if fmt == "json":
        return f"localemu-snapshot-{stamp}.json"
    if fmt == "terraform":
        return f"localemu-snapshot-{stamp}.tf.zip"
    if fmt == "cloudformation":
        return f"localemu-snapshot-{stamp}.cfn.yaml"
    return f"localemu-snapshot-{stamp}"


__all__ = ["export_group", "export_cmd", "import_snapshot"]
