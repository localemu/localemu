"""Top-level real-AWS export orchestrator.

Wires every phase together. The single public entry point is
:meth:`RealAwsExporter.export`. Failures at any phase abort the whole
export — there is no partial-success exit. The user gets either a
ready-to-deploy directory or a clear error.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from localemu.export.formats._providers_tf import provider_alias_for_region  # noqa: F401
from localemu.export.formats.hcl_serializer import HclRaw, HclSerializer
from localemu.export.formats.tf_specs import get_tf_spec, translate
from localemu.export.formats.terraform import safe_tf_name
from localemu.export.ir import Ref, Resource, Snapshot
from localemu.export.orchestrator import Orchestrator
from localemu.export.realaws.lambda_code import LambdaCodeResult, prepare_lambda_code
from localemu.export.realaws.manifest import build_manifest
from localemu.export.realaws.preflight import (
    AwsCredentials,
    PreflightError,
    check_localemu_reachable,
    verify_aws_account,
)
from localemu.export.realaws.providers import (
    build_deploy_script,
    build_providers_tf,
    build_tfvars_example,
    build_variables_tf,
)
from localemu.export.realaws.rewrite import rewrite_snapshot
from localemu.export.realaws.secrets import SecretSlot, _Sentinel, extract_secrets
from localemu.export.realaws.verify import (
    VerifyError,
    VerifyResult,
    verify_cloudformation,
    verify_terraform,
)
from localemu.export.references import resolve_references

LOG = logging.getLogger(__name__)


class RealAwsExportError(RuntimeError):
    """Top-level error wrapping any phase failure."""


@dataclass
class RealAwsExportResult:
    """Outcome of :meth:`RealAwsExporter.export`."""

    output_dir: Path
    fmt: str
    target_account: str
    target_region: str
    resources_written: int
    secret_slots: list[SecretSlot] = field(default_factory=list)
    unsupported: list[tuple[str, str, str, str]] = field(default_factory=list)
    skipped_lambdas: list[tuple[str, str]] = field(default_factory=list)
    deployment_bucket: str | None = None
    verify: VerifyResult | None = None


class RealAwsExporter:
    """Drive the seven-phase real-AWS export pipeline."""

    def __init__(
        self,
        creds: AwsCredentials,
        target_account: str,
        target_region: str,
        localemu_endpoint: str = "http://localhost:4566",
    ) -> None:
        self._creds = creds
        self._target_account = target_account
        self._target_region = target_region
        self._localemu_endpoint = localemu_endpoint

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export(
        self,
        fmt: str,
        output_dir: Path,
        verify_mode: str = "plan",
    ) -> RealAwsExportResult:
        """Run the full pipeline.

        Args:
            fmt: ``"terraform"`` or ``"cloudformation"``.
            output_dir: Destination directory; created if missing.
            verify_mode: ``"plan"`` (default), ``"apply"``, or ``"skip"``.

        Raises:
            RealAwsExportError: On any phase failure. The error message
                names the phase and includes the underlying failure.
        """
        fmt = fmt.lower()
        if fmt not in ("terraform", "cloudformation"):
            raise RealAwsExportError(f"unknown format: {fmt!r}")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # --- Phase 1: Preflight ---------------------------------------
        try:
            check_localemu_reachable(self._localemu_endpoint)
            verify_aws_account(
                self._creds, self._target_account, self._target_region
            )
        except PreflightError as exc:
            raise RealAwsExportError(f"Preflight failed: {exc}") from exc

        # --- Phase 2: Discovery ---------------------------------------
        # ``localemu export`` runs in a SEPARATE process from the LocalEmu
        # server. The collectors read in-memory moto / localemu service
        # state, so calling ``Orchestrator().export(...)`` here returns an
        # empty snapshot — the CLI process has none of the state the user
        # actually created. We MUST fetch the snapshot from the running
        # LocalEmu server via its HTTP export endpoint, which executes the
        # orchestrator inside the server process where the state lives.
        snapshot = self._fetch_snapshot_via_http()

        # --- Phase 4: Account / region rewrite (before refs so ARN
        # joins still work) -------------------------------------------
        snapshot = rewrite_snapshot(
            snapshot, self._target_account, self._target_region
        )

        # --- Phase 5: Lambda code packaging ---------------------------
        lambda_result: LambdaCodeResult = prepare_lambda_code(
            snapshot, self._target_account, self._target_region
        )
        snapshot = lambda_result.snapshot

        # --- Phase 6: Secrets -> variables ----------------------------
        secrets_result = extract_secrets(snapshot)
        snapshot = secrets_result.snapshot

        # --- Reference resolution (after rewrite + lambda + secrets) -
        snapshot = resolve_references(snapshot)

        # --- Phase 3: Translation + write -----------------------------
        if fmt == "terraform":
            unsupported = self._write_terraform(
                snapshot, output_dir, secrets_result.slots
            )
        else:
            from localemu.export.realaws.cfn import write_cloudformation

            unsupported = write_cloudformation(
                snapshot,
                output_dir,
                self._target_account,
                self._target_region,
                secrets_result.slots,
            )

        # --- Manifest -------------------------------------------------
        manifest = build_manifest(
            snapshot=snapshot,
            target_account=self._target_account,
            target_region=self._target_region,
            fmt=fmt,
            secret_slots=secrets_result.slots,
            unsupported=unsupported,
            skipped_lambdas=lambda_result.skipped,
            deployment_bucket=lambda_result.deployment_bucket_logical_id,
        )
        (output_dir / "MANIFEST.md").write_text(manifest, encoding="utf-8")

        # --- Phase 7: Verification gate -------------------------------
        verify_result: VerifyResult | None = None
        if verify_mode != "skip":
            try:
                if fmt == "terraform":
                    verify_result = verify_terraform(
                        output_dir,
                        self._creds,
                        self._target_region,
                        self._target_account,
                        mode=verify_mode,
                    )
                else:
                    verify_result = verify_cloudformation(
                        output_dir, self._creds, self._target_region
                    )
            except VerifyError as exc:
                raise RealAwsExportError(
                    "Verification gate failed; export output is not deployable "
                    f"as-is.\n{exc}"
                ) from exc

        return RealAwsExportResult(
            output_dir=output_dir,
            fmt=fmt,
            target_account=self._target_account,
            target_region=self._target_region,
            resources_written=len(snapshot.resources),
            secret_slots=secrets_result.slots,
            unsupported=unsupported,
            skipped_lambdas=lambda_result.skipped,
            deployment_bucket=lambda_result.deployment_bucket_logical_id,
            verify=verify_result,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fetch_snapshot_via_http(self) -> Snapshot:
        """Fetch a full snapshot from the running LocalEmu server.

        Uses the ``/_localemu/api/export`` endpoint with
        ``include_secrets=1`` and ``include_data=1`` so that Lambda code
        bytes and tagged secret slots come through. Sensitive flags
        require ``LOCALEMU_EXPORT_AUTH_TOKEN`` to be set in BOTH the
        server process (where it gates the request) AND the CLI process
        (so we know what bearer to send). When the token is unset the
        endpoint refuses the request, which we surface as a real
        :class:`RealAwsExportError` rather than silently producing an
        empty snapshot.
        """
        import io
        import os
        import tempfile
        import urllib.error
        import urllib.request
        import zipfile

        from localemu.export.formats.json_format import JsonReader

        token = os.environ.get("LOCALEMU_EXPORT_AUTH_TOKEN") or os.environ.get(
            "LOCALEMU_EXPORT_TOKEN"
        ) or ""
        if not token:
            raise RealAwsExportError(
                "LOCALEMU_EXPORT_AUTH_TOKEN is not set. The export "
                "endpoint requires this token to authorize sensitive "
                "(include_secrets / include_data) reads. Set the same "
                "token in BOTH the LocalEmu server environment AND your "
                "shell before invoking 'localemu export'."
            )

        url = (
            self._localemu_endpoint.rstrip("/")
            + "/_localemu/api/export?format=json&include_data=1&include_secrets=1"
        )
        req = urllib.request.Request(
            url, method="GET", headers={"Authorization": f"Bearer {token}"}
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = resp.read()
                content_type = resp.headers.get("Content-Type", "") or ""
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RealAwsExportError(
                f"LocalEmu export endpoint returned HTTP {exc.code}: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RealAwsExportError(
                f"Failed to call LocalEmu export endpoint at {url}: {exc}"
            ) from exc

        # The endpoint always returns an attachment: either a single
        # ``localemu-snapshot.json`` (no sidecars) or a ``.zip`` archive
        # containing the JSON plus sidecar payloads (Lambda code, etc.).
        # Persist to a tempfile because :class:`JsonReader` is path-based,
        # then deserialize back into our IR.
        is_zip = (
            "zip" in content_type.lower()
            or (len(payload) >= 4 and payload[:2] == b"PK")
        )
        suffix = ".zip" if is_zip else ".json"
        with tempfile.NamedTemporaryFile(
            "wb", suffix=suffix, delete=False
        ) as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        try:
            return JsonReader().read(Path(tmp_path))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _write_terraform(
        self,
        snapshot: Snapshot,
        output_dir: Path,
        secret_slots: list[SecretSlot],
    ) -> list[tuple[str, str, str, str]]:
        """Render and write the Terraform output.

        Returns:
            ``unsupported`` list of ``(service, type, id, reason)``.
        """
        # 1) Assign collision-free logical names.
        logical_names: dict[tuple[str, str, str], tuple[str, str]] = {}
        used_per_type: dict[str, set[str]] = {}
        for r in snapshot.resources:
            spec = get_tf_spec(r.service, r.resource_type)
            if spec is None:
                continue
            base = safe_tf_name(r.resource_id)
            used = used_per_type.setdefault(spec.resource_type, set())
            candidate = base
            suffix = 1
            while candidate in used:
                suffix += 1
                candidate = f"{base}_{suffix}"
            used.add(candidate)
            logical_names[(r.service, r.resource_type, r.resource_id)] = (
                spec.resource_type,
                candidate,
            )

        def resolve_ref(ref: Ref) -> str:
            entry = logical_names.get(
                (ref.service, ref.resource_type, ref.resource_id)
            )
            if entry is None:
                # Unknown target — the writer would otherwise generate an
                # unresolvable address that breaks ``terraform plan``. Fall
                # back to a synthesized address; the verify step will
                # surface the failure.
                safe = safe_tf_name(ref.resource_id)
                return f"aws_{ref.service}_{ref.resource_type}.{safe}.{ref.attribute}"
            tf_type, logical = entry
            return f"{tf_type}.{logical}.{ref.attribute}"

        serializer = HclSerializer(ref_resolver=resolve_ref)

        # 2) Translate each resource.
        supported: dict[str, dict[str, dict[str, Any]]] = {}
        unsupported: list[tuple[str, str, str, str]] = []
        sidecars: dict[str, bytes] = dict(snapshot.sidecar_files)

        for r in snapshot.resources:
            spec = get_tf_spec(r.service, r.resource_type)
            if spec is None:
                unsupported.append(
                    (r.service, r.resource_type, r.resource_id,
                     _unsupported_reason(r.service, r.resource_type))
                )
                continue
            ctx: dict[str, Any] = {}
            attrs = translate(r, ctx)
            if attrs is None:
                unsupported.append(
                    (r.service, r.resource_type, r.resource_id,
                     "translation returned None")
                )
                continue

            # Convert secret sentinels to ``var.<name>`` HCL refs.
            attrs = _replace_sentinels(attrs)

            # Companion resources (e.g. S3 versioning).
            if spec.extra_resources is not None:
                extras = spec.extra_resources(r, attrs)
                for (extra_type, extra_name), extra_attrs in extras.items():
                    supported.setdefault(extra_type, {})[
                        safe_tf_name(extra_name)
                    ] = _replace_sentinels(extra_attrs)

            tf_type, logical = logical_names[
                (r.service, r.resource_type, r.resource_id)
            ]
            supported.setdefault(tf_type, {})[logical] = attrs

        # 3) Write files.
        main_tf = serializer.serialize(supported)
        (output_dir / "main.tf").write_text(main_tf, encoding="utf-8")
        (output_dir / "providers.tf").write_text(
            build_providers_tf(self._target_account, self._target_region),
            encoding="utf-8",
        )
        (output_dir / "variables.tf").write_text(
            build_variables_tf(secret_slots), encoding="utf-8"
        )
        (output_dir / "terraform.tfvars.example").write_text(
            build_tfvars_example(
                self._target_account, self._target_region, secret_slots
            ),
            encoding="utf-8",
        )
        deploy_path = output_dir / "deploy.sh"
        deploy_path.write_text(build_deploy_script(), encoding="utf-8")
        deploy_path.chmod(0o755)

        for rel_path, payload in sidecars.items():
            dest = output_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)

        return unsupported


# Well-known reasons for resources the exporter deliberately refuses to
# translate. Keyed by ``(service, resource_type)`` so each entry can be
# matched at the same precision the spec tables use.
_UNSUPPORTED_REASONS: dict[tuple[str, str], str] = {
    ("ec2", "instance"): (
        "LocalEmu EC2 is Docker-container-backed; instance state has no "
        "deterministic real-AWS launch-template mapping."
    ),
}


def _unsupported_reason(service: str, resource_type: str) -> str:
    """Return the MANIFEST reason string for ``(service, resource_type)``."""
    return _UNSUPPORTED_REASONS.get(
        (service, resource_type), "no Terraform spec registered"
    )


def _replace_sentinels(value: Any) -> Any:
    """Recursively swap :class:`_Sentinel` (secret refs) → :class:`HclRaw`."""
    if isinstance(value, _Sentinel):
        return HclRaw(f"var.{value.variable_name}")
    if isinstance(value, dict):
        return {k: _replace_sentinels(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_sentinels(v) for v in value]
    if dataclasses.is_dataclass(value) and type(value).__name__ == "JsonEncoded":
        # Recurse inside a JsonEncoded wrapper so secrets nested in IAM
        # policy documents end up as ``${var.X}`` interpolations inside
        # the jsonencode call's argument.
        return type(value)(_replace_sentinels(value.value))
    return value
