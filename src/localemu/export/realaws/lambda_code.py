"""Phase 5 — Lambda function code packaging.

Lambda functions need their code uploaded to S3 (or inlined in
``Code.ZipFile`` for very small bundles) before they can be created on
real AWS. The legacy ``aws``-target Terraform writer assumed the user
would manually drop a sidecar zip in ``lambda/<name>.zip``; that fails
the "deploy unedited" requirement.

This module emits, for every Lambda we have code bytes for, an
``aws_s3_object`` block that uploads the zip to a deployment bucket
created by the same plan, and rewires the Lambda's ``s3_bucket`` /
``s3_key`` to point at that object. When code bytes are not available
(LocalEmu was started fresh, or the Lambda was created via a layer
without inline code) the function is added to the MANIFEST under
``unsupported`` rather than emitted with an unresolvable filename.

The deployment bucket itself is included in the snapshot as an
``aws_s3_bucket`` resource so the whole plan is self-contained: a single
``terraform apply`` creates the bucket, uploads the zips, then creates
the functions that reference them. Terraform's dependency graph derives
the ordering from the ``${aws_s3_object.X.key}`` references.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from localemu.export.ir import Resource, Snapshot

LOG = logging.getLogger(__name__)

# AWS Lambda will accept up to 4 MB of inline ``ZipFile`` for CFN and
# zero for Terraform (terraform always requires ``filename`` or
# ``s3_*``). To keep TF and CFN paths symmetric we always upload via S3
# above this threshold; below it we still upload via S3 because inline
# is brittle and harder to roll back.
_MAX_INLINE_BYTES = 0  # always go via S3


@dataclass
class LambdaCodeResult:
    """Outcome of :func:`prepare_lambda_code`."""

    snapshot: Snapshot
    sidecar_files: dict[str, bytes] = field(default_factory=dict)
    deployment_bucket_logical_id: str | None = None
    skipped: list[tuple[str, str]] = field(default_factory=list)
    """List of (function_name, reason) tuples for functions we cannot deploy."""


def _bucket_name_for(target_account: str, target_region: str) -> str:
    """Stable, deterministic deployment bucket name (≤63 chars, lowercase).

    Determinism matters: a re-export against the same account/region
    should reuse the same bucket so terraform doesn't churn. We hash the
    inputs to keep the name short and globally-unique-ish.
    """
    digest = hashlib.sha256(
        f"{target_account}/{target_region}".encode("utf-8")
    ).hexdigest()[:12]
    return f"localemu-export-deploy-{target_account}-{digest}"


def prepare_lambda_code(
    snapshot: Snapshot,
    target_account: str,
    target_region: str,
) -> LambdaCodeResult:
    """Emit S3 deployment bucket + per-function ``aws_s3_object`` resources.

    Mutates a copy of the snapshot to:

    * Add an ``s3.bucket`` resource for the deployment bucket (if any
      Lambda function with code is present).
    * Add an ``s3.object`` resource per Lambda function, keyed
      ``functions/<name>.zip``.
    * Rewrite each Lambda function's attributes so it carries
      ``s3_bucket`` / ``s3_key`` / ``s3_object_version`` rather than a
      bare ``filename`` field.
    """
    sidecars: dict[str, bytes] = dict(snapshot.sidecar_files)
    new_resources: list[Resource] = list(snapshot.resources)
    skipped: list[tuple[str, str]] = []

    lambdas = [
        r
        for r in new_resources
        if r.service == "lambda" and r.resource_type == "function"
    ]
    if not lambdas:
        return LambdaCodeResult(snapshot=snapshot)

    bucket_name = _bucket_name_for(target_account, target_region)
    bucket_resource: Resource | None = None

    out_resources: list[Resource] = []
    for r in new_resources:
        if not (r.service == "lambda" and r.resource_type == "function"):
            out_resources.append(r)
            continue

        code = (
            r.attributes.get("code_zip")
            or r.attributes.get("zip_bytes")
            or r.attributes.get("code")
        )
        if isinstance(code, dict):
            # Several collector encodings:
            #   1. ``code['ZipFile']`` — raw inlined bytes (legacy)
            #   2. ``code['sidecar_path']`` — pointer into
            #      ``snapshot.sidecar_files`` written by the Lambda
            #      collector (current default; keeps the JSON snapshot
            #      slim and lets the bytes travel as a separate zip
            #      member). Resolve the pointer to the actual bytes.
            inline = code.get("ZipFile") or code.get("zip_file")
            if isinstance(inline, (bytes, bytearray)):
                code = inline
            else:
                sidecar_path = code.get("sidecar_path")
                if sidecar_path and sidecar_path in sidecars:
                    code = sidecars[sidecar_path]

        if not isinstance(code, (bytes, bytearray)):
            skipped.append(
                (
                    r.resource_id,
                    "no code bytes available — function created without inline code",
                )
            )
            # Drop the function so we don't emit an unresolvable filename.
            continue

        # Lazily materialize the deployment bucket on first usable lambda.
        if bucket_resource is None:
            bucket_resource = Resource(
                service="s3",
                resource_type="bucket",
                resource_id=bucket_name,
                account_id=target_account,
                region=target_region,
                attributes={
                    "bucket_name": bucket_name,
                    "force_destroy": True,
                },
                tags={"localemu:purpose": "lambda-deployment"},
            )
            out_resources.append(bucket_resource)

        key = f"functions/{r.resource_id}.zip"
        sidecar_path = f"lambda/{r.resource_id}.zip"
        sidecars[sidecar_path] = bytes(code)
        etag = hashlib.md5(bytes(code)).hexdigest()  # noqa: S324 — etag, not crypto

        # The S3 object resource that uploads the zip. The Terraform
        # builder for ``s3.object`` references the sidecar by relative
        # path via ``filename``.
        out_resources.append(
            Resource(
                service="s3",
                resource_type="object",
                resource_id=f"{r.resource_id}-code",
                account_id=target_account,
                region=target_region,
                attributes={
                    "bucket": bucket_name,
                    "key": key,
                    "source": sidecar_path,
                    "etag": etag,
                },
            )
        )

        # Rewire the Lambda attributes onto S3.
        new_attrs = dict(r.attributes)
        new_attrs.pop("code_zip", None)
        new_attrs.pop("zip_bytes", None)
        new_attrs.pop("code", None)
        new_attrs["s3_bucket"] = bucket_name
        new_attrs["s3_key"] = key
        new_attrs["source_code_hash_b64"] = hashlib.sha256(bytes(code)).digest().hex()

        out_resources.append(
            Resource(
                service=r.service,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                account_id=r.account_id,
                region=r.region,
                attributes=new_attrs,
                tags=dict(r.tags),
                created_at=r.created_at,
            )
        )

    new_snapshot = Snapshot(
        schema_version=snapshot.schema_version,
        exported_at=snapshot.exported_at,
        localemu_version=snapshot.localemu_version,
        resources=out_resources,
        redacted_secrets=list(snapshot.redacted_secrets),
        export_warnings=list(snapshot.export_warnings),
        sidecar_files=sidecars,
    )

    return LambdaCodeResult(
        snapshot=new_snapshot,
        sidecar_files=sidecars,
        deployment_bucket_logical_id=bucket_name if bucket_resource else None,
        skipped=skipped,
    )
