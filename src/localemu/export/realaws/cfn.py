"""CloudFormation real-AWS writer.

Wraps :class:`localemu.export.formats.cloudformation.CfnWriter` to emit a
template that meets the real-AWS deploy requirement:

* ``Parameters`` section with one ``String / NoEcho`` entry per secret
  slot, plus mandatory ``AwsAccountId`` and ``AwsRegion`` parameters.
* A ``Conditions`` block + ``Rules`` section asserting the stack is
  deployed to the expected account / region — so a misconfigured CLI
  invocation cannot accidentally deploy to the wrong place.
* Secret ``_Sentinel`` values are replaced with ``{"Ref": "<param>"}``
  CFN intrinsics before the underlying writer renders YAML.

Lambda code is handled in the snapshot-mutation phase upstream
(:mod:`localemu.export.realaws.lambda_code`), which converts inline code
bytes into ``s3.bucket`` + ``s3.object`` IR resources. The CFN spec
table already maps those to ``AWS::S3::Bucket`` and we add an
``AWS::S3::Object`` mapping below since CFN doesn't natively support S3
object uploads — instead we emit an ``AWS::CloudFormation::CustomResource``
backed by a Lambda-less inline approach: in practice we emit
``AWS::S3::Bucket`` for the deployment bucket and recommend pre-uploading
zips via ``aws s3 cp`` from ``deploy.sh`` so the template stays standard.

(CFN does not have a native ``AWS::S3::Object`` resource. Production
CFN deployments universally either pre-upload zips and pass S3
references in, or use SAM. We follow the pre-upload path: ``deploy.sh``
runs ``aws s3 cp`` for every staged zip before ``aws cloudformation
deploy``, and the template references the resulting object keys.)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from localemu.export.formats.cfn_specs import get_spec
from localemu.export.formats.cloudformation import CfnWriter
from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.secrets import SecretSlot, _Sentinel


def _cfn_param_name(tf_name: str) -> str:
    """Convert a Terraform-style snake_case variable name into a CFN-legal,
    PascalCase, alphanumeric Parameter name.

    CloudFormation rejects parameter names containing underscores, hyphens or
    any non-alphanumeric character at template-validate time, so the same
    :class:`SecretSlot.variable_name` we hand to Terraform must be transformed
    before it shows up in a CFN template.
    """
    parts = [p for p in tf_name.split("_") if p]
    if not parts:
        return "Secret"
    pascal = "".join(p[:1].upper() + p[1:] for p in parts)
    # Strip anything CFN won't accept (defensive — split on _ should leave only
    # alnum, but tf_name may contain digits at boundaries the user would not
    # expect from a "parameter name").
    cleaned = "".join(c for c in pascal if c.isalnum())
    if not cleaned:
        cleaned = "Secret"
    if not cleaned[0].isalpha():
        cleaned = "P" + cleaned
    return cleaned


def _wire_lambda_code_to_deployment_bucket(
    document: dict[str, Any], deployment_bucket_name: str | None
) -> None:
    """Replace ``S3Bucket: REPLACE_ME_BUCKET`` placeholders with the real bucket name.

    The CFN Lambda builder emits ``REPLACE_ME_BUCKET`` because at write-time
    the spec does not know the deployment bucket name. The deploy.sh
    creates / re-uses that bucket OUTSIDE of the CloudFormation stack
    (CFN has no native S3-object-upload mechanism), so the Lambda
    resource references the bucket by its literal name string — there
    is no in-template ``!Ref`` to make, and a DependsOn would point at
    a non-existent logical id.
    """
    if deployment_bucket_name is None:
        return
    resources = document.get("Resources")
    if not isinstance(resources, dict):
        return
    for body in resources.values():
        if not isinstance(body, dict) or body.get("Type") != "AWS::Lambda::Function":
            continue
        props = body.setdefault("Properties", {})
        code = props.get("Code")
        if not isinstance(code, dict):
            continue
        if code.get("S3Bucket") != "REPLACE_ME_BUCKET":
            continue
        code["S3Bucket"] = deployment_bucket_name
        body.pop("Metadata", None)


def _replace_sentinels_for_cfn(value: Any) -> Any:
    """Swap :class:`_Sentinel` values for CFN ``{"Ref": "<param>"}`` dicts."""
    if isinstance(value, _Sentinel):
        return {"Ref": _cfn_param_name(value.variable_name)}
    if isinstance(value, dict):
        return {k: _replace_sentinels_for_cfn(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_sentinels_for_cfn(v) for v in value]
    return value


def _filter_snapshot_for_cfn(snapshot: Snapshot) -> tuple[Snapshot, list[Resource]]:
    """Strip s3.object **and** the synthetic Lambda deployment bucket.

    CloudFormation has no built-in mechanism for uploading object bodies
    to S3 (Terraform has ``aws_s3_object``), so the export's
    ``deploy.sh`` is responsible for both creating the deployment bucket
    and copying every Lambda zip into it BEFORE ``create-stack`` runs.
    That means the CFN template must not also declare those resources —
    if it did, the stack would fail with ``BucketAlreadyExists`` on the
    second run, and our PoC hit exactly that on the first run because
    deploy.sh creates the bucket from outside CFN's view.

    Returns ``(filtered_snapshot, stripped_objects)`` where
    ``stripped_objects`` carries the original ``s3.object`` IR items so
    the deploy script can pre-upload them.
    """
    # Find the deployment bucket: it carries a ``localemu:purpose`` tag.
    deployment_bucket_id: str | None = None
    for r in snapshot.resources:
        if (
            r.service == "s3"
            and r.resource_type == "bucket"
            and r.tags.get("localemu:purpose") == "lambda-deployment"
        ):
            deployment_bucket_id = r.resource_id
            break

    kept: list[Resource] = []
    stripped: list[Resource] = []
    for r in snapshot.resources:
        if r.service == "s3" and r.resource_type == "object":
            stripped.append(r)
            continue
        if (
            deployment_bucket_id
            and r.service == "s3"
            and r.resource_type == "bucket"
            and r.resource_id == deployment_bucket_id
        ):
            # Deployment bucket is owned by deploy.sh, NOT by CFN.
            continue
        # Apply sentinel replacement here so the underlying CfnWriter
        # never sees a sentinel object.
        kept.append(
            Resource(
                service=r.service,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                account_id=r.account_id,
                region=r.region,
                attributes=_replace_sentinels_for_cfn(r.attributes),
                tags=dict(r.tags),
                created_at=r.created_at,
            )
        )
    return (
        Snapshot(
            schema_version=snapshot.schema_version,
            exported_at=snapshot.exported_at,
            localemu_version=snapshot.localemu_version,
            resources=kept,
            redacted_secrets=list(snapshot.redacted_secrets),
            export_warnings=list(snapshot.export_warnings),
            sidecar_files=dict(snapshot.sidecar_files),
        ),
        stripped,
    )


def _build_parameters_section(secret_slots: list[SecretSlot]) -> dict[str, Any]:
    """Return the ``Parameters`` block for the template."""
    params: dict[str, Any] = {
        "AwsAccountId": {
            "Type": "String",
            "Description": "Target AWS account id (asserted at deploy time).",
            "AllowedPattern": r"^\d{12}$",
        },
        "AwsRegion": {
            "Type": "String",
            "Description": "Target AWS region (asserted at deploy time).",
        },
    }
    for slot in secret_slots:
        params[_cfn_param_name(slot.variable_name)] = {
            "Type": "String",
            "NoEcho": True,
            "Description": (
                f"Secret value for {slot.service}.{slot.resource_type} "
                f"{slot.resource_id} ({slot.attribute_path})."
            ),
        }
    return params


def _build_rules_section() -> dict[str, Any]:
    """Return ``Rules`` enforcing account / region match."""
    return {
        "AssertAccount": {
            "Assertions": [
                {
                    "Assert": {
                        "Fn::Equals": [
                            {"Ref": "AWS::AccountId"},
                            {"Ref": "AwsAccountId"},
                        ]
                    },
                    "AssertDescription": (
                        "Refusing to deploy: stack account does not match "
                        "AwsAccountId parameter."
                    ),
                }
            ]
        },
        "AssertRegion": {
            "Assertions": [
                {
                    "Assert": {
                        "Fn::Equals": [
                            {"Ref": "AWS::Region"},
                            {"Ref": "AwsRegion"},
                        ]
                    },
                    "AssertDescription": (
                        "Refusing to deploy: stack region does not match "
                        "AwsRegion parameter."
                    ),
                }
            ]
        },
    }


def _build_deploy_script(
    target_region: str,
    deployment_bucket: str | None,
    s3_objects: list[Resource],
    secret_slots: list[SecretSlot],
    sidecars: dict[str, bytes],
) -> str:
    """Build the CFN ``deploy.sh`` that pre-uploads zips, then deploys."""
    lines = [
        "#!/usr/bin/env bash",
        "# Deploy this LocalEmu CloudFormation export to real AWS.",
        "set -euo pipefail",
        'cd "$(dirname "$0")"',
        "",
        ': "${AWS_ACCOUNT_ID:?set AWS_ACCOUNT_ID before running}"',
        f': "${{AWS_REGION:={target_region}}}"',
        "",
    ]

    if deployment_bucket and s3_objects:
        lines.extend(
            [
                "# Ensure the Lambda deployment bucket exists.",
                f'if ! aws s3api head-bucket --bucket "{deployment_bucket}" '
                '--region "$AWS_REGION" 2>/dev/null; then',
                f'  aws s3 mb "s3://{deployment_bucket}" --region "$AWS_REGION"',
                "fi",
                "",
                "# Pre-upload Lambda code zips.",
            ]
        )
        for obj in s3_objects:
            source = obj.attributes.get("source")
            key = obj.attributes.get("key")
            if source and key:
                lines.append(
                    f'aws s3 cp "{source}" "s3://{deployment_bucket}/{key}" '
                    '--region "$AWS_REGION"'
                )
        lines.append("")

    # Build parameter overrides.
    overrides = ['AwsAccountId="$AWS_ACCOUNT_ID"', 'AwsRegion="$AWS_REGION"']
    for slot in secret_slots:
        cfn_name = _cfn_param_name(slot.variable_name)
        env_var = f"LOCALEMU_SECRET_{slot.variable_name.upper()}"
        overrides.append(
            f'{cfn_name}="${{{env_var}:?set {env_var} before deploying}}"'
        )

    overrides_str = " \\\n    ".join(overrides)
    lines.extend(
        [
            "aws cloudformation deploy \\",
            "  --stack-name localemu-export \\",
            "  --template-file main.yaml \\",
            "  --capabilities CAPABILITY_NAMED_IAM \\",
            '  --region "$AWS_REGION" \\',
            "  --parameter-overrides \\",
            f"    {overrides_str}",
            "",
        ]
    )
    return "\n".join(lines)


def write_cloudformation(
    snapshot: Snapshot,
    output_dir: Path,
    target_account: str,
    target_region: str,
    secret_slots: list[SecretSlot],
) -> list[tuple[str, str, str, str]]:
    """Write the CFN template, deploy script, and asset zips.

    Returns:
        ``unsupported`` list of ``(service, type, id, reason)``.
    """
    filtered, stripped_objects = _filter_snapshot_for_cfn(snapshot)

    # Render the base template.
    template_path = output_dir / "main.yaml"
    CfnWriter().write(filtered, template_path)

    # Splice in Parameters + Rules. We re-read and re-write the YAML so
    # we don't leak the writer's internal template-state representation.
    # Use the matching CFN-aware loader/dumper so short-form intrinsics
    # (!Ref, !GetAtt, !Sub, ...) round-trip cleanly — the stdlib SafeLoader
    # rejects them with ConstructorError.
    import yaml  # type: ignore

    from localemu.export.formats._cfn_intrinsics import (
        CfnSafeDumper,
        CfnSafeLoader,
    )

    # Compute the deployment bucket name early so we can both wire it
    # into Lambda Code blocks AND pass it to deploy.sh. Bucket name comes
    # from the s3.object IR records the filter just stripped out.
    from localemu.export.ir import Ref

    deployment_bucket: str | None = None
    for obj in stripped_objects:
        bucket_value = obj.attributes.get("bucket")
        if isinstance(bucket_value, Ref):
            deployment_bucket = bucket_value.resource_id
        elif isinstance(bucket_value, str):
            deployment_bucket = bucket_value
        if deployment_bucket:
            break

    text = template_path.read_text(encoding="utf-8")
    document = yaml.load(text, Loader=CfnSafeLoader) or {}
    document["Parameters"] = _build_parameters_section(secret_slots)
    document["Rules"] = _build_rules_section()
    _wire_lambda_code_to_deployment_bucket(document, deployment_bucket)
    # Re-order the top-level keys for readability: AWSTemplateFormatVersion,
    # Description, Parameters, Rules, Resources, Outputs.
    ordered: dict[str, Any] = {}
    for key in ("AWSTemplateFormatVersion", "Description", "Parameters", "Rules"):
        if key in document:
            ordered[key] = document[key]
    for key in document:
        if key not in ordered:
            ordered[key] = document[key]
    template_path.write_text(
        yaml.dump(
            ordered,
            Dumper=CfnSafeDumper,
            sort_keys=False,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )

    # Write asset sidecars.
    for rel, payload in snapshot.sidecar_files.items():
        dest = output_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)

    deploy = _build_deploy_script(
        target_region,
        deployment_bucket,
        stripped_objects,
        secret_slots,
        snapshot.sidecar_files,
    )
    deploy_path = output_dir / "deploy.sh"
    deploy_path.write_text(deploy, encoding="utf-8")
    deploy_path.chmod(0o755)

    # Build the unsupported list. Reasons are matched against a shared
    # table in the exporter module so the same "instance is Docker-backed"
    # message lands in MANIFEST.md for both Terraform and CloudFormation
    # outputs.
    from localemu.export.realaws.exporter import _unsupported_reason

    unsupported: list[tuple[str, str, str, str]] = []
    for r in snapshot.resources:
        if r.service == "s3" and r.resource_type == "object":
            continue  # handled via deploy.sh pre-upload
        if get_spec(r.service, r.resource_type) is None:
            unsupported.append(
                (
                    r.service,
                    r.resource_type,
                    r.resource_id,
                    _unsupported_reason(r.service, r.resource_type),
                )
            )
    return unsupported
