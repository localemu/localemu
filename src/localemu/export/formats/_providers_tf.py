"""Generate ``providers.tf`` content for the Terraform writer.

Two targets are supported:

* ``localemu`` — provider blocks point at ``http://localhost:4566`` for
  every service, use hardcoded test credentials, skip AWS-side
  validation (``skip_credentials_validation``, ``s3_use_path_style``,
  ...). This is what users get by default — the whole point of the
  export is to reproduce their LocalEmu sandbox with ``terraform apply``
  against the same LocalEmu instance.

* ``aws`` — a minimal provider block with no credentials; users supply
  them via the usual AWS credential chain (env vars, shared config,
  instance role). This target is intended for graduating a sandbox into
  a real AWS account.

Multi-region snapshots are supported by emitting one ``provider "aws"``
block per region, each with ``alias = "r_<region_with_underscores>"``.
The writer tags each resource with the matching ``provider = aws.<alias>``
line so Terraform routes the API calls to the right provider instance.
"""

from __future__ import annotations

# Services for which the AWS provider accepts a custom endpoint. We list
# the 15 v1 services plus a few common extras (sts, ec2) that LocalEmu
# uses even when not explicitly exported.
_LOCALEMU_ENDPOINT_SERVICES: tuple[str, ...] = (
    "apigateway",
    "cloudwatch",
    "dynamodb",
    "ec2",
    "events",
    "firehose",
    "iam",
    "kinesis",
    "kms",
    "lambda",
    "logs",
    "s3",
    "secretsmanager",
    "ses",
    "sns",
    "sqs",
    "ssm",
    "stepfunctions",
    "sts",
)

_LOCALEMU_ENDPOINT = "http://localhost:4566"


def _alias_for(region: str) -> str:
    """Return the Terraform provider alias for ``region``.

    ``eu-west-1`` → ``r_eu_west_1``. The ``r_`` prefix avoids collisions
    with HCL reserved words and makes the alias unambiguously a region.
    """
    return "r_" + region.replace("-", "_")


def build_providers_block(regions: list[str], target: str = "localemu") -> str:
    """Build the full ``providers.tf`` content for ``regions``.

    Args:
        regions: Deduplicated list of AWS regions referenced by the
            snapshot. The first region is emitted as the *default*
            provider (no ``alias``); the rest get aliased blocks.
        target: Either ``"localemu"`` (default) or ``"aws"``.

    Returns:
        HCL text with trailing newline.
    """
    if not regions:
        regions = ["us-east-1"]
    if target not in ("localemu", "aws"):
        raise ValueError(f"unknown target: {target!r}")

    sections: list[str] = [_required_providers_block()]

    default_region = regions[0]
    sections.append(_provider_block(default_region, alias=None, target=target))

    for region in regions[1:]:
        sections.append(_provider_block(region, alias=_alias_for(region), target=target))

    return "\n\n".join(sections) + "\n"


def _required_providers_block() -> str:
    """Emit the ``terraform { required_providers { ... } }`` block."""
    return (
        "terraform {\n"
        '  required_version = ">= 1.5"\n'
        "  required_providers {\n"
        "    aws = {\n"
        '      source  = "hashicorp/aws"\n'
        '      version = "~> 5.0"\n'
        "    }\n"
        "  }\n"
        "}"
    )


def _provider_block(region: str, alias: str | None, target: str) -> str:
    """Emit a single ``provider "aws" { ... }`` block."""
    lines: list[str] = ['provider "aws" {']
    if alias:
        lines.append(f'  alias  = "{alias}"')
    lines.append(f'  region = "{region}"')

    if target == "localemu":
        lines.extend(
            [
                '  access_key                  = "test"',
                '  secret_key                  = "test"',
                "  skip_credentials_validation = true",
                "  skip_metadata_api_check     = true",
                "  skip_requesting_account_id  = true",
                "  s3_use_path_style           = true",
                "",
                "  endpoints {",
            ]
        )
        for svc in _LOCALEMU_ENDPOINT_SERVICES:
            lines.append(f'    {svc} = "{_LOCALEMU_ENDPOINT}"')
        lines.append("  }")
    else:
        # target == "aws": credentials via the standard AWS chain.
        lines.append("  # Credentials resolved via environment / shared config / instance role.")

    lines.append("}")
    return "\n".join(lines)


def provider_alias_for_region(region: str, default_region: str) -> str | None:
    """Return the ``provider = aws.<alias>`` value for a resource.

    Resources in the default region do not need a provider attribute
    (they pick up the unaliased provider). Resources in any other
    region get ``aws.r_<region_with_underscores>``.
    """
    if region == default_region:
        return None
    return f"aws.{_alias_for(region)}"
