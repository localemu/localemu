"""Phase 4 — account / region rewrite.

LocalEmu uses the moto-default account ``000000000000`` and (by default)
``us-east-1``. Real AWS targets are something else entirely. This module
walks every collected resource and rewrites:

* Account ids inside ARNs and any string field that contains the literal
  LocalEmu account id.
* Regions inside ARNs (only when ``--aws-region`` differs from the
  resource's home region — we do not collapse a multi-region snapshot).
* The resource's own ``account_id`` and ``region`` IR fields, so the
  downstream writer emits the correct provider routing.

This pass runs *before* :mod:`localemu.export.references.resolve_references`
in the real-AWS pipeline so that intra-snapshot ARN matches still join
correctly after rewriting.
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from typing import Any

from localemu.export.ir import Resource, Snapshot

LOG = logging.getLogger(__name__)

# LocalEmu's default moto account id. Documented under
# ``localemu.constants.DEFAULT_AWS_ACCOUNT_ID`` but we hard-code here to
# avoid an import cycle when this module is consumed standalone.
LOCALEMU_DEFAULT_ACCOUNT = "000000000000"

# Strict ARN regex — we only rewrite strings we are sure are ARNs to
# avoid corrupting unrelated text that happens to contain an account-id
# substring.
_ARN_RE = re.compile(
    r"arn:(?P<partition>aws[\w-]*):(?P<service>[\w-]+):"
    r"(?P<region>[\w-]*):(?P<account>\d{12}|):(?P<rest>[^\"\s,]+)"
)


def _rewrite_arn(
    arn: str,
    target_account: str,
    target_region: str,
    source_region: str,
) -> str:
    """Return ``arn`` with account and region remapped to the target.

    Region is only rewritten when the ARN's region equals ``source_region``
    (the resource's home region). Cross-region ARNs (e.g. an IAM role in
    ``us-east-1`` referenced from a Lambda in ``eu-west-1``) are left as
    structurally-correct cross-region references.
    """

    def _sub(match: re.Match[str]) -> str:
        partition = match.group("partition")
        service = match.group("service")
        region = match.group("region")
        account = match.group("account")
        rest = match.group("rest")

        # S3 (and a handful of others) omit the account-id segment entirely;
        # rewriting an empty segment to a non-empty one corrupts the ARN.
        # Only rewrite when the ARN explicitly carries the LocalEmu account.
        new_account = target_account if account == LOCALEMU_DEFAULT_ACCOUNT else account
        new_region = target_region if region == source_region else region
        # Global services keep their empty region segment.

        # Some ARNs embed the account id inside the resource path rather
        # than (or in addition to) the dedicated segment — notably:
        #   arn:aws:s3:::<bucket>/AWSLogs/<account>/*     (CloudTrail policy)
        #   arn:aws:iam::<acct>:role/aws-service-role/... (path embeds acct)
        # Replace path-embedded ``/<localemu-default>/`` and
        # ``/<localemu-default>$`` segments so CloudTrail / cross-account
        # path-based bucket policies don't carry the wrong principal.
        new_rest = rest
        if LOCALEMU_DEFAULT_ACCOUNT in new_rest:
            new_rest = new_rest.replace(
                f"/{LOCALEMU_DEFAULT_ACCOUNT}/",
                f"/{target_account}/",
            )
            if new_rest.endswith(f"/{LOCALEMU_DEFAULT_ACCOUNT}"):
                new_rest = new_rest[: -len(LOCALEMU_DEFAULT_ACCOUNT)] + target_account
        return f"arn:{partition}:{service}:{new_region}:{new_account}:{new_rest}"

    return _ARN_RE.sub(_sub, arn)


_AZ_RE = re.compile(r"^([a-z]{2}-[a-z]+-\d)([a-z])$")


def _rewrite_az(value: str, target_region: str, source_region: str) -> str:
    """Rewrite an Availability Zone literal when the region changes.

    AZ strings follow ``<region><suffix>`` (``us-east-1a``). When the
    target region differs from the source, we remap the region prefix
    but preserve the suffix letter — target_region has no guarantee of
    having the same suffix set, but picking an arbitrary one is still
    a better default than leaving a wrong-region AZ in the template
    (Terraform rejects ``us-east-1a`` declared under an ``eu-west-1``
    provider at plan time). The user can edit ``main.tf`` to pick a
    specific AZ if the default-suffix guess doesn't match their needs.
    """
    m = _AZ_RE.match(value)
    if not m:
        return value
    az_region, suffix = m.group(1), m.group(2)
    if az_region != source_region or target_region == source_region:
        return value
    return f"{target_region}{suffix}"


def _walk(
    value: Any,
    target_account: str,
    target_region: str,
    source_region: str,
) -> Any:
    """Recursively rewrite ARNs / account ids / AZs inside ``value``."""
    if isinstance(value, str):
        if "arn:" in value:
            return _rewrite_arn(value, target_account, target_region, source_region)
        # Bare account-id string (e.g. ``"Principal": "000000000000"``):
        # only rewrite an *exact* match — substring rewrites would break
        # things like a 12-digit substring of a longer id.
        if value == LOCALEMU_DEFAULT_ACCOUNT:
            return target_account
        # Availability Zones: rewrite only on exact AZ-literal match.
        if _AZ_RE.match(value):
            return _rewrite_az(value, target_region, source_region)
        return value
    if isinstance(value, dict):
        return {
            k: _walk(v, target_account, target_region, source_region)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _walk(v, target_account, target_region, source_region) for v in value
        ]
    return value


def rewrite_snapshot(
    snapshot: Snapshot,
    target_account: str,
    target_region: str,
) -> Snapshot:
    """Return a new :class:`Snapshot` rewritten for the target account/region.

    The IR ``region`` is preserved as the *source* region for ARN-rewrite
    decisions, but the resource's recorded ``region`` is updated to
    ``target_region`` so providers route correctly. ``account_id`` is
    always set to ``target_account``.
    """
    new_resources: list[Resource] = []
    for r in snapshot.resources:
        new_attrs = _walk(r.attributes, target_account, target_region, r.region)
        new_resources.append(
            replace(
                r,
                attributes=new_attrs,
                tags=dict(r.tags),
                account_id=target_account,
                region=target_region,
            )
        )

    return Snapshot(
        schema_version=snapshot.schema_version,
        exported_at=snapshot.exported_at,
        localemu_version=snapshot.localemu_version,
        resources=new_resources,
        redacted_secrets=list(snapshot.redacted_secrets),
        export_warnings=list(snapshot.export_warnings),
        sidecar_files=dict(snapshot.sidecar_files),
    )
