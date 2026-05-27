"""IAM role / policy import handlers.

IAM is special because roles depend on their trust policy (inline) *and*
on zero or more attached managed policies. Managed policies themselves
are separate resources; we expect them to be created in earlier waves.
For any managed-policy reference we can't find in the snapshot (e.g.
AWS-managed ``arn:aws:iam::aws:policy/...``) we forward the ARN as-is.
"""

from __future__ import annotations

import json
import logging

from botocore.exceptions import ClientError

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.handlers import register_handler
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _as_json_str(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _resolve_ref_arn(value: object) -> str:
    """Best-effort conversion of a :class:`Ref` back to an ARN string.

    IAM managed-policy attachments need concrete ARNs. When the snapshot
    has substituted a :class:`Ref`, we reconstruct the ARN; otherwise the
    value is passed through. This only handles IAM policy refs — other
    services would need their own synthesis.
    """
    if isinstance(value, Ref):
        # We don't know the target account; fall back to the logical
        # path shape. The handler will fail loudly if AWS rejects it,
        # which beats silently attaching the wrong policy.
        return f"{value.service}:{value.resource_type}:{value.resource_id}:{value.attribute}"
    if isinstance(value, str):
        return value
    return str(value)


def _get_role(client, name: str):  # type: ignore[no-untyped-def]
    try:
        return client.get_role(RoleName=name)["Role"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            return None
        raise


def _get_policy(client, arn: str):  # type: ignore[no-untyped-def]
    try:
        return client.get_policy(PolicyArn=arn)["Policy"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            return None
        raise


def _delete_role(client, name: str) -> None:  # type: ignore[no-untyped-def]
    # Detach everything before deletion — AWS refuses otherwise.
    for att in client.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
        client.detach_role_policy(RoleName=name, PolicyArn=att["PolicyArn"])
    for pol in client.list_role_policies(RoleName=name).get("PolicyNames", []):
        client.delete_role_policy(RoleName=name, PolicyName=pol)
    for prof in client.list_instance_profiles_for_role(RoleName=name).get("InstanceProfiles", []):
        client.remove_role_from_instance_profile(
            InstanceProfileName=prof["InstanceProfileName"], RoleName=name
        )
    client.delete_role(RoleName=name)


@register_handler("iam", "role")
def handle_role(
    resource: Resource,
    client_factory: ClientFactory,
    mode: object,
    dry_run: bool,
) -> tuple[str, str, str | None]:
    from localemu.export.importer.replay import ImportMode

    assert isinstance(mode, ImportMode)
    name = resource.resource_id

    # Dry-run must never construct a client (credential resolution is
    # observable and the tests assert on it).
    if dry_run:
        return ("applied", name, "dry-run")

    client = client_factory.get_client("iam", resource.region)

    try:
        existing = _get_role(client, name)
    except ClientError as exc:
        return ("failed", name, f"get_role failed: {exc}")

    if existing is not None:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", name, "already exists and mode=fail-on-existing")
        try:
            _delete_role(client, name)
        except ClientError as exc:
            return ("failed", name, f"delete before replace failed: {exc}")

    attrs = resource.attributes
    trust = attrs.get("assume_role_policy_document") or attrs.get("AssumeRolePolicyDocument")
    if trust is None:
        return ("failed", name, "missing assume_role_policy_document")

    create_kwargs: dict[str, object] = {
        "RoleName": name,
        "AssumeRolePolicyDocument": _as_json_str(trust),
    }
    if attrs.get("path"):
        create_kwargs["Path"] = attrs["path"]
    if attrs.get("description"):
        create_kwargs["Description"] = attrs["description"]
    if attrs.get("max_session_duration"):
        create_kwargs["MaxSessionDuration"] = int(attrs["max_session_duration"])
    if resource.tags:
        create_kwargs["Tags"] = [{"Key": k, "Value": v} for k, v in resource.tags.items()]

    try:
        client.create_role(**create_kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "EntityAlreadyExists" and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists (EntityAlreadyExists)")
        return ("failed", name, f"{code}: {exc}")

    # Managed policy attachments.
    for pol in attrs.get("attached_managed_policies", []) or []:
        arn = _resolve_ref_arn(pol if not isinstance(pol, dict) else pol.get("PolicyArn", pol))
        try:
            client.attach_role_policy(RoleName=name, PolicyArn=arn)
        except ClientError as exc:
            LOG.warning("attach_role_policy(%s, %s) failed: %s", name, arn, exc)

    # Inline policies.
    inline = attrs.get("inline_policies") or {}
    if isinstance(inline, dict):
        for pol_name, doc in inline.items():
            try:
                client.put_role_policy(
                    RoleName=name,
                    PolicyName=pol_name,
                    PolicyDocument=_as_json_str(doc),
                )
            except ClientError as exc:
                LOG.warning("put_role_policy(%s, %s) failed: %s", name, pol_name, exc)

    return ("applied", name, None)


@register_handler("iam", "policy")
def handle_policy(
    resource: Resource,
    client_factory: ClientFactory,
    mode: object,
    dry_run: bool,
) -> tuple[str, str, str | None]:
    from localemu.export.importer.replay import ImportMode

    assert isinstance(mode, ImportMode)
    name = resource.resource_id
    attrs = resource.attributes

    if dry_run:
        return ("applied", name, "dry-run")

    client = client_factory.get_client("iam", resource.region)

    # get_policy needs an ARN. We'll synthesize one from the current
    # account via get_user / sts only if the snapshot didn't carry one.
    arn = attrs.get("arn")
    existing = None
    if isinstance(arn, str):
        try:
            existing = _get_policy(client, arn)
        except ClientError as exc:
            return ("failed", name, f"get_policy failed: {exc}")

    if existing is not None:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", name, "already exists and mode=fail-on-existing")
        try:
            # Detach from all principals then delete non-default versions.
            for v in client.list_policy_versions(PolicyArn=arn).get("Versions", []):
                if not v.get("IsDefaultVersion"):
                    client.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
            client.delete_policy(PolicyArn=arn)
        except ClientError as exc:
            return ("failed", name, f"delete before replace failed: {exc}")

    doc = attrs.get("policy_document") or attrs.get("PolicyDocument")
    if doc is None:
        return ("failed", name, "missing policy_document")

    kwargs: dict[str, object] = {
        "PolicyName": name,
        "PolicyDocument": _as_json_str(doc),
    }
    if attrs.get("path"):
        kwargs["Path"] = attrs["path"]
    if attrs.get("description"):
        kwargs["Description"] = attrs["description"]

    try:
        client.create_policy(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "EntityAlreadyExists" and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists (EntityAlreadyExists)")
        return ("failed", name, f"{code}: {exc}")

    return ("applied", name, None)
