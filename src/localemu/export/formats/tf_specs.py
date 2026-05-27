"""Terraform-specific resource specs and builders.

This module maps LocalEmu :class:`~localemu.export.ir.Resource` values
onto Terraform AWS-provider resource schemas. It is **deliberately
separate** from the CloudFormation specs: sharing a single spec table
between the two formats was the largest source of bugs in v1 (Terraform
output ended up with CloudFormation property names and vice-versa).

A :class:`TfSpec` entry declares:

* the Terraform ``resource_type`` (e.g. ``aws_s3_bucket``);
* an ``attribute_map`` that translates canonical LocalEmu attribute
  names to Terraform argument names for the simple 1:1 cases;
* an optional ``builder`` callable for services that need real
  translation logic (DynamoDB key schema splitting, Lambda sidecar
  references, IAM policy document JSON encoding, etc.).

Builders return a plain ``dict[str, Any]`` that the HCL serializer can
consume. They may insert :class:`HclRaw` values to force verbatim
emission of HCL function calls (``jsonencode(...)``,
``filebase64sha256(...)``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from localemu.export.formats.hcl_serializer import HclRaw
from localemu.export.ir import Ref, Resource

# Builder signature: resource + attributes already translated via the
# simple attribute_map, plus a context dict the writer uses to stash
# sidecar filenames and the like. Returns the final attribute dict.
Builder = Callable[[Resource, dict[str, Any], dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class TfSpec:
    """Terraform resource specification for one LocalEmu resource type.

    Attributes:
        resource_type: Terraform resource type (e.g. ``aws_s3_bucket``).
        attribute_map: Mapping of canonical LocalEmu attribute names to
            Terraform argument names for trivial 1:1 renames. Builders
            receive the already-renamed dict.
        builder: Optional callable applying service-specific logic.
        extra_resources: Optional builder that returns *additional*
            Terraform resources that must accompany this one (e.g. the
            modern AWS provider splits S3 versioning / policy into
            separate resources). Keyed by ``(tf_type, logical_name)``.
    """

    resource_type: str
    attribute_map: dict[str, str] = field(default_factory=dict)
    builder: Builder | None = None
    extra_resources: Callable[[Resource, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]] | None = None


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------


def _apply_attribute_map(attrs: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    """Apply a canonical-to-Terraform attribute rename.

    Attributes not listed in ``mapping`` are dropped — builders can
    re-add anything they need. This keeps generated HCL free of random
    provider-side attributes that LocalEmu happens to track.
    """
    out: dict[str, Any] = {}
    for canonical, tf_name in mapping.items():
        if canonical in attrs and attrs[canonical] is not None:
            out[tf_name] = attrs[canonical]
    return out


@dataclass(frozen=True)
class JsonEncoded:
    """Sentinel asking the HCL serializer to emit ``jsonencode(value)``.

    Using a sentinel defers rendering until the *writer's* HCL
    serializer is active, so any :class:`Ref` nested inside the
    encoded value is resolved against the real Terraform logical
    names rather than the fallback defaults.
    """

    value: Any


def _jsonencode(value: Any) -> "JsonEncoded":
    """Return a sentinel wrapping ``value`` in ``jsonencode(...)``.

    The HCL serializer (see
    :mod:`localemu.export.formats.hcl_serializer`) recognizes this
    sentinel and renders it with the active ref resolver.
    """
    return JsonEncoded(value)


# ----------------------------------------------------------------------
# Per-service builders
# ----------------------------------------------------------------------


def _build_s3_object(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Build an ``aws_s3_object`` (used by the real-AWS Lambda code path).

    The ``source`` attribute is a path *relative* to the export
    directory; we wrap it with ``filemd5(...)`` as the ETag so terraform
    re-uploads only when the bytes change. The ``source_hash`` argument
    (TF >= 5.65) is preferred over ``etag`` for non-MD5 cases but
    ``etag`` works on every supported AWS provider version.
    """
    source = resource.attributes.get("source")
    if source:
        attrs["source"] = source
        attrs["etag"] = HclRaw(f'filemd5("{source}")')
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_s3_bucket(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Build an ``aws_s3_bucket`` argument dict.

    Tags are passed through; policy / versioning / encryption are
    handled by separate Terraform resources in the modern AWS provider,
    so we do not emit them here. Those are added by
    :func:`_extra_s3_bucket`.

    The S3 bucket name is the resource's primary identifier. When the
    IR carries an explicit ``bucket_name`` / ``name`` attribute the
    attribute_map pass captures it; when the exporter has only the
    resource id (common — we collected a bucket from an ARN and never
    cross-populated ``bucket_name``), fall back to ``resource_id`` so
    the emitted ``aws_s3_bucket`` block always contains
    ``bucket = "<name>"``. An S3 bucket block without a bucket name is
    not valid Terraform.
    """
    if not attrs.get("bucket"):
        attrs["bucket"] = resource.resource_id
    # Pass through ``force_destroy`` (used by the deployment bucket the
    # real-AWS Lambda code path creates so ``terraform destroy`` succeeds
    # even if zip objects still live in the bucket).
    if resource.attributes.get("force_destroy"):
        attrs["force_destroy"] = True
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _extra_s3_bucket(
    resource: Resource, attrs: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Emit companion resources for an S3 bucket (versioning, etc.)."""
    extras: dict[tuple[str, str], dict[str, Any]] = {}
    bucket_name = attrs.get("bucket")
    if not bucket_name:
        return extras

    # The S3 collector records the bucket's versioning state under
    # ``versioning_status`` (matches the AWS Get/PutBucketVersioning
    # vocabulary). The legacy key ``versioning`` is still honoured for
    # back-compat with snapshots written by older builds.
    versioning = (
        resource.attributes.get("versioning_status")
        or resource.attributes.get("versioning")
    )
    if versioning and versioning != "Disabled":
        status = "Enabled" if versioning is True or versioning == "Enabled" else "Suspended"
        logical = f"{resource.resource_id}_versioning"
        extras[("aws_s3_bucket_versioning", logical)] = {
            "bucket": Ref("s3", "bucket", resource.resource_id, attribute="id"),
            "versioning_configuration": [{"status": status}],
        }
    return extras


def _build_dynamodb_table(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Translate DynamoDB key schema / GSIs into Terraform blocks."""
    src = resource.attributes
    key_schema = src.get("key_schema") or []
    for entry in key_schema:
        if entry.get("key_type") == "HASH" or entry.get("KeyType") == "HASH":
            attrs["hash_key"] = entry.get("attribute_name") or entry.get("AttributeName")
        elif entry.get("key_type") == "RANGE" or entry.get("KeyType") == "RANGE":
            attrs["range_key"] = entry.get("attribute_name") or entry.get("AttributeName")

    attr_defs = src.get("attribute_definitions") or []
    if attr_defs:
        attrs["attribute"] = [
            {
                "name": a.get("attribute_name") or a.get("AttributeName"),
                "type": a.get("attribute_type") or a.get("AttributeType"),
            }
            for a in attr_defs
        ]

    gsis = src.get("global_secondary_indexes") or []
    if gsis:
        blocks: list[dict[str, Any]] = []
        for gsi in gsis:
            block: dict[str, Any] = {"name": gsi.get("index_name") or gsi.get("IndexName")}
            gsi_keys = gsi.get("key_schema") or gsi.get("KeySchema") or []
            for k in gsi_keys:
                if k.get("key_type") == "HASH" or k.get("KeyType") == "HASH":
                    block["hash_key"] = k.get("attribute_name") or k.get("AttributeName")
                elif k.get("key_type") == "RANGE" or k.get("KeyType") == "RANGE":
                    block["range_key"] = k.get("attribute_name") or k.get("AttributeName")
            proj = gsi.get("projection") or gsi.get("Projection") or {}
            block["projection_type"] = proj.get("projection_type") or proj.get("ProjectionType") or "ALL"
            blocks.append(block)
        attrs["global_secondary_index"] = blocks

    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_lambda_function(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Wire a Lambda function to its sidecar zip.

    ``ctx['sidecar_zip']`` (set by the writer) holds the relative path
    of the code bundle inside the export directory. We emit both
    ``filename`` and ``source_code_hash`` so Terraform detects code
    changes.
    """
    sidecar = ctx.get("sidecar_zip")
    if sidecar:
        attrs["filename"] = sidecar
        attrs["source_code_hash"] = HclRaw(f'filebase64sha256("{sidecar}")')

    env = resource.attributes.get("environment") or {}
    env_vars = env.get("variables") if isinstance(env, dict) else None
    if env_vars:
        attrs["environment"] = [{"variables": dict(env_vars)}]

    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_iam_role(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Emit an IAM role with ``jsonencode``'d assume-role policy."""
    policy = resource.attributes.get("assume_role_policy_document") or resource.attributes.get(
        "assume_role_policy"
    )
    if policy is not None:
        attrs["assume_role_policy"] = _jsonencode(policy)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _extra_iam_role(
    resource: Resource, attrs: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Emit ``aws_iam_role_policy_attachment`` and ``aws_iam_role_policy``
    companion resources for every managed-policy attachment and inline
    policy stored on the role.

    Without these companion resources the exported role has the right
    trust policy but ZERO permissions, which makes Lambda execution and
    every other downstream invocation fail at runtime even though
    ``terraform apply`` succeeded.
    """
    extras: dict[tuple[str, str], dict[str, Any]] = {}
    role_name = attrs.get("name") or resource.resource_id

    managed = resource.attributes.get("attached_managed_policies") or []
    for idx, ref_or_arn in enumerate(managed):
        # Use a stable suffix derived from the policy ARN tail when
        # present so re-exports don't churn the resource address.
        if isinstance(ref_or_arn, str):
            tail = ref_or_arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        else:
            # IR ``Ref`` objects serialize through HCL writer.
            tail = getattr(ref_or_arn, "resource_id", None) or f"attach{idx}"
        logical = f"{role_name}_attach_{tail}"
        extras[("aws_iam_role_policy_attachment", logical)] = {
            "role": Ref("iam", "role", resource.resource_id, attribute="name"),
            "policy_arn": ref_or_arn,
        }

    inline = resource.attributes.get("inline_policies") or {}
    if isinstance(inline, dict):
        for pname, pdoc in inline.items():
            logical = f"{role_name}_inline_{pname}"
            extras[("aws_iam_role_policy", logical)] = {
                "name": pname,
                "role": Ref("iam", "role", resource.resource_id, attribute="name"),
                "policy": _jsonencode(pdoc),
            }
    return extras


def _build_iam_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Emit a managed IAM policy document (JSON-encoded)."""
    doc = resource.attributes.get("policy_document") or resource.attributes.get("document")
    if doc is not None:
        attrs["policy"] = _jsonencode(doc)
    return attrs


def _build_iam_user(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iam_user``: copy tags through; force_destroy stays opt-in."""
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _extra_iam_user(
    resource: Resource, attrs: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Emit ``aws_iam_user_policy_attachment`` for managed policies and
    ``aws_iam_user_policy`` for inline policies. Each is a separate
    Terraform resource so the dependency graph is correct (the user
    must exist before policies are attached)."""
    extras: dict[tuple[str, str], dict[str, Any]] = {}
    user_name = attrs.get("name") or resource.resource_id

    for idx, ref_or_arn in enumerate(
        resource.attributes.get("attached_managed_policies") or []
    ):
        if isinstance(ref_or_arn, str):
            tail = ref_or_arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        else:
            tail = getattr(ref_or_arn, "resource_id", None) or f"attach{idx}"
        logical = f"{user_name}_attach_{tail}"
        extras[("aws_iam_user_policy_attachment", logical)] = {
            "user": Ref("iam", "user", resource.resource_id, attribute="name"),
            "policy_arn": ref_or_arn,
        }

    inline = resource.attributes.get("inline_policies") or {}
    if isinstance(inline, dict):
        for pname, pdoc in inline.items():
            logical = f"{user_name}_inline_{pname}"
            extras[("aws_iam_user_policy", logical)] = {
                "name": pname,
                "user": Ref("iam", "user", resource.resource_id, attribute="name"),
                "policy": _jsonencode(pdoc),
            }

    # ``user.groups`` lists the group names this user belongs to. AWS does
    # not have a single-user multi-group resource in TF; it has one entry
    # per (user, group). We emit ``aws_iam_user_group_membership``,
    # singular: one resource per user listing all groups. Entries may
    # already be ``Ref`` objects when the upstream resolver pre-wrapped
    # them — pass those through unchanged instead of wrapping again.
    raw_groups = resource.attributes.get("groups") or []
    group_refs: list[Ref] = []
    for g in raw_groups:
        if isinstance(g, Ref):
            # Force the attribute we want — pre-wrapped Refs default to
            # ``arn`` but membership requires the group NAME.
            group_refs.append(
                Ref(g.service, g.resource_type, g.resource_id, attribute="name")
            )
        elif g:
            group_refs.append(Ref("iam", "group", g, attribute="name"))
    if group_refs:
        extras[("aws_iam_user_group_membership", f"{user_name}_groups")] = {
            "user": Ref("iam", "user", resource.resource_id, attribute="name"),
            "groups": group_refs,
        }
    return extras


def _build_iam_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iam_group``: name + path."""
    return attrs


def _extra_iam_group(
    resource: Resource, attrs: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Emit ``aws_iam_group_policy_attachment`` and
    ``aws_iam_group_policy`` for managed and inline policies."""
    extras: dict[tuple[str, str], dict[str, Any]] = {}
    group_name = attrs.get("name") or resource.resource_id

    for idx, ref_or_arn in enumerate(
        resource.attributes.get("attached_managed_policies") or []
    ):
        if isinstance(ref_or_arn, str):
            tail = ref_or_arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        else:
            tail = getattr(ref_or_arn, "resource_id", None) or f"attach{idx}"
        logical = f"{group_name}_attach_{tail}"
        extras[("aws_iam_group_policy_attachment", logical)] = {
            "group": Ref("iam", "group", resource.resource_id, attribute="name"),
            "policy_arn": ref_or_arn,
        }

    inline = resource.attributes.get("inline_policies") or {}
    if isinstance(inline, dict):
        for pname, pdoc in inline.items():
            logical = f"{group_name}_inline_{pname}"
            extras[("aws_iam_group_policy", logical)] = {
                "name": pname,
                "group": Ref("iam", "group", resource.resource_id, attribute="name"),
                "policy": _jsonencode(pdoc),
            }
    return extras


def _build_iam_instance_profile(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iam_instance_profile``: ``role`` is the role name (Ref)."""
    role = resource.attributes.get("role")
    if role is not None:
        attrs["role"] = role
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_iam_oidc_provider(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iam_openid_connect_provider``: lists must be quoted strings."""
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_iam_saml_provider(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iam_saml_provider``: name + saml_metadata_document."""
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sqs_queue(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """SQS queue: redrive policy must be a JSON-encoded string."""
    redrive = resource.attributes.get("redrive_policy")
    if redrive is not None:
        attrs["redrive_policy"] = _jsonencode(redrive)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sns_topic(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """SNS topic with optional access policy."""
    policy = resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    elif isinstance(policy, str):
        attrs["policy"] = policy
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_kms_key(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """KMS key: policy must be a JSON string."""
    policy = resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    elif isinstance(policy, str):
        attrs["policy"] = policy
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_tags_only(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Default builder for services needing nothing beyond the map + tags."""
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ecs_capacity_provider(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ecs_capacity_provider``: auto_scaling_group_provider required."""
    asg = resource.attributes.get("auto_scaling_group_provider")
    if isinstance(asg, (dict, list)):
        attrs["auto_scaling_group_provider"] = asg if isinstance(asg, list) else [asg]
    else:
        attrs["auto_scaling_group_provider"] = [{"auto_scaling_group_arn": "arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:placeholder:autoScalingGroupName/placeholder"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_lambda_code_signing(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_lambda_code_signing_config``: allowed_publishers required."""
    pubs = resource.attributes.get("allowed_publishers")
    if isinstance(pubs, (dict, list)):
        attrs["allowed_publishers"] = pubs if isinstance(pubs, list) else [pubs]
    else:
        attrs["allowed_publishers"] = [{"signing_profile_version_arns": ["arn:aws:signer:us-east-1:000000000000:/signing-profiles/placeholder"]}]
    return attrs


def _build_sfn_alias(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sfn_alias``: routing_configuration required."""
    rc = resource.attributes.get("routing_configuration")
    if isinstance(rc, list):
        attrs["routing_configuration"] = rc
    else:
        attrs["routing_configuration"] = [{"state_machine_version_arn": "REPLACE_ME", "weight": 100}]
    return attrs


def _build_sm_rotation(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_secretsmanager_secret_rotation``: rotation_rules required."""
    rules = resource.attributes.get("rotation_rules")
    if isinstance(rules, (dict, list)):
        attrs["rotation_rules"] = rules if isinstance(rules, list) else [rules]
    else:
        attrs["rotation_rules"] = [{"automatically_after_days": 30}]
    return attrs


def _build_cloudfront_cache_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudfront_cache_policy``: parameters_in_cache_key required."""
    params = resource.attributes.get("parameters_in_cache_key_and_forwarded_to_origin")
    if isinstance(params, (dict, list)):
        attrs["parameters_in_cache_key_and_forwarded_to_origin"] = params if isinstance(params, list) else [params]
    else:
        attrs["parameters_in_cache_key_and_forwarded_to_origin"] = [{
            "cookies_config": [{"cookie_behavior": "none"}],
            "headers_config": [{"header_behavior": "none"}],
            "query_strings_config": [{"query_string_behavior": "none"}],
        }]
    return attrs


def _build_events_connection(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudwatch_event_connection``: auth_parameters required.

    The TF schema enforces *nested blocks* for ``auth_parameters`` and for
    each ``api_key`` / ``basic`` / ``oauth`` sub-block. The HCL serializer
    treats a list-of-dicts as a block list and a bare dict as a map
    attribute — the two render differently and only the former is valid
    here. We always emit each sub-block as ``[{...}]``.
    """
    auth_type = attrs.get("authorization_type") or "API_KEY"
    auth_params = resource.attributes.get("auth_parameters")
    if isinstance(auth_params, dict):
        normalized: dict[str, Any] = {}
        for sub_key in ("api_key", "basic", "oauth"):
            sub = auth_params.get(sub_key)
            if isinstance(sub, dict):
                # Inner block needs the same list-wrap. For oauth the
                # nested ``client_parameters`` is also a block.
                if sub_key == "oauth":
                    client = sub.get("client_parameters")
                    if isinstance(client, dict):
                        sub = {**sub, "client_parameters": [client]}
                normalized[sub_key] = [sub]
        inv = auth_params.get("invocation_http_parameters")
        if isinstance(inv, dict):
            normalized["invocation_http_parameters"] = [inv]
        attrs["auth_parameters"] = [normalized] if normalized else [auth_params]
    else:
        # Placeholder — user fills before deploy
        if auth_type == "API_KEY":
            attrs["auth_parameters"] = [{"api_key": [{"key": "x-api-key", "value": "REPLACE_ME"}]}]
        elif auth_type == "OAUTH_CLIENT_CREDENTIALS":
            attrs["auth_parameters"] = [{"oauth": [{"authorization_endpoint": "https://example.com/oauth", "http_method": "POST", "client_parameters": [{"client_id": "REPLACE_ME", "client_secret": "REPLACE_ME"}]}]}]
        else:
            attrs["auth_parameters"] = [{"basic": [{"username": "REPLACE_ME", "password": "REPLACE_ME"}]}]
    return attrs


def _build_apigwv2_domain(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_apigatewayv2_domain_name``: domain_name_configuration required."""
    cert_arn = resource.attributes.get("certificate_arn")
    attrs["domain_name_configuration"] = [{
        "certificate_arn": cert_arn or "arn:aws:acm:us-east-1:000000000000:certificate/placeholder",
        "endpoint_type": "REGIONAL",
        "security_policy": "TLS_1_2",
    }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_resource_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_resourcegroups_group``: resource_query is required."""
    query = resource.attributes.get("resource_query")
    if isinstance(query, (dict, list)):
        attrs["resource_query"] = query if isinstance(query, list) else [query]
    else:
        attrs["resource_query"] = [{"query": "{\"ResourceTypeFilters\":[\"AWS::AllSupported\"],\"TagFilters\":[]}",  "type": "TAG_FILTERS_1_0"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_lambda_layer(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_lambda_layer_version``: requires a filename or s3 source.
    Emit a placeholder filename the user must supply."""
    if "filename" not in attrs and "s3_bucket" not in attrs:
        attrs["filename"] = "layer.zip"
    return attrs


def _build_cognito_pool(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cognito_user_pool``: password_policy + lambda_config blocks."""
    pp = resource.attributes.get("password_policy")
    if isinstance(pp, dict):
        pw = pp.get("PasswordPolicy") or pp
        attrs["password_policy"] = [{
            "minimum_length": pw.get("MinimumLength", pw.get("minimum_length", 8)),
            "require_lowercase": pw.get("RequireLowercase", pw.get("require_lowercase", True)),
            "require_uppercase": pw.get("RequireUppercase", pw.get("require_uppercase", True)),
            "require_numbers": pw.get("RequireNumbers", pw.get("require_numbers", True)),
            "require_symbols": pw.get("RequireSymbols", pw.get("require_symbols", True)),
        }]
    lc = resource.attributes.get("lambda_config")
    if isinstance(lc, dict) and any(lc.values()):
        attrs["lambda_config"] = [{k: v for k, v in lc.items() if v}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_firehose(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_kinesis_firehose_delivery_stream``: minimal — TF requires
    at least a destination block. Emit extended_s3_configuration as a
    placeholder when no destination is available from the IR."""
    dest = resource.attributes.get("destination")
    if not dest:
        # Firehose requires at least one destination. Emit an
        # extended_s3_configuration placeholder the user must fill.
        attrs["destination"] = "extended_s3"
        attrs["extended_s3_configuration"] = [{
            "role_arn": "arn:aws:iam::000000000000:role/firehose-delivery-role",
            "bucket_arn": "arn:aws:s3:::firehose-delivery-bucket",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_scheduler_schedule(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_scheduler_schedule``: flexible_time_window + target blocks.

    Moto stores these as the AWS-API CamelCase shape
    (``{"Mode": "OFF"}`` / ``{"Arn": ..., "RoleArn": ..., "RetryPolicy":
    {"MaximumEventAgeInSeconds": ..., "MaximumRetryAttempts": ...}}``).
    The Terraform schema uses snake_case throughout, so we walk and
    rewrite keys before wrapping each block in a list (block syntax).
    """
    def _snake(value: Any) -> Any:
        if isinstance(value, dict):
            return {_camel_to_snake(k): _snake(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_snake(v) for v in value]
        return value

    ftw = resource.attributes.get("flexible_time_window")
    if isinstance(ftw, dict):
        attrs["flexible_time_window"] = [_snake(ftw)]
    else:
        attrs["flexible_time_window"] = [{"mode": "OFF"}]

    target = resource.attributes.get("target")
    if isinstance(target, dict):
        translated = _snake(target)
        # ``retry_policy`` must render as a nested block (list-wrap).
        rp = translated.get("retry_policy")
        if isinstance(rp, dict):
            translated["retry_policy"] = [rp]
        attrs["target"] = [translated]
    else:
        attrs["target"] = [{"arn": "REPLACE_ME", "role_arn": "REPLACE_ME"}]
    return attrs


def _build_s3_bucket_policy_tf(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_policy.policy`` is a JSON STRING, not a dict."""
    policy = attrs.get("policy") or resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    return attrs


def _build_apigateway_method(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_api_gateway_method.authorization`` is required; default to ``NONE``."""
    if not attrs.get("authorization"):
        attrs["authorization"] = "NONE"
    return attrs


def _build_sns_topic_policy_tf(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sns_topic_policy.policy`` is a JSON STRING, not a dict."""
    policy = attrs.get("policy") or resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    return attrs


def _build_sqs_queue_policy_tf(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sqs_queue_policy.policy`` is a JSON STRING, not a dict."""
    policy = attrs.get("policy") or resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    return attrs


def _camel_to_snake(name: str) -> str:
    """``MaximumEventAgeInSeconds`` → ``maximum_event_age_in_seconds``."""
    out: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and not name[i - 1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _build_ecs_task_definition(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ecs_task_definition``: container_definitions must be JSON string."""
    cds = resource.attributes.get("container_definitions")
    if isinstance(cds, list):
        attrs["container_definitions"] = _jsonencode(cds)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_route53_zone(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_route53_zone``: emit vpc block for private zones."""
    vpc_blocks = resource.attributes.get("vpc")
    if isinstance(vpc_blocks, list) and vpc_blocks:
        first = vpc_blocks[0]
        attrs["vpc"] = [
            {"vpc_id": first.get("vpc_id"), "vpc_region": first.get("vpc_region")}
        ]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_route53_record(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_route53_record``: emit alias block OR (ttl + records)."""
    alias = resource.attributes.get("alias")
    if isinstance(alias, dict):
        attrs["alias"] = [{
            "name": alias.get("name"),
            "zone_id": alias.get("zone_id"),
            "evaluate_target_health": bool(alias.get("evaluate_target_health", False)),
        }]
        attrs.pop("ttl", None)
        attrs.pop("records", None)
    return attrs


def _build_route53_health_check(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_route53_health_check``: coerce numeric fields."""
    for k in ("port", "request_interval", "failure_threshold"):
        if k in attrs and attrs[k] is not None:
            try:
                attrs[k] = int(attrs[k])
            except (TypeError, ValueError):
                pass
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_elbv2_listener(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_lb_listener``: drop ``ssl_policy`` and ``certificate_arn`` for
    non-TLS protocols — AWS rejects them on HTTP listeners."""
    proto = (attrs.get("protocol") or "").upper()
    if proto not in ("HTTPS", "TLS"):
        attrs.pop("ssl_policy", None)
        attrs.pop("certificate_arn", None)
    return attrs


def _build_stepfunctions(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Step Functions state machine: ``definition`` is a JSON string."""
    definition = resource.attributes.get("definition")
    if isinstance(definition, dict):
        attrs["definition"] = _jsonencode(definition)
    elif isinstance(definition, str):
        attrs["definition"] = definition
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_events_rule(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """EventBridge rule: event pattern must be a JSON string."""
    pattern = resource.attributes.get("event_pattern")
    if isinstance(pattern, dict):
        attrs["event_pattern"] = _jsonencode(pattern)
    elif isinstance(pattern, str):
        attrs["event_pattern"] = pattern
    # Drop ``event_bus_name`` when it points at the implicit ``default``
    # bus. The default bus exists in every region of every AWS account,
    # is NOT a Terraform-managed resource here, and any Ref we leave in
    # place would resolve to an undeclared ``aws_cloudwatch_event_bus``
    # reference at plan time.
    bus = attrs.get("event_bus_name")
    if bus is None:
        pass
    else:
        from localemu.export.ir import Ref

        bus_id = bus.resource_id if isinstance(bus, Ref) else bus
        if bus_id in (None, "", "default"):
            attrs.pop("event_bus_name", None)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _extra_events_rule(
    resource: Resource, attrs: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Emit ``aws_cloudwatch_event_target`` per declared target, plus a
    matching ``aws_lambda_permission`` whenever the target is a Lambda
    function — without that permission AWS rejects the EventBridge
    invocation, so a dangling rule appears to deploy fine but never
    fires."""
    extras: dict[tuple[str, str], dict[str, Any]] = {}
    rule_name = attrs.get("name") or resource.resource_id
    bus_name = attrs.get("event_bus_name") or "default"
    targets = resource.attributes.get("targets") or []
    if not isinstance(targets, list):
        return extras
    for idx, t in enumerate(targets):
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or t.get("Id") or f"target{idx}"
        arn = t.get("arn") or t.get("Arn")
        if arn is None:
            continue
        logical = f"{rule_name}_target_{tid}"
        target_attrs: dict[str, Any] = {
            "rule": Ref("events", "rule", rule_name, attribute="name"),
            "target_id": tid,
            "arn": arn,
        }
        if bus_name and bus_name != "default":
            target_attrs["event_bus_name"] = bus_name
        if "input" in t:
            target_attrs["input"] = t["input"]
        if "input_path" in t:
            target_attrs["input_path"] = t["input_path"]
        extras[("aws_cloudwatch_event_target", logical)] = target_attrs

        # Lambda invocation requires lambda:InvokeFunction granted to
        # events.amazonaws.com with the rule ARN as source.
        if isinstance(arn, Ref) and arn.service == "lambda":
            perm_logical = f"{rule_name}_invoke_{arn.resource_id}"
            extras[("aws_lambda_permission", perm_logical)] = {
                "statement_id": f"AllowEventBridge-{rule_name}-{tid}",
                "action": "lambda:InvokeFunction",
                "function_name": arn,
                "principal": "events.amazonaws.com",
                "source_arn": Ref(
                    service="events",
                    resource_type="rule",
                    resource_id=rule_name,
                    attribute="arn",
                ),
            }
    return extras


def _build_lb_listener_rule(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_lb_listener_rule``: each condition's ``path_pattern`` /
    ``host_header`` / ``http_header`` sub-block must be a list so the HCL
    serializer emits it as a nested block."""
    conditions = attrs.get("condition")
    if isinstance(conditions, list):
        fixed: list[dict[str, Any]] = []
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            new_cond: dict[str, Any] = {}
            for sub_key in ("path_pattern", "host_header", "http_header"):
                sub = cond.get(sub_key)
                if isinstance(sub, dict):
                    new_cond[sub_key] = [dict(sub)]
                elif isinstance(sub, list):
                    new_cond[sub_key] = list(sub)
            fixed.append(new_cond)
        attrs["condition"] = fixed
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_lb_target_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_lb_target_group``: wrap single ``health_check`` dict as a list
    so the HCL serializer emits it as a nested block (TF rejects a map)."""
    hc = resource.attributes.get("health_check")
    if isinstance(hc, dict):
        attrs["health_check"] = [dict(hc)]
    elif isinstance(hc, list):
        attrs["health_check"] = list(hc)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ec2_passthrough(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """Default EC2 builder: copy cross-resource Refs + tags straight through.

    Most EC2/VPC resources map 1:1 onto Terraform arguments, but the
    :class:`Ref` values carry through the simple attribute_map so a
    dedicated builder is only needed to attach tags and avoid emitting
    ``None`` for the handful of optional fields that the AWS provider
    rejects when null.
    """
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_cloudfront_origin_request_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudfront_origin_request_policy``: required nested blocks."""
    cookies = resource.attributes.get("cookies_config")
    headers = resource.attributes.get("headers_config")
    query_strings = resource.attributes.get("query_strings_config")
    attrs["cookies_config"] = [cookies] if isinstance(cookies, dict) else [{"cookie_behavior": "none"}]
    attrs["headers_config"] = [headers] if isinstance(headers, dict) else [{"header_behavior": "none"}]
    attrs["query_strings_config"] = [query_strings] if isinstance(query_strings, dict) else [{"query_string_behavior": "none"}]
    return attrs


def _build_cloudfront_response_headers_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudfront_response_headers_policy``: at least one config block."""
    sec = resource.attributes.get("security_headers_config")
    if isinstance(sec, dict):
        attrs["security_headers_config"] = [sec]
    else:
        attrs["security_headers_config"] = [{
            "content_type_options": [{"override": True}],
        }]
    return attrs


def _build_cloudfront_fle_config(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudfront_field_level_encryption_config``: content_type_profile_config required."""
    ct = resource.attributes.get("content_type_profile_config")
    if isinstance(ct, (dict, list)):
        attrs["content_type_profile_config"] = ct if isinstance(ct, list) else [ct]
    else:
        attrs["content_type_profile_config"] = [{
            "forward_when_content_type_is_unknown": True,
            "content_type_profiles": [{"items": [{"content_type": "application/x-www-form-urlencoded", "format": "URLEncoded"}]}],
        }]
    qap = resource.attributes.get("query_arg_profile_config")
    if isinstance(qap, (dict, list)):
        attrs["query_arg_profile_config"] = qap if isinstance(qap, list) else [qap]
    else:
        attrs["query_arg_profile_config"] = [{"forward_when_query_arg_profile_is_unknown": True}]
    return attrs


def _build_cloudfront_fle_profile(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudfront_field_level_encryption_profile``: encryption_entities required."""
    ee = resource.attributes.get("encryption_entities")
    if isinstance(ee, (dict, list)):
        attrs["encryption_entities"] = ee if isinstance(ee, list) else [ee]
    else:
        attrs["encryption_entities"] = [{
            "items": [{
                "public_key_id": "PLACEHOLDER",
                "provider_id": "PLACEHOLDER",
                "field_patterns": [{"items": ["field"]}],
            }],
        }]
    return attrs


def _build_config_aggregator(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_config_configuration_aggregator``: account_aggregation_source required."""
    src = resource.attributes.get("account_aggregation_source")
    if isinstance(src, (dict, list)):
        attrs["account_aggregation_source"] = src if isinstance(src, list) else [src]
    else:
        attrs["account_aggregation_source"] = [{"account_ids": ["000000000000"], "regions": ["us-east-1"]}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ami(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ami``: ebs_block_device required for registration."""
    ebs = resource.attributes.get("ebs_block_device")
    if isinstance(ebs, list):
        attrs["ebs_block_device"] = ebs
    else:
        attrs["ebs_block_device"] = [{"device_name": "/dev/xvda", "snapshot_id": "snap-placeholder"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_spot_fleet(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_spot_fleet_request``: launch_specification required."""
    ls = resource.attributes.get("launch_specification")
    if isinstance(ls, list):
        attrs["launch_specification"] = ls
    else:
        attrs["launch_specification"] = [{"ami": "ami-12345678", "instance_type": "t3.micro"}]
    return attrs


def _build_ec2_fleet(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ec2_fleet``: launch_template_config and target_capacity_specification required."""
    ltc = resource.attributes.get("launch_template_config")
    if isinstance(ltc, list):
        attrs["launch_template_config"] = ltc
    else:
        attrs["launch_template_config"] = [{
            "launch_template_specification": [{
                "launch_template_id": "lt-placeholder",
                "version": "$Latest",
            }],
        }]
    tcs = resource.attributes.get("target_capacity_specification")
    if isinstance(tcs, (dict, list)):
        attrs["target_capacity_specification"] = tcs if isinstance(tcs, list) else [tcs]
    else:
        attrs["target_capacity_specification"] = [{"default_target_capacity_type": "on-demand", "total_target_capacity": 1}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_vpc_ipam(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_vpc_ipam``: operating_regions required."""
    regions = resource.attributes.get("operating_regions")
    if isinstance(regions, list):
        attrs["operating_regions"] = regions
    else:
        attrs["operating_regions"] = [{"region_name": "us-east-1"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ecr_scanning_config(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ecr_registry_scanning_configuration``: rule is required."""
    rules = resource.attributes.get("rule")
    if isinstance(rules, list):
        attrs["rule"] = rules
    else:
        attrs["rule"] = [{"scan_frequency": "SCAN_ON_PUSH", "repository_filter": [{"filter": "*", "filter_type": "WILDCARD"}]}]
    return attrs


def _build_ecr_replication(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ecr_replication_configuration``: replication_configuration required."""
    rc = resource.attributes.get("replication_configuration")
    if isinstance(rc, (dict, list)):
        attrs["replication_configuration"] = rc if isinstance(rc, list) else [rc]
    else:
        attrs["replication_configuration"] = [{"rule": [{"destination": [{"region": "eu-west-1", "registry_id": "000000000000"}]}]}]
    return attrs


def _build_eks_identity_provider_config(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_eks_identity_provider_config``: oidc required."""
    oidc = resource.attributes.get("oidc")
    if isinstance(oidc, (dict, list)):
        attrs["oidc"] = oidc if isinstance(oidc, list) else [oidc]
    else:
        attrs["oidc"] = [{"client_id": "sts.amazonaws.com", "identity_provider_config_name": "cov-oidc", "issuer_url": "https://token.actions.githubusercontent.com"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_opensearch_package(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_opensearch_package``: package_source required."""
    src = resource.attributes.get("package_source")
    if isinstance(src, (dict, list)):
        attrs["package_source"] = src if isinstance(src, list) else [src]
    else:
        attrs["package_source"] = [{"s3_bucket_name": "cov-bucket", "s3_key": "packages/synonyms.txt"}]
    return attrs


def _build_redshift_scheduled_action(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_redshift_scheduled_action``: target_action required."""
    ta = resource.attributes.get("target_action")
    if isinstance(ta, (dict, list)):
        attrs["target_action"] = ta if isinstance(ta, list) else [ta]
    else:
        attrs["target_action"] = [{"pause_cluster": [{"cluster_identifier": "cov-cluster"}]}]
    return attrs


def _build_s3_directory_bucket(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_directory_bucket``: location required."""
    loc = resource.attributes.get("location")
    if isinstance(loc, (dict, list)):
        attrs["location"] = loc if isinstance(loc, list) else [loc]
    else:
        attrs["location"] = [{"name": "use1-az4", "type": "AvailabilityZone"}]
    return attrs


def _build_storage_lens(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3control_storage_lens_configuration``: storage_lens_configuration required."""
    slc = resource.attributes.get("storage_lens_configuration")
    if isinstance(slc, (dict, list)):
        attrs["storage_lens_configuration"] = slc if isinstance(slc, list) else [slc]
    else:
        attrs["storage_lens_configuration"] = [{
            "enabled": True,
            "account_level": [{"bucket_level": [{}]}],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_multi_region_ap(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3control_multi_region_access_point``: details required."""
    details = resource.attributes.get("details")
    if isinstance(details, (dict, list)):
        attrs["details"] = details if isinstance(details, list) else [details]
    else:
        attrs["details"] = [{"name": "cov-mrap", "region": [{"bucket": "cov-bucket"}]}]
    return attrs


def _build_multi_region_ap_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3control_multi_region_access_point_policy``: details required."""
    details = resource.attributes.get("details")
    if isinstance(details, (dict, list)):
        attrs["details"] = details if isinstance(details, list) else [details]
    else:
        attrs["details"] = [{"name": "cov-mrap", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}]
    return attrs


def _build_object_lambda_ap(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3control_object_lambda_access_point``: configuration required."""
    cfg = resource.attributes.get("configuration")
    if isinstance(cfg, (dict, list)):
        attrs["configuration"] = cfg if isinstance(cfg, list) else [cfg]
    else:
        attrs["configuration"] = [{
            "supporting_access_point": "arn:aws:s3:us-east-1:000000000000:accesspoint/cov-ap",
            "transformation_configuration": [{"actions": ["GetObject"], "content_transformation": [{"aws_lambda": [{"function_arn": "arn:aws:lambda:us-east-1:000000000000:function:cov-fn"}]}]}],
        }]
    return attrs


def _build_ses_event_destination(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ses_event_destination``: at least one destination config block."""
    if "cloudwatch_destination" not in attrs and "kinesis_destination" not in attrs and "sns_destination" not in attrs:
        attrs["cloudwatch_destination"] = [{
            "default_value": "0",
            "dimension_name": "ses-event",
            "value_source": "messageTag",
        }]
    return attrs


def _build_sesv2_vdm(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sesv2_account_vdm_attributes``: vdm_enabled required."""
    if "vdm_enabled" not in attrs:
        attrs["vdm_enabled"] = "ENABLED"
    return attrs


def _build_ssm_mw_target(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ssm_maintenance_window_target``: targets required."""
    targets = resource.attributes.get("targets")
    if isinstance(targets, list):
        attrs["targets"] = targets
    else:
        attrs["targets"] = [{"key": "tag:Name", "values": ["coverage"]}]
    return attrs


def _build_ssm_mw_task(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ssm_maintenance_window_task``: targets required."""
    targets = resource.attributes.get("targets")
    if isinstance(targets, list):
        attrs["targets"] = targets
    else:
        attrs["targets"] = [{"key": "WindowTargetIds", "values": ["PLACEHOLDER"]}]
    return attrs


def _build_ssm_data_sync(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_ssm_resource_data_sync``: s3_destination required."""
    s3 = resource.attributes.get("s3_destination")
    if isinstance(s3, (dict, list)):
        attrs["s3_destination"] = s3 if isinstance(s3, list) else [s3]
    else:
        attrs["s3_destination"] = [{"bucket_name": "cov-sync-bucket", "region": "us-east-1"}]
    return attrs


def _build_ga_listener(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_globalaccelerator_listener``: port_range block required."""
    pr = resource.attributes.get("port_range")
    if isinstance(pr, list) and pr:
        attrs["port_range"] = pr
    else:
        attrs["port_range"] = [{"from_port": 80, "to_port": 80}]
    return attrs


def _build_ga_endpoint_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_globalaccelerator_endpoint_group``: needs at least endpoint_group_region."""
    attrs.setdefault("endpoint_group_region", "us-east-1")
    ec = resource.attributes.get("endpoint_configuration")
    if isinstance(ec, list) and ec:
        attrs["endpoint_configuration"] = ec
    return attrs


def _build_datasync_location_s3(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_datasync_location_s3``: s3_config block required."""
    s3c = resource.attributes.get("s3_config")
    if isinstance(s3c, (dict, list)):
        attrs["s3_config"] = s3c if isinstance(s3c, list) else [s3c]
    else:
        attrs["s3_config"] = [{
            "bucket_access_role_arn": "arn:aws:iam::000000000000:role/cov-datasync-role",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_datasync_location_efs(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_datasync_location_efs``: ec2_config block required."""
    ec2c = resource.attributes.get("ec2_config")
    if isinstance(ec2c, (dict, list)):
        attrs["ec2_config"] = ec2c if isinstance(ec2c, list) else [ec2c]
    else:
        attrs["ec2_config"] = [{
            "security_group_arns": ["arn:aws:ec2:us-east-1:000000000000:security-group/sg-cov"],
            "subnet_arn": "arn:aws:ec2:us-east-1:000000000000:subnet/subnet-cov",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_datasync_location_nfs(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_datasync_location_nfs``: on_prem_config block required."""
    opc = resource.attributes.get("on_prem_config")
    if isinstance(opc, (dict, list)):
        attrs["on_prem_config"] = opc if isinstance(opc, list) else [opc]
    else:
        attrs["on_prem_config"] = [{
            "agent_arns": ["arn:aws:datasync:us-east-1:000000000000:agent/agent-cov"],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_amplify_domain_association(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_amplify_domain_association``: at least one sub_domain block."""
    sd = resource.attributes.get("sub_domain")
    if isinstance(sd, list) and sd:
        attrs["sub_domain"] = sd
    else:
        attrs["sub_domain"] = [{
            "branch_name": "main",
            "prefix": "",
        }]
    return attrs


def _build_apprunner_service(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_apprunner_service``: source_configuration required."""
    sc = resource.attributes.get("source_configuration")
    if isinstance(sc, (dict, list)):
        attrs["source_configuration"] = sc if isinstance(sc, list) else [sc]
    else:
        attrs["source_configuration"] = [{
            "auto_deployments_enabled": False,
            "image_repository": [{
                "image_identifier": "public.ecr.aws/aws-containers/hello-app-runner:latest",
                "image_repository_type": "ECR_PUBLIC",
                "image_configuration": [{"port": "8080"}],
            }],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_apprunner_autoscaling(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_apprunner_auto_scaling_configuration_version``: nothing required
    beyond name, but fill sensible defaults."""
    attrs.setdefault("min_size", 1)
    attrs.setdefault("max_size", 10)
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_apprunner_vpc_connector(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_apprunner_vpc_connector``: subnets required."""
    subnets = resource.attributes.get("subnets")
    if isinstance(subnets, list) and subnets:
        attrs["subnets"] = subnets
    else:
        attrs["subnets"] = ["subnet-cov-a", "subnet-cov-b"]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_appmesh_virtual_node(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_appmesh_virtual_node``: spec block required."""
    spec = resource.attributes.get("spec")
    if isinstance(spec, (dict, list)):
        attrs["spec"] = spec if isinstance(spec, list) else [spec]
    else:
        attrs["spec"] = [{
            "listener": [{"port_mapping": [{"port": 8080, "protocol": "http"}]}],
            "service_discovery": [{"dns": [{"hostname": "cov.example.local"}]}],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_appmesh_virtual_service(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_appmesh_virtual_service``: spec block required."""
    spec = resource.attributes.get("spec")
    if isinstance(spec, (dict, list)):
        attrs["spec"] = spec if isinstance(spec, list) else [spec]
    else:
        attrs["spec"] = [{
            "provider": [{"virtual_node": [{"virtual_node_name": "cov-virtual-node"}]}],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sagemaker_endpoint_config(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sagemaker_endpoint_configuration``: production_variants required."""
    pv = resource.attributes.get("production_variants")
    if isinstance(pv, list) and pv:
        attrs["production_variants"] = pv
    else:
        attrs["production_variants"] = [{
            "variant_name": "AllTraffic",
            "model_name": "cov-sm-model",
            "initial_instance_count": 1,
            "instance_type": "ml.t2.medium",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sagemaker_model(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sagemaker_model``: at least one of primary_container/container."""
    pc = resource.attributes.get("primary_container")
    if isinstance(pc, (dict, list)):
        attrs["primary_container"] = pc if isinstance(pc, list) else [pc]
    else:
        cs = resource.attributes.get("container")
        if isinstance(cs, list) and cs:
            attrs["container"] = cs
        else:
            attrs["primary_container"] = [{
                "image": "000000000000.dkr.ecr.us-east-1.amazonaws.com/cov-sm-image:latest",
            }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sagemaker_feature_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sagemaker_feature_group``: feature_definition + online_config required."""
    fd = resource.attributes.get("feature_definition")
    if isinstance(fd, list) and fd:
        attrs["feature_definition"] = fd
    else:
        attrs["feature_definition"] = [
            {"feature_name": attrs.get("record_identifier_feature_name") or "cov_id", "feature_type": "String"},
            {"feature_name": attrs.get("event_time_feature_name") or "cov_event_time", "feature_type": "Fractional"},
        ]
    oc = resource.attributes.get("online_store_config")
    if isinstance(oc, (dict, list)):
        attrs["online_store_config"] = oc if isinstance(oc, list) else [oc]
    else:
        attrs["online_store_config"] = [{"enable_online_store": True}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_sagemaker_domain(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_sagemaker_domain``: default_user_settings required."""
    dus = resource.attributes.get("default_user_settings")
    if isinstance(dus, (dict, list)):
        attrs["default_user_settings"] = dus if isinstance(dus, list) else [dus]
    else:
        attrs["default_user_settings"] = [{
            "execution_role": "arn:aws:iam::000000000000:role/cov-sagemaker-role",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_batch_compute_environment(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_batch_compute_environment``: compute_resources block for MANAGED envs."""
    cr = resource.attributes.get("compute_resources")
    if isinstance(cr, (dict, list)):
        attrs["compute_resources"] = cr if isinstance(cr, list) else [cr]
    else:
        # Only MANAGED envs require compute_resources; UNMANAGED don't. Default
        # to a Fargate-spot-ish placeholder so the most common case works.
        if (attrs.get("type") or "MANAGED").upper() == "MANAGED":
            attrs["compute_resources"] = [{
                "type": "FARGATE",
                "max_vcpus": 16,
                "subnets": ["subnet-a", "subnet-b"],
                "security_group_ids": ["sg-batch"],
            }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_batch_job_queue(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_batch_job_queue``: compute_environment_order block required."""
    ceo = resource.attributes.get("compute_environment_order")
    if isinstance(ceo, list) and ceo:
        attrs["compute_environment_order"] = ceo
    else:
        attrs["compute_environment_order"] = [{
            "order": 1,
            "compute_environment": "arn:aws:batch:us-east-1:000000000000:compute-environment/cov-batch-ce",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_batch_scheduling_policy(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_batch_scheduling_policy``: fair_share_policy required."""
    fsp = resource.attributes.get("fair_share_policy")
    if isinstance(fsp, (dict, list)):
        attrs["fair_share_policy"] = fsp if isinstance(fsp, list) else [fsp]
    else:
        attrs["fair_share_policy"] = [{
            "compute_reservation": 1,
            "share_decay_seconds": 3600,
            "share_distribution": [{"share_identifier": "default", "weight_factor": 1.0}],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_msk_cluster(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_msk_cluster``: broker_node_group_info required."""
    bng = resource.attributes.get("broker_node_group_info")
    if isinstance(bng, (dict, list)):
        attrs["broker_node_group_info"] = bng if isinstance(bng, list) else [bng]
    else:
        attrs["broker_node_group_info"] = [{
            "client_subnets": ["subnet-a", "subnet-b"],
            "instance_type": "kafka.t3.small",
            "security_groups": ["sg-msk"],
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_msk_serverless_cluster(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_msk_serverless_cluster``: vpc_config + client_authentication required."""
    vpc = resource.attributes.get("vpc_config")
    if isinstance(vpc, list) and vpc:
        attrs["vpc_config"] = vpc
    else:
        attrs["vpc_config"] = [{
            "subnet_ids": ["subnet-a", "subnet-b"],
            "security_group_ids": ["sg-msk-serverless"],
        }]
    ca = resource.attributes.get("client_authentication")
    if isinstance(ca, (dict, list)):
        attrs["client_authentication"] = ca if isinstance(ca, list) else [ca]
    else:
        attrs["client_authentication"] = [{"sasl": [{"iam": [{"enabled": True}]}]}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_mq_broker(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_mq_broker``: at least one user block required."""
    users = resource.attributes.get("user")
    if isinstance(users, list) and users:
        attrs["user"] = users
    else:
        attrs["user"] = [{"username": "covuser", "password": "CovPassword1!"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_iot_topic_rule(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_iot_topic_rule``: sql + sql_version + enabled always required.

    At least one action block (``republish`` / ``lambda`` / ``s3`` / etc.)
    is required; if the IR carries no action, emit a ``republish`` to
    the fallback topic so the resource is valid without being a silent
    no-op.
    """
    attrs.setdefault("sql", "SELECT * FROM 'cov/topic'")
    attrs.setdefault("sql_version", "2016-03-23")
    attrs.setdefault("enabled", True)
    action_keys = ("republish", "lambda", "s3", "sns", "sqs", "dynamodb",
                   "kinesis", "firehose", "cloudwatch_alarm",
                   "cloudwatch_metric", "elasticsearch", "kafka",
                   "kinesis_video_streams", "step_functions",
                   "cloudwatch_logs", "timestream", "http")
    for k in action_keys:
        v = resource.attributes.get(k)
        if isinstance(v, (dict, list)):
            attrs[k] = v if isinstance(v, list) else [v]
    if not any(k in attrs for k in action_keys):
        attrs["republish"] = [{
            "role_arn": "arn:aws:iam::000000000000:role/cov-iot-republish-role",
            "topic": "cov/republish",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_codebuild_project(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_codebuild_project``: source + artifacts + environment required."""
    src = resource.attributes.get("source")
    if isinstance(src, (dict, list)):
        attrs["source"] = src if isinstance(src, list) else [src]
    else:
        attrs["source"] = [{"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello"}]
    art = resource.attributes.get("artifacts")
    if isinstance(art, (dict, list)):
        attrs["artifacts"] = art if isinstance(art, list) else [art]
    else:
        attrs["artifacts"] = [{"type": "NO_ARTIFACTS"}]
    env = resource.attributes.get("environment")
    if isinstance(env, (dict, list)):
        attrs["environment"] = env if isinstance(env, list) else [env]
    else:
        attrs["environment"] = [{
            "compute_type": "BUILD_GENERAL1_SMALL",
            "image": "aws/codebuild/standard:7.0",
            "type": "LINUX_CONTAINER",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_codebuild_report_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_codebuild_report_group``: export_config required."""
    ec = resource.attributes.get("export_config")
    if isinstance(ec, (dict, list)):
        attrs["export_config"] = ec if isinstance(ec, list) else [ec]
    else:
        attrs["export_config"] = [{"type": "NO_EXPORT"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_codepipeline(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_codepipeline``: artifact_store + at least 2 stage blocks required."""
    store = resource.attributes.get("artifact_store")
    if isinstance(store, (dict, list)):
        attrs["artifact_store"] = store if isinstance(store, list) else [store]
    else:
        attrs["artifact_store"] = [{"location": "cov-pipeline-artifacts", "type": "S3"}]
    stages = resource.attributes.get("stage")
    if isinstance(stages, list) and len(stages) >= 2:
        attrs["stage"] = stages
    else:
        attrs["stage"] = [
            {"name": "Source", "action": [{
                "name": "Source",
                "category": "Source",
                "owner": "AWS",
                "provider": "S3",
                "version": "1",
                "output_artifacts": ["source_output"],
                "configuration": {"S3Bucket": "cov-pipeline-src", "S3ObjectKey": "src.zip"},
            }]},
            {"name": "Deploy", "action": [{
                "name": "Deploy",
                "category": "Deploy",
                "owner": "AWS",
                "provider": "S3",
                "version": "1",
                "input_artifacts": ["source_output"],
                "configuration": {"BucketName": "cov-pipeline-deploy", "Extract": "true"},
            }]},
        ]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_codedeploy_deployment_config(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_codedeploy_deployment_config``: at least one of
    ``minimum_healthy_hosts`` / ``traffic_routing_config`` / ``zonal_config``."""
    for k in ("minimum_healthy_hosts", "traffic_routing_config", "zonal_config"):
        v = resource.attributes.get(k)
        if isinstance(v, (dict, list)):
            attrs[k] = v if isinstance(v, list) else [v]
    if not any(k in attrs for k in ("minimum_healthy_hosts",
                                     "traffic_routing_config", "zonal_config")):
        attrs["minimum_healthy_hosts"] = [{"type": "HOST_COUNT", "value": 1}]
    return attrs


def _build_glue_job(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_glue_job``: command block required."""
    cmd = resource.attributes.get("command")
    if isinstance(cmd, (dict, list)):
        attrs["command"] = cmd if isinstance(cmd, list) else [cmd]
    else:
        attrs["command"] = [{
            "name": "glueetl",
            "script_location": "s3://cov-bucket/scripts/cov-job.py",
            "python_version": "3",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_glue_crawler(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_glue_crawler``: at least one target block required."""
    for key in ("s3_target", "jdbc_target", "dynamodb_target",
                "catalog_target", "mongodb_target", "delta_target"):
        val = resource.attributes.get(key)
        if isinstance(val, list):
            attrs[key] = val
    if not any(k in attrs for k in ("s3_target", "jdbc_target", "dynamodb_target",
                                     "catalog_target", "mongodb_target", "delta_target")):
        attrs["s3_target"] = [{"path": "s3://cov-bucket/crawl-root/"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_glue_trigger(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_glue_trigger``: at least one actions block required."""
    actions = resource.attributes.get("actions")
    if isinstance(actions, list) and actions:
        attrs["actions"] = actions
    else:
        attrs["actions"] = [{"job_name": "cov-job"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_wafv2_web_acl(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_wafv2_web_acl``: default_action + visibility_config required."""
    da = resource.attributes.get("default_action")
    if isinstance(da, (dict, list)):
        attrs["default_action"] = da if isinstance(da, list) else [da]
    else:
        attrs["default_action"] = [{"allow": [{}]}]
    vc = resource.attributes.get("visibility_config")
    if isinstance(vc, (dict, list)):
        attrs["visibility_config"] = vc if isinstance(vc, list) else [vc]
    else:
        attrs["visibility_config"] = [{
            "cloudwatch_metrics_enabled": True,
            "metric_name": attrs.get("name") or "cov-web-acl",
            "sampled_requests_enabled": True,
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_wafv2_rule_group(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_wafv2_rule_group``: visibility_config required."""
    vc = resource.attributes.get("visibility_config")
    if isinstance(vc, (dict, list)):
        attrs["visibility_config"] = vc if isinstance(vc, list) else [vc]
    else:
        attrs["visibility_config"] = [{
            "cloudwatch_metrics_enabled": True,
            "metric_name": attrs.get("name") or "cov-rule-group",
            "sampled_requests_enabled": True,
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_wafv2_regex_set(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_wafv2_regex_pattern_set``: at least one ``regular_expression``."""
    re_block = resource.attributes.get("regular_expression")
    if isinstance(re_block, list) and re_block:
        attrs["regular_expression"] = re_block
    else:
        attrs["regular_expression"] = [{"regex_string": ".*"}]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_wafv2_logging(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_wafv2_web_acl_logging_configuration``: log_destination_configs + redacted_fields."""
    lds = resource.attributes.get("log_destination_configs")
    if isinstance(lds, list) and lds:
        attrs["log_destination_configs"] = lds
    else:
        attrs["log_destination_configs"] = [
            "arn:aws:firehose:us-east-1:000000000000:deliverystream/aws-waf-logs-cov"
        ]
    return attrs


def _build_backup_plan(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_backup_plan``: at least one rule block required."""
    rule = resource.attributes.get("rule")
    if isinstance(rule, list) and rule:
        attrs["rule"] = rule
    else:
        attrs["rule"] = [{
            "rule_name": "cov-daily",
            "target_vault_name": "cov-vault",
            "schedule": "cron(0 12 * * ? *)",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_transcribe_language_model(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_transcribe_language_model``: input_data_config required."""
    idc = resource.attributes.get("input_data_config")
    if isinstance(idc, (dict, list)):
        attrs["input_data_config"] = idc if isinstance(idc, list) else [idc]
    else:
        attrs["input_data_config"] = [{
            "data_access_role_arn": "arn:aws:iam::000000000000:role/cov-transcribe-role",
            "s3_uri": "s3://cov-bucket/training-data/",
        }]
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_s3_replication_configuration(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_replication_configuration``: role + at least one rule.

    The provider requires a ``role`` ARN and at least one ``rule`` block
    with ``status`` and a ``destination.bucket`` ARN. Builders populate
    sane placeholders when the IR is incomplete so ``terraform validate``
    accepts the output; operators edit the role and destination before
    deploying.
    """
    role = resource.attributes.get("role")
    attrs["role"] = role or "arn:aws:iam::000000000000:role/s3-replication-role"
    rule = resource.attributes.get("rule")
    if isinstance(rule, list) and rule:
        attrs["rule"] = rule
    else:
        attrs["rule"] = [{
            "id": "cov-replication-rule",
            "status": "Enabled",
            "destination": [{
                "bucket": "arn:aws:s3:::cov-replication-destination",
                "storage_class": "STANDARD",
            }],
            "filter": [{"prefix": ""}],
            "delete_marker_replication": [{"status": "Disabled"}],
        }]
    return attrs


def _build_s3_intelligent_tiering(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_intelligent_tiering_configuration``: ``tiering`` required."""
    tiering = resource.attributes.get("tiering")
    if isinstance(tiering, list) and tiering:
        attrs["tiering"] = tiering
    else:
        attrs["tiering"] = [{"access_tier": "ARCHIVE_ACCESS", "days": 90}]
    return attrs


def _build_s3_inventory(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_inventory``: schedule + destination + included_object_versions."""
    attrs.setdefault("included_object_versions", "All")
    schedule = resource.attributes.get("schedule")
    if isinstance(schedule, (dict, list)):
        attrs["schedule"] = schedule if isinstance(schedule, list) else [schedule]
    else:
        attrs["schedule"] = [{"frequency": "Daily"}]
    destination = resource.attributes.get("destination")
    if isinstance(destination, (dict, list)):
        attrs["destination"] = destination if isinstance(destination, list) else [destination]
    else:
        attrs["destination"] = [{
            "bucket": [{
                "format": "CSV",
                "bucket_arn": "arn:aws:s3:::cov-inventory-destination",
            }],
        }]
    return attrs


def _build_s3_object_lock(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_object_lock_configuration``: only bucket required; rule optional.

    Object lock must be enabled on the bucket itself. The resource only
    configures the default retention policy if present.
    """
    rule = resource.attributes.get("rule")
    if isinstance(rule, (dict, list)):
        attrs["rule"] = rule if isinstance(rule, list) else [rule]
    return attrs


def _build_s3_accelerate(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_s3_bucket_accelerate_configuration``: status must be Enabled/Suspended."""
    attrs.setdefault("status", "Suspended")
    return attrs


def _build_events_endpoint(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cloudwatch_event_endpoint``: exactly 2 event_bus blocks + routing_config.

    AWS Global Endpoints are always a two-region pair (primary + secondary),
    so the Terraform schema enforces a minimum of 2 ``event_bus`` blocks.
    A single-bus configuration is rejected at plan time.
    """
    eb = resource.attributes.get("event_bus")
    if isinstance(eb, list) and len(eb) >= 2:
        attrs["event_bus"] = eb
    else:
        attrs["event_bus"] = [
            {"event_bus_arn": "arn:aws:events:us-east-1:000000000000:event-bus/default"},
            {"event_bus_arn": "arn:aws:events:us-west-2:000000000000:event-bus/default"},
        ]
    rc = resource.attributes.get("routing_config")
    if isinstance(rc, (dict, list)):
        attrs["routing_config"] = rc if isinstance(rc, list) else [rc]
    else:
        attrs["routing_config"] = [{"failover_config": [{"primary": [{"health_check": "arn:aws:route53:::healthcheck/placeholder"}], "secondary": [{"route": "us-west-2"}]}]}]
    return attrs


def _build_cognito_risk_configuration(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_cognito_risk_configuration``: at least one risk block required.

    The AWS provider schema enforces that exactly one (or more) of
    ``account_takeover_risk_configuration``,
    ``compromised_credentials_risk_configuration`` and
    ``risk_exception_configuration`` is set. If the collected IR carries
    any of the three we pass them through verbatim; otherwise we fall
    back to a minimal ``compromised_credentials_risk_configuration`` with
    a ``BLOCK`` event action, which is the least-surprising default for a
    placeholder that the operator will edit before deploy.
    """
    pass_through_keys = (
        "account_takeover_risk_configuration",
        "compromised_credentials_risk_configuration",
        "risk_exception_configuration",
    )
    has_block = False
    for key in pass_through_keys:
        value = resource.attributes.get(key)
        if isinstance(value, dict):
            attrs[key] = [value]
            has_block = True
        elif isinstance(value, list) and value:
            attrs[key] = value
            has_block = True
    if not has_block:
        attrs["compromised_credentials_risk_configuration"] = [
            {"actions": [{"event_action": "BLOCK"}]}
        ]
    return attrs


def _build_ec2_vpc(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_vpc``: ensure booleans are actual bools and copy tags."""
    for bool_key in ("enable_dns_support", "enable_dns_hostnames"):
        if bool_key in attrs:
            attrs[bool_key] = bool(attrs[bool_key])
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ec2_eip(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_eip``: always ``domain = "vpc"``; drop the stored allocation_id
    (that is an *output*, not an input)."""
    attrs["domain"] = "vpc"
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ec2_vpc_endpoint(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_vpc_endpoint``: policy (if present) must be a JSON string."""
    policy = resource.attributes.get("policy")
    if isinstance(policy, dict):
        attrs["policy"] = _jsonencode(policy)
    elif isinstance(policy, str):
        attrs["policy"] = policy
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


def _build_ec2_security_group_rule(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_security_group_rule``: no tags, and ``from_port``/``to_port``
    must be set (``-1`` for "all" protocols) — Terraform rejects
    ``null`` for these when the protocol is TCP/UDP/ICMP."""
    protocol = str(attrs.get("protocol") or "-1")
    if attrs.get("from_port") is None:
        attrs["from_port"] = 0 if protocol != "-1" else -1
    if attrs.get("to_port") is None:
        # 0 is a valid port; use 65535 for TCP/UDP wildcards, -1 for "all".
        attrs["to_port"] = 65535 if protocol in ("tcp", "udp") else -1
    return attrs


def _build_ec2_key_pair(
    resource: Resource, attrs: dict[str, Any], ctx: dict[str, Any]
) -> dict[str, Any]:
    """``aws_key_pair``: pass public_key through verbatim."""
    if resource.tags:
        attrs["tags"] = dict(resource.tags)
    return attrs


# ----------------------------------------------------------------------
# The spec table
# ----------------------------------------------------------------------


TF_SPECS: dict[tuple[str, str], TfSpec] = {
    # --- S3 ------------------------------------------------------------
    ("s3", "bucket"): TfSpec(
        resource_type="aws_s3_bucket",
        attribute_map={"bucket_name": "bucket", "name": "bucket"},
        builder=_build_s3_bucket,
        extra_resources=_extra_s3_bucket,
    ),
    ("s3", "object"): TfSpec(
        resource_type="aws_s3_object",
        attribute_map={
            "bucket": "bucket",
            "key": "key",
            "content_type": "content_type",
            "storage_class": "storage_class",
        },
        builder=_build_s3_object,
    ),
    # --- DynamoDB ------------------------------------------------------
    ("dynamodb", "table"): TfSpec(
        resource_type="aws_dynamodb_table",
        attribute_map={
            "table_name": "name",
            "name": "name",
            "billing_mode": "billing_mode",
            "read_capacity": "read_capacity",
            "write_capacity": "write_capacity",
        },
        builder=_build_dynamodb_table,
    ),
    # --- Lambda --------------------------------------------------------
    ("lambda", "function"): TfSpec(
        resource_type="aws_lambda_function",
        attribute_map={
            "function_name": "function_name",
            "name": "function_name",
            "handler": "handler",
            "runtime": "runtime",
            "role": "role",
            "timeout": "timeout",
            "memory_size": "memory_size",
            "description": "description",
            "architectures": "architectures",
            # When the collector observed aliases or published versions on
            # the source function, ``publish = true`` is set so apply
            # creates a numbered version every time. Without this any
            # ``aws_lambda_alias`` referencing version ``"1"`` would fail
            # at apply with "Function not found".
            "publish": "publish",
            # Real-AWS Lambda code path: the lambda_code phase rewrites
            # inline code to S3 references that we pass straight through.
            "s3_bucket": "s3_bucket",
            "s3_key": "s3_key",
            "s3_object_version": "s3_object_version",
        },
        builder=_build_lambda_function,
    ),
    # --- IAM -----------------------------------------------------------
    ("iam", "role"): TfSpec(
        resource_type="aws_iam_role",
        attribute_map={
            "role_name": "name",
            "name": "name",
            "path": "path",
            "description": "description",
            "max_session_duration": "max_session_duration",
        },
        builder=_build_iam_role,
        extra_resources=_extra_iam_role,
    ),
    ("iam", "policy"): TfSpec(
        resource_type="aws_iam_policy",
        attribute_map={
            "policy_name": "name",
            "name": "name",
            "path": "path",
            "description": "description",
        },
        builder=_build_iam_policy,
    ),
    ("iam", "user"): TfSpec(
        resource_type="aws_iam_user",
        attribute_map={
            "name": "name",
            "user_name": "name",
            "path": "path",
            "permissions_boundary": "permissions_boundary",
        },
        builder=_build_iam_user,
        extra_resources=_extra_iam_user,
    ),
    ("iam", "group"): TfSpec(
        resource_type="aws_iam_group",
        attribute_map={
            "name": "name",
            "group_name": "name",
            "path": "path",
        },
        builder=_build_iam_group,
        extra_resources=_extra_iam_group,
    ),
    ("iam", "instance_profile"): TfSpec(
        resource_type="aws_iam_instance_profile",
        attribute_map={
            "name": "name",
            "instance_profile_name": "name",
            "path": "path",
        },
        builder=_build_iam_instance_profile,
    ),
    ("iam", "oidc_provider"): TfSpec(
        resource_type="aws_iam_openid_connect_provider",
        attribute_map={
            "url": "url",
            "client_id_list": "client_id_list",
            "thumbprint_list": "thumbprint_list",
        },
        builder=_build_iam_oidc_provider,
    ),
    ("iam", "saml_provider"): TfSpec(
        resource_type="aws_iam_saml_provider",
        attribute_map={
            "name": "name",
            "saml_metadata_document": "saml_metadata_document",
        },
        builder=_build_iam_saml_provider,
    ),
    # --- SQS -----------------------------------------------------------
    ("sqs", "queue"): TfSpec(
        resource_type="aws_sqs_queue",
        attribute_map={
            "queue_name": "name",
            "name": "name",
            "delay_seconds": "delay_seconds",
            "max_message_size": "max_message_size",
            "message_retention_seconds": "message_retention_seconds",
            "visibility_timeout_seconds": "visibility_timeout_seconds",
            "fifo_queue": "fifo_queue",
        },
        builder=_build_sqs_queue,
    ),
    # --- SNS -----------------------------------------------------------
    ("sns", "topic"): TfSpec(
        resource_type="aws_sns_topic",
        attribute_map={
            "topic_name": "name",
            "name": "name",
            "display_name": "display_name",
            "fifo_topic": "fifo_topic",
        },
        builder=_build_sns_topic,
    ),
    # --- EventBridge ---------------------------------------------------
    ("events", "rule"): TfSpec(
        resource_type="aws_cloudwatch_event_rule",
        attribute_map={
            "rule_name": "name",
            "name": "name",
            "description": "description",
            "schedule_expression": "schedule_expression",
            "state": "state",
            "event_bus_name": "event_bus_name",
        },
        builder=_build_events_rule,
        extra_resources=_extra_events_rule,
    ),
    # --- CloudWatch Logs ----------------------------------------------
    ("logs", "log_group"): TfSpec(
        resource_type="aws_cloudwatch_log_group",
        attribute_map={
            "log_group_name": "name",
            "name": "name",
            "retention_in_days": "retention_in_days",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    # --- CloudWatch Metrics / Alarms ----------------------------------
    ("cloudwatch", "alarm"): TfSpec(
        resource_type="aws_cloudwatch_metric_alarm",
        attribute_map={
            "alarm_name": "alarm_name",
            "name": "alarm_name",
            "comparison_operator": "comparison_operator",
            "evaluation_periods": "evaluation_periods",
            "metric_name": "metric_name",
            "namespace": "namespace",
            "period": "period",
            "statistic": "statistic",
            "threshold": "threshold",
            # The cloudwatch collector emits ``description`` (not
            # ``alarm_description``); both names appear in moto/AWS
            # responses depending on context, so accept either.
            "description": "alarm_description",
            "alarm_description": "alarm_description",
            "actions_enabled": "actions_enabled",
            "treat_missing_data": "treat_missing_data",
        },
        builder=_build_tags_only,
    ),
    # --- Secrets Manager ----------------------------------------------
    ("secretsmanager", "secret"): TfSpec(
        resource_type="aws_secretsmanager_secret",
        attribute_map={
            "secret_name": "name",
            "name": "name",
            "description": "description",
            "kms_key_id": "kms_key_id",
            "recovery_window_in_days": "recovery_window_in_days",
        },
        builder=_build_tags_only,
    ),
    # --- SSM Parameter Store ------------------------------------------
    ("ssm", "parameter"): TfSpec(
        resource_type="aws_ssm_parameter",
        attribute_map={
            "parameter_name": "name",
            "name": "name",
            "type": "type",
            "value": "value",
            "description": "description",
            "tier": "tier",
        },
        builder=_build_tags_only,
    ),
    # --- KMS -----------------------------------------------------------
    ("kms", "key"): TfSpec(
        resource_type="aws_kms_key",
        attribute_map={
            "description": "description",
            "key_usage": "key_usage",
            "deletion_window_in_days": "deletion_window_in_days",
            "enable_key_rotation": "enable_key_rotation",
        },
        builder=_build_kms_key,
    ),
    # --- API Gateway (REST v1) ----------------------------------------
    ("apigateway", "rest_api"): TfSpec(
        resource_type="aws_api_gateway_rest_api",
        attribute_map={
            "api_name": "name",
            "name": "name",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- Step Functions -----------------------------------------------
    ("stepfunctions", "state_machine"): TfSpec(
        resource_type="aws_sfn_state_machine",
        attribute_map={
            "state_machine_name": "name",
            "name": "name",
            "role_arn": "role_arn",
            "type": "type",
        },
        builder=_build_stepfunctions,
    ),
    # --- EC2 / VPC -----------------------------------------------------
    ("ec2", "vpc"): TfSpec(
        resource_type="aws_vpc",
        attribute_map={
            "cidr_block": "cidr_block",
            "instance_tenancy": "instance_tenancy",
            "enable_dns_support": "enable_dns_support",
            "enable_dns_hostnames": "enable_dns_hostnames",
        },
        builder=_build_ec2_vpc,
    ),
    ("ec2", "subnet"): TfSpec(
        resource_type="aws_subnet",
        attribute_map={
            "vpc_id": "vpc_id",
            "cidr_block": "cidr_block",
            "availability_zone": "availability_zone",
            "map_public_ip_on_launch": "map_public_ip_on_launch",
            "assign_ipv6_address_on_creation": "assign_ipv6_address_on_creation",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "security_group"): TfSpec(
        resource_type="aws_security_group",
        attribute_map={
            "name": "name",
            "description": "description",
            "vpc_id": "vpc_id",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "security_group_rule"): TfSpec(
        resource_type="aws_security_group_rule",
        attribute_map={
            "type": "type",
            "security_group_id": "security_group_id",
            "protocol": "protocol",
            "from_port": "from_port",
            "to_port": "to_port",
            "cidr_blocks": "cidr_blocks",
            "ipv6_cidr_blocks": "ipv6_cidr_blocks",
            "source_security_group_id": "source_security_group_id",
            "description": "description",
        },
        builder=_build_ec2_security_group_rule,
    ),
    ("ec2", "internet_gateway"): TfSpec(
        resource_type="aws_internet_gateway",
        attribute_map={
            "vpc_id": "vpc_id",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "internet_gateway_attachment"): TfSpec(
        resource_type="aws_internet_gateway_attachment",
        attribute_map={
            "internet_gateway_id": "internet_gateway_id",
            "vpc_id": "vpc_id",
        },
    ),
    ("ec2", "nat_gateway"): TfSpec(
        resource_type="aws_nat_gateway",
        attribute_map={
            "subnet_id": "subnet_id",
            "allocation_id": "allocation_id",
            "connectivity_type": "connectivity_type",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "elastic_ip"): TfSpec(
        resource_type="aws_eip",
        attribute_map={},
        builder=_build_ec2_eip,
    ),
    ("ec2", "route_table"): TfSpec(
        resource_type="aws_route_table",
        attribute_map={
            "vpc_id": "vpc_id",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "route"): TfSpec(
        resource_type="aws_route",
        attribute_map={
            "route_table_id": "route_table_id",
            "destination_cidr_block": "destination_cidr_block",
            "destination_ipv6_cidr_block": "destination_ipv6_cidr_block",
            "gateway_id": "gateway_id",
            "nat_gateway_id": "nat_gateway_id",
            "vpc_peering_connection_id": "vpc_peering_connection_id",
            "vpc_endpoint_id": "vpc_endpoint_id",
            "transit_gateway_id": "transit_gateway_id",
        },
        # ``aws_route`` is untagged.
        builder=None,
    ),
    ("ec2", "route_table_association"): TfSpec(
        resource_type="aws_route_table_association",
        attribute_map={
            "route_table_id": "route_table_id",
            "subnet_id": "subnet_id",
            "gateway_id": "gateway_id",
        },
        builder=None,
    ),
    ("ec2", "vpc_endpoint"): TfSpec(
        resource_type="aws_vpc_endpoint",
        attribute_map={
            "vpc_id": "vpc_id",
            "service_name": "service_name",
            "vpc_endpoint_type": "vpc_endpoint_type",
            "route_table_ids": "route_table_ids",
            "subnet_ids": "subnet_ids",
            "security_group_ids": "security_group_ids",
            "private_dns_enabled": "private_dns_enabled",
        },
        builder=_build_ec2_vpc_endpoint,
    ),
    ("ec2", "network_acl"): TfSpec(
        resource_type="aws_network_acl",
        attribute_map={
            "vpc_id": "vpc_id",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "network_acl_rule"): TfSpec(
        resource_type="aws_network_acl_rule",
        attribute_map={
            "network_acl_id": "network_acl_id",
            "rule_number": "rule_number",
            "egress": "egress",
            "protocol": "protocol",
            "rule_action": "rule_action",
            "cidr_block": "cidr_block",
            "ipv6_cidr_block": "ipv6_cidr_block",
            "from_port": "from_port",
            "to_port": "to_port",
            "icmp_type": "icmp_type",
            "icmp_code": "icmp_code",
        },
        builder=None,
    ),
    ("ec2", "vpc_peering_connection"): TfSpec(
        resource_type="aws_vpc_peering_connection",
        attribute_map={
            "vpc_id": "vpc_id",
            "peer_vpc_id": "peer_vpc_id",
            "peer_owner_id": "peer_owner_id",
            "peer_region": "peer_region",
            "auto_accept": "auto_accept",
        },
        builder=_build_ec2_passthrough,
    ),
    ("ec2", "key_pair"): TfSpec(
        resource_type="aws_key_pair",
        attribute_map={
            "key_name": "key_name",
            "public_key": "public_key",
        },
        builder=_build_ec2_key_pair,
    ),
    # --- RDS -----------------------------------------------------------
    ("rds", "db_instance"): TfSpec(
        resource_type="aws_db_instance",
        attribute_map={
            "identifier": "identifier",
            "engine": "engine",
            "engine_version": "engine_version",
            "instance_class": "instance_class",
            "allocated_storage": "allocated_storage",
            "db_name": "db_name",
            "username": "username",
            "password": "password",
            "port": "port",
            "vpc_security_group_ids": "vpc_security_group_ids",
            "db_subnet_group_name": "db_subnet_group_name",
            "parameter_group_name": "parameter_group_name",
            "publicly_accessible": "publicly_accessible",
            "skip_final_snapshot": "skip_final_snapshot",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_cluster"): TfSpec(
        resource_type="aws_rds_cluster",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "engine": "engine",
            "engine_version": "engine_version",
            "master_username": "master_username",
            "master_password": "master_password",
            "database_name": "database_name",
            "vpc_security_group_ids": "vpc_security_group_ids",
            "db_subnet_group_name": "db_subnet_group_name",
            "db_cluster_parameter_group_name": "db_cluster_parameter_group_name",
            "skip_final_snapshot": "skip_final_snapshot",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_subnet_group"): TfSpec(
        resource_type="aws_db_subnet_group",
        attribute_map={
            "name": "name",
            "description": "description",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_parameter_group"): TfSpec(
        resource_type="aws_db_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
            "parameters": "parameter",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_cluster_parameter_group"): TfSpec(
        resource_type="aws_rds_cluster_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
            "parameters": "parameter",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_option_group"): TfSpec(
        resource_type="aws_db_option_group",
        attribute_map={
            "name": "name",
            "engine_name": "engine_name",
            "major_engine_version": "major_engine_version",
            "description": "option_group_description",
        },
        builder=_build_tags_only,
    ),
    # --- ELBv2 ---------------------------------------------------------
    ("elbv2", "load_balancer"): TfSpec(
        resource_type="aws_lb",
        attribute_map={
            "name": "name",
            "load_balancer_type": "load_balancer_type",
            "internal": "internal",
            "subnets": "subnets",
            "security_groups": "security_groups",
        },
        builder=_build_tags_only,
    ),
    ("elbv2", "target_group"): TfSpec(
        resource_type="aws_lb_target_group",
        attribute_map={
            "name": "name",
            "port": "port",
            "protocol": "protocol",
            "vpc_id": "vpc_id",
            "target_type": "target_type",
        },
        builder=_build_lb_target_group,
    ),
    ("elbv2", "listener"): TfSpec(
        resource_type="aws_lb_listener",
        attribute_map={
            "load_balancer_arn": "load_balancer_arn",
            "port": "port",
            "protocol": "protocol",
            "ssl_policy": "ssl_policy",
            "certificate_arn": "certificate_arn",
            "default_action": "default_action",
        },
        builder=_build_elbv2_listener,
    ),
    ("elbv2", "listener_rule"): TfSpec(
        resource_type="aws_lb_listener_rule",
        attribute_map={
            "listener_arn": "listener_arn",
            "priority": "priority",
            "action": "action",
            "condition": "condition",
        },
        builder=_build_lb_listener_rule,
    ),
    # --- Kinesis -------------------------------------------------------
    ("kinesis", "stream"): TfSpec(
        resource_type="aws_kinesis_stream",
        attribute_map={
            "stream_name": "name",
            "name": "name",
            "shard_count": "shard_count",
            "retention_period": "retention_period",
        },
        builder=_build_tags_only,
    ),
    # --- Route53 -----------------------------------------------------------
    ("route53", "zone"): TfSpec(
        resource_type="aws_route53_zone",
        attribute_map={
            "name": "name",
            "comment": "comment",
        },
        builder=_build_route53_zone,
    ),
    ("route53", "record"): TfSpec(
        resource_type="aws_route53_record",
        attribute_map={
            "zone_id": "zone_id",
            "name": "name",
            "type": "type",
            "ttl": "ttl",
            "records": "records",
        },
        builder=_build_route53_record,
    ),
    ("route53", "health_check"): TfSpec(
        resource_type="aws_route53_health_check",
        attribute_map={
            "type": "type",
            "fqdn": "fqdn",
            "ip_address": "ip_address",
            "port": "port",
            "resource_path": "resource_path",
            "request_interval": "request_interval",
            "failure_threshold": "failure_threshold",
        },
        builder=_build_route53_health_check,
    ),
    # --- ECR ---------------------------------------------------------------
    ("ecr", "repository"): TfSpec(
        resource_type="aws_ecr_repository",
        attribute_map={
            "name": "name",
            "image_tag_mutability": "image_tag_mutability",
        },
        builder=_build_tags_only,
    ),
    # --- ECS ---------------------------------------------------------------
    ("ecs", "cluster"): TfSpec(
        resource_type="aws_ecs_cluster",
        attribute_map={
            "name": "name",
            "setting": "setting",
        },
        builder=_build_tags_only,
    ),
    ("ecs", "task_definition"): TfSpec(
        resource_type="aws_ecs_task_definition",
        attribute_map={
            "family": "family",
            "network_mode": "network_mode",
            "requires_compatibilities": "requires_compatibilities",
            "cpu": "cpu",
            "memory": "memory",
            "task_role_arn": "task_role_arn",
            "execution_role_arn": "execution_role_arn",
            "volume": "volume",
        },
        builder=_build_ecs_task_definition,
    ),
    ("ecs", "service"): TfSpec(
        resource_type="aws_ecs_service",
        attribute_map={
            "name": "name",
            "cluster": "cluster",
            "task_definition": "task_definition",
            "desired_count": "desired_count",
            "launch_type": "launch_type",
            "network_configuration": "network_configuration",
            "load_balancer": "load_balancer",
        },
        builder=_build_tags_only,
    ),
    # --- EKS ---------------------------------------------------------------
    ("eks", "cluster"): TfSpec(
        resource_type="aws_eks_cluster",
        attribute_map={
            "name": "name",
            "version": "version",
            "role_arn": "role_arn",
            "vpc_config": "vpc_config",
        },
        builder=_build_tags_only,
    ),
    ("eks", "node_group"): TfSpec(
        resource_type="aws_eks_node_group",
        attribute_map={
            "cluster_name": "cluster_name",
            "node_group_name": "node_group_name",
            "node_role_arn": "node_role_arn",
            "subnet_ids": "subnet_ids",
            "instance_types": "instance_types",
            "scaling_config": "scaling_config",
        },
        builder=_build_tags_only,
    ),
    # --- CloudTrail --------------------------------------------------------
    ("cloudtrail", "trail"): TfSpec(
        resource_type="aws_cloudtrail",
        attribute_map={
            "name": "name",
            "s3_bucket_name": "s3_bucket_name",
            "s3_key_prefix": "s3_key_prefix",
            "include_global_service_events": "include_global_service_events",
            "is_multi_region_trail": "is_multi_region_trail",
            "enable_logging": "enable_logging",
            "enable_log_file_validation": "enable_log_file_validation",
            "sns_topic_name": "sns_topic_name",
            "cloud_watch_logs_group_arn": "cloud_watch_logs_group_arn",
            "cloud_watch_logs_role_arn": "cloud_watch_logs_role_arn",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    # --- Firehose ----------------------------------------------------------
    ("firehose", "delivery_stream"): TfSpec(
        resource_type="aws_kinesis_firehose_delivery_stream",
        attribute_map={
            "name": "name",
        },
        builder=_build_firehose,
    ),
    # --- Scheduler ---------------------------------------------------------
    ("scheduler", "schedule_group"): TfSpec(
        resource_type="aws_scheduler_schedule_group",
        attribute_map={"name": "name"},
        builder=_build_tags_only,
    ),
    ("scheduler", "schedule"): TfSpec(
        resource_type="aws_scheduler_schedule",
        attribute_map={
            "name": "name",
            "schedule_expression": "schedule_expression",
            "schedule_expression_timezone": "schedule_expression_timezone",
            "state": "state",
            "group_name": "group_name",
            "description": "description",
        },
        builder=_build_scheduler_schedule,
    ),
    # --- Lambda extensions --------------------------------------------------
    ("lambda", "permission"): TfSpec(
        resource_type="aws_lambda_permission",
        attribute_map={
            "statement_id": "statement_id",
            "action": "action",
            "function_name": "function_name",
            "principal": "principal",
            "source_arn": "source_arn",
        },
    ),
    ("lambda", "event_source_mapping"): TfSpec(
        resource_type="aws_lambda_event_source_mapping",
        attribute_map={
            "event_source_arn": "event_source_arn",
            "function_name": "function_name",
            "batch_size": "batch_size",
            "enabled": "enabled",
            "starting_position": "starting_position",
        },
    ),
    ("lambda", "layer_version"): TfSpec(
        resource_type="aws_lambda_layer_version",
        attribute_map={
            "layer_name": "layer_name",
            "compatible_runtimes": "compatible_runtimes",
            "description": "description",
        },
        builder=_build_lambda_layer,
    ),
    # --- Lambda function_url ------------------------------------------------
    ("lambda", "function_url"): TfSpec(
        resource_type="aws_lambda_function_url",
        attribute_map={
            "function_name": "function_name",
            "authorization_type": "authorization_type",
            "cors": "cors",
        },
    ),
    # --- SNS subscription ---------------------------------------------------
    ("sns", "subscription"): TfSpec(
        resource_type="aws_sns_topic_subscription",
        attribute_map={
            "topic_arn": "topic_arn",
            "protocol": "protocol",
            "endpoint": "endpoint",
            "filter_policy": "filter_policy",
            "raw_message_delivery": "raw_message_delivery",
            "confirmation_timeout_in_minutes": "confirmation_timeout_in_minutes",
        },
    ),
    # --- OpenSearch ---------------------------------------------------------
    ("opensearch", "domain"): TfSpec(
        resource_type="aws_opensearch_domain",
        attribute_map={
            "domain_name": "domain_name",
            "engine_version": "engine_version",
            "cluster_config": "cluster_config",
            "ebs_options": "ebs_options",
            "access_policies": "access_policies",
        },
        builder=_build_tags_only,
    ),
    # --- API Gateway v2 ----------------------------------------------------
    ("apigatewayv2", "api"): TfSpec(
        resource_type="aws_apigatewayv2_api",
        attribute_map={
            "name": "name",
            "protocol_type": "protocol_type",
            "description": "description",
            "route_selection_expression": "route_selection_expression",
            "cors_configuration": "cors_configuration",
        },
        builder=_build_tags_only,
    ),
    ("apigatewayv2", "stage"): TfSpec(
        resource_type="aws_apigatewayv2_stage",
        attribute_map={
            "api_id": "api_id",
            "name": "name",
            "auto_deploy": "auto_deploy",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("apigatewayv2", "route"): TfSpec(
        resource_type="aws_apigatewayv2_route",
        attribute_map={
            "api_id": "api_id",
            "route_key": "route_key",
            "target": "target",
        },
    ),
    ("apigatewayv2", "integration"): TfSpec(
        resource_type="aws_apigatewayv2_integration",
        attribute_map={
            "api_id": "api_id",
            "integration_type": "integration_type",
            "integration_uri": "integration_uri",
            "integration_method": "integration_method",
            "payload_format_version": "payload_format_version",
        },
    ),
    # --- API Gateway v2 extensions ------------------------------------------
    ("apigatewayv2", "authorizer"): TfSpec(
        resource_type="aws_apigatewayv2_authorizer",
        attribute_map={
            "api_id": "api_id",
            "name": "name",
            "authorizer_type": "authorizer_type",
            "identity_sources": "identity_sources",
            "authorizer_uri": "authorizer_uri",
        },
    ),
    ("apigatewayv2", "deployment"): TfSpec(
        resource_type="aws_apigatewayv2_deployment",
        attribute_map={
            "api_id": "api_id",
            "description": "description",
        },
    ),
    ("apigatewayv2", "domain_name"): TfSpec(
        resource_type="aws_apigatewayv2_domain_name",
        attribute_map={
            "domain_name": "domain_name",
        },
        builder=_build_apigwv2_domain,
    ),
    ("apigatewayv2", "integration_response"): TfSpec(
        resource_type="aws_apigatewayv2_integration_response",
        attribute_map={
            "api_id": "api_id",
            "integration_id": "integration_id",
            "integration_response_key": "integration_response_key",
        },
    ),
    ("apigatewayv2", "route_response"): TfSpec(
        resource_type="aws_apigatewayv2_route_response",
        attribute_map={
            "api_id": "api_id",
            "route_id": "route_id",
            "route_response_key": "route_response_key",
        },
    ),
    ("apigatewayv2", "api_mapping"): TfSpec(
        resource_type="aws_apigatewayv2_api_mapping",
        attribute_map={
            "api_id": "api_id",
            "domain_name": "domain_name",
            "stage": "stage",
        },
    ),
    ("apigatewayv2", "vpc_link"): TfSpec(
        resource_type="aws_apigatewayv2_vpc_link",
        attribute_map={
            "name": "name",
            "subnet_ids": "subnet_ids",
            "security_group_ids": "security_group_ids",
        },
        builder=_build_tags_only,
    ),
    ("apigatewayv2", "model"): TfSpec(
        resource_type="aws_apigatewayv2_model",
        attribute_map={
            "api_id": "api_id",
            "name": "name",
            "content_type": "content_type",
            "schema": "schema",
        },
    ),
    # --- Cognito extensions -------------------------------------------------
    ("cognito", "user_pool_domain"): TfSpec(
        resource_type="aws_cognito_user_pool_domain",
        attribute_map={
            "domain": "domain",
            "user_pool_id": "user_pool_id",
        },
    ),
    ("cognito", "identity_provider"): TfSpec(
        resource_type="aws_cognito_identity_provider",
        attribute_map={
            "user_pool_id": "user_pool_id",
            "provider_name": "provider_name",
            "provider_type": "provider_type",
            "provider_details": "provider_details",
            "attribute_mapping": "attribute_mapping",
        },
    ),
    ("cognito", "user_group"): TfSpec(
        resource_type="aws_cognito_user_group",
        attribute_map={
            "name": "name",
            "user_pool_id": "user_pool_id",
            "description": "description",
            "role_arn": "role_arn",
            "precedence": "precedence",
        },
    ),
    # --- SES extensions -----------------------------------------------------
    ("ses", "receipt_rule_set"): TfSpec(
        resource_type="aws_ses_receipt_rule_set",
        attribute_map={"rule_set_name": "rule_set_name"},
    ),
    # --- Cognito -----------------------------------------------------------
    ("cognito", "user_pool"): TfSpec(
        resource_type="aws_cognito_user_pool",
        attribute_map={
            "name": "name",
            "auto_verified_attributes": "auto_verified_attributes",
            "username_attributes": "username_attributes",
            "mfa_configuration": "mfa_configuration",
            "schema": "schema",
        },
        builder=_build_cognito_pool,
    ),
    ("cognito", "user_pool_client"): TfSpec(
        resource_type="aws_cognito_user_pool_client",
        attribute_map={
            "name": "name",
            "user_pool_id": "user_pool_id",
            "explicit_auth_flows": "explicit_auth_flows",
            "generate_secret": "generate_secret",
            "allowed_oauth_flows": "allowed_oauth_flows",
            "allowed_oauth_scopes": "allowed_oauth_scopes",
            "callback_urls": "callback_urls",
            "logout_urls": "logout_urls",
            "supported_identity_providers": "supported_identity_providers",
        },
    ),
    # --- SES ---------------------------------------------------------------
    ("ses", "email_identity"): TfSpec(
        resource_type="aws_sesv2_email_identity",
        attribute_map={"email_identity": "email_identity"},
        builder=_build_tags_only,
    ),
    ("ses", "template"): TfSpec(
        resource_type="aws_ses_template",
        attribute_map={
            "name": "name",
            "subject": "subject",
            "html": "html",
            "text": "text",
        },
    ),
    ("ses", "configuration_set"): TfSpec(
        resource_type="aws_ses_configuration_set",
        attribute_map={"name": "name"},
    ),
    # --- Events extensions --------------------------------------------------
    ("events", "archive"): TfSpec(
        resource_type="aws_cloudwatch_event_archive",
        attribute_map={
            "name": "name",
            "event_source_arn": "event_source_arn",
            "description": "description",
            "event_pattern": "event_pattern",
            "retention_days": "retention_days",
        },
    ),
    ("events", "connection"): TfSpec(
        resource_type="aws_cloudwatch_event_connection",
        attribute_map={
            "name": "name",
            "description": "description",
            "authorization_type": "authorization_type",
        },
        builder=_build_events_connection,
    ),
    ("events", "api_destination"): TfSpec(
        resource_type="aws_cloudwatch_event_api_destination",
        attribute_map={
            "name": "name",
            "description": "description",
            "invocation_endpoint": "invocation_endpoint",
            "http_method": "http_method",
            "connection_arn": "connection_arn",
            "invocation_rate_limit_per_second": "invocation_rate_limit_per_second",
        },
    ),
    # --- Redshift extensions ------------------------------------------------
    ("redshift", "parameter_group"): TfSpec(
        resource_type="aws_redshift_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- EC2 more -----------------------------------------------------------
    ("ec2", "placement_group"): TfSpec(
        resource_type="aws_placement_group",
        attribute_map={
            "name": "name",
            "strategy": "strategy",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ebs_snapshot"): TfSpec(
        resource_type="aws_ebs_snapshot",
        attribute_map={
            "volume_id": "volume_id",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- KMS alias ----------------------------------------------------------
    ("kms", "alias"): TfSpec(
        resource_type="aws_kms_alias",
        attribute_map={
            "alias_name": "name",
            "name": "name",
            "target_key_id": "target_key_id",
        },
    ),
    # --- Events event_bus ---------------------------------------------------
    ("events", "event_bus"): TfSpec(
        resource_type="aws_cloudwatch_event_bus",
        attribute_map={
            "name": "name",
        },
        builder=_build_tags_only,
    ),
    # --- Step Functions activity ---------------------------------------------
    ("stepfunctions", "activity"): TfSpec(
        resource_type="aws_sfn_activity",
        attribute_map={
            "name": "name",
        },
        builder=_build_tags_only,
    ),
    # --- EC2 extensions -----------------------------------------------------
    ("ec2", "launch_template"): TfSpec(
        resource_type="aws_launch_template",
        attribute_map={
            "name": "name",
            "description": "description",
            "image_id": "image_id",
            "instance_type": "instance_type",
            "key_name": "key_name",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ebs_volume"): TfSpec(
        resource_type="aws_ebs_volume",
        attribute_map={
            "availability_zone": "availability_zone",
            "size": "size",
            "type": "type",
            "iops": "iops",
            "throughput": "throughput",
            "encrypted": "encrypted",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "flow_log"): TfSpec(
        resource_type="aws_flow_log",
        attribute_map={
            "log_destination": "log_destination",
            "log_destination_type": "log_destination_type",
            "traffic_type": "traffic_type",
            "vpc_id": "vpc_id",
            "subnet_id": "subnet_id",
            "iam_role_arn": "iam_role_arn",
        },
        builder=_build_tags_only,
    ),
    # --- EC2 more networking ------------------------------------------------
    ("ec2", "transit_gateway"): TfSpec(
        resource_type="aws_ec2_transit_gateway",
        attribute_map={
            "description": "description",
            "amazon_side_asn": "amazon_side_asn",
            "auto_accept_shared_attachments": "auto_accept_shared_attachments",
            "default_route_table_association": "default_route_table_association",
            "default_route_table_propagation": "default_route_table_propagation",
            "dns_support": "dns_support",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "transit_gateway_vpc_attachment"): TfSpec(
        resource_type="aws_ec2_transit_gateway_vpc_attachment",
        attribute_map={
            "transit_gateway_id": "transit_gateway_id",
            "vpc_id": "vpc_id",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "dhcp_options"): TfSpec(
        resource_type="aws_vpc_dhcp_options",
        attribute_map={
            "domain_name": "domain_name",
            "domain_name_servers": "domain_name_servers",
            "ntp_servers": "ntp_servers",
            "netbios_name_servers": "netbios_name_servers",
            "netbios_node_type": "netbios_node_type",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "network_interface"): TfSpec(
        resource_type="aws_network_interface",
        attribute_map={
            "subnet_id": "subnet_id",
            "description": "description",
            "private_ips": "private_ips",
            "security_groups": "security_groups",
        },
        builder=_build_tags_only,
    ),
    # --- Resource Groups ----------------------------------------------------
    ("resource_groups", "group"): TfSpec(
        resource_type="aws_resourcegroups_group",
        attribute_map={
            "name": "name",
            "description": "description",
        },
        builder=_build_resource_group,
    ),
    # --- API Gateway v1 extensions ------------------------------------------
    ("apigateway", "resource"): TfSpec(
        resource_type="aws_api_gateway_resource",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "parent_id": "parent_id",
            "path_part": "path_part",
        },
    ),
    ("apigateway", "method"): TfSpec(
        resource_type="aws_api_gateway_method",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "resource_id": "resource_id",
            "http_method": "http_method",
            "authorization": "authorization",
            # moto stores ``authorization_type`` on Method objects;
            # ``aws_api_gateway_method`` spells the required arg
            # ``authorization``. Map both so either IR key works.
            "authorization_type": "authorization",
            "authorizer_id": "authorizer_id",
            "api_key_required": "api_key_required",
        },
        builder=_build_apigateway_method,
    ),
    ("apigateway", "stage"): TfSpec(
        resource_type="aws_api_gateway_stage",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "stage_name": "stage_name",
            "deployment_id": "deployment_id",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("apigateway", "authorizer"): TfSpec(
        resource_type="aws_api_gateway_authorizer",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "name": "name",
            "type": "type",
            "authorizer_uri": "authorizer_uri",
            "authorizer_credentials": "authorizer_credentials",
            "identity_source": "identity_source",
        },
    ),
    ("apigateway", "api_key"): TfSpec(
        resource_type="aws_api_gateway_api_key",
        attribute_map={
            "name": "name",
            "description": "description",
            "enabled": "enabled",
        },
        builder=_build_tags_only,
    ),
    ("apigateway", "usage_plan"): TfSpec(
        resource_type="aws_api_gateway_usage_plan",
        attribute_map={
            "name": "name",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("apigateway", "integration"): TfSpec(
        resource_type="aws_api_gateway_integration",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "resource_id": "resource_id",
            "http_method": "http_method",
            "type": "type",
            # moto's Integration stores ``integration_type`` (not ``type``);
            # the AWS API itself accepts both names but the TF schema
            # requires ``type``. Accept either IR key.
            "integration_type": "type",
            "integration_http_method": "integration_http_method",
            "request_templates": "request_templates",
            "uri": "uri",
            "connection_type": "connection_type",
            "credentials": "credentials",
            "passthrough_behavior": "passthrough_behavior",
            "timeout_in_millis": "timeout_milliseconds",
            "content_handling": "content_handling",
            "cache_key_parameters": "cache_key_parameters",
        },
    ),
    ("apigateway", "deployment"): TfSpec(
        resource_type="aws_api_gateway_deployment",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "description": "description",
        },
    ),
    ("apigateway", "gateway_response"): TfSpec(
        resource_type="aws_api_gateway_gateway_response",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "response_type": "response_type",
            "status_code": "status_code",
            "response_parameters": "response_parameters",
            "response_templates": "response_templates",
        },
    ),
    ("apigateway", "model"): TfSpec(
        resource_type="aws_api_gateway_model",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "name": "name",
            "content_type": "content_type",
            "schema": "schema",
            "description": "description",
        },
    ),
    ("apigateway", "method_response"): TfSpec(
        resource_type="aws_api_gateway_method_response",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "resource_id": "resource_id",
            "http_method": "http_method",
            "status_code": "status_code",
            "response_models": "response_models",
            "response_parameters": "response_parameters",
        },
    ),
    ("apigateway", "integration_response"): TfSpec(
        resource_type="aws_api_gateway_integration_response",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "resource_id": "resource_id",
            "http_method": "http_method",
            "status_code": "status_code",
            "response_templates": "response_templates",
            "response_parameters": "response_parameters",
        },
    ),
    ("apigateway", "usage_plan_key"): TfSpec(
        resource_type="aws_api_gateway_usage_plan_key",
        attribute_map={
            "key_id": "key_id",
            "key_type": "key_type",
            "usage_plan_id": "usage_plan_id",
        },
    ),
    ("apigateway", "base_path_mapping"): TfSpec(
        resource_type="aws_api_gateway_base_path_mapping",
        attribute_map={
            "api_id": "api_id",
            "domain_name": "domain_name",
            "stage_name": "stage_name",
            "base_path": "base_path",
        },
    ),
    ("apigateway", "account"): TfSpec(
        resource_type="aws_api_gateway_account",
        attribute_map={
            "cloudwatch_role_arn": "cloudwatch_role_arn",
        },
    ),
    ("apigateway", "request_validator"): TfSpec(
        resource_type="aws_api_gateway_request_validator",
        attribute_map={
            "rest_api_id": "rest_api_id",
            "name": "name",
            "validate_request_body": "validate_request_body",
            "validate_request_parameters": "validate_request_parameters",
        },
    ),
    # --- RDS extensions -----------------------------------------------------
    ("rds", "db_event_subscription"): TfSpec(
        resource_type="aws_db_event_subscription",
        attribute_map={
            "name": "name",
            "sns_topic": "sns_topic",
            "source_type": "source_type",
            "event_categories": "event_categories",
            "enabled": "enabled",
        },
        builder=_build_tags_only,
    ),
    # --- EC2 VPN family -----------------------------------------------------
    ("ec2", "customer_gateway"): TfSpec(
        resource_type="aws_customer_gateway",
        attribute_map={
            "bgp_asn": "bgp_asn",
            "ip_address": "ip_address",
            "type": "type",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "vpn_gateway"): TfSpec(
        resource_type="aws_vpn_gateway",
        attribute_map={
            "amazon_side_asn": "amazon_side_asn",
            "availability_zone": "availability_zone",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "vpn_connection"): TfSpec(
        resource_type="aws_vpn_connection",
        attribute_map={
            "customer_gateway_id": "customer_gateway_id",
            "vpn_gateway_id": "vpn_gateway_id",
            "transit_gateway_id": "transit_gateway_id",
            "type": "type",
            "static_routes_only": "static_routes_only",
        },
        builder=_build_tags_only,
    ),
    ("apigateway", "vpc_link"): TfSpec(
        resource_type="aws_api_gateway_vpc_link",
        attribute_map={
            "name": "name",
            "description": "description",
            "target_arns": "target_arns",
        },
        builder=_build_tags_only,
    ),
    ("apigateway", "domain_name"): TfSpec(
        resource_type="aws_api_gateway_domain_name",
        attribute_map={
            "domain_name": "domain_name",
            "certificate_arn": "certificate_arn",
            "regional_certificate_arn": "regional_certificate_arn",
            "security_policy": "security_policy",
        },
        builder=_build_tags_only,
    ),
    # --- Cognito identity_pool -----------------------------------------------
    ("cognito", "identity_pool"): TfSpec(
        resource_type="aws_cognito_identity_pool",
        attribute_map={
            "identity_pool_name": "identity_pool_name",
            "allow_unauthenticated_identities": "allow_unauthenticated_identities",
            "allow_classic_flow": "allow_classic_flow",
        },
        builder=_build_tags_only,
    ),
    # --- IAM access_key (metadata only, secret redacted) --------------------
    ("iam", "access_key"): TfSpec(
        resource_type="aws_iam_access_key",
        attribute_map={
            "user": "user",
            "status": "status",
        },
    ),
    # --- CloudWatch extensions ----------------------------------------------
    ("cloudwatch", "dashboard"): TfSpec(
        resource_type="aws_cloudwatch_dashboard",
        attribute_map={
            "dashboard_name": "dashboard_name",
            "dashboard_body": "dashboard_body",
        },
    ),
    # --- Logs extensions ----------------------------------------------------
    ("logs", "metric_filter"): TfSpec(
        resource_type="aws_cloudwatch_log_metric_filter",
        attribute_map={
            "name": "name",
            "log_group_name": "log_group_name",
            "pattern": "pattern",
            "metric_transformation": "metric_transformation",
        },
    ),
    ("logs", "subscription_filter"): TfSpec(
        resource_type="aws_cloudwatch_log_subscription_filter",
        attribute_map={
            "name": "name",
            "log_group_name": "log_group_name",
            "filter_pattern": "filter_pattern",
            "destination_arn": "destination_arn",
            "role_arn": "role_arn",
        },
    ),
    # --- ConfigService ------------------------------------------------------
    ("configservice", "configuration_recorder"): TfSpec(
        resource_type="aws_config_configuration_recorder",
        attribute_map={
            "name": "name",
            "role_arn": "role_arn",
            "recording_group": "recording_group",
        },
    ),
    ("configservice", "config_rule"): TfSpec(
        resource_type="aws_config_config_rule",
        attribute_map={
            "name": "name",
            "description": "description",
            "source": "source",
            "scope": "scope",
            "input_parameters": "input_parameters",
            "maximum_execution_frequency": "maximum_execution_frequency",
        },
    ),
    # --- SSM document -------------------------------------------------------
    ("ssm", "document"): TfSpec(
        resource_type="aws_ssm_document",
        attribute_map={
            "name": "name",
            "document_type": "document_type",
            "content": "content",
            "document_format": "document_format",
        },
        builder=_build_tags_only,
    ),
    # --- SecretsManager extensions ------------------------------------------
    ("secretsmanager", "secret_policy"): TfSpec(
        resource_type="aws_secretsmanager_secret_policy",
        attribute_map={
            "secret_arn": "secret_arn",
            "policy": "policy",
        },
    ),
    # --- DynamoDB global_table -----------------------------------------------
    ("dynamodb", "global_table"): TfSpec(
        resource_type="aws_dynamodb_global_table",
        attribute_map={
            "name": "name",
            "replica": "replica",
        },
    ),
    # --- SWF ----------------------------------------------------------------
    ("swf", "domain"): TfSpec(
        resource_type="aws_swf_domain",
        attribute_map={
            "name": "name",
            "description": "description",
            "workflow_execution_retention_period_in_days": "workflow_execution_retention_period_in_days",
        },
    ),
    # --- Kinesis stream_consumer ---------------------------------------------
    ("kinesis", "stream_consumer"): TfSpec(
        resource_type="aws_kinesis_stream_consumer",
        attribute_map={
            "name": "name",
            "stream_arn": "stream_arn",
        },
    ),
    # --- Route53Resolver ----------------------------------------------------
    ("route53resolver", "endpoint"): TfSpec(
        resource_type="aws_route53_resolver_endpoint",
        attribute_map={
            "name": "name",
            "direction": "direction",
            "security_group_ids": "security_group_ids",
            "ip_address": "ip_address",
        },
        builder=_build_tags_only,
    ),
    ("route53resolver", "rule"): TfSpec(
        resource_type="aws_route53_resolver_rule",
        attribute_map={
            "name": "name",
            "domain_name": "domain_name",
            "rule_type": "rule_type",
            "resolver_endpoint_id": "resolver_endpoint_id",
            "target_ip": "target_ip",
        },
        builder=_build_tags_only,
    ),
    ("route53resolver", "rule_association"): TfSpec(
        resource_type="aws_route53_resolver_rule_association",
        attribute_map={
            "name": "name",
            "resolver_rule_id": "resolver_rule_id",
            "vpc_id": "vpc_id",
        },
    ),
    # --- Redshift security_group: removed — deprecated in modern AWS provider.
    # --- CloudFront --------------------------------------------------------
    ("cloudfront", "distribution"): TfSpec(
        resource_type="aws_cloudfront_distribution",
        attribute_map={
            "enabled": "enabled",
            "comment": "comment",
            "origin": "origin",
            "default_cache_behavior": "default_cache_behavior",
            "restrictions": "restrictions",
            "viewer_certificate": "viewer_certificate",
        },
        builder=_build_tags_only,
    ),
    # --- CloudFormation stack ------------------------------------------------
    ("cloudformation", "stack"): TfSpec(
        resource_type="aws_cloudformation_stack",
        attribute_map={
            "name": "name",
            "template_body": "template_body",
            "parameters": "parameters",
            "capabilities": "capabilities",
        },
        builder=_build_tags_only,
    ),
    # --- CloudFront extensions -----------------------------------------------
    ("cloudfront", "origin_access_identity"): TfSpec(
        resource_type="aws_cloudfront_origin_access_identity",
        attribute_map={"comment": "comment"},
    ),
    ("cloudfront", "origin_access_control"): TfSpec(
        resource_type="aws_cloudfront_origin_access_control",
        attribute_map={
            "name": "name",
            "origin_access_control_origin_type": "origin_access_control_origin_type",
            "signing_behavior": "signing_behavior",
            "signing_protocol": "signing_protocol",
        },
    ),
    ("cloudfront", "cache_policy"): TfSpec(
        resource_type="aws_cloudfront_cache_policy",
        attribute_map={
            "name": "name",
            "comment": "comment",
            "default_ttl": "default_ttl",
            "max_ttl": "max_ttl",
            "min_ttl": "min_ttl",
        },
        builder=_build_cloudfront_cache_policy,
    ),
    ("cloudfront", "function"): TfSpec(
        resource_type="aws_cloudfront_function",
        attribute_map={
            "name": "name",
            "runtime": "runtime",
            "code": "code",
            "comment": "comment",
        },
    ),
    # --- CloudTrail extension ------------------------------------------------
    ("cloudtrail", "event_data_store"): TfSpec(
        resource_type="aws_cloudtrail_event_data_store",
        attribute_map={
            "name": "name",
            "retention_period": "retention_period",
            "multi_region_enabled": "multi_region_enabled",
            "organization_enabled": "organization_enabled",
        },
        builder=_build_tags_only,
    ),
    # --- CloudWatch/Logs extensions ------------------------------------------
    ("cloudwatch", "composite_alarm"): TfSpec(
        resource_type="aws_cloudwatch_composite_alarm",
        attribute_map={
            "alarm_name": "alarm_name",
            "alarm_rule": "alarm_rule",
            "alarm_description": "alarm_description",
        },
        builder=_build_tags_only,
    ),
    ("logs", "log_stream"): TfSpec(
        resource_type="aws_cloudwatch_log_stream",
        attribute_map={
            "name": "name",
            "log_group_name": "log_group_name",
        },
    ),
    ("logs", "resource_policy"): TfSpec(
        resource_type="aws_cloudwatch_log_resource_policy",
        attribute_map={
            "policy_name": "policy_name",
            "policy_document": "policy_document",
        },
    ),
    ("logs", "query_definition"): TfSpec(
        resource_type="aws_cloudwatch_query_definition",
        attribute_map={
            "name": "name",
            "query_string": "query_string",
            "log_group_names": "log_group_names",
        },
    ),
    # --- Cognito remaining ---------------------------------------------------
    ("cognito", "resource_server"): TfSpec(
        resource_type="aws_cognito_resource_server",
        attribute_map={
            "identifier": "identifier",
            "name": "name",
            "user_pool_id": "user_pool_id",
            "scope": "scope",
        },
    ),
    ("cognito", "identity_pool_roles_attachment"): TfSpec(
        resource_type="aws_cognito_identity_pool_roles_attachment",
        attribute_map={
            "identity_pool_id": "identity_pool_id",
            "roles": "roles",
        },
    ),
    # --- ConfigService remaining ---------------------------------------------
    ("configservice", "delivery_channel"): TfSpec(
        resource_type="aws_config_delivery_channel",
        attribute_map={
            "name": "name",
            "s3_bucket_name": "s3_bucket_name",
            "s3_key_prefix": "s3_key_prefix",
            "sns_topic_arn": "sns_topic_arn",
        },
    ),
    # --- Redshift ----------------------------------------------------------
    ("redshift", "cluster"): TfSpec(
        resource_type="aws_redshift_cluster",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "node_type": "node_type",
            "number_of_nodes": "number_of_nodes",
            "master_username": "master_username",
            "master_password": "master_password",
            "database_name": "database_name",
            "cluster_type": "cluster_type",
            "skip_final_snapshot": "skip_final_snapshot",
            "vpc_security_group_ids": "vpc_security_group_ids",
            "cluster_subnet_group_name": "cluster_subnet_group_name",
        },
        builder=_build_tags_only,
    ),
    ("redshift", "subnet_group"): TfSpec(
        resource_type="aws_redshift_subnet_group",
        attribute_map={
            "name": "name",
            "subnet_ids": "subnet_ids",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- S3 extensions ------------------------------------------------------
    ("s3", "bucket_policy"): TfSpec(
        resource_type="aws_s3_bucket_policy",
        attribute_map={
            "bucket": "bucket",
            "policy": "policy",
        },
        builder=_build_s3_bucket_policy_tf,
    ),
    # --- SQS extensions -----------------------------------------------------
    ("sqs", "queue_policy"): TfSpec(
        resource_type="aws_sqs_queue_policy",
        attribute_map={
            "queue_url": "queue_url",
            "policy": "policy",
        },
        builder=_build_sqs_queue_policy_tf,
    ),
    # --- DynamoDB extensions -------------------------------------------------
    ("dynamodb", "kinesis_streaming_destination"): TfSpec(
        resource_type="aws_dynamodb_kinesis_streaming_destination",
        attribute_map={"table_name": "table_name", "stream_arn": "stream_arn"},
    ),
    ("dynamodb", "contributor_insights"): TfSpec(
        resource_type="aws_dynamodb_contributor_insights",
        attribute_map={"table_name": "table_name"},
    ),
    ("dynamodb", "table_replica"): TfSpec(
        resource_type="aws_dynamodb_table_replica",
        attribute_map={"global_table_arn": "global_table_arn"},
        builder=_build_tags_only,
    ),
    # --- EC2 remaining -------------------------------------------------------
    ("ec2", "volume_attachment"): TfSpec(
        resource_type="aws_volume_attachment",
        attribute_map={"device_name": "device_name", "instance_id": "instance_id", "volume_id": "volume_id"},
    ),
    ("ec2", "vpn_gateway_attachment"): TfSpec(
        resource_type="aws_vpn_gateway_attachment",
        attribute_map={"vpn_gateway_id": "vpn_gateway_id", "vpc_id": "vpc_id"},
    ),
    ("ec2", "vpn_connection_route"): TfSpec(
        resource_type="aws_vpn_connection_route",
        attribute_map={"destination_cidr_block": "destination_cidr_block", "vpn_connection_id": "vpn_connection_id"},
    ),
    ("ec2", "egress_only_internet_gateway"): TfSpec(
        resource_type="aws_egress_only_internet_gateway",
        attribute_map={"vpc_id": "vpc_id"},
        builder=_build_tags_only,
    ),
    ("ec2", "dhcp_options_association"): TfSpec(
        resource_type="aws_vpc_dhcp_options_association",
        attribute_map={"dhcp_options_id": "dhcp_options_id", "vpc_id": "vpc_id"},
    ),
    ("ec2", "eip_association"): TfSpec(
        resource_type="aws_eip_association",
        attribute_map={"allocation_id": "allocation_id", "instance_id": "instance_id", "network_interface_id": "network_interface_id"},
    ),
    ("ec2", "vpc_endpoint_service"): TfSpec(
        resource_type="aws_vpc_endpoint_service",
        attribute_map={"acceptance_required": "acceptance_required", "network_load_balancer_arns": "network_load_balancer_arns"},
        builder=_build_tags_only,
    ),
    ("ec2", "ec2_managed_prefix_list"): TfSpec(
        resource_type="aws_ec2_managed_prefix_list",
        attribute_map={"name": "name", "address_family": "address_family", "max_entries": "max_entries"},
        builder=_build_tags_only,
    ),
    ("ec2", "transit_gateway_route_table"): TfSpec(
        resource_type="aws_ec2_transit_gateway_route_table",
        attribute_map={"transit_gateway_id": "transit_gateway_id"},
        builder=_build_tags_only,
    ),
    ("ec2", "transit_gateway_route"): TfSpec(
        resource_type="aws_ec2_transit_gateway_route",
        attribute_map={"destination_cidr_block": "destination_cidr_block", "transit_gateway_route_table_id": "transit_gateway_route_table_id", "transit_gateway_attachment_id": "transit_gateway_attachment_id"},
    ),
    # --- ECR remaining -------------------------------------------------------
    ("ecr", "lifecycle_policy"): TfSpec(
        resource_type="aws_ecr_lifecycle_policy",
        attribute_map={"repository": "repository", "policy": "policy"},
    ),
    ("ecr", "repository_policy"): TfSpec(
        resource_type="aws_ecr_repository_policy",
        attribute_map={"repository": "repository", "policy": "policy"},
    ),
    # --- ECS remaining -------------------------------------------------------
    ("ecs", "capacity_provider"): TfSpec(
        resource_type="aws_ecs_capacity_provider",
        attribute_map={"name": "name"},
        builder=_build_ecs_capacity_provider,
    ),
    # --- EKS remaining -------------------------------------------------------
    ("eks", "fargate_profile"): TfSpec(
        resource_type="aws_eks_fargate_profile",
        attribute_map={"cluster_name": "cluster_name", "fargate_profile_name": "fargate_profile_name", "pod_execution_role_arn": "pod_execution_role_arn", "subnet_ids": "subnet_ids", "selector": "selector"},
        builder=_build_tags_only,
    ),
    ("eks", "addon"): TfSpec(
        resource_type="aws_eks_addon",
        attribute_map={"cluster_name": "cluster_name", "addon_name": "addon_name", "addon_version": "addon_version"},
        builder=_build_tags_only,
    ),
    # --- Events remaining ----------------------------------------------------
    ("events", "event_bus_policy"): TfSpec(
        resource_type="aws_cloudwatch_event_bus_policy",
        attribute_map={"event_bus_name": "event_bus_name", "policy": "policy"},
    ),
    # --- IAM remaining -------------------------------------------------------
    ("iam", "server_certificate"): TfSpec(
        resource_type="aws_iam_server_certificate",
        attribute_map={"name": "name", "certificate_body": "certificate_body", "private_key": "private_key", "certificate_chain": "certificate_chain", "path": "path"},
    ),
    ("iam", "service_linked_role"): TfSpec(
        resource_type="aws_iam_service_linked_role",
        attribute_map={"aws_service_name": "aws_service_name", "description": "description"},
    ),
    # --- Lambda remaining ----------------------------------------------------
    ("lambda", "alias"): TfSpec(
        resource_type="aws_lambda_alias",
        attribute_map={"name": "name", "function_name": "function_name", "function_version": "function_version", "description": "description"},
    ),
    ("lambda", "code_signing_config"): TfSpec(
        resource_type="aws_lambda_code_signing_config",
        attribute_map={"description": "description"},
        builder=_build_lambda_code_signing,
    ),
    ("lambda", "layer_version_permission"): TfSpec(
        resource_type="aws_lambda_layer_version_permission",
        attribute_map={"layer_name": "layer_name", "version_number": "version_number", "statement_id": "statement_id", "action": "action", "principal": "principal"},
    ),
    # --- RDS remaining -------------------------------------------------------
    ("rds", "db_proxy"): TfSpec(
        resource_type="aws_db_proxy",
        attribute_map={"name": "name", "engine_family": "engine_family", "role_arn": "role_arn", "vpc_subnet_ids": "vpc_subnet_ids", "auth": "auth"},
        builder=_build_tags_only,
    ),
    ("rds", "global_cluster"): TfSpec(
        resource_type="aws_rds_global_cluster",
        attribute_map={"global_cluster_identifier": "global_cluster_identifier", "engine": "engine", "engine_version": "engine_version", "database_name": "database_name"},
    ),
    # --- Redshift remaining --------------------------------------------------
    ("redshift", "event_subscription"): TfSpec(
        resource_type="aws_redshift_event_subscription",
        attribute_map={"name": "name", "sns_topic_arn": "sns_topic_arn", "source_type": "source_type", "event_categories": "event_categories", "enabled": "enabled"},
        builder=_build_tags_only,
    ),
    # --- S3 remaining --------------------------------------------------------
    ("s3", "bucket_lifecycle_configuration"): TfSpec(
        resource_type="aws_s3_bucket_lifecycle_configuration",
        attribute_map={"bucket": "bucket", "rule": "rule"},
    ),
    ("s3", "bucket_cors_configuration"): TfSpec(
        resource_type="aws_s3_bucket_cors_configuration",
        attribute_map={"bucket": "bucket", "cors_rule": "cors_rule"},
    ),
    ("s3", "bucket_acl"): TfSpec(
        resource_type="aws_s3_bucket_acl",
        attribute_map={"bucket": "bucket", "acl": "acl"},
    ),
    ("s3", "bucket_ownership_controls"): TfSpec(
        resource_type="aws_s3_bucket_ownership_controls",
        attribute_map={"bucket": "bucket", "rule": "rule"},
    ),
    ("s3", "bucket_public_access_block"): TfSpec(
        resource_type="aws_s3_bucket_public_access_block",
        attribute_map={"bucket": "bucket", "block_public_acls": "block_public_acls", "block_public_policy": "block_public_policy", "ignore_public_acls": "ignore_public_acls", "restrict_public_buckets": "restrict_public_buckets"},
    ),
    ("s3", "bucket_server_side_encryption_configuration"): TfSpec(
        resource_type="aws_s3_bucket_server_side_encryption_configuration",
        attribute_map={"bucket": "bucket", "rule": "rule"},
    ),
    ("s3", "bucket_logging"): TfSpec(
        resource_type="aws_s3_bucket_logging",
        attribute_map={"bucket": "bucket", "target_bucket": "target_bucket", "target_prefix": "target_prefix"},
    ),
    ("s3", "bucket_notification"): TfSpec(
        resource_type="aws_s3_bucket_notification",
        attribute_map={"bucket": "bucket"},
    ),
    ("s3", "bucket_website_configuration"): TfSpec(
        resource_type="aws_s3_bucket_website_configuration",
        attribute_map={"bucket": "bucket", "index_document": "index_document", "error_document": "error_document"},
    ),
    # --- SES remaining -------------------------------------------------------
    ("ses", "domain_identity"): TfSpec(
        resource_type="aws_ses_domain_identity",
        attribute_map={"domain": "domain"},
    ),
    ("ses", "receipt_filter"): TfSpec(
        resource_type="aws_ses_receipt_filter",
        attribute_map={"name": "name", "cidr": "cidr", "policy": "policy"},
    ),
    ("ses", "receipt_rule"): TfSpec(
        resource_type="aws_ses_receipt_rule",
        attribute_map={"name": "name", "rule_set_name": "rule_set_name", "recipients": "recipients", "enabled": "enabled", "scan_enabled": "scan_enabled"},
    ),
    # --- SNS remaining -------------------------------------------------------
    ("sns", "topic_policy"): TfSpec(
        resource_type="aws_sns_topic_policy",
        attribute_map={"arn": "arn", "policy": "policy"},
        builder=_build_sns_topic_policy_tf,
    ),
    ("sns", "platform_application"): TfSpec(
        resource_type="aws_sns_platform_application",
        attribute_map={"name": "name", "platform": "platform", "platform_credential": "platform_credential"},
    ),
    # --- SQS remaining -------------------------------------------------------
    ("sqs", "queue_redrive_policy"): TfSpec(
        resource_type="aws_sqs_queue_redrive_policy",
        attribute_map={"queue_url": "queue_url", "redrive_policy": "redrive_policy"},
    ),
    ("sqs", "queue_redrive_allow_policy"): TfSpec(
        resource_type="aws_sqs_queue_redrive_allow_policy",
        attribute_map={"queue_url": "queue_url", "redrive_allow_policy": "redrive_allow_policy"},
    ),
    # --- SSM remaining -------------------------------------------------------
    ("ssm", "association"): TfSpec(
        resource_type="aws_ssm_association",
        attribute_map={"name": "name", "association_name": "association_name"},
    ),
    ("ssm", "maintenance_window"): TfSpec(
        resource_type="aws_ssm_maintenance_window",
        attribute_map={"name": "name", "schedule": "schedule", "duration": "duration", "cutoff": "cutoff", "allow_unassociated_targets": "allow_unassociated_targets"},
        builder=_build_tags_only,
    ),
    ("ssm", "patch_baseline"): TfSpec(
        resource_type="aws_ssm_patch_baseline",
        attribute_map={"name": "name", "operating_system": "operating_system", "description": "description"},
        builder=_build_tags_only,
    ),
    # --- Step Functions remaining ---------------------------------------------
    ("stepfunctions", "alias"): TfSpec(
        resource_type="aws_sfn_alias",
        attribute_map={"name": "name", "description": "description"},
        builder=_build_sfn_alias,
    ),
    # --- SecretsManager remaining --------------------------------------------
    ("secretsmanager", "secret_rotation"): TfSpec(
        resource_type="aws_secretsmanager_secret_rotation",
        attribute_map={"secret_id": "secret_id", "rotation_lambda_arn": "rotation_lambda_arn"},
        builder=_build_sm_rotation,
    ),
    # --- Transcribe ----------------------------------------------------------
    ("transcribe", "vocabulary"): TfSpec(
        resource_type="aws_transcribe_vocabulary",
        attribute_map={"vocabulary_name": "vocabulary_name", "language_code": "language_code", "vocabulary_file_uri": "vocabulary_file_uri"},
        builder=_build_tags_only,
    ),
    ("transcribe", "vocabulary_filter"): TfSpec(
        resource_type="aws_transcribe_vocabulary_filter",
        attribute_map={"vocabulary_filter_name": "vocabulary_filter_name", "language_code": "language_code", "words": "words", "vocabulary_filter_file_uri": "vocabulary_filter_file_uri"},
        builder=_build_tags_only,
    ),
    # --- CloudFormation extensions ------------------------------------------
    ("cloudformation", "stack_set"): TfSpec(
        resource_type="aws_cloudformation_stack_set",
        attribute_map={
            "name": "name",
            "description": "description",
            "template_body": "template_body",
            "template_url": "template_url",
            "capabilities": "capabilities",
            "administration_role_arn": "administration_role_arn",
            "execution_role_name": "execution_role_name",
        },
        builder=_build_tags_only,
    ),
    # --- CloudFront extensions (new) ----------------------------------------
    ("cloudfront", "origin_request_policy"): TfSpec(
        resource_type="aws_cloudfront_origin_request_policy",
        attribute_map={
            "name": "name",
            "comment": "comment",
        },
        builder=_build_cloudfront_origin_request_policy,
    ),
    ("cloudfront", "response_headers_policy"): TfSpec(
        resource_type="aws_cloudfront_response_headers_policy",
        attribute_map={
            "name": "name",
            "comment": "comment",
        },
        builder=_build_cloudfront_response_headers_policy,
    ),
    ("cloudfront", "key_group"): TfSpec(
        resource_type="aws_cloudfront_key_group",
        attribute_map={
            "name": "name",
            "comment": "comment",
            "items": "items",
        },
    ),
    ("cloudfront", "public_key"): TfSpec(
        resource_type="aws_cloudfront_public_key",
        attribute_map={
            "name": "name",
            "comment": "comment",
            "encoded_key": "encoded_key",
        },
    ),
    ("cloudfront", "realtime_log_config"): TfSpec(
        resource_type="aws_cloudfront_realtime_log_config",
        attribute_map={
            "name": "name",
            "sampling_rate": "sampling_rate",
            "fields": "fields",
            "endpoint": "endpoint",
        },
    ),
    ("cloudfront", "field_level_encryption_config"): TfSpec(
        resource_type="aws_cloudfront_field_level_encryption_config",
        attribute_map={
            "comment": "comment",
        },
        builder=_build_cloudfront_fle_config,
    ),
    ("cloudfront", "field_level_encryption_profile"): TfSpec(
        resource_type="aws_cloudfront_field_level_encryption_profile",
        attribute_map={
            "name": "name",
            "comment": "comment",
        },
        builder=_build_cloudfront_fle_profile,
    ),
    # --- CloudWatch extensions (new) ----------------------------------------
    ("cloudwatch", "metric_stream"): TfSpec(
        resource_type="aws_cloudwatch_metric_stream",
        attribute_map={
            "name": "name",
            "firehose_arn": "firehose_arn",
            "role_arn": "role_arn",
            "output_format": "output_format",
        },
        builder=_build_tags_only,
    ),
    ("logs", "log_destination"): TfSpec(
        resource_type="aws_cloudwatch_log_destination",
        attribute_map={
            "name": "name",
            "target_arn": "target_arn",
            "role_arn": "role_arn",
        },
    ),
    # --- Cognito extensions (new) -------------------------------------------
    ("cognito", "risk_configuration"): TfSpec(
        resource_type="aws_cognito_risk_configuration",
        attribute_map={
            "user_pool_id": "user_pool_id",
            "client_id": "client_id",
        },
        builder=_build_cognito_risk_configuration,
    ),
    ("cognito", "ui_customization"): TfSpec(
        resource_type="aws_cognito_user_pool_ui_customization",
        attribute_map={
            "user_pool_id": "user_pool_id",
            "client_id": "client_id",
            "css": "css",
        },
    ),
    # --- ConfigService extensions (new) -------------------------------------
    ("configservice", "aggregate_authorization"): TfSpec(
        resource_type="aws_config_aggregate_authorization",
        attribute_map={
            "account_id": "account_id",
            "region": "region",
        },
        builder=_build_tags_only,
    ),
    ("configservice", "configuration_aggregator"): TfSpec(
        resource_type="aws_config_configuration_aggregator",
        attribute_map={
            "name": "name",
        },
        builder=_build_config_aggregator,
    ),
    ("configservice", "conformance_pack"): TfSpec(
        resource_type="aws_config_conformance_pack",
        attribute_map={
            "name": "name",
            "template_body": "template_body",
            "template_s3_uri": "template_s3_uri",
        },
    ),
    ("configservice", "organization_conformance_pack"): TfSpec(
        resource_type="aws_config_organization_conformance_pack",
        attribute_map={
            "name": "name",
            "template_body": "template_body",
            "template_s3_uri": "template_s3_uri",
        },
    ),
    ("configservice", "organization_managed_rule"): TfSpec(
        resource_type="aws_config_organization_managed_rule",
        attribute_map={
            "name": "name",
            "rule_identifier": "rule_identifier",
            "description": "description",
        },
    ),
    ("configservice", "organization_custom_rule"): TfSpec(
        resource_type="aws_config_organization_custom_rule",
        attribute_map={
            "name": "name",
            "lambda_function_arn": "lambda_function_arn",
            "trigger_types": "trigger_types",
            "description": "description",
        },
    ),
    ("configservice", "remediation_configuration"): TfSpec(
        resource_type="aws_config_remediation_configuration",
        attribute_map={
            "config_rule_name": "config_rule_name",
            "target_type": "target_type",
            "target_id": "target_id",
        },
    ),
    ("configservice", "retention_configuration"): TfSpec(
        resource_type="aws_config_retention_configuration",
        attribute_map={
            "retention_period_in_days": "retention_period_in_days",
        },
    ),
    # --- EC2 extensions (new) -----------------------------------------------
    ("ec2", "ami"): TfSpec(
        resource_type="aws_ami",
        attribute_map={
            "name": "name",
            "description": "description",
            "root_device_name": "root_device_name",
            "virtualization_type": "virtualization_type",
        },
        builder=_build_ami,
    ),
    ("ec2", "launch_configuration"): TfSpec(
        resource_type="aws_launch_configuration",
        attribute_map={
            "name": "name",
            "image_id": "image_id",
            "instance_type": "instance_type",
            "key_name": "key_name",
            "security_groups": "security_groups",
        },
    ),
    ("ec2", "spot_fleet_request"): TfSpec(
        resource_type="aws_spot_fleet_request",
        attribute_map={
            "iam_fleet_role": "iam_fleet_role",
            "target_capacity": "target_capacity",
            "allocation_strategy": "allocation_strategy",
            "terminate_instances_with_expiration": "terminate_instances_with_expiration",
        },
        builder=_build_spot_fleet,
    ),
    ("ec2", "fleet"): TfSpec(
        resource_type="aws_ec2_fleet",
        attribute_map={
            "type": "type",
            "terminate_instances": "terminate_instances",
        },
        builder=_build_ec2_fleet,
    ),
    ("ec2", "capacity_reservation"): TfSpec(
        resource_type="aws_ec2_capacity_reservation",
        attribute_map={
            "instance_type": "instance_type",
            "instance_platform": "instance_platform",
            "availability_zone": "availability_zone",
            "instance_count": "instance_count",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "dedicated_host"): TfSpec(
        resource_type="aws_ec2_host",
        attribute_map={
            "instance_type": "instance_type",
            "availability_zone": "availability_zone",
            "auto_placement": "auto_placement",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "transit_gateway_route_table_association"): TfSpec(
        resource_type="aws_ec2_transit_gateway_route_table_association",
        attribute_map={
            "transit_gateway_attachment_id": "transit_gateway_attachment_id",
            "transit_gateway_route_table_id": "transit_gateway_route_table_id",
        },
    ),
    ("ec2", "transit_gateway_route_table_propagation"): TfSpec(
        resource_type="aws_ec2_transit_gateway_route_table_propagation",
        attribute_map={
            "transit_gateway_attachment_id": "transit_gateway_attachment_id",
            "transit_gateway_route_table_id": "transit_gateway_route_table_id",
        },
    ),
    ("ec2", "transit_gateway_peering_attachment"): TfSpec(
        resource_type="aws_ec2_transit_gateway_peering_attachment",
        attribute_map={
            "transit_gateway_id": "transit_gateway_id",
            "peer_transit_gateway_id": "peer_transit_gateway_id",
            "peer_account_id": "peer_account_id",
            "peer_region": "peer_region",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "network_interface_attachment"): TfSpec(
        resource_type="aws_network_interface_attachment",
        attribute_map={
            "instance_id": "instance_id",
            "network_interface_id": "network_interface_id",
            "device_index": "device_index",
        },
    ),
    ("ec2", "network_acl_association"): TfSpec(
        resource_type="aws_network_acl_association",
        attribute_map={
            "network_acl_id": "network_acl_id",
            "subnet_id": "subnet_id",
        },
    ),
    ("ec2", "vpc_endpoint_service_allowed_principal"): TfSpec(
        resource_type="aws_vpc_endpoint_service_allowed_principal",
        attribute_map={
            "vpc_endpoint_service_id": "vpc_endpoint_service_id",
            "principal_arn": "principal_arn",
        },
    ),
    ("ec2", "vpc_endpoint_connection_notification"): TfSpec(
        resource_type="aws_vpc_endpoint_connection_notification",
        attribute_map={
            "vpc_endpoint_service_id": "vpc_endpoint_service_id",
            "connection_notification_arn": "connection_notification_arn",
            "connection_events": "connection_events",
        },
    ),
    ("ec2", "vpc_peering_connection_accepter"): TfSpec(
        resource_type="aws_vpc_peering_connection_accepter",
        attribute_map={
            "vpc_peering_connection_id": "vpc_peering_connection_id",
            "auto_accept": "auto_accept",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "vpc_ipv4_cidr_block_association"): TfSpec(
        resource_type="aws_vpc_ipv4_cidr_block_association",
        attribute_map={
            "vpc_id": "vpc_id",
            "cidr_block": "cidr_block",
        },
    ),
    ("ec2", "vpc_ipv6_cidr_block_association"): TfSpec(
        resource_type="aws_vpc_ipv6_cidr_block_association",
        attribute_map={
            "vpc_id": "vpc_id",
            "ipv6_ipam_pool_id": "ipv6_ipam_pool_id",
            "ipv6_netmask_length": "ipv6_netmask_length",
        },
    ),
    ("ec2", "vpc_ipam"): TfSpec(
        resource_type="aws_vpc_ipam",
        attribute_map={
            "description": "description",
        },
        builder=_build_vpc_ipam,
    ),
    ("ec2", "vpc_ipam_pool"): TfSpec(
        resource_type="aws_vpc_ipam_pool",
        attribute_map={
            "address_family": "address_family",
            "ipam_scope_id": "ipam_scope_id",
            "description": "description",
            "locale": "locale",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "vpc_ipam_scope"): TfSpec(
        resource_type="aws_vpc_ipam_scope",
        attribute_map={
            "ipam_id": "ipam_id",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ec2_traffic_mirror_filter"): TfSpec(
        resource_type="aws_ec2_traffic_mirror_filter",
        attribute_map={
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ec2_traffic_mirror_filter_rule"): TfSpec(
        resource_type="aws_ec2_traffic_mirror_filter_rule",
        attribute_map={
            "traffic_mirror_filter_id": "traffic_mirror_filter_id",
            "traffic_direction": "traffic_direction",
            "rule_number": "rule_number",
            "rule_action": "rule_action",
            "destination_cidr_block": "destination_cidr_block",
            "source_cidr_block": "source_cidr_block",
            "protocol": "protocol",
        },
    ),
    ("ec2", "ec2_traffic_mirror_session"): TfSpec(
        resource_type="aws_ec2_traffic_mirror_session",
        attribute_map={
            "traffic_mirror_target_id": "traffic_mirror_target_id",
            "traffic_mirror_filter_id": "traffic_mirror_filter_id",
            "network_interface_id": "network_interface_id",
            "session_number": "session_number",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ec2_traffic_mirror_target"): TfSpec(
        resource_type="aws_ec2_traffic_mirror_target",
        attribute_map={
            "network_interface_id": "network_interface_id",
            "network_load_balancer_arn": "network_load_balancer_arn",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- ECR extensions (new) -----------------------------------------------
    ("ecr", "pull_through_cache_rule"): TfSpec(
        resource_type="aws_ecr_pull_through_cache_rule",
        attribute_map={
            "ecr_repository_prefix": "ecr_repository_prefix",
            "upstream_registry_url": "upstream_registry_url",
        },
    ),
    ("ecr", "registry_policy"): TfSpec(
        resource_type="aws_ecr_registry_policy",
        attribute_map={
            "policy": "policy",
        },
    ),
    ("ecr", "registry_scanning_configuration"): TfSpec(
        resource_type="aws_ecr_registry_scanning_configuration",
        attribute_map={
            "scan_type": "scan_type",
        },
        builder=_build_ecr_scanning_config,
    ),
    ("ecr", "replication_configuration"): TfSpec(
        resource_type="aws_ecr_replication_configuration",
        attribute_map={},
        builder=_build_ecr_replication,
    ),
    # --- ECS extensions (new) -----------------------------------------------
    ("ecs", "cluster_capacity_providers"): TfSpec(
        resource_type="aws_ecs_cluster_capacity_providers",
        attribute_map={
            "cluster_name": "cluster_name",
            "capacity_providers": "capacity_providers",
            "default_capacity_provider_strategy": "default_capacity_provider_strategy",
        },
    ),
    ("ecs", "task_set"): TfSpec(
        resource_type="aws_ecs_task_set",
        attribute_map={
            "service": "service",
            "cluster": "cluster",
            "task_definition": "task_definition",
            "launch_type": "launch_type",
        },
    ),
    # --- EKS extensions (new) -----------------------------------------------
    ("eks", "identity_provider_config"): TfSpec(
        resource_type="aws_eks_identity_provider_config",
        attribute_map={
            "cluster_name": "cluster_name",
        },
        builder=_build_eks_identity_provider_config,
    ),
    ("eks", "access_entry"): TfSpec(
        resource_type="aws_eks_access_entry",
        attribute_map={
            "cluster_name": "cluster_name",
            "principal_arn": "principal_arn",
            "type": "type",
        },
        builder=_build_tags_only,
    ),
    ("eks", "pod_identity_association"): TfSpec(
        resource_type="aws_eks_pod_identity_association",
        attribute_map={
            "cluster_name": "cluster_name",
            "namespace": "namespace",
            "service_account": "service_account",
            "role_arn": "role_arn",
        },
        builder=_build_tags_only,
    ),
    # --- OpenSearch extensions (new) ----------------------------------------
    ("opensearch", "package"): TfSpec(
        resource_type="aws_opensearch_package",
        attribute_map={
            "package_name": "package_name",
            "package_type": "package_type",
        },
        builder=_build_opensearch_package,
    ),
    ("opensearch", "serverless_collection"): TfSpec(
        resource_type="aws_opensearchserverless_collection",
        attribute_map={
            "name": "name",
            "type": "type",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("opensearch", "serverless_security_policy"): TfSpec(
        resource_type="aws_opensearchserverless_security_policy",
        attribute_map={
            "name": "name",
            "type": "type",
            "policy": "policy",
            "description": "description",
        },
    ),
    ("opensearch", "serverless_access_policy"): TfSpec(
        resource_type="aws_opensearchserverless_access_policy",
        attribute_map={
            "name": "name",
            "type": "type",
            "policy": "policy",
            "description": "description",
        },
    ),
    ("opensearch", "serverless_vpc_endpoint"): TfSpec(
        resource_type="aws_opensearchserverless_vpc_endpoint",
        attribute_map={
            "name": "name",
            "vpc_id": "vpc_id",
            "subnet_ids": "subnet_ids",
            "security_group_ids": "security_group_ids",
        },
    ),
    ("opensearch", "serverless_lifecycle_policy"): TfSpec(
        resource_type="aws_opensearchserverless_lifecycle_policy",
        attribute_map={
            "name": "name",
            "type": "type",
            "policy": "policy",
            "description": "description",
        },
    ),
    # --- Kinesis extensions (new) -------------------------------------------
    ("kinesis", "analytics_application"): TfSpec(
        resource_type="aws_kinesis_analytics_application",
        attribute_map={
            "name": "name",
            "code": "code",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("kinesis", "analyticsv2_application"): TfSpec(
        resource_type="aws_kinesisanalyticsv2_application",
        attribute_map={
            "name": "name",
            "runtime_environment": "runtime_environment",
            "service_execution_role": "service_execution_role",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("kinesis", "video_stream"): TfSpec(
        resource_type="aws_kinesis_video_stream",
        attribute_map={
            "name": "name",
            "data_retention_in_hours": "data_retention_in_hours",
            "device_name": "device_name",
            "media_type": "media_type",
        },
        builder=_build_tags_only,
    ),
    # --- Lambda extensions (new) --------------------------------------------
    ("lambda", "function_event_invoke_config"): TfSpec(
        resource_type="aws_lambda_function_event_invoke_config",
        attribute_map={
            "function_name": "function_name",
            "maximum_event_age_in_seconds": "maximum_event_age_in_seconds",
            "maximum_retry_attempts": "maximum_retry_attempts",
            "qualifier": "qualifier",
        },
    ),
    # --- RDS extensions (new) -----------------------------------------------
    ("rds", "db_proxy_target"): TfSpec(
        resource_type="aws_db_proxy_target",
        attribute_map={
            "db_proxy_name": "db_proxy_name",
            "target_group_name": "target_group_name",
            "db_instance_identifier": "db_instance_identifier",
            "db_cluster_identifier": "db_cluster_identifier",
        },
    ),
    ("rds", "db_proxy_endpoint"): TfSpec(
        resource_type="aws_db_proxy_endpoint",
        attribute_map={
            "db_proxy_name": "db_proxy_name",
            "db_proxy_endpoint_name": "db_proxy_endpoint_name",
            "vpc_subnet_ids": "vpc_subnet_ids",
            "vpc_security_group_ids": "vpc_security_group_ids",
            "target_role": "target_role",
        },
        builder=_build_tags_only,
    ),
    ("rds", "cluster_endpoint"): TfSpec(
        resource_type="aws_rds_cluster_endpoint",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "cluster_endpoint_identifier": "cluster_endpoint_identifier",
            "custom_endpoint_type": "custom_endpoint_type",
            "static_members": "static_members",
            "excluded_members": "excluded_members",
        },
        builder=_build_tags_only,
    ),
    # --- Redshift extensions (new) ------------------------------------------
    ("redshift", "snapshot_schedule"): TfSpec(
        resource_type="aws_redshift_snapshot_schedule",
        attribute_map={
            "identifier": "identifier",
            "description": "description",
            "definitions": "definitions",
        },
        builder=_build_tags_only,
    ),
    ("redshift", "authentication_profile"): TfSpec(
        resource_type="aws_redshift_authentication_profile",
        attribute_map={
            "authentication_profile_name": "authentication_profile_name",
            "authentication_profile_content": "authentication_profile_content",
        },
    ),
    ("redshift", "endpoint_access"): TfSpec(
        resource_type="aws_redshift_endpoint_access",
        attribute_map={
            "endpoint_name": "endpoint_name",
            "subnet_group_name": "subnet_group_name",
            "cluster_identifier": "cluster_identifier",
            "vpc_security_group_ids": "vpc_security_group_ids",
        },
    ),
    ("redshift", "scheduled_action"): TfSpec(
        resource_type="aws_redshift_scheduled_action",
        attribute_map={
            "name": "name",
            "schedule": "schedule",
            "iam_role": "iam_role",
            "description": "description",
        },
        builder=_build_redshift_scheduled_action,
    ),
    ("redshift", "serverless_namespace"): TfSpec(
        resource_type="aws_redshiftserverless_namespace",
        attribute_map={
            "namespace_name": "namespace_name",
            "admin_user_password": "admin_user_password",
            "admin_username": "admin_username",
            "db_name": "db_name",
        },
        builder=_build_tags_only,
    ),
    ("redshift", "serverless_workgroup"): TfSpec(
        resource_type="aws_redshiftserverless_workgroup",
        attribute_map={
            "workgroup_name": "workgroup_name",
            "namespace_name": "namespace_name",
            "base_capacity": "base_capacity",
        },
        builder=_build_tags_only,
    ),
    # --- Route53 extensions (new) -------------------------------------------
    ("route53", "zone_association"): TfSpec(
        resource_type="aws_route53_zone_association",
        attribute_map={
            "zone_id": "zone_id",
            "vpc_id": "vpc_id",
            "vpc_region": "vpc_region",
        },
    ),
    ("route53", "query_log"): TfSpec(
        resource_type="aws_route53_query_log",
        attribute_map={
            "zone_id": "zone_id",
            "cloudwatch_log_group_arn": "cloudwatch_log_group_arn",
        },
    ),
    ("route53", "key_signing_key"): TfSpec(
        resource_type="aws_route53_key_signing_key",
        attribute_map={
            "hosted_zone_id": "hosted_zone_id",
            "key_management_service_arn": "key_management_service_arn",
            "name": "name",
            "status": "status",
        },
    ),
    ("route53", "cidr_collection"): TfSpec(
        resource_type="aws_route53_cidr_collection",
        attribute_map={
            "name": "name",
        },
    ),
    # --- Route53 Resolver extensions (new) ----------------------------------
    ("route53resolver", "query_log_config"): TfSpec(
        resource_type="aws_route53_resolver_query_log_config",
        attribute_map={
            "name": "name",
            "destination_arn": "destination_arn",
        },
        builder=_build_tags_only,
    ),
    ("route53resolver", "query_log_config_association"): TfSpec(
        resource_type="aws_route53_resolver_query_log_config_association",
        attribute_map={
            "resolver_query_log_config_id": "resolver_query_log_config_id",
            "resource_id": "resource_id",
        },
    ),
    ("route53resolver", "dnssec_config"): TfSpec(
        resource_type="aws_route53_resolver_dnssec_config",
        attribute_map={
            "resource_id": "resource_id",
        },
    ),
    ("route53resolver", "firewall_config"): TfSpec(
        resource_type="aws_route53_resolver_firewall_config",
        attribute_map={
            "resource_id": "resource_id",
            "firewall_fail_open": "firewall_fail_open",
        },
    ),
    ("route53resolver", "firewall_domain_list"): TfSpec(
        resource_type="aws_route53_resolver_firewall_domain_list",
        attribute_map={
            "name": "name",
            "domains": "domains",
        },
        builder=_build_tags_only,
    ),
    ("route53resolver", "firewall_rule_group"): TfSpec(
        resource_type="aws_route53_resolver_firewall_rule_group",
        attribute_map={
            "name": "name",
        },
        builder=_build_tags_only,
    ),
    ("route53resolver", "firewall_rule_group_association"): TfSpec(
        resource_type="aws_route53_resolver_firewall_rule_group_association",
        attribute_map={
            "name": "name",
            "firewall_rule_group_id": "firewall_rule_group_id",
            "vpc_id": "vpc_id",
            "priority": "priority",
            "mutation_protection": "mutation_protection",
        },
        builder=_build_tags_only,
    ),
    # --- S3 extensions (new) ------------------------------------------------
    ("s3", "directory_bucket"): TfSpec(
        resource_type="aws_s3_directory_bucket",
        attribute_map={
            "bucket": "bucket",
        },
        builder=_build_s3_directory_bucket,
    ),
    ("s3", "access_point"): TfSpec(
        resource_type="aws_s3_access_point",
        attribute_map={
            "name": "name",
            "bucket": "bucket",
            "policy": "policy",
        },
    ),
    # --- S3 Control extensions (new) ----------------------------------------
    ("s3control", "storage_lens_configuration"): TfSpec(
        resource_type="aws_s3control_storage_lens_configuration",
        attribute_map={
            "config_id": "config_id",
        },
        builder=_build_storage_lens,
    ),
    ("s3control", "multi_region_access_point"): TfSpec(
        resource_type="aws_s3control_multi_region_access_point",
        attribute_map={},
        builder=_build_multi_region_ap,
    ),
    ("s3control", "multi_region_access_point_policy"): TfSpec(
        resource_type="aws_s3control_multi_region_access_point_policy",
        attribute_map={},
        builder=_build_multi_region_ap_policy,
    ),
    ("s3control", "object_lambda_access_point"): TfSpec(
        resource_type="aws_s3control_object_lambda_access_point",
        attribute_map={
            "name": "name",
        },
        builder=_build_object_lambda_ap,
    ),
    ("s3control", "object_lambda_access_point_policy"): TfSpec(
        resource_type="aws_s3control_object_lambda_access_point_policy",
        attribute_map={
            "name": "name",
            "policy": "policy",
        },
    ),
    ("s3control", "bucket"): TfSpec(
        resource_type="aws_s3control_bucket",
        attribute_map={
            "bucket": "bucket",
            "outpost_id": "outpost_id",
        },
        builder=_build_tags_only,
    ),
    # --- SES extensions (new) -----------------------------------------------
    ("ses", "event_destination"): TfSpec(
        resource_type="aws_ses_event_destination",
        attribute_map={
            "name": "name",
            "configuration_set_name": "configuration_set_name",
            "enabled": "enabled",
            "matching_types": "matching_types",
        },
        builder=_build_ses_event_destination,
    ),
    ("ses", "contact_list"): TfSpec(
        resource_type="aws_sesv2_contact_list",
        attribute_map={
            "contact_list_name": "contact_list_name",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("ses", "dedicated_ip_pool"): TfSpec(
        resource_type="aws_sesv2_dedicated_ip_pool",
        attribute_map={
            "pool_name": "pool_name",
            "scaling_mode": "scaling_mode",
        },
        builder=_build_tags_only,
    ),
    ("ses", "account_vdm_attributes"): TfSpec(
        resource_type="aws_sesv2_account_vdm_attributes",
        attribute_map={
            "vdm_enabled": "vdm_enabled",
        },
        builder=_build_sesv2_vdm,
    ),
    # --- SSM extensions (new) -----------------------------------------------
    ("ssm", "maintenance_window_target"): TfSpec(
        resource_type="aws_ssm_maintenance_window_target",
        attribute_map={
            "window_id": "window_id",
            "resource_type": "resource_type",
            "name": "name",
            "description": "description",
        },
        builder=_build_ssm_mw_target,
    ),
    ("ssm", "maintenance_window_task"): TfSpec(
        resource_type="aws_ssm_maintenance_window_task",
        attribute_map={
            "window_id": "window_id",
            "task_type": "task_type",
            "task_arn": "task_arn",
            "max_concurrency": "max_concurrency",
            "max_errors": "max_errors",
            "priority": "priority",
            "service_role_arn": "service_role_arn",
            "name": "name",
        },
        builder=_build_ssm_mw_task,
    ),
    ("ssm", "resource_data_sync"): TfSpec(
        resource_type="aws_ssm_resource_data_sync",
        attribute_map={
            "name": "name",
        },
        builder=_build_ssm_data_sync,
    ),
    # NOTE: ``stepfunctions.state_machine_version`` has no dedicated Terraform
    # resource — AWS provider exposes versioning via ``publish = true`` on
    # ``aws_sfn_state_machine``. Do not add a ``TfSpec`` here; any IR
    # resource of this type is routed to the "unsupported" MANIFEST section.
    # --- Events / EventBridge extensions (new) ------------------------------
    ("events", "endpoint"): TfSpec(
        resource_type="aws_cloudwatch_event_endpoint",
        attribute_map={
            "name": "name",
            "description": "description",
        },
        builder=_build_events_endpoint,
    ),
    # --- Pipes (new) --------------------------------------------------------
    ("pipes", "pipe"): TfSpec(
        resource_type="aws_pipes_pipe",
        attribute_map={
            "name": "name",
            "source": "source",
            "target": "target",
            "role_arn": "role_arn",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- KMS extensions (new) -----------------------------------------------
    ("kms", "replica_key"): TfSpec(
        resource_type="aws_kms_replica_key",
        attribute_map={
            "primary_key_arn": "primary_key_arn",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- ACM ---------------------------------------------------------------
    ("acm", "certificate"): TfSpec(
        resource_type="aws_acm_certificate",
        attribute_map={
            "domain_name": "domain_name",
            "subject_alternative_names": "subject_alternative_names",
            "validation_method": "validation_method",
        },
        builder=_build_tags_only,
    ),
    # --- IAM extensions (new) ----------------------------------------------
    ("iam", "account_alias"): TfSpec(
        resource_type="aws_iam_account_alias",
        attribute_map={"account_alias": "account_alias"},
    ),
    ("iam", "account_password_policy"): TfSpec(
        resource_type="aws_iam_account_password_policy",
        attribute_map={
            "minimum_password_length": "minimum_password_length",
            "require_lowercase_characters": "require_lowercase_characters",
            "require_uppercase_characters": "require_uppercase_characters",
            "require_numbers": "require_numbers",
            "require_symbols": "require_symbols",
            "allow_users_to_change_password": "allow_users_to_change_password",
            "max_password_age": "max_password_age",
            "password_reuse_prevention": "password_reuse_prevention",
            "hard_expiry": "hard_expiry",
        },
    ),
    ("iam", "group_membership"): TfSpec(
        resource_type="aws_iam_group_membership",
        attribute_map={
            "name": "name",
            "users": "users",
            "group": "group",
        },
    ),
    ("iam", "user_login_profile"): TfSpec(
        resource_type="aws_iam_user_login_profile",
        attribute_map={
            "user": "user",
            "password_length": "password_length",
            "password_reset_required": "password_reset_required",
            "pgp_key": "pgp_key",
        },
    ),
    ("iam", "user_ssh_key"): TfSpec(
        resource_type="aws_iam_user_ssh_key",
        attribute_map={
            "username": "username",
            "encoding": "encoding",
            "public_key": "public_key",
            "status": "status",
        },
    ),
    ("iam", "virtual_mfa_device"): TfSpec(
        resource_type="aws_iam_virtual_mfa_device",
        attribute_map={
            "virtual_mfa_device_name": "virtual_mfa_device_name",
            "path": "path",
        },
        builder=_build_tags_only,
    ),
    ("iam", "signing_certificate"): TfSpec(
        resource_type="aws_iam_signing_certificate",
        attribute_map={
            "user_name": "user_name",
            "certificate_body": "certificate_body",
            "status": "status",
        },
    ),
    # --- S3 bucket configuration extensions (2026-04-18) -------------------
    ("s3", "bucket_replication_configuration"): TfSpec(
        resource_type="aws_s3_bucket_replication_configuration",
        attribute_map={"bucket": "bucket"},
        builder=_build_s3_replication_configuration,
    ),
    ("s3", "bucket_request_payment_configuration"): TfSpec(
        resource_type="aws_s3_bucket_request_payment_configuration",
        attribute_map={"bucket": "bucket", "payer": "payer"},
    ),
    ("s3", "bucket_object_lock_configuration"): TfSpec(
        resource_type="aws_s3_bucket_object_lock_configuration",
        attribute_map={
            "bucket": "bucket",
            "object_lock_enabled": "object_lock_enabled",
            "token": "token",
        },
        builder=_build_s3_object_lock,
    ),
    ("s3", "bucket_intelligent_tiering_configuration"): TfSpec(
        resource_type="aws_s3_bucket_intelligent_tiering_configuration",
        attribute_map={
            "bucket": "bucket",
            "name": "name",
            "status": "status",
        },
        builder=_build_s3_intelligent_tiering,
    ),
    ("s3", "bucket_inventory"): TfSpec(
        resource_type="aws_s3_bucket_inventory",
        attribute_map={
            "bucket": "bucket",
            "name": "name",
            "enabled": "enabled",
            "optional_fields": "optional_fields",
        },
        builder=_build_s3_inventory,
    ),
    ("s3", "bucket_metric"): TfSpec(
        resource_type="aws_s3_bucket_metric",
        attribute_map={
            "bucket": "bucket",
            "name": "name",
            "filter": "filter",
        },
    ),
    ("s3", "bucket_analytics_configuration"): TfSpec(
        resource_type="aws_s3_bucket_analytics_configuration",
        attribute_map={
            "bucket": "bucket",
            "name": "name",
            "filter": "filter",
            "storage_class_analysis": "storage_class_analysis",
        },
    ),
    ("s3", "bucket_accelerate_configuration"): TfSpec(
        resource_type="aws_s3_bucket_accelerate_configuration",
        attribute_map={
            "bucket": "bucket",
            "status": "status",
        },
        builder=_build_s3_accelerate,
    ),
    # --- Route53 extensions (2026-04-18) -----------------------------------
    ("route53", "vpc_association_authorization"): TfSpec(
        resource_type="aws_route53_vpc_association_authorization",
        attribute_map={
            "zone_id": "zone_id",
            "vpc_id": "vpc_id",
            "vpc_region": "vpc_region",
        },
    ),
    ("route53", "delegation_set"): TfSpec(
        resource_type="aws_route53_delegation_set",
        attribute_map={"reference_name": "reference_name"},
    ),
    ("route53", "traffic_policy"): TfSpec(
        resource_type="aws_route53_traffic_policy",
        attribute_map={
            "name": "name",
            "comment": "comment",
            "document": "document",
        },
    ),
    ("route53", "traffic_policy_instance"): TfSpec(
        resource_type="aws_route53_traffic_policy_instance",
        attribute_map={
            "name": "name",
            "hosted_zone_id": "hosted_zone_id",
            "traffic_policy_id": "traffic_policy_id",
            "traffic_policy_version": "traffic_policy_version",
            "ttl": "ttl",
        },
    ),
    ("route53", "hosted_zone_dnssec"): TfSpec(
        resource_type="aws_route53_hosted_zone_dnssec",
        attribute_map={
            "hosted_zone_id": "hosted_zone_id",
            "signing_status": "signing_status",
        },
    ),
    # --- RDS extensions (2026-04-18) ---------------------------------------
    ("rds", "db_snapshot"): TfSpec(
        resource_type="aws_db_snapshot",
        attribute_map={
            "db_instance_identifier": "db_instance_identifier",
            "db_snapshot_identifier": "db_snapshot_identifier",
            "shared_accounts": "shared_accounts",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_cluster_snapshot"): TfSpec(
        resource_type="aws_db_cluster_snapshot",
        attribute_map={
            "db_cluster_identifier": "db_cluster_identifier",
            "db_cluster_snapshot_identifier": "db_cluster_snapshot_identifier",
        },
        builder=_build_tags_only,
    ),
    ("rds", "db_instance_role_association"): TfSpec(
        resource_type="aws_db_instance_role_association",
        attribute_map={
            "db_instance_identifier": "db_instance_identifier",
            "role_arn": "role_arn",
            "feature_name": "feature_name",
        },
    ),
    ("rds", "db_cluster_role_association"): TfSpec(
        resource_type="aws_rds_cluster_role_association",
        attribute_map={
            "db_cluster_identifier": "db_cluster_identifier",
            "role_arn": "role_arn",
            "feature_name": "feature_name",
        },
    ),
    ("rds", "db_cluster_activity_stream"): TfSpec(
        resource_type="aws_rds_cluster_activity_stream",
        attribute_map={
            "resource_arn": "resource_arn",
            "mode": "mode",
            "kms_key_id": "kms_key_id",
            "engine_native_audit_fields_included": "engine_native_audit_fields_included",
        },
    ),
    # --- KMS extensions (2026-04-18) ---------------------------------------
    ("kms", "grant"): TfSpec(
        resource_type="aws_kms_grant",
        attribute_map={
            "name": "name",
            "key_id": "key_id",
            "grantee_principal": "grantee_principal",
            "operations": "operations",
            "retiring_principal": "retiring_principal",
        },
    ),
    ("kms", "key_policy"): TfSpec(
        resource_type="aws_kms_key_policy",
        attribute_map={
            "key_id": "key_id",
            "policy": "policy",
        },
    ),
    ("kms", "custom_key_store"): TfSpec(
        resource_type="aws_kms_custom_key_store",
        attribute_map={
            "custom_key_store_name": "custom_key_store_name",
            "custom_key_store_type": "custom_key_store_type",
            "cloud_hsm_cluster_id": "cloud_hsm_cluster_id",
            "key_store_password": "key_store_password",
            "trust_anchor_certificate": "trust_anchor_certificate",
        },
    ),
    ("kms", "external_key"): TfSpec(
        resource_type="aws_kms_external_key",
        attribute_map={
            "description": "description",
            "policy": "policy",
            "key_material_base64": "key_material_base64",
            "valid_to": "valid_to",
            "bypass_policy_lockout_safety_check": "bypass_policy_lockout_safety_check",
            "deletion_window_in_days": "deletion_window_in_days",
            "enabled": "enabled",
            "multi_region": "multi_region",
        },
        builder=_build_tags_only,
    ),
    # --- Misc singletons across services (2026-04-18) -----------------------
    ("acm", "certificate_validation"): TfSpec(
        resource_type="aws_acm_certificate_validation",
        attribute_map={
            "certificate_arn": "certificate_arn",
            "validation_record_fqdns": "validation_record_fqdns",
        },
    ),
    ("secretsmanager", "secret_version"): TfSpec(
        resource_type="aws_secretsmanager_secret_version",
        attribute_map={
            "secret_id": "secret_id",
            "secret_string": "secret_string",
            "secret_binary": "secret_binary",
            "version_stages": "version_stages",
        },
    ),
    ("lambda", "provisioned_concurrency_config"): TfSpec(
        resource_type="aws_lambda_provisioned_concurrency_config",
        attribute_map={
            "function_name": "function_name",
            "provisioned_concurrent_executions": "provisioned_concurrent_executions",
            "qualifier": "qualifier",
        },
    ),
    ("dynamodb", "resource_policy"): TfSpec(
        resource_type="aws_dynamodb_resource_policy",
        attribute_map={
            "resource_arn": "resource_arn",
            "policy": "policy",
        },
    ),
    ("dynamodb", "tag"): TfSpec(
        resource_type="aws_dynamodb_tag",
        attribute_map={
            "resource_arn": "resource_arn",
            "key": "key",
            "value": "value",
        },
    ),
    ("ecs", "account_setting_default"): TfSpec(
        resource_type="aws_ecs_account_setting_default",
        attribute_map={
            "name": "name",
            "value": "value",
        },
    ),
    ("redshift", "logging"): TfSpec(
        resource_type="aws_redshift_logging",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "log_destination_type": "log_destination_type",
            "log_exports": "log_exports",
            "bucket_name": "bucket_name",
            "s3_key_prefix": "s3_key_prefix",
        },
    ),
    ("redshift", "snapshot_copy_grant"): TfSpec(
        resource_type="aws_redshift_snapshot_copy_grant",
        attribute_map={
            "snapshot_copy_grant_name": "snapshot_copy_grant_name",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    ("sns", "data_protection_policy"): TfSpec(
        resource_type="aws_sns_topic_data_protection_policy",
        attribute_map={
            "arn": "arn",
            "policy": "policy",
        },
    ),
    ("transcribe", "medical_vocabulary"): TfSpec(
        resource_type="aws_transcribe_medical_vocabulary",
        attribute_map={
            "vocabulary_name": "vocabulary_name",
            "language_code": "language_code",
            "vocabulary_file_uri": "vocabulary_file_uri",
        },
        builder=_build_tags_only,
    ),
    ("transcribe", "language_model"): TfSpec(
        resource_type="aws_transcribe_language_model",
        attribute_map={
            "model_name": "model_name",
            "language_code": "language_code",
            "base_model_name": "base_model_name",
        },
        builder=_build_transcribe_language_model,
    ),
    ("logs", "destination_policy"): TfSpec(
        resource_type="aws_cloudwatch_log_destination_policy",
        attribute_map={
            "destination_name": "destination_name",
            "access_policy": "access_policy",
            "force_update": "force_update",
        },
    ),
    # --- EC2 association extensions (2026-04-18) ---------------------------
    ("ec2", "main_route_table_association"): TfSpec(
        resource_type="aws_main_route_table_association",
        attribute_map={
            "vpc_id": "vpc_id",
            "route_table_id": "route_table_id",
        },
    ),
    # NOTE: there is no ``aws_nat_gateway_eip_association`` resource in
    # hashicorp/aws. Additional EIPs on a NAT Gateway are attached via
    # ``secondary_allocation_ids`` directly on ``aws_nat_gateway``, so no
    # standalone spec makes sense here. Kept as a comment anchor so the
    # absence is deliberate.
    ("ec2", "vpc_endpoint_route_table_association"): TfSpec(
        resource_type="aws_vpc_endpoint_route_table_association",
        attribute_map={
            "vpc_endpoint_id": "vpc_endpoint_id",
            "route_table_id": "route_table_id",
        },
    ),
    ("ec2", "vpc_endpoint_subnet_association"): TfSpec(
        resource_type="aws_vpc_endpoint_subnet_association",
        attribute_map={
            "vpc_endpoint_id": "vpc_endpoint_id",
            "subnet_id": "subnet_id",
        },
    ),
    ("ec2", "vpc_endpoint_security_group_association"): TfSpec(
        resource_type="aws_vpc_endpoint_security_group_association",
        attribute_map={
            "vpc_endpoint_id": "vpc_endpoint_id",
            "security_group_id": "security_group_id",
        },
    ),
    ("ec2", "vpc_endpoint_connection_accepter"): TfSpec(
        resource_type="aws_vpc_endpoint_connection_accepter",
        attribute_map={
            "vpc_endpoint_service_id": "vpc_endpoint_service_id",
            "vpc_endpoint_id": "vpc_endpoint_id",
        },
    ),
    ("ec2", "vpc_peering_connection_options"): TfSpec(
        resource_type="aws_vpc_peering_connection_options",
        attribute_map={
            "vpc_peering_connection_id": "vpc_peering_connection_id",
            "accepter": "accepter",
            "requester": "requester",
        },
    ),
    ("ec2", "network_interface_sg_attachment"): TfSpec(
        resource_type="aws_network_interface_sg_attachment",
        attribute_map={
            "security_group_id": "security_group_id",
            "network_interface_id": "network_interface_id",
        },
    ),
    ("ec2", "ec2_managed_prefix_list_entry"): TfSpec(
        resource_type="aws_ec2_managed_prefix_list_entry",
        attribute_map={
            "prefix_list_id": "prefix_list_id",
            "cidr": "cidr",
            "description": "description",
        },
    ),
    ("ec2", "ebs_snapshot_copy"): TfSpec(
        resource_type="aws_ebs_snapshot_copy",
        attribute_map={
            "source_snapshot_id": "source_snapshot_id",
            "source_region": "source_region",
            "description": "description",
            "encrypted": "encrypted",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    ("ec2", "ebs_default_kms_key"): TfSpec(
        resource_type="aws_ebs_default_kms_key",
        attribute_map={
            "key_arn": "key_arn",
        },
    ),
    ("ec2", "ebs_encryption_by_default"): TfSpec(
        resource_type="aws_ebs_encryption_by_default",
        attribute_map={
            "enabled": "enabled",
        },
    ),
    # --- SES extensions (2026-04-18) ---------------------------------------
    ("ses", "domain_dkim"): TfSpec(
        resource_type="aws_ses_domain_dkim",
        attribute_map={"domain": "domain"},
    ),
    ("ses", "domain_mail_from"): TfSpec(
        resource_type="aws_ses_domain_mail_from",
        attribute_map={
            "domain": "domain",
            "mail_from_domain": "mail_from_domain",
            "behavior_on_mx_failure": "behavior_on_mx_failure",
        },
    ),
    ("ses", "identity_notification_topic"): TfSpec(
        resource_type="aws_ses_identity_notification_topic",
        attribute_map={
            "identity": "identity",
            "notification_type": "notification_type",
            "topic_arn": "topic_arn",
            "include_original_headers": "include_original_headers",
        },
    ),
    ("ses", "identity_policy"): TfSpec(
        resource_type="aws_ses_identity_policy",
        attribute_map={
            "identity": "identity",
            "name": "name",
            "policy": "policy",
        },
    ),
    ("ses", "active_receipt_rule_set"): TfSpec(
        resource_type="aws_ses_active_receipt_rule_set",
        attribute_map={"rule_set_name": "rule_set_name"},
    ),
    ("ses", "domain_identity_verification"): TfSpec(
        resource_type="aws_ses_domain_identity_verification",
        attribute_map={"domain": "domain"},
    ),
    # --- Redshift extensions (2026-04-18) ----------------------------------
    ("redshift", "snapshot_schedule_association"): TfSpec(
        resource_type="aws_redshift_snapshot_schedule_association",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "schedule_identifier": "schedule_identifier",
        },
    ),
    ("redshift", "usage_limit"): TfSpec(
        resource_type="aws_redshift_usage_limit",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "feature_type": "feature_type",
            "limit_type": "limit_type",
            "amount": "amount",
            "breach_action": "breach_action",
            "period": "period",
        },
        builder=_build_tags_only,
    ),
    ("redshift", "resource_policy"): TfSpec(
        resource_type="aws_redshift_resource_policy",
        attribute_map={
            "resource_arn": "resource_arn",
            "policy": "policy",
        },
    ),
    ("redshift", "cluster_iam_roles"): TfSpec(
        resource_type="aws_redshift_cluster_iam_roles",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "iam_role_arns": "iam_role_arns",
            "default_iam_role_arn": "default_iam_role_arn",
        },
    ),
    # --- Elasticache (2026-04-19) ------------------------------------------
    ("elasticache", "cluster"): TfSpec(
        resource_type="aws_elasticache_cluster",
        attribute_map={
            "cluster_id": "cluster_id",
            "engine": "engine",
            "engine_version": "engine_version",
            "node_type": "node_type",
            "num_cache_nodes": "num_cache_nodes",
            "parameter_group_name": "parameter_group_name",
            "port": "port",
            "subnet_group_name": "subnet_group_name",
            "security_group_ids": "security_group_ids",
            "snapshot_retention_limit": "snapshot_retention_limit",
            "apply_immediately": "apply_immediately",
        },
        builder=_build_tags_only,
    ),
    ("elasticache", "replication_group"): TfSpec(
        resource_type="aws_elasticache_replication_group",
        attribute_map={
            "replication_group_id": "replication_group_id",
            "description": "description",
            "engine": "engine",
            "engine_version": "engine_version",
            "node_type": "node_type",
            "num_cache_clusters": "num_cache_clusters",
            "automatic_failover_enabled": "automatic_failover_enabled",
            "multi_az_enabled": "multi_az_enabled",
            "port": "port",
            "parameter_group_name": "parameter_group_name",
            "subnet_group_name": "subnet_group_name",
            "security_group_ids": "security_group_ids",
            "at_rest_encryption_enabled": "at_rest_encryption_enabled",
            "transit_encryption_enabled": "transit_encryption_enabled",
        },
        builder=_build_tags_only,
    ),
    ("elasticache", "subnet_group"): TfSpec(
        resource_type="aws_elasticache_subnet_group",
        attribute_map={
            "name": "name",
            "description": "description",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_tags_only,
    ),
    ("elasticache", "parameter_group"): TfSpec(
        resource_type="aws_elasticache_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
            "parameter": "parameter",
        },
        builder=_build_tags_only,
    ),
    ("elasticache", "user"): TfSpec(
        resource_type="aws_elasticache_user",
        attribute_map={
            "user_id": "user_id",
            "user_name": "user_name",
            "access_string": "access_string",
            "engine": "engine",
            "passwords": "passwords",
        },
        builder=_build_tags_only,
    ),
    ("elasticache", "user_group"): TfSpec(
        resource_type="aws_elasticache_user_group",
        attribute_map={
            "user_group_id": "user_group_id",
            "engine": "engine",
            "user_ids": "user_ids",
        },
        builder=_build_tags_only,
    ),
    # --- Backup (2026-04-19) -----------------------------------------------
    ("backup", "vault"): TfSpec(
        resource_type="aws_backup_vault",
        attribute_map={
            "name": "name",
            "kms_key_arn": "kms_key_arn",
            "force_destroy": "force_destroy",
        },
        builder=_build_tags_only,
    ),
    ("backup", "plan"): TfSpec(
        resource_type="aws_backup_plan",
        attribute_map={
            "name": "name",
            "advanced_backup_setting": "advanced_backup_setting",
        },
        builder=_build_backup_plan,
    ),
    ("backup", "selection"): TfSpec(
        resource_type="aws_backup_selection",
        attribute_map={
            "name": "name",
            "plan_id": "plan_id",
            "iam_role_arn": "iam_role_arn",
            "resources": "resources",
            "not_resources": "not_resources",
        },
    ),
    ("backup", "vault_policy"): TfSpec(
        resource_type="aws_backup_vault_policy",
        attribute_map={
            "backup_vault_name": "backup_vault_name",
            "policy": "policy",
        },
    ),
    ("backup", "vault_lock_configuration"): TfSpec(
        resource_type="aws_backup_vault_lock_configuration",
        attribute_map={
            "backup_vault_name": "backup_vault_name",
            "max_retention_days": "max_retention_days",
            "min_retention_days": "min_retention_days",
            "changeable_for_days": "changeable_for_days",
        },
    ),
    # --- WAF v2 (2026-04-19) -----------------------------------------------
    ("wafv2", "web_acl"): TfSpec(
        resource_type="aws_wafv2_web_acl",
        attribute_map={
            "name": "name",
            "scope": "scope",
            "description": "description",
        },
        builder=_build_wafv2_web_acl,
    ),
    ("wafv2", "rule_group"): TfSpec(
        resource_type="aws_wafv2_rule_group",
        attribute_map={
            "name": "name",
            "scope": "scope",
            "capacity": "capacity",
            "description": "description",
        },
        builder=_build_wafv2_rule_group,
    ),
    ("wafv2", "ip_set"): TfSpec(
        resource_type="aws_wafv2_ip_set",
        attribute_map={
            "name": "name",
            "scope": "scope",
            "ip_address_version": "ip_address_version",
            "addresses": "addresses",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("wafv2", "regex_pattern_set"): TfSpec(
        resource_type="aws_wafv2_regex_pattern_set",
        attribute_map={
            "name": "name",
            "scope": "scope",
            "description": "description",
        },
        builder=_build_wafv2_regex_set,
    ),
    ("wafv2", "web_acl_association"): TfSpec(
        resource_type="aws_wafv2_web_acl_association",
        attribute_map={
            "web_acl_arn": "web_acl_arn",
            "resource_arn": "resource_arn",
        },
    ),
    ("wafv2", "web_acl_logging_configuration"): TfSpec(
        resource_type="aws_wafv2_web_acl_logging_configuration",
        attribute_map={
            "resource_arn": "resource_arn",
        },
        builder=_build_wafv2_logging,
    ),
    # --- Glue (2026-04-19) -------------------------------------------------
    ("glue", "catalog_database"): TfSpec(
        resource_type="aws_glue_catalog_database",
        attribute_map={
            "name": "name",
            "description": "description",
            "location_uri": "location_uri",
            "parameters": "parameters",
        },
    ),
    ("glue", "catalog_table"): TfSpec(
        resource_type="aws_glue_catalog_table",
        attribute_map={
            "name": "name",
            "database_name": "database_name",
            "description": "description",
            "table_type": "table_type",
            "parameters": "parameters",
            "storage_descriptor": "storage_descriptor",
        },
    ),
    ("glue", "job"): TfSpec(
        resource_type="aws_glue_job",
        attribute_map={
            "name": "name",
            "role_arn": "role_arn",
            "description": "description",
            "glue_version": "glue_version",
            "max_capacity": "max_capacity",
            "max_retries": "max_retries",
            "number_of_workers": "number_of_workers",
            "worker_type": "worker_type",
            "timeout": "timeout",
        },
        builder=_build_glue_job,
    ),
    ("glue", "crawler"): TfSpec(
        resource_type="aws_glue_crawler",
        attribute_map={
            "name": "name",
            "role": "role",
            "database_name": "database_name",
            "description": "description",
            "schedule": "schedule",
            "table_prefix": "table_prefix",
            "classifiers": "classifiers",
        },
        builder=_build_glue_crawler,
    ),
    ("glue", "trigger"): TfSpec(
        resource_type="aws_glue_trigger",
        attribute_map={
            "name": "name",
            "type": "type",
            "description": "description",
            "schedule": "schedule",
            "workflow_name": "workflow_name",
            "enabled": "enabled",
        },
        builder=_build_glue_trigger,
    ),
    ("glue", "workflow"): TfSpec(
        resource_type="aws_glue_workflow",
        attribute_map={
            "name": "name",
            "description": "description",
            "max_concurrent_runs": "max_concurrent_runs",
        },
        builder=_build_tags_only,
    ),
    # --- AppConfig (2026-04-19) --------------------------------------------
    ("appconfig", "application"): TfSpec(
        resource_type="aws_appconfig_application",
        attribute_map={
            "name": "name",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("appconfig", "environment"): TfSpec(
        resource_type="aws_appconfig_environment",
        attribute_map={
            "name": "name",
            "application_id": "application_id",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("appconfig", "configuration_profile"): TfSpec(
        resource_type="aws_appconfig_configuration_profile",
        attribute_map={
            "name": "name",
            "application_id": "application_id",
            "location_uri": "location_uri",
            "retrieval_role_arn": "retrieval_role_arn",
            "type": "type",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("appconfig", "deployment_strategy"): TfSpec(
        resource_type="aws_appconfig_deployment_strategy",
        attribute_map={
            "name": "name",
            "deployment_duration_in_minutes": "deployment_duration_in_minutes",
            "growth_factor": "growth_factor",
            "replicate_to": "replicate_to",
            "growth_type": "growth_type",
            "final_bake_time_in_minutes": "final_bake_time_in_minutes",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("appconfig", "hosted_configuration_version"): TfSpec(
        resource_type="aws_appconfig_hosted_configuration_version",
        attribute_map={
            "application_id": "application_id",
            "configuration_profile_id": "configuration_profile_id",
            "content": "content",
            "content_type": "content_type",
            "description": "description",
        },
    ),
    # --- CodeCommit (2026-04-19) -------------------------------------------
    ("codecommit", "repository"): TfSpec(
        resource_type="aws_codecommit_repository",
        attribute_map={
            "repository_name": "repository_name",
            "description": "description",
            "default_branch": "default_branch",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    ("codecommit", "approval_rule_template"): TfSpec(
        resource_type="aws_codecommit_approval_rule_template",
        attribute_map={
            "name": "name",
            "content": "content",
            "description": "description",
        },
    ),
    # --- CodeBuild (2026-04-19) --------------------------------------------
    ("codebuild", "project"): TfSpec(
        resource_type="aws_codebuild_project",
        attribute_map={
            "name": "name",
            "service_role": "service_role",
            "description": "description",
            "build_timeout": "build_timeout",
            "queued_timeout": "queued_timeout",
            "concurrent_build_limit": "concurrent_build_limit",
        },
        builder=_build_codebuild_project,
    ),
    ("codebuild", "webhook"): TfSpec(
        resource_type="aws_codebuild_webhook",
        attribute_map={
            "project_name": "project_name",
            "branch_filter": "branch_filter",
            "build_type": "build_type",
            "filter_group": "filter_group",
        },
    ),
    ("codebuild", "report_group"): TfSpec(
        resource_type="aws_codebuild_report_group",
        attribute_map={
            "name": "name",
            "type": "type",
            "delete_reports": "delete_reports",
        },
        builder=_build_codebuild_report_group,
    ),
    ("codebuild", "source_credential"): TfSpec(
        resource_type="aws_codebuild_source_credential",
        attribute_map={
            "auth_type": "auth_type",
            "server_type": "server_type",
            "token": "token",
            "user_name": "user_name",
        },
    ),
    # --- CodePipeline (2026-04-19) -----------------------------------------
    ("codepipeline", "codepipeline"): TfSpec(
        resource_type="aws_codepipeline",
        attribute_map={
            "name": "name",
            "role_arn": "role_arn",
            "pipeline_type": "pipeline_type",
            "execution_mode": "execution_mode",
        },
        builder=_build_codepipeline,
    ),
    ("codepipeline", "webhook"): TfSpec(
        resource_type="aws_codepipeline_webhook",
        attribute_map={
            "name": "name",
            "authentication": "authentication",
            "target_action": "target_action",
            "target_pipeline": "target_pipeline",
            "filter": "filter",
            "authentication_configuration": "authentication_configuration",
        },
        builder=_build_tags_only,
    ),
    ("codepipeline", "custom_action_type"): TfSpec(
        resource_type="aws_codepipeline_custom_action_type",
        attribute_map={
            "category": "category",
            "provider_name": "provider_name",
            "version": "version",
            "input_artifact_details": "input_artifact_details",
            "output_artifact_details": "output_artifact_details",
        },
        builder=_build_tags_only,
    ),
    # --- CodeDeploy (2026-04-19) -------------------------------------------
    ("codedeploy", "app"): TfSpec(
        resource_type="aws_codedeploy_app",
        attribute_map={
            "name": "name",
            "compute_platform": "compute_platform",
        },
        builder=_build_tags_only,
    ),
    ("codedeploy", "deployment_group"): TfSpec(
        resource_type="aws_codedeploy_deployment_group",
        attribute_map={
            "app_name": "app_name",
            "deployment_group_name": "deployment_group_name",
            "service_role_arn": "service_role_arn",
            "deployment_config_name": "deployment_config_name",
            "autoscaling_groups": "autoscaling_groups",
        },
        builder=_build_tags_only,
    ),
    ("codedeploy", "deployment_config"): TfSpec(
        resource_type="aws_codedeploy_deployment_config",
        attribute_map={
            "deployment_config_name": "deployment_config_name",
            "compute_platform": "compute_platform",
        },
        builder=_build_codedeploy_deployment_config,
    ),
    # --- IoT Core (2026-04-19) ---------------------------------------------
    ("iot", "thing"): TfSpec(
        resource_type="aws_iot_thing",
        attribute_map={
            "name": "name",
            "thing_type_name": "thing_type_name",
            "attributes": "attributes",
        },
    ),
    ("iot", "thing_type"): TfSpec(
        resource_type="aws_iot_thing_type",
        attribute_map={
            "name": "name",
            "deprecated": "deprecated",
            "properties": "properties",
        },
        builder=_build_tags_only,
    ),
    ("iot", "thing_group"): TfSpec(
        resource_type="aws_iot_thing_group",
        attribute_map={
            "name": "name",
            "parent_group_name": "parent_group_name",
            "properties": "properties",
        },
        builder=_build_tags_only,
    ),
    ("iot", "policy"): TfSpec(
        resource_type="aws_iot_policy",
        attribute_map={
            "name": "name",
            "policy": "policy",
        },
    ),
    ("iot", "topic_rule"): TfSpec(
        resource_type="aws_iot_topic_rule",
        attribute_map={
            "name": "name",
            "description": "description",
        },
        builder=_build_iot_topic_rule,
    ),
    ("iot", "role_alias"): TfSpec(
        resource_type="aws_iot_role_alias",
        attribute_map={
            "alias": "alias",
            "role_arn": "role_arn",
            "credential_duration": "credential_duration",
        },
    ),
    # --- Organizations (2026-04-19) ----------------------------------------
    ("organizations", "organization"): TfSpec(
        resource_type="aws_organizations_organization",
        attribute_map={
            "feature_set": "feature_set",
            "aws_service_access_principals": "aws_service_access_principals",
            "enabled_policy_types": "enabled_policy_types",
        },
    ),
    ("organizations", "account"): TfSpec(
        resource_type="aws_organizations_account",
        attribute_map={
            "name": "name",
            "email": "email",
            "parent_id": "parent_id",
            "role_name": "role_name",
            "iam_user_access_to_billing": "iam_user_access_to_billing",
            "close_on_deletion": "close_on_deletion",
        },
        builder=_build_tags_only,
    ),
    ("organizations", "organizational_unit"): TfSpec(
        resource_type="aws_organizations_organizational_unit",
        attribute_map={
            "name": "name",
            "parent_id": "parent_id",
        },
        builder=_build_tags_only,
    ),
    ("organizations", "policy"): TfSpec(
        resource_type="aws_organizations_policy",
        attribute_map={
            "name": "name",
            "content": "content",
            "type": "type",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("organizations", "policy_attachment"): TfSpec(
        resource_type="aws_organizations_policy_attachment",
        attribute_map={
            "policy_id": "policy_id",
            "target_id": "target_id",
        },
    ),
    # --- MSK / Kafka (2026-04-19) ------------------------------------------
    ("kafka", "cluster"): TfSpec(
        resource_type="aws_msk_cluster",
        attribute_map={
            "cluster_name": "cluster_name",
            "kafka_version": "kafka_version",
            "number_of_broker_nodes": "number_of_broker_nodes",
            "enhanced_monitoring": "enhanced_monitoring",
        },
        builder=_build_msk_cluster,
    ),
    ("kafka", "configuration"): TfSpec(
        resource_type="aws_msk_configuration",
        attribute_map={
            "name": "name",
            "kafka_versions": "kafka_versions",
            "server_properties": "server_properties",
            "description": "description",
        },
    ),
    ("kafka", "scram_secret_association"): TfSpec(
        resource_type="aws_msk_scram_secret_association",
        attribute_map={
            "cluster_arn": "cluster_arn",
            "secret_arn_list": "secret_arn_list",
        },
    ),
    ("kafka", "serverless_cluster"): TfSpec(
        resource_type="aws_msk_serverless_cluster",
        attribute_map={
            "cluster_name": "cluster_name",
        },
        builder=_build_msk_serverless_cluster,
    ),
    # --- Neptune (2026-04-19) ----------------------------------------------
    ("neptune", "cluster"): TfSpec(
        resource_type="aws_neptune_cluster",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "engine": "engine",
            "engine_version": "engine_version",
            "backup_retention_period": "backup_retention_period",
            "preferred_backup_window": "preferred_backup_window",
            "iam_database_authentication_enabled": "iam_database_authentication_enabled",
            "skip_final_snapshot": "skip_final_snapshot",
            "apply_immediately": "apply_immediately",
        },
        builder=_build_tags_only,
    ),
    ("neptune", "cluster_instance"): TfSpec(
        resource_type="aws_neptune_cluster_instance",
        attribute_map={
            "cluster_identifier": "cluster_identifier",
            "instance_class": "instance_class",
            "engine": "engine",
            "apply_immediately": "apply_immediately",
        },
        builder=_build_tags_only,
    ),
    ("neptune", "cluster_parameter_group"): TfSpec(
        resource_type="aws_neptune_cluster_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("neptune", "parameter_group"): TfSpec(
        resource_type="aws_neptune_parameter_group",
        attribute_map={
            "name": "name",
            "family": "family",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("neptune", "subnet_group"): TfSpec(
        resource_type="aws_neptune_subnet_group",
        attribute_map={
            "name": "name",
            "description": "description",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_tags_only,
    ),
    # --- MQ (2026-04-19) ---------------------------------------------------
    ("mq", "broker"): TfSpec(
        resource_type="aws_mq_broker",
        attribute_map={
            "broker_name": "broker_name",
            "engine_type": "engine_type",
            "engine_version": "engine_version",
            "host_instance_type": "host_instance_type",
            "deployment_mode": "deployment_mode",
            "publicly_accessible": "publicly_accessible",
        },
        builder=_build_mq_broker,
    ),
    ("mq", "configuration"): TfSpec(
        resource_type="aws_mq_configuration",
        attribute_map={
            "name": "name",
            "engine_type": "engine_type",
            "engine_version": "engine_version",
            "data": "data",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- Batch (2026-04-19) ------------------------------------------------
    ("batch", "compute_environment"): TfSpec(
        resource_type="aws_batch_compute_environment",
        attribute_map={
            "name": "compute_environment_name",
            "compute_environment_name": "compute_environment_name",
            "service_role": "service_role",
            "type": "type",
            "state": "state",
        },
        builder=_build_batch_compute_environment,
    ),
    ("batch", "job_queue"): TfSpec(
        resource_type="aws_batch_job_queue",
        attribute_map={
            "name": "name",
            "state": "state",
            "priority": "priority",
            "scheduling_policy_arn": "scheduling_policy_arn",
        },
        builder=_build_batch_job_queue,
    ),
    ("batch", "job_definition"): TfSpec(
        resource_type="aws_batch_job_definition",
        attribute_map={
            "name": "name",
            "type": "type",
            "platform_capabilities": "platform_capabilities",
            "propagate_tags": "propagate_tags",
            "container_properties": "container_properties",
            "ecs_properties": "ecs_properties",
            "node_properties": "node_properties",
        },
        builder=_build_tags_only,
    ),
    ("batch", "scheduling_policy"): TfSpec(
        resource_type="aws_batch_scheduling_policy",
        attribute_map={"name": "name"},
        builder=_build_batch_scheduling_policy,
    ),
    # --- EMR (2026-04-19) --------------------------------------------------
    ("emr", "cluster"): TfSpec(
        resource_type="aws_emr_cluster",
        attribute_map={
            "name": "name",
            "release_label": "release_label",
            "service_role": "service_role",
            "applications": "applications",
            "ec2_attributes": "ec2_attributes",
            "master_instance_group": "master_instance_group",
            "core_instance_group": "core_instance_group",
            "step": "step",
        },
        builder=_build_tags_only,
    ),
    ("emr", "security_configuration"): TfSpec(
        resource_type="aws_emr_security_configuration",
        attribute_map={
            "name": "name",
            "configuration": "configuration",
        },
    ),
    ("emr", "managed_scaling_policy"): TfSpec(
        resource_type="aws_emr_managed_scaling_policy",
        attribute_map={
            "cluster_id": "cluster_id",
            "compute_limits": "compute_limits",
        },
    ),
    # --- Timestream Write (2026-04-19) -------------------------------------
    ("timestream-write", "database"): TfSpec(
        resource_type="aws_timestreamwrite_database",
        attribute_map={
            "database_name": "database_name",
            "kms_key_id": "kms_key_id",
        },
        builder=_build_tags_only,
    ),
    ("timestream-write", "table"): TfSpec(
        resource_type="aws_timestreamwrite_table",
        attribute_map={
            "database_name": "database_name",
            "table_name": "table_name",
            "retention_properties": "retention_properties",
            "magnetic_store_write_properties": "magnetic_store_write_properties",
        },
        builder=_build_tags_only,
    ),
    # --- GuardDuty (2026-04-19) --------------------------------------------
    ("guardduty", "detector"): TfSpec(
        resource_type="aws_guardduty_detector",
        attribute_map={
            "enable": "enable",
            "finding_publishing_frequency": "finding_publishing_frequency",
            "datasources": "datasources",
        },
        builder=_build_tags_only,
    ),
    ("guardduty", "filter"): TfSpec(
        resource_type="aws_guardduty_filter",
        attribute_map={
            "name": "name",
            "detector_id": "detector_id",
            "action": "action",
            "rank": "rank",
            "finding_criteria": "finding_criteria",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    ("guardduty", "ipset"): TfSpec(
        resource_type="aws_guardduty_ipset",
        attribute_map={
            "name": "name",
            "detector_id": "detector_id",
            "format": "format",
            "location": "location",
            "activate": "activate",
        },
        builder=_build_tags_only,
    ),
    ("guardduty", "threatintelset"): TfSpec(
        resource_type="aws_guardduty_threatintelset",
        attribute_map={
            "name": "name",
            "detector_id": "detector_id",
            "format": "format",
            "location": "location",
            "activate": "activate",
        },
        builder=_build_tags_only,
    ),
    ("guardduty", "member"): TfSpec(
        resource_type="aws_guardduty_member",
        attribute_map={
            "account_id": "account_id",
            "detector_id": "detector_id",
            "email": "email",
            "invite": "invite",
            "invitation_message": "invitation_message",
        },
    ),
    ("guardduty", "organization_admin_account"): TfSpec(
        resource_type="aws_guardduty_organization_admin_account",
        attribute_map={"admin_account_id": "admin_account_id"},
    ),
    # --- Lake Formation (2026-04-19) ---------------------------------------
    ("lakeformation", "data_lake_settings"): TfSpec(
        resource_type="aws_lakeformation_data_lake_settings",
        attribute_map={
            "catalog_id": "catalog_id",
            "admins": "admins",
            "read_only_admins": "read_only_admins",
            "trusted_resource_owners": "trusted_resource_owners",
            "allow_external_data_filtering": "allow_external_data_filtering",
            "authorized_session_tag_value_list": "authorized_session_tag_value_list",
        },
    ),
    ("lakeformation", "permissions"): TfSpec(
        resource_type="aws_lakeformation_permissions",
        attribute_map={
            "principal": "principal",
            "permissions": "permissions",
            "permissions_with_grant_option": "permissions_with_grant_option",
            "database": "database",
            "table": "table",
            "table_with_columns": "table_with_columns",
            "data_location": "data_location",
            "catalog_resource": "catalog_resource",
        },
    ),
    ("lakeformation", "resource"): TfSpec(
        resource_type="aws_lakeformation_resource",
        attribute_map={
            "arn": "arn",
            "role_arn": "role_arn",
            "use_service_linked_role": "use_service_linked_role",
        },
    ),
    ("lakeformation", "lf_tag"): TfSpec(
        resource_type="aws_lakeformation_lf_tag",
        attribute_map={
            "key": "key",
            "values": "values",
            "catalog_id": "catalog_id",
        },
    ),
    # --- DMS (Database Migration Service) (2026-04-19) ---------------------
    ("dms", "replication_instance"): TfSpec(
        resource_type="aws_dms_replication_instance",
        attribute_map={
            "replication_instance_id": "replication_instance_id",
            "replication_instance_class": "replication_instance_class",
            "allocated_storage": "allocated_storage",
            "engine_version": "engine_version",
            "publicly_accessible": "publicly_accessible",
            "multi_az": "multi_az",
            "apply_immediately": "apply_immediately",
        },
        builder=_build_tags_only,
    ),
    ("dms", "replication_subnet_group"): TfSpec(
        resource_type="aws_dms_replication_subnet_group",
        attribute_map={
            "replication_subnet_group_id": "replication_subnet_group_id",
            "replication_subnet_group_description": "replication_subnet_group_description",
            "subnet_ids": "subnet_ids",
        },
        builder=_build_tags_only,
    ),
    ("dms", "endpoint"): TfSpec(
        resource_type="aws_dms_endpoint",
        attribute_map={
            "endpoint_id": "endpoint_id",
            "endpoint_type": "endpoint_type",
            "engine_name": "engine_name",
            "database_name": "database_name",
            "server_name": "server_name",
            "port": "port",
            "username": "username",
            "password": "password",
        },
        builder=_build_tags_only,
    ),
    ("dms", "replication_task"): TfSpec(
        resource_type="aws_dms_replication_task",
        attribute_map={
            "replication_task_id": "replication_task_id",
            "migration_type": "migration_type",
            "replication_instance_arn": "replication_instance_arn",
            "source_endpoint_arn": "source_endpoint_arn",
            "target_endpoint_arn": "target_endpoint_arn",
            "table_mappings": "table_mappings",
            "replication_task_settings": "replication_task_settings",
        },
        builder=_build_tags_only,
    ),
    ("dms", "event_subscription"): TfSpec(
        resource_type="aws_dms_event_subscription",
        attribute_map={
            "name": "name",
            "sns_topic_arn": "sns_topic_arn",
            "source_type": "source_type",
            "event_categories": "event_categories",
            "enabled": "enabled",
        },
        builder=_build_tags_only,
    ),
    # --- SageMaker (2026-04-19) --------------------------------------------
    ("sagemaker", "endpoint"): TfSpec(
        resource_type="aws_sagemaker_endpoint",
        attribute_map={
            "name": "name",
            "endpoint_config_name": "endpoint_config_name",
        },
        builder=_build_tags_only,
    ),
    ("sagemaker", "endpoint_configuration"): TfSpec(
        resource_type="aws_sagemaker_endpoint_configuration",
        attribute_map={
            "name": "name",
            "kms_key_arn": "kms_key_arn",
        },
        builder=_build_sagemaker_endpoint_config,
    ),
    ("sagemaker", "model"): TfSpec(
        resource_type="aws_sagemaker_model",
        attribute_map={
            "name": "name",
            "execution_role_arn": "execution_role_arn",
        },
        builder=_build_sagemaker_model,
    ),
    ("sagemaker", "notebook_instance"): TfSpec(
        resource_type="aws_sagemaker_notebook_instance",
        attribute_map={
            "name": "name",
            "role_arn": "role_arn",
            "instance_type": "instance_type",
            "volume_size": "volume_size",
            "platform_identifier": "platform_identifier",
            "direct_internet_access": "direct_internet_access",
        },
        builder=_build_tags_only,
    ),
    ("sagemaker", "feature_group"): TfSpec(
        resource_type="aws_sagemaker_feature_group",
        attribute_map={
            "feature_group_name": "feature_group_name",
            "record_identifier_feature_name": "record_identifier_feature_name",
            "event_time_feature_name": "event_time_feature_name",
            "role_arn": "role_arn",
            "description": "description",
        },
        builder=_build_sagemaker_feature_group,
    ),
    ("sagemaker", "domain"): TfSpec(
        resource_type="aws_sagemaker_domain",
        attribute_map={
            "domain_name": "domain_name",
            "auth_mode": "auth_mode",
            "vpc_id": "vpc_id",
            "subnet_ids": "subnet_ids",
            "app_network_access_type": "app_network_access_type",
        },
        builder=_build_sagemaker_domain,
    ),
    # --- Inspector v2 (2026-04-19) -----------------------------------------
    ("inspector2", "enabler"): TfSpec(
        resource_type="aws_inspector2_enabler",
        attribute_map={
            "account_ids": "account_ids",
            "resource_types": "resource_types",
        },
    ),
    ("inspector2", "delegated_admin_account"): TfSpec(
        resource_type="aws_inspector2_delegated_admin_account",
        attribute_map={"account_id": "account_id"},
    ),
    ("inspector2", "organization_configuration"): TfSpec(
        resource_type="aws_inspector2_organization_configuration",
        attribute_map={
            "auto_enable": "auto_enable",
        },
    ),
    ("inspector2", "member_association"): TfSpec(
        resource_type="aws_inspector2_member_association",
        attribute_map={"account_id": "account_id"},
    ),
    # --- Shield (2026-04-19) -----------------------------------------------
    ("shield", "protection"): TfSpec(
        resource_type="aws_shield_protection",
        attribute_map={
            "name": "name",
            "resource_arn": "resource_arn",
        },
        builder=_build_tags_only,
    ),
    ("shield", "protection_group"): TfSpec(
        resource_type="aws_shield_protection_group",
        attribute_map={
            "protection_group_id": "protection_group_id",
            "aggregation": "aggregation",
            "pattern": "pattern",
            "resource_type": "resource_type",
            "members": "members",
        },
        builder=_build_tags_only,
    ),
    # --- Macie2 (2026-04-19) -----------------------------------------------
    ("macie2", "account"): TfSpec(
        resource_type="aws_macie2_account",
        attribute_map={
            "finding_publishing_frequency": "finding_publishing_frequency",
            "status": "status",
        },
    ),
    ("macie2", "classification_job"): TfSpec(
        resource_type="aws_macie2_classification_job",
        attribute_map={
            "name": "name",
            "job_type": "job_type",
            "s3_job_definition": "s3_job_definition",
        },
        builder=_build_tags_only,
    ),
    ("macie2", "member"): TfSpec(
        resource_type="aws_macie2_member",
        attribute_map={
            "account_id": "account_id",
            "email": "email",
            "invite": "invite",
            "status": "status",
        },
        builder=_build_tags_only,
    ),
    ("macie2", "custom_data_identifier"): TfSpec(
        resource_type="aws_macie2_custom_data_identifier",
        attribute_map={
            "name": "name",
            "regex": "regex",
            "keywords": "keywords",
            "ignore_words": "ignore_words",
            "maximum_match_distance": "maximum_match_distance",
            "description": "description",
        },
        builder=_build_tags_only,
    ),
    # --- Detective (2026-04-19) --------------------------------------------
    ("detective", "graph"): TfSpec(
        resource_type="aws_detective_graph",
        attribute_map={},
        builder=_build_tags_only,
    ),
    ("detective", "member"): TfSpec(
        resource_type="aws_detective_member",
        attribute_map={
            "graph_arn": "graph_arn",
            "account_id": "account_id",
            "email_address": "email_address",
            "message": "message",
            "disable_email_notification": "disable_email_notification",
        },
    ),
    ("detective", "invitation_accepter"): TfSpec(
        resource_type="aws_detective_invitation_accepter",
        attribute_map={"graph_arn": "graph_arn"},
    ),
    # --- Service Catalog (2026-04-19) --------------------------------------
    ("servicecatalog", "portfolio"): TfSpec(
        resource_type="aws_servicecatalog_portfolio",
        attribute_map={
            "name": "name",
            "description": "description",
            "provider_name": "provider_name",
        },
        builder=_build_tags_only,
    ),
    ("servicecatalog", "product"): TfSpec(
        resource_type="aws_servicecatalog_product",
        attribute_map={
            "name": "name",
            "owner": "owner",
            "type": "type",
            "description": "description",
            "distributor": "distributor",
            "support_description": "support_description",
            "support_email": "support_email",
            "support_url": "support_url",
            "provisioning_artifact_parameters": "provisioning_artifact_parameters",
        },
        builder=_build_tags_only,
    ),
    ("servicecatalog", "constraint"): TfSpec(
        resource_type="aws_servicecatalog_constraint",
        attribute_map={
            "portfolio_id": "portfolio_id",
            "product_id": "product_id",
            "type": "type",
            "parameters": "parameters",
            "description": "description",
        },
    ),
    ("servicecatalog", "principal_portfolio_association"): TfSpec(
        resource_type="aws_servicecatalog_principal_portfolio_association",
        attribute_map={
            "portfolio_id": "portfolio_id",
            "principal_arn": "principal_arn",
            "principal_type": "principal_type",
        },
    ),
    # --- App Runner (2026-04-19) -------------------------------------------
    ("apprunner", "service"): TfSpec(
        resource_type="aws_apprunner_service",
        attribute_map={
            "service_name": "service_name",
            "auto_scaling_configuration_arn": "auto_scaling_configuration_arn",
            "health_check_configuration": "health_check_configuration",
            "instance_configuration": "instance_configuration",
        },
        builder=_build_apprunner_service,
    ),
    ("apprunner", "auto_scaling_configuration_version"): TfSpec(
        resource_type="aws_apprunner_auto_scaling_configuration_version",
        attribute_map={
            "auto_scaling_configuration_name": "auto_scaling_configuration_name",
            "max_concurrency": "max_concurrency",
        },
        builder=_build_apprunner_autoscaling,
    ),
    ("apprunner", "connection"): TfSpec(
        resource_type="aws_apprunner_connection",
        attribute_map={
            "connection_name": "connection_name",
            "provider_type": "provider_type",
        },
        builder=_build_tags_only,
    ),
    ("apprunner", "observability_configuration"): TfSpec(
        resource_type="aws_apprunner_observability_configuration",
        attribute_map={
            "observability_configuration_name": "observability_configuration_name",
            "trace_configuration": "trace_configuration",
        },
        builder=_build_tags_only,
    ),
    ("apprunner", "vpc_connector"): TfSpec(
        resource_type="aws_apprunner_vpc_connector",
        attribute_map={
            "vpc_connector_name": "vpc_connector_name",
            "security_groups": "security_groups",
        },
        builder=_build_apprunner_vpc_connector,
    ),
    # --- AppMesh (2026-04-19) ----------------------------------------------
    ("appmesh", "mesh"): TfSpec(
        resource_type="aws_appmesh_mesh",
        attribute_map={"name": "name", "spec": "spec"},
        builder=_build_tags_only,
    ),
    ("appmesh", "virtual_node"): TfSpec(
        resource_type="aws_appmesh_virtual_node",
        attribute_map={
            "name": "name",
            "mesh_name": "mesh_name",
            "mesh_owner": "mesh_owner",
        },
        builder=_build_appmesh_virtual_node,
    ),
    ("appmesh", "virtual_service"): TfSpec(
        resource_type="aws_appmesh_virtual_service",
        attribute_map={
            "name": "name",
            "mesh_name": "mesh_name",
            "mesh_owner": "mesh_owner",
        },
        builder=_build_appmesh_virtual_service,
    ),
    # --- DataSync (2026-04-19) ---------------------------------------------
    ("datasync", "agent"): TfSpec(
        resource_type="aws_datasync_agent",
        attribute_map={
            "activation_key": "activation_key",
            "name": "name",
            "ip_address": "ip_address",
            "vpc_endpoint_id": "vpc_endpoint_id",
            "subnet_arns": "subnet_arns",
            "security_group_arns": "security_group_arns",
        },
        builder=_build_tags_only,
    ),
    ("datasync", "location_s3"): TfSpec(
        resource_type="aws_datasync_location_s3",
        attribute_map={
            "s3_bucket_arn": "s3_bucket_arn",
            "subdirectory": "subdirectory",
            "s3_storage_class": "s3_storage_class",
        },
        builder=_build_datasync_location_s3,
    ),
    ("datasync", "location_efs"): TfSpec(
        resource_type="aws_datasync_location_efs",
        attribute_map={
            "efs_file_system_arn": "efs_file_system_arn",
            "subdirectory": "subdirectory",
            "access_point_arn": "access_point_arn",
        },
        builder=_build_datasync_location_efs,
    ),
    ("datasync", "location_nfs"): TfSpec(
        resource_type="aws_datasync_location_nfs",
        attribute_map={
            "server_hostname": "server_hostname",
            "subdirectory": "subdirectory",
            "mount_options": "mount_options",
        },
        builder=_build_datasync_location_nfs,
    ),
    ("datasync", "task"): TfSpec(
        resource_type="aws_datasync_task",
        attribute_map={
            "name": "name",
            "source_location_arn": "source_location_arn",
            "destination_location_arn": "destination_location_arn",
            "cloudwatch_log_group_arn": "cloudwatch_log_group_arn",
            "options": "options",
            "schedule": "schedule",
        },
        builder=_build_tags_only,
    ),
    # --- FSx (2026-04-19) --------------------------------------------------
    ("fsx", "lustre_file_system"): TfSpec(
        resource_type="aws_fsx_lustre_file_system",
        attribute_map={
            "storage_capacity": "storage_capacity",
            "subnet_ids": "subnet_ids",
            "deployment_type": "deployment_type",
            "per_unit_storage_throughput": "per_unit_storage_throughput",
            "storage_type": "storage_type",
        },
        builder=_build_tags_only,
    ),
    ("fsx", "windows_file_system"): TfSpec(
        resource_type="aws_fsx_windows_file_system",
        attribute_map={
            "storage_capacity": "storage_capacity",
            "subnet_ids": "subnet_ids",
            "throughput_capacity": "throughput_capacity",
            "deployment_type": "deployment_type",
            "active_directory_id": "active_directory_id",
            "skip_final_backup": "skip_final_backup",
        },
        builder=_build_tags_only,
    ),
    ("fsx", "openzfs_file_system"): TfSpec(
        resource_type="aws_fsx_openzfs_file_system",
        attribute_map={
            "storage_capacity": "storage_capacity",
            "subnet_ids": "subnet_ids",
            "deployment_type": "deployment_type",
            "throughput_capacity": "throughput_capacity",
            "storage_type": "storage_type",
        },
        builder=_build_tags_only,
    ),
    # --- Amplify (2026-04-19) ----------------------------------------------
    ("amplify", "app"): TfSpec(
        resource_type="aws_amplify_app",
        attribute_map={
            "name": "name",
            "repository": "repository",
            "description": "description",
            "platform": "platform",
            "enable_auto_branch_creation": "enable_auto_branch_creation",
        },
        builder=_build_tags_only,
    ),
    ("amplify", "branch"): TfSpec(
        resource_type="aws_amplify_branch",
        attribute_map={
            "app_id": "app_id",
            "branch_name": "branch_name",
            "description": "description",
            "framework": "framework",
            "stage": "stage",
            "enable_auto_build": "enable_auto_build",
        },
        builder=_build_tags_only,
    ),
    ("amplify", "webhook"): TfSpec(
        resource_type="aws_amplify_webhook",
        attribute_map={
            "app_id": "app_id",
            "branch_name": "branch_name",
            "description": "description",
        },
    ),
    ("amplify", "backend_environment"): TfSpec(
        resource_type="aws_amplify_backend_environment",
        attribute_map={
            "app_id": "app_id",
            "environment_name": "environment_name",
            "deployment_artifacts": "deployment_artifacts",
            "stack_name": "stack_name",
        },
    ),
    ("amplify", "domain_association"): TfSpec(
        resource_type="aws_amplify_domain_association",
        attribute_map={
            "app_id": "app_id",
            "domain_name": "domain_name",
            "enable_auto_sub_domain": "enable_auto_sub_domain",
            "wait_for_verification": "wait_for_verification",
        },
        builder=_build_amplify_domain_association,
    ),
    # --- AppSync (2026-04-19) ----------------------------------------------
    ("appsync", "graphql_api"): TfSpec(
        resource_type="aws_appsync_graphql_api",
        attribute_map={
            "name": "name",
            "authentication_type": "authentication_type",
            "schema": "schema",
            "xray_enabled": "xray_enabled",
            "introspection_config": "introspection_config",
            "query_depth_limit": "query_depth_limit",
            "resolver_count_limit": "resolver_count_limit",
        },
        builder=_build_tags_only,
    ),
    ("appsync", "api_key"): TfSpec(
        resource_type="aws_appsync_api_key",
        attribute_map={
            "api_id": "api_id",
            "description": "description",
            "expires": "expires",
        },
    ),
    ("appsync", "datasource"): TfSpec(
        resource_type="aws_appsync_datasource",
        attribute_map={
            "api_id": "api_id",
            "name": "name",
            "type": "type",
            "description": "description",
            "service_role_arn": "service_role_arn",
            "dynamodb_config": "dynamodb_config",
            "lambda_config": "lambda_config",
            "http_config": "http_config",
            "elasticsearch_config": "elasticsearch_config",
        },
    ),
    ("appsync", "resolver"): TfSpec(
        resource_type="aws_appsync_resolver",
        attribute_map={
            "api_id": "api_id",
            "type": "type",
            "field": "field",
            "data_source": "data_source",
            "request_template": "request_template",
            "response_template": "response_template",
            "kind": "kind",
        },
    ),
    ("appsync", "function"): TfSpec(
        resource_type="aws_appsync_function",
        attribute_map={
            "api_id": "api_id",
            "data_source": "data_source",
            "name": "name",
            "request_mapping_template": "request_mapping_template",
            "response_mapping_template": "response_mapping_template",
            "description": "description",
        },
    ),
    # --- Global Accelerator (2026-04-19) -----------------------------------
    ("globalaccelerator", "accelerator"): TfSpec(
        resource_type="aws_globalaccelerator_accelerator",
        attribute_map={
            "name": "name",
            "ip_address_type": "ip_address_type",
            "enabled": "enabled",
            "attributes": "attributes",
        },
        builder=_build_tags_only,
    ),
    ("globalaccelerator", "listener"): TfSpec(
        resource_type="aws_globalaccelerator_listener",
        attribute_map={
            "accelerator_arn": "accelerator_arn",
            "protocol": "protocol",
            "client_affinity": "client_affinity",
        },
        builder=_build_ga_listener,
    ),
    ("globalaccelerator", "endpoint_group"): TfSpec(
        resource_type="aws_globalaccelerator_endpoint_group",
        attribute_map={
            "listener_arn": "listener_arn",
            "health_check_protocol": "health_check_protocol",
            "health_check_port": "health_check_port",
            "traffic_dial_percentage": "traffic_dial_percentage",
        },
        builder=_build_ga_endpoint_group,
    ),
    # --- CodeArtifact (2026-04-19) -----------------------------------------
    ("codeartifact", "domain"): TfSpec(
        resource_type="aws_codeartifact_domain",
        attribute_map={
            "domain": "domain",
            "encryption_key": "encryption_key",
        },
        builder=_build_tags_only,
    ),
    ("codeartifact", "repository"): TfSpec(
        resource_type="aws_codeartifact_repository",
        attribute_map={
            "repository": "repository",
            "domain": "domain",
            "description": "description",
            "domain_owner": "domain_owner",
            "upstream": "upstream",
            "external_connections": "external_connections",
        },
        builder=_build_tags_only,
    ),
}


def get_tf_spec(service: str, resource_type: str) -> TfSpec | None:
    """Look up the :class:`TfSpec` for ``(service, resource_type)``.

    Returns ``None`` when no spec exists — the writer records such
    resources in the ``# Unsupported resources`` comment block rather
    than silently dropping them.
    """
    return TF_SPECS.get((service, resource_type))


def translate(resource: Resource, ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Translate ``resource`` to a Terraform attribute dict.

    Returns ``None`` when the resource type has no spec. ``ctx`` carries
    writer-provided data (sidecar zip paths, etc.) to builders.
    """
    spec = get_tf_spec(resource.service, resource.resource_type)
    if spec is None:
        return None
    mapped = _apply_attribute_map(resource.attributes, spec.attribute_map)
    if spec.builder is not None:
        mapped = spec.builder(resource, mapped, ctx)
    return mapped


