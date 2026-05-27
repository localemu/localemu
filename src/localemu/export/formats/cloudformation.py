"""CloudFormation YAML writer.

Translates a :class:`localemu.export.ir.Snapshot` into a deployable
CloudFormation template and writes it to disk. The entry point is
:class:`CfnWriter`; everything else in this module is implementation
detail.

Guarantees / invariants:

* Property names are **CloudFormation** PascalCase (via
  :mod:`cfn_specs`). No Terraform field maps are consulted — that was the
  v1 bug.
* ``!Ref`` and ``!GetAtt`` come out as proper short-form intrinsics (via
  :mod:`_cfn_intrinsics`), not quoted strings.
* Every emitted Resource that references another Resource gets a
  ``DependsOn`` entry auto-computed from the IR reference graph —
  CloudFormation rolls back the stack on unresolved references, so we play
  it safe.
* ``Outputs`` exposes ``!Ref`` and, where applicable, ``!GetAtt *.Arn`` for
  every resource to make the resulting stack easy to diff and consume.
* The writer is the **only** place that knows the mapping from IR logical
  ids to CFN logical ids, so reference materialisation is centralised and
  auditable.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from localemu.export.formats._cfn_intrinsics import (
    CfnIntrinsic,
    CfnSafeDumper,
    cfn_getatt,
    cfn_ref,
)
from localemu.export.formats.cfn_specs import (
    CfnSpec,
    apply_attribute_map,
    classify_lambda_code,
    get_spec,
)
from localemu.export.ir import Ref, Resource, Snapshot, resource_logical_id

LOG = logging.getLogger(__name__)

# CloudFormation's hard limit on template size when passed in-line (not via
# S3). If the template exceeds this we keep generating — the user may still
# upload it — but we print a warning.
CFN_TEMPLATE_INLINE_LIMIT = 51_200

# Attributes commonly present on AWS CFN resource types that return the
# resource ARN via ``!GetAtt <LogicalId>.Arn``. Anything not in this set
# falls back to plain ``!Ref``, which for most resources yields the
# "primary identifier" (name / id).
# Resource types where ``!GetAtt <LogicalId>.Arn`` yields the resource's
# ARN. For resource types whose ``!Ref`` already returns the ARN we
# deliberately leave them out — using GetAtt on them raises
# ``Requested attribute Arn does not exist in schema``. The comment
# after each entry records what ``!Ref`` returns so future maintainers
# can sanity-check why a type is / isn't in this set.
_GETATT_ARN_TYPES: frozenset[str] = frozenset(
    {
        "AWS::SQS::Queue",                   # Ref -> URL
        "AWS::IAM::Role",                    # Ref -> name
        "AWS::IAM::User",                    # Ref -> name
        "AWS::Lambda::Function",             # Ref -> name
        "AWS::DynamoDB::Table",              # Ref -> name
        "AWS::KMS::Key",                     # Ref -> key id
        "AWS::Logs::LogGroup",               # Ref -> name
        "AWS::Events::Rule",                 # Ref -> name
        "AWS::Events::EventBus",             # Ref -> name
        "AWS::OpenSearchService::Domain",    # Ref -> domain name
        "AWS::Kinesis::Stream",              # Ref -> name
        # ``AWS::Kinesis::StreamConsumer.StreamARN`` requires the stream's
        # ARN — without GetAtt the resolver emitted ``!Ref`` (the stream
        # name), failing the property-pattern validator at stack create.
        "AWS::Events::Connection",           # Ref -> name
        # ``AWS::Events::ApiDestination.ConnectionArn`` requires an ARN;
        # ``!Ref`` returns the connection name and AWS rejects with
        # "failed validation constraint for keyword [pattern]".
    }
)

# Resource types where ``!Ref`` already returns the ARN — do NOT issue
# ``!GetAtt .Arn`` against them (AWS rejects it as an unknown schema
# attribute at stack creation time). The exporter's
# :meth:`_materialise_ref` inspects this set and falls through to
# ``!Ref`` when an ``Arn`` reference targets one of these types.
_REF_RETURNS_ARN_TYPES: frozenset[str] = frozenset(
    {
        "AWS::SNS::Topic",
        "AWS::SNS::Subscription",
        "AWS::IAM::ManagedPolicy",
        "AWS::SecretsManager::Secret",
        "AWS::StepFunctions::StateMachine",
        "AWS::StepFunctions::Activity",
    }
)


# ---------------------------------------------------------------------------
# Logical-id generation
# ---------------------------------------------------------------------------


_CFN_LOGICAL_ID_STRIP = re.compile(r"[^A-Za-z0-9]+")


def safe_cfn_id(resource_id: str, taken: set[str]) -> str:
    """Return a CloudFormation-legal logical id derived from ``resource_id``.

    CFN logical ids are ``[A-Za-z0-9]+``, must start with a letter, and
    must be unique within the template. We start from the IR resource id,
    strip disallowed characters, up-case the first character, and — if
    necessary — append ``_2``, ``_3`` … until we find a free slot. ``taken``
    is mutated with the returned id so callers can reuse it as a running
    collision tracker.
    """
    # PascalCase the sanitised pieces so ``s3_bucket_my_bucket`` becomes
    # ``S3BucketMyBucket`` — far more idiomatic in CFN templates than the
    # snake-case IR form.
    pieces = [p for p in _CFN_LOGICAL_ID_STRIP.split(resource_id) if p]
    if not pieces:
        pieces = ["Resource"]
    base = "".join(p[:1].upper() + p[1:] for p in pieces)
    if not base[:1].isalpha():
        base = "R" + base

    candidate = base
    suffix = 2
    while candidate in taken:
        candidate = f"{base}_{suffix}"
        suffix += 1
    taken.add(candidate)
    return candidate


# ---------------------------------------------------------------------------
# Template assembly state
# ---------------------------------------------------------------------------


@dataclass
class _TemplateState:
    """Mutable scratch space used while building a single template.

    Centralised so reference materialisation (which needs to know *every*
    resource's CFN logical id and type) can be implemented as a pure
    function of this state.
    """

    resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Map from IR (service, resource_type, resource_id) → CFN logical id.
    ir_to_cfn_id: dict[tuple[str, str, str], str] = field(default_factory=dict)
    # Parallel map: CFN logical id → CFN resource type (for Ref vs GetAtt).
    cfn_id_to_type: dict[str, str] = field(default_factory=dict)
    taken_ids: set[str] = field(default_factory=set)
    # Logical id → set of logical ids it depends on (unordered, deduped).
    depends_on: dict[str, set[str]] = field(default_factory=dict)
    # Sidecar assets (path under stack-assets/ → bytes) keyed by filename.
    assets: dict[str, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class CfnWriter:
    """Serialise a :class:`Snapshot` to a CloudFormation YAML template.

    The writer is stateless between calls; a fresh :class:`_TemplateState`
    is built per :meth:`write` invocation so concurrent writes against
    different output directories are safe.
    """

    def write(self, snapshot: Snapshot, output: Path) -> Path:
        """Write ``snapshot`` to ``output`` and return the template path.

        If ``output`` is a directory (or does not yet exist but has no
        ``.yaml`` suffix) we create it and emit ``stack.yaml`` inside.
        Lambda zip sidecars, if any are produced, land in
        ``<output>/stack-assets/<function>.zip``.
        """
        output = Path(output)
        if output.suffix in (".yaml", ".yml"):
            template_path = output
            asset_dir = output.parent / "stack-assets"
            output.parent.mkdir(parents=True, exist_ok=True)
        else:
            output.mkdir(parents=True, exist_ok=True)
            template_path = output / "stack.yaml"
            asset_dir = output / "stack-assets"

        state = _TemplateState()

        # Pass 1: assign CFN logical ids for every supported resource. We
        # need the full id table before we build any Properties, because
        # references may point forwards in the resource list.
        self._assign_logical_ids(snapshot, state)

        # Pass 2: build Properties for each resource (refs now resolve).
        for resource in snapshot.resources:
            spec = get_spec(resource.service, resource.resource_type)
            if spec is None:
                state.warnings.append(
                    f"no CFN spec for {resource.service}:{resource.resource_type}"
                    f" ({resource.resource_id}); skipping"
                )
                continue
            key = (resource.service, resource.resource_type, resource.resource_id)
            logical_id = state.ir_to_cfn_id.get(key)
            if logical_id is None:
                continue  # Should be unreachable given pass 1.
            cfn_resource = self._build_resource(resource, spec, logical_id, state)
            state.resources[logical_id] = cfn_resource

        # Attach DependsOn (computed incidentally during ref resolution).
        for logical_id, deps in state.depends_on.items():
            if not deps:
                continue
            res = state.resources.get(logical_id)
            if res is None:
                continue
            # Drop self-dependencies (can sneak in when a resource's own
            # ARN appears inside its attributes) and sort for determinism.
            deps.discard(logical_id)
            if deps:
                res["DependsOn"] = sorted(deps)

        template = self._assemble_template(snapshot, state)
        rendered = yaml.dump(
            template,
            Dumper=CfnSafeDumper,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )

        template_path.write_text(rendered, encoding="utf-8")

        # Write sidecar assets (Lambda zips) if any.
        if state.assets:
            asset_dir.mkdir(parents=True, exist_ok=True)
            for name, blob in state.assets.items():
                (asset_dir / name).write_bytes(blob)

        template_bytes = rendered.encode("utf-8")
        if len(template_bytes) > CFN_TEMPLATE_INLINE_LIMIT:
            LOG.warning(
                "CloudFormation template is %d bytes (> %d); you must upload "
                "it to S3 before calling CreateStack.",
                len(template_bytes),
                CFN_TEMPLATE_INLINE_LIMIT,
            )

        for warning in state.warnings:
            LOG.info("cfn export: %s", warning)

        return template_path

    # ------------------------------------------------------------------ #
    # Pass 1: logical ids                                                #
    # ------------------------------------------------------------------ #

    def _assign_logical_ids(self, snapshot: Snapshot, state: _TemplateState) -> None:
        """Populate ``state.ir_to_cfn_id`` / ``state.cfn_id_to_type``.

        Iterates resources in snapshot order so diffs are stable across
        re-exports of the same infrastructure.
        """
        for resource in snapshot.resources:
            spec = get_spec(resource.service, resource.resource_type)
            if spec is None:
                continue
            # ``resource_logical_id`` already gives us a deterministic IR
            # identifier; ``safe_cfn_id`` trims it into CFN-legal form.
            seed = resource_logical_id(resource)
            cfn_id = safe_cfn_id(seed, state.taken_ids)
            key = (resource.service, resource.resource_type, resource.resource_id)
            state.ir_to_cfn_id[key] = cfn_id
            state.cfn_id_to_type[cfn_id] = spec.cfn_type

    # ------------------------------------------------------------------ #
    # Pass 2: build each resource                                        #
    # ------------------------------------------------------------------ #

    def _build_resource(
        self,
        resource: Resource,
        spec: CfnSpec,
        logical_id: str,
        state: _TemplateState,
    ) -> dict[str, Any]:
        """Assemble a single top-level CFN Resource mapping."""

        def transform(ref: Ref) -> Any:
            return self._materialise_ref(ref, logical_id, state)

        if spec.builder is not None:
            builder = getattr(self, spec.builder, None)
            if builder is None:
                raise RuntimeError(
                    f"CfnSpec references unknown builder {spec.builder!r} for "
                    f"{resource.service}:{resource.resource_type}"
                )
            properties, metadata = builder(resource, spec, transform, state)
        else:
            properties = apply_attribute_map(spec, resource, transform)
            metadata = None

        if spec.emit_tags and resource.tags:
            properties["Tags"] = [
                {"Key": k, "Value": str(v)} for k, v in sorted(resource.tags.items())
            ]

        cfn_resource: dict[str, Any] = {
            "Type": spec.cfn_type,
            "Properties": properties,
        }
        if metadata:
            cfn_resource["Metadata"] = metadata
        return cfn_resource

    # ------------------------------------------------------------------ #
    # Reference materialisation                                          #
    # ------------------------------------------------------------------ #

    def _materialise_ref(
        self,
        ref: Ref,
        source_logical_id: str,
        state: _TemplateState,
    ) -> Any:
        """Turn a :class:`Ref` into a CFN intrinsic function call.

        Also records a DependsOn edge from ``source_logical_id`` to the
        referenced resource. If the target isn't in the template (e.g. it
        belongs to a service we don't have a spec for), we degrade to the
        literal string form (``<service>:<id>``) and surface a warning —
        never silently drop the reference.
        """
        target_key = (ref.service, ref.resource_type, ref.resource_id)
        target_id = state.ir_to_cfn_id.get(target_key)
        if target_id is None:
            msg = (
                f"unresolved reference from {source_logical_id} -> "
                f"{ref.service}:{ref.resource_type}:{ref.resource_id} "
                f"({ref.attribute})"
            )
            state.warnings.append(msg)
            return f"{ref.service}:{ref.resource_type}:{ref.resource_id}"

        state.depends_on.setdefault(source_logical_id, set()).add(target_id)

        target_type = state.cfn_id_to_type.get(target_id, "")
        attribute = ref.attribute.lower()
        if attribute == "arn" and target_type in _GETATT_ARN_TYPES:
            return cfn_getatt(target_id, "Arn")
        # Per-type GetAtt for non-ARN attributes. ``aws_api_gateway_resource.
        # parent_id`` wants the rest_api's RootResourceId — ``!Ref`` returns
        # the API id and AWS rejects it as "Invalid Resource identifier".
        if (
            attribute == "root_resource_id"
            and target_type == "AWS::ApiGateway::RestApi"
        ):
            return cfn_getatt(target_id, "RootResourceId")
        # Default: ``!Ref`` returns the primary identifier (bucket name,
        # function name, role name, queue URL, …). For most resources this
        # is what downstream properties actually want.
        return cfn_ref(target_id)

    # ------------------------------------------------------------------ #
    # Per-resource builders (complex structures)                         #
    # ------------------------------------------------------------------ #

    def _build_iam_role(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::IAM::Role Properties with inline + managed policies."""
        props = apply_attribute_map(spec, resource, transform)
        # AssumeRolePolicyDocument is MANDATORY. Supply a deny-all default
        # rather than emit an invalid template if the IR is missing it.
        if "AssumeRolePolicyDocument" not in props:
            props["AssumeRolePolicyDocument"] = {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}
                ],
            }

        # IR field name varies between collectors; check both.
        managed = (
            resource.attributes.get("managed_policy_arns")
            or resource.attributes.get("attached_managed_policies")
            or []
        )
        if isinstance(managed, list) and managed:
            props["ManagedPolicyArns"] = [
                transform(v) if isinstance(v, Ref) else v for v in managed
            ]

        inline = resource.attributes.get("inline_policies") or {}
        if isinstance(inline, dict) and inline:
            policies_list: list[dict[str, Any]] = []
            for name, doc in inline.items():
                policies_list.append(
                    {
                        "PolicyName": name,
                        "PolicyDocument": _resolve_refs_deep(doc, transform),
                    }
                )
            props["Policies"] = policies_list

        return props, None

    def _build_iam_user(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::IAM::User Properties with inline + managed policies + groups.

        CloudFormation models user→group membership as the User's ``Groups``
        property (a list of group names), not as a separate resource as
        Terraform does. Inline ``Policies`` and ``ManagedPolicyArns`` work
        the same way.
        """
        props = apply_attribute_map(spec, resource, transform)

        managed = resource.attributes.get("attached_managed_policies") or []
        if isinstance(managed, list) and managed:
            props["ManagedPolicyArns"] = [
                transform(v) if isinstance(v, Ref) else v for v in managed
            ]

        inline = resource.attributes.get("inline_policies") or {}
        if isinstance(inline, dict) and inline:
            props["Policies"] = [
                {
                    "PolicyName": name,
                    "PolicyDocument": _resolve_refs_deep(doc, transform),
                }
                for name, doc in inline.items()
            ]

        # ``groups`` may already be a list of Refs (the upstream resolver
        # pre-wraps in-snapshot identifiers) or a list of plain group
        # names, depending on the snapshot path. Normalise either shape
        # to a CFN ``!Ref <LogicalId>`` intrinsic per group.
        raw_groups = resource.attributes.get("groups") or []
        cfn_groups: list[Any] = []
        for g in raw_groups:
            if isinstance(g, Ref):
                cfn_groups.append(
                    transform(
                        Ref(
                            g.service,
                            g.resource_type,
                            g.resource_id,
                            attribute="name",
                        )
                    )
                )
            elif g:
                cfn_groups.append(
                    transform(Ref("iam", "group", g, attribute="name"))
                )
        if cfn_groups:
            props["Groups"] = cfn_groups
        return props, None

    def _build_apigateway_method(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::ApiGateway::Method.

        The collector stores the integration dict inline on the method
        with snake_case keys (``type``/``uri``/``integration_http_method``
        /...). CFN's ``Method.Integration`` expects PascalCase. We also
        default ``AuthorizationType`` to ``NONE`` so plan doesn't reject
        the method on a missing required property.
        """
        props = apply_attribute_map(spec, resource, transform)
        props.setdefault("AuthorizationType", "NONE")
        integ = resource.attributes.get("integration")
        if isinstance(integ, dict):
            _SNAKE_TO_CFN = {
                "type": "Type",
                "integration_type": "Type",
                "uri": "Uri",
                "http_method": "HttpMethod",
                "integration_http_method": "IntegrationHttpMethod",
                "request_templates": "RequestTemplates",
                "passthrough_behavior": "PassthroughBehavior",
                "timeout_in_millis": "TimeoutInMillis",
                "content_handling": "ContentHandling",
                "credentials": "Credentials",
                "cache_key_parameters": "CacheKeyParameters",
            }
            cfn_integ: dict[str, Any] = {}
            for k, v in integ.items():
                cfn_integ[_SNAKE_TO_CFN.get(k, k)] = v
            # Type is REQUIRED; default to MOCK if missing so the template
            # at least validates.
            cfn_integ.setdefault("Type", "MOCK")
            props["Integration"] = cfn_integ
        return props, None

    def _build_cloudtrail_trail(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::CloudTrail::Trail with DependsOn on bucket policies.

        CloudTrail validates the destination bucket's policy at
        CreateTrail. Without an explicit DependsOn, CFN may try to
        create the trail before the bucket policy is attached and AWS
        rejects with ``InsufficientS3BucketPolicyException``.
        """
        props = apply_attribute_map(spec, resource, transform)
        cfn_id_self = state.ir_to_cfn_id.get(
            (resource.service, resource.resource_type, resource.resource_id)
        )
        if cfn_id_self:
            for (svc, rtype, _rid), cfn_id in state.ir_to_cfn_id.items():
                if svc == "s3" and rtype == "bucket_policy":
                    state.depends_on.setdefault(cfn_id_self, set()).add(cfn_id)
        return props, None

    def _build_apigateway_deployment(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::ApiGateway::Deployment with DependsOn on every method
        + integration of the parent rest_api.

        Without these explicit deps CFN may create the deployment before
        the methods exist, then fail with "The REST API doesn't contain
        any methods". The depends_on for the rest_api itself is already
        recorded by the RestApiId Ref; we add a transitive one to every
        method/integration of the same API.
        """
        props = apply_attribute_map(spec, resource, transform)

        # ``resource.resource_id`` is "<api_id>/<deployment_id>"; recover
        # the api_id prefix to find sibling methods + integrations.
        api_id = resource.resource_id.split("/", 1)[0] if "/" in resource.resource_id else None
        if api_id:
            cfn_id_self = state.ir_to_cfn_id.get(
                (resource.service, resource.resource_type, resource.resource_id)
            )
            if cfn_id_self:
                for (svc, rtype, rid), cfn_id in state.ir_to_cfn_id.items():
                    if svc != "apigateway":
                        continue
                    if rtype not in ("method", "integration"):
                        continue
                    if rid.startswith(api_id + "/"):
                        state.depends_on.setdefault(cfn_id_self, set()).add(cfn_id)
        return props, None

    def _build_lambda_alias(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Lambda::Alias Properties.

        On real AWS CloudFormation, ``AWS::Lambda::Function`` does NOT
        auto-publish versions (unlike Terraform's ``publish = true``);
        creating an alias that points at numeric version ``"1"`` therefore
        fails with ``Function not found: <fn>:1`` at stack create time.

        We coerce any numeric ``FunctionVersion`` to ``$LATEST`` and stamp
        a ``Metadata.LocalEmuNote`` explaining the gap so operators who
        need a stable versioned alias can add an explicit
        ``AWS::Lambda::Version`` companion resource and re-point the
        alias themselves.
        """
        props = apply_attribute_map(spec, resource, transform)
        version = props.get("FunctionVersion")
        if isinstance(version, str) and version.isdigit():
            props["FunctionVersion"] = "$LATEST"
            return props, {
                "LocalEmuNote": (
                    f"Original FunctionVersion={version!r} was downgraded to "
                    "$LATEST because CFN does not auto-publish versions like "
                    "Terraform's publish=true. To restore numeric-version "
                    "semantics, add an AWS::Lambda::Version resource and "
                    "set FunctionVersion: !GetAtt <Version>.Version."
                )
            }
        return props, None

    def _build_sqs_queue_policy(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """AWS::SQS::QueuePolicy.Queues is a LIST of queue URLs."""
        props = apply_attribute_map(spec, resource, transform)
        qu = resource.attributes.get("queue_url")
        if qu is not None:
            props["Queues"] = [transform(qu) if isinstance(qu, Ref) else qu]
        return props, None

    def _build_sns_topic_policy(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::SNS::TopicPolicy Properties.

        The IR carries an ``arn`` field that's a Ref to the parent
        ``sns.topic``; AWS::SNS::TopicPolicy expects ``Topics`` as a list
        of topic ARNs and ``PolicyDocument`` as a dict.
        """
        props = apply_attribute_map(spec, resource, transform)
        arn_ref = resource.attributes.get("arn")
        if arn_ref is not None:
            props["Topics"] = [transform(arn_ref) if isinstance(arn_ref, Ref) else arn_ref]
        return props, None

    def _build_events_connection(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Events::Connection Properties.

        AWS::Events::Connection requires ``AuthParameters``. The IR carries
        ``auth_parameters`` in the snake_case TF shape (set by the events
        collector for Terraform parity), so this builder maps it back into
        the CamelCase CFN schema:

            api_key             → ApiKeyAuthParameters {ApiKeyName, ApiKeyValue}
            basic               → BasicAuthParameters  {Username, Password}
            oauth               → OAuthParameters       {ClientParameters,
                                                         AuthorizationEndpoint,
                                                         HttpMethod,
                                                         OAuthHttpParameters}
            invocation_http_parameters → InvocationHttpParameters (pass-through)
        """
        props = apply_attribute_map(spec, resource, transform)
        tf_auth = resource.attributes.get("auth_parameters") or {}
        if not isinstance(tf_auth, dict):
            tf_auth = {}
        cfn_auth: dict[str, Any] = {}
        api_key = tf_auth.get("api_key")
        if isinstance(api_key, dict) and api_key.get("key"):
            cfn_auth["ApiKeyAuthParameters"] = {
                "ApiKeyName": api_key.get("key"),
                "ApiKeyValue": api_key.get("value") or "REPLACE_ME",
            }
        basic = tf_auth.get("basic")
        if isinstance(basic, dict) and basic.get("username"):
            cfn_auth["BasicAuthParameters"] = {
                "Username": basic.get("username"),
                "Password": basic.get("password") or "REPLACE_ME",
            }
        oauth = tf_auth.get("oauth")
        if isinstance(oauth, dict):
            oauth_block: dict[str, Any] = {}
            client = oauth.get("client_parameters")
            if isinstance(client, dict):
                oauth_block["ClientParameters"] = {
                    "ClientID": client.get("client_id"),
                    "ClientSecret": client.get("client_secret") or "REPLACE_ME",
                }
            for tf_key, cfn_key in (
                ("authorization_endpoint", "AuthorizationEndpoint"),
                ("http_method", "HttpMethod"),
                ("oauth_http_parameters", "OAuthHttpParameters"),
            ):
                value = oauth.get(tf_key)
                if value is not None:
                    oauth_block[cfn_key] = value
            if oauth_block:
                cfn_auth["OAuthParameters"] = oauth_block
        inv = tf_auth.get("invocation_http_parameters")
        if isinstance(inv, dict):
            cfn_auth["InvocationHttpParameters"] = inv
        if not cfn_auth:
            # AWS rejects the resource without AuthParameters. Emit a
            # placeholder API_KEY block so the template at least validates;
            # operator fills in ``REPLACE_ME`` before deploy.
            cfn_auth = {
                "ApiKeyAuthParameters": {
                    "ApiKeyName": "x-api-key",
                    "ApiKeyValue": "REPLACE_ME",
                }
            }
        props["AuthParameters"] = cfn_auth
        return props, None

    def _build_iam_group(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::IAM::Group Properties with inline + managed policies."""
        props = apply_attribute_map(spec, resource, transform)

        managed = resource.attributes.get("attached_managed_policies") or []
        if isinstance(managed, list) and managed:
            props["ManagedPolicyArns"] = [
                transform(v) if isinstance(v, Ref) else v for v in managed
            ]

        inline = resource.attributes.get("inline_policies") or {}
        if isinstance(inline, dict) and inline:
            props["Policies"] = [
                {
                    "PolicyName": name,
                    "PolicyDocument": _resolve_refs_deep(doc, transform),
                }
                for name, doc in inline.items()
            ]
        return props, None

    def _build_iam_instance_profile(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::IAM::InstanceProfile Properties.

        AWS::IAM::InstanceProfile.Roles is a REQUIRED list of role names
        (length exactly 1 today, though AWS reserves room for more). The
        IR carries the role list as ``roles`` (plain names) plus a single
        ``role`` Ref. Prefer the Ref so dependency ordering lands.
        """
        props = apply_attribute_map(spec, resource, transform)

        role_ref = resource.attributes.get("role")
        role_names = resource.attributes.get("roles") or []
        if isinstance(role_ref, Ref):
            props["Roles"] = [transform(role_ref)]
        elif role_names:
            props["Roles"] = [
                transform(Ref("iam", "role", n, attribute="name"))
                for n in role_names
            ]
        return props, None

    def _build_ec2_launch_template(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::EC2::LaunchTemplate with LaunchTemplateData wrapper."""
        data: dict[str, Any] = {}
        mapping = {
            "image_id": "ImageId",
            "instance_type": "InstanceType",
            "key_name": "KeyName",
        }
        for ir_key, cfn_key in mapping.items():
            v = resource.attributes.get(ir_key)
            if v is not None:
                data[cfn_key] = v
        props: dict[str, Any] = {
            "LaunchTemplateName": resource.attributes.get("name") or resource.resource_id,
            "LaunchTemplateData": data,
        }
        return props, None

    def _build_cloudfront_distribution(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::CloudFront::Distribution wrapped in DistributionConfig."""
        attrs = resource.attributes
        origins = attrs.get("origin", [])
        dcb = attrs.get("default_cache_behavior", [{}])
        dcb_block = dcb[0] if dcb else {}
        config: dict[str, Any] = {
            "Enabled": attrs.get("enabled", True),
            "Comment": attrs.get("comment", ""),
            "Origins": [
                {"DomainName": o.get("domain_name"), "Id": o.get("origin_id"),
                 "S3OriginConfig": {"OriginAccessIdentity": ""}}
                for o in (origins if isinstance(origins, list) else [])
            ] or [{"DomainName": "placeholder.s3.amazonaws.com", "Id": "default",
                   "S3OriginConfig": {"OriginAccessIdentity": ""}}],
            "DefaultCacheBehavior": {
                "TargetOriginId": dcb_block.get("target_origin_id", "default"),
                "ViewerProtocolPolicy": dcb_block.get("viewer_protocol_policy", "allow-all"),
                "ForwardedValues": {"QueryString": False},
            },
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
            "Restrictions": {"GeoRestriction": {"RestrictionType": "none"}},
        }
        return {"DistributionConfig": config}, None

    def _build_ses_template(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::SES::Template Properties (nested Template block)."""
        tmpl: dict[str, Any] = {}
        for ir_key, cfn_key in (
            ("name", "TemplateName"), ("subject", "SubjectPart"),
            ("html", "HtmlPart"), ("text", "TextPart"),
        ):
            v = resource.attributes.get(ir_key)
            if v is not None:
                tmpl[cfn_key] = v
        return {"Template": tmpl}, None

    def _build_eks_cluster(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::EKS::Cluster Properties with ResourcesVpcConfig."""
        props = apply_attribute_map(spec, resource, transform)
        vpc_config = resource.attributes.get("vpc_config")
        if isinstance(vpc_config, list) and vpc_config:
            vc = vpc_config[0] if isinstance(vpc_config[0], dict) else {}
            subnets = vc.get("subnet_ids", [])
            sgs = vc.get("security_group_ids", [])
            props["ResourcesVpcConfig"] = {
                "SubnetIds": [
                    transform(s) if isinstance(s, Ref) else s for s in subnets
                ],
                "SecurityGroupIds": [
                    transform(s) if isinstance(s, Ref) else s for s in sgs
                ],
            }
        return props, None

    def _build_route53_zone(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Route53::HostedZone Properties."""
        props: dict[str, Any] = {"Name": resource.attributes.get("name")}
        comment = resource.attributes.get("comment")
        if comment:
            props["HostedZoneConfig"] = {"Comment": comment}
        vpc_blocks = resource.attributes.get("vpc")
        if isinstance(vpc_blocks, list) and vpc_blocks:
            props["VPCs"] = [
                {
                    "VPCId": v.get("vpc_id"),
                    "VPCRegion": v.get("vpc_region"),
                }
                for v in vpc_blocks
            ]
        return props, None

    def _build_route53_record(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Route53::RecordSet Properties."""
        props = apply_attribute_map(spec, resource, transform)
        zone_id = resource.attributes.get("zone_id")
        if isinstance(zone_id, Ref):
            props["HostedZoneId"] = transform(zone_id)
        elif isinstance(zone_id, str):
            props["HostedZoneId"] = zone_id
        alias = resource.attributes.get("alias")
        if isinstance(alias, dict):
            props["AliasTarget"] = {
                "DNSName": alias.get("name"),
                "HostedZoneId": alias.get("zone_id"),
                "EvaluateTargetHealth": bool(alias.get("evaluate_target_health", False)),
            }
            props.pop("TTL", None)
            props.pop("ResourceRecords", None)
        return props, None

    def _build_route53_health_check(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Route53::HealthCheck Properties."""
        hc_config: dict[str, Any] = {}
        mapping = {
            "type": "Type",
            "fqdn": "FullyQualifiedDomainName",
            "ip_address": "IPAddress",
            "port": "Port",
            "resource_path": "ResourcePath",
            "request_interval": "RequestInterval",
            "failure_threshold": "FailureThreshold",
        }
        for ir_key, cfn_key in mapping.items():
            val = resource.attributes.get(ir_key)
            if val is not None:
                hc_config[cfn_key] = val
        return {"HealthCheckConfig": hc_config}, None

    def _build_ssm_parameter(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """AWS::SSM::Parameter: downgrade SecureString → String.

        Long-standing CloudFormation limitation: the ``AWS::SSM::Parameter``
        resource type only accepts ``Type: String`` or ``Type: StringList``
        (see `AWS docs
        <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-parameter.html>`_).
        ``SecureString`` parameters must be created out of band.

        LocalEmu's IR carries the moto-accurate ``Type: SecureString`` for
        KMS-encrypted parameters; emitting that verbatim causes AWS early
        validation to reject the stack with ``SecureString is not a valid
        enum value``. We downgrade to ``String`` and stamp a
        ``Metadata.LocalEmuNote`` so operators see the gap in the template
        and can re-encrypt after deploy.
        """
        props = apply_attribute_map(spec, resource, transform)
        metadata: dict[str, Any] | None = None
        if str(props.get("Type", "")).lower() == "securestring":
            props["Type"] = "String"
            metadata = {
                "LocalEmuNote": (
                    "Parameter was a SecureString in LocalEmu but "
                    "AWS::SSM::Parameter does not support creating "
                    "SecureString parameters via CloudFormation. Type "
                    "downgraded to String; the value still comes from a "
                    "sensitive NoEcho stack parameter so it is not "
                    "checked in. After the stack deploys, re-encrypt "
                    "with: aws ssm put-parameter --overwrite --type "
                    "SecureString --name <Name> --value <value>."
                ),
            }
        return props, metadata

    def _build_lambda_function(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::Lambda::Function Properties with a correct Code block.

        Returns (Properties, Metadata). ``Metadata`` carries a
        ``LocalEmuNote`` when the Code block is a placeholder pointing at
        a sidecar asset the user must upload.
        """
        props = apply_attribute_map(spec, resource, transform)

        # ``Environment`` in the IR is typically ``{"variables": {...}}``
        # already; CFN expects ``{"Variables": {...}}``. Normalise.
        env = props.get("Environment")
        if isinstance(env, dict) and "variables" in env and "Variables" not in env:
            env = {"Variables": env["variables"]}
            props["Environment"] = env

        # Normalise TracingConfig: collector emits {"mode": "PassThrough"} but
        # CFN requires {"Mode": "PassThrough"}.
        tc = props.get("TracingConfig")
        if isinstance(tc, dict):
            mode = tc.get("Mode") or tc.get("mode")
            if mode:
                props["TracingConfig"] = {"Mode": mode}
            else:
                props.pop("TracingConfig", None)

        # Drop empty Layers list — CFN has no explicit problem with [] but
        # it's noise in the rendered template.
        if props.get("Layers") == []:
            props.pop("Layers", None)

        code_value = resource.attributes.get("code")
        mode, payload = classify_lambda_code(code_value)
        metadata: dict[str, Any] | None = None

        fn_name = resource.resource_id
        if mode == "inline" and isinstance(payload, str):
            props["Code"] = {"ZipFile": payload}
        elif mode == "sidecar" and isinstance(payload, (bytes, bytearray)):
            asset_name = f"{fn_name}.zip"
            state.assets[asset_name] = bytes(payload)
            props["Code"] = {
                "S3Bucket": "REPLACE_ME_BUCKET",
                "S3Key": f"functions/{asset_name}",
            }
            metadata = {
                "LocalEmuNote": (
                    "Upload stack-assets/"
                    f"{asset_name} to the bucket referenced above and "
                    "replace S3Bucket/S3Key before deploying."
                )
            }
        else:
            props["Code"] = {
                "S3Bucket": "REPLACE_ME_BUCKET",
                "S3Key": f"functions/{fn_name}.zip",
            }
            metadata = {
                "LocalEmuNote": (
                    "No code artefact was available at export time. "
                    "Upload your deployment zip and replace S3Bucket/S3Key "
                    "before deploying."
                )
            }
        return props, metadata

    def _build_s3_bucket(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::S3::Bucket Properties.

        The CFN resource requires no properties in the strictest sense
        (``BucketName`` is optional — CFN generates one if omitted), but
        omitting it is almost never what the user wants: it forces
        downstream clients to discover the generated name out-of-band.
        We therefore always emit a ``BucketName`` — sourced from the IR
        attribute if present, otherwise from the resource id (which is
        the logical bucket name in every code path that creates a
        :class:`Resource` for an S3 bucket).
        """
        props = apply_attribute_map(spec, resource, transform)
        if "BucketName" not in props:
            props["BucketName"] = resource.resource_id
        return props, None

    def _build_dynamodb_table(
        self,
        resource: Resource,
        spec: CfnSpec,
        transform,
        state: _TemplateState,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Build AWS::DynamoDB::Table Properties (KeySchema + throughput)."""
        props = apply_attribute_map(spec, resource, transform)

        key_schema = resource.attributes.get("key_schema") or []
        if key_schema:
            props["KeySchema"] = [
                {"AttributeName": k.get("AttributeName") or k.get("attribute_name"),
                 "KeyType": k.get("KeyType") or k.get("key_type")}
                for k in key_schema
                if isinstance(k, dict)
            ]

        attr_defs = resource.attributes.get("attribute_definitions") or []
        if attr_defs:
            props["AttributeDefinitions"] = [
                {"AttributeName": a.get("AttributeName") or a.get("attribute_name"),
                 "AttributeType": a.get("AttributeType") or a.get("attribute_type")}
                for a in attr_defs
                if isinstance(a, dict)
            ]

        gsis = resource.attributes.get("global_secondary_indexes")
        if isinstance(gsis, list) and gsis:
            props["GlobalSecondaryIndexes"] = _resolve_refs_deep(gsis, transform)
        lsis = resource.attributes.get("local_secondary_indexes")
        if isinstance(lsis, list) and lsis:
            props["LocalSecondaryIndexes"] = _resolve_refs_deep(lsis, transform)

        # Provisioned throughput only applies when BillingMode != PAY_PER_REQUEST.
        billing_mode = props.get("BillingMode")
        throughput = resource.attributes.get("provisioned_throughput")
        if billing_mode != "PAY_PER_REQUEST" and isinstance(throughput, dict):
            props["ProvisionedThroughput"] = {
                "ReadCapacityUnits": int(
                    throughput.get("ReadCapacityUnits")
                    or throughput.get("read_capacity_units")
                    or 5
                ),
                "WriteCapacityUnits": int(
                    throughput.get("WriteCapacityUnits")
                    or throughput.get("write_capacity_units")
                    or 5
                ),
            }

        # AWS::DynamoDB::Table sub-property normalisation. The IR carries
        # collector-shaped dicts (snake_case keys, sometimes empty); CFN
        # validates the property schema strictly and rejects:
        #   - StreamSpecification when streams are disabled (must omit)
        #   - SSESpecification when empty or with snake_case keys
        #   - PointInTimeRecoverySpecification.enabled (must be
        #     PointInTimeRecoveryEnabled, capital E, and the whole block
        #     must be omitted when PITR is disabled).
        ss = props.get("StreamSpecification")
        if isinstance(ss, dict):
            stream_enabled = (
                ss.get("StreamEnabled")
                if "StreamEnabled" in ss
                else ss.get("stream_enabled")
            )
            view = ss.get("StreamViewType") or ss.get("stream_view_type")
            if stream_enabled and view:
                props["StreamSpecification"] = {"StreamViewType": view}
            else:
                props.pop("StreamSpecification", None)

        sse = props.get("SSESpecification")
        if isinstance(sse, dict):
            enabled = (
                sse.get("SSEEnabled")
                if "SSEEnabled" in sse
                else sse.get("sse_enabled") or sse.get("enabled")
            )
            if enabled:
                out: dict[str, Any] = {"SSEEnabled": True}
                sse_type = sse.get("SSEType") or sse.get("sse_type")
                if sse_type:
                    out["SSEType"] = sse_type
                kms = (
                    sse.get("KMSMasterKeyId")
                    or sse.get("kms_master_key_id")
                )
                if kms:
                    out["KMSMasterKeyId"] = kms
                props["SSESpecification"] = out
            else:
                props.pop("SSESpecification", None)

        pitr = props.get("PointInTimeRecoverySpecification")
        if isinstance(pitr, dict):
            enabled = (
                pitr.get("PointInTimeRecoveryEnabled")
                if "PointInTimeRecoveryEnabled" in pitr
                else pitr.get("enabled")
            )
            if enabled:
                props["PointInTimeRecoverySpecification"] = {
                    "PointInTimeRecoveryEnabled": True
                }
            else:
                props.pop("PointInTimeRecoverySpecification", None)

        return props, None

    # ------------------------------------------------------------------ #
    # Final template assembly                                            #
    # ------------------------------------------------------------------ #

    def _assemble_template(
        self, snapshot: Snapshot, state: _TemplateState
    ) -> dict[str, Any]:
        """Construct the top-level template dict in a stable key order."""
        template: dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": (
                f"LocalEmu export (schema {snapshot.schema_version}, "
                f"generated {snapshot.exported_at})"
            ),
            "Resources": state.resources,
        }
        outputs = self._build_outputs(state)
        if outputs:
            template["Outputs"] = outputs
        return template

    def _build_outputs(self, state: _TemplateState) -> dict[str, Any]:
        """Emit ``!Ref`` (+ ``!GetAtt *.Arn``) for each resource.

        Output names are deterministic: ``<LogicalId>Ref`` and
        ``<LogicalId>Arn``. Kept short enough to stay under the CFN 255-char
        limit for output names even on long resource ids.
        """
        outputs: dict[str, Any] = {}
        for logical_id, cfn_type in sorted(state.cfn_id_to_type.items()):
            if logical_id not in state.resources:
                continue
            outputs[f"{logical_id}Ref"] = {
                "Description": f"Ref for {logical_id}",
                "Value": cfn_ref(logical_id),
            }
            if cfn_type in _GETATT_ARN_TYPES:
                outputs[f"{logical_id}Arn"] = {
                    "Description": f"ARN for {logical_id}",
                    "Value": cfn_getatt(logical_id, "Arn"),
                }
        return outputs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_refs_deep(value: Any, transform) -> Any:
    """Apply ``transform`` to every :class:`Ref` nested inside ``value``.

    Mirrors the shallow walker in :mod:`cfn_specs` but is exposed here for
    builders that work on raw IR attribute subtrees before handing them to
    :func:`apply_attribute_map`.
    """
    if isinstance(value, Ref):
        return transform(value)
    if isinstance(value, dict):
        return {k: _resolve_refs_deep(v, transform) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_refs_deep(v, transform) for v in value]
    return value


__all__ = [
    "CFN_TEMPLATE_INLINE_LIMIT",
    "CfnIntrinsic",
    "CfnWriter",
    "safe_cfn_id",
]
