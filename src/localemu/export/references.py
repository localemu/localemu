"""Cross-resource reference resolution.

Collectors emit raw attribute strings — an IAM role ARN embedded in a
Lambda's ``role`` field, an S3 bucket name embedded in a notification
configuration, etc. Writers need these as *symbolic* references so the
generated IaC links resources correctly. This module indexes every
resource in a :class:`Snapshot` by ARN / name / id, walks every attribute
of every resource, and substitutes matching strings with :class:`Ref`
instances. Cycles are reported as warnings — they are legal in AWS (e.g.
security groups referencing each other) and must not abort the export.
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from typing import Any

from localemu.export.ir import Ref, Resource, Snapshot

LOG = logging.getLogger(__name__)

# Conservative ARN regex: arn:<partition>:<service>:<region>:<account>:<rest>
_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws[\w-]*):(?P<service>[\w-]+):(?P<region>[\w-]*):"
    r"(?P<account>\d*):(?P<rest>.+)$"
)


def _arn_to_key(arn: str) -> str:
    """Normalize an ARN for index lookup (identity for now, but centralized)."""
    return arn


def _index_resources(
    snapshot: Snapshot,
) -> tuple[dict[str, Resource], dict[tuple[str, str, str, str], Resource]]:
    """Build ARN and (service, type, region, id/name) indices.

    Returns a tuple ``(arn_index, id_index)``. ``arn_index`` maps
    normalized ARN strings to their owning :class:`Resource`. ``id_index``
    maps ``(service, resource_type, region, resource_id_or_name)`` to the
    resource — used for non-ARN id references (e.g. S3 bucket names,
    security-group ids).
    """
    arn_index: dict[str, Resource] = {}
    id_index: dict[tuple[str, str, str, str], Resource] = {}

    for r in snapshot.resources:
        arn = r.attributes.get("arn")
        if isinstance(arn, str) and arn.startswith("arn:"):
            arn_index[_arn_to_key(arn)] = r

        # Primary id: the resource_id itself.
        id_index[(r.service, r.resource_type, r.region, r.resource_id)] = r
        # Secondary ids: name, id, <type>_id, <type>_name attributes.
        for attr_key in ("name", "id", f"{r.resource_type}_id", f"{r.resource_type}_name"):
            val = r.attributes.get(attr_key)
            if isinstance(val, str) and val:
                id_index[(r.service, r.resource_type, r.region, val)] = r

    return arn_index, id_index


def _ref_for_resource(target: Resource, attribute: str = "arn") -> Ref:
    """Construct a :class:`Ref` pointing at ``target``."""
    return Ref(
        service=target.service,
        resource_type=target.resource_type,
        resource_id=target.resource_id,
        attribute=attribute,
    )


def _try_resolve_string(
    value: str,
    arn_index: dict[str, Resource],
    id_index: dict[tuple[str, str, str, str], Resource],
) -> Ref | None:
    """Attempt to resolve a string value into a :class:`Ref`.

    ARN matches are tried first (they are globally unique). If the string
    is not an ARN, we fall back to scanning ``id_index`` for any resource
    whose ``resource_id`` exactly equals ``value``. This second pass can
    produce false positives across services, so we require the match to
    be unambiguous (exactly one hit).
    """
    m = _ARN_RE.match(value)
    if m:
        hit = arn_index.get(_arn_to_key(value))
        if hit is not None:
            return _ref_for_resource(hit, attribute="arn")
        # Unresolved ARN — leave as-is. Writers can still emit the literal.
        return None

    # Non-ARN id lookup: gather all index entries whose id-slot matches.
    # Guard: skip extremely short values and well-known AWS enum strings
    # that collide with auto-generated resource names (e.g. "default" is
    # both an instance-tenancy mode and the name of every VPC's auto-
    # created default security group — resolving it produces a cycle).
    if len(value) < 3 or value in _NON_REF_VALUES:
        return None
    matches = [res for key, res in id_index.items() if key[3] == value]
    # Deduplicate by identity: the same Resource may appear via multiple
    # id slots (``resource_id`` *and* ``attributes.name``).
    unique = {id(r): r for r in matches}
    if len(unique) == 1:
        target = next(iter(unique.values()))
        return _ref_for_resource(target, attribute="id")
    return None


# Strings that are valid AWS enum/mode values but also happen to match
# auto-created resource names. These must NEVER be resolved as cross-
# resource references — they're scalar config values, not identifiers.
_NON_REF_VALUES: frozenset[str] = frozenset({
    # EC2
    "default",          # instance_tenancy, SG name, NACL name
    "dedicated",        # instance_tenancy
    "host",             # instance_tenancy
    # S3
    "private",          # bucket ACL
    "public-read",      # bucket ACL
    "public-read-write",
    "authenticated-read",
    "log-delivery-write",
    "bucket-owner-read",
    "bucket-owner-full-control",
    # ELBv2
    "application",      # load_balancer_type
    "network",          # load_balancer_type
    "gateway",          # load_balancer_type
    "internal",         # scheme
    "internet-facing",  # scheme
    "instance",         # target_type
    "ip",               # target_type
    "lambda",           # target_type
    "alb",              # target_type
    # Lambda
    "python3.11", "python3.12", "python3.13",
    "nodejs18.x", "nodejs20.x", "nodejs22.x",
    "java11", "java17", "java21",
    "provided", "provided.al2", "provided.al2023",
    # DynamoDB
    "PAY_PER_REQUEST",  # billing_mode
    "PROVISIONED",
    # General
    "true", "false", "none", "null", "yes", "no",
    "ENABLED", "DISABLED", "Enabled", "Disabled",
    "ACTIVE", "INACTIVE",
    "Active", "Inactive",
})


def _walk(
    value: Any,
    source: Resource,
    arn_index: dict[str, Resource],
    id_index: dict[tuple[str, str, str, str], Resource],
    stack: set[tuple[str, str, str]],
    cycles: list[str],
) -> Any:
    """Recursively walk ``value`` substituting resolvable strings with Refs."""
    if isinstance(value, str):
        # Don't self-resolve: a resource's own ARN/id should stay literal
        # inside its own attributes.
        ref = _try_resolve_string(value, arn_index, id_index)
        if ref is None:
            return value
        target_key = (ref.service, ref.resource_type, ref.resource_id)
        source_key = (source.service, source.resource_type, source.resource_id)
        if target_key == source_key:
            return value
        if target_key in stack:
            cycles.append(
                f"{source.service}:{source.resource_id} -> "
                f"{ref.service}:{ref.resource_id} (cycle)"
            )
            # Still emit the Ref — cycles are legal in AWS.
        return ref
    if isinstance(value, dict):
        return {k: _walk(v, source, arn_index, id_index, stack, cycles) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, source, arn_index, id_index, stack, cycles) for v in value]
    return value


def resolve_references(snapshot: Snapshot) -> Snapshot:
    """Return a new :class:`Snapshot` with inter-resource refs substituted.

    The input snapshot is not mutated. Cycle detections are appended to
    ``export_warnings`` rather than raised, because AWS permits cyclic
    references (security groups are the canonical example) and the caller
    typically wants the export to succeed anyway.
    """
    arn_index, id_index = _index_resources(snapshot)
    cycles: list[str] = []
    new_resources: list[Resource] = []

    # ``stack`` tracks resources currently being walked. With a flat walk
    # (no recursive Resource traversal) it is effectively a singleton per
    # resource, but we keep the structure so future deep-resolution passes
    # can detect true cycles.
    for r in snapshot.resources:
        stack: set[tuple[str, str, str]] = {(r.service, r.resource_type, r.resource_id)}
        new_attrs = _walk(r.attributes, r, arn_index, id_index, stack, cycles)
        new_resources.append(replace(r, attributes=new_attrs, tags=dict(r.tags)))

    warnings = list(snapshot.export_warnings)
    for c in cycles:
        msg = f"reference cycle detected: {c}"
        LOG.info(msg)
        warnings.append(msg)

    return Snapshot(
        schema_version=snapshot.schema_version,
        exported_at=snapshot.exported_at,
        localemu_version=snapshot.localemu_version,
        resources=new_resources,
        redacted_secrets=list(snapshot.redacted_secrets),
        export_warnings=warnings,
        sidecar_files=dict(snapshot.sidecar_files),
    )
