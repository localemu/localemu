"""Phase 6 — secrets handling.

Any value that is plausibly secret (Lambda env vars, SSM ``SecureString``
parameters, Secrets Manager values, RDS passwords, ...) MUST NOT land in
the generated Terraform / CloudFormation. Instead:

* The output declares a Terraform ``variable`` (or CloudFormation
  ``Parameter``) named ``secret_<resource>_<field>``.
* The original value (if known) is written to ``terraform.tfvars.example``
  / a sample parameters file the user must populate before deploying.
* The MANIFEST lists every secret the user owes a value for.

The redaction pass that already ships with the v2 export
(:mod:`localemu.export.redaction`) also wipes secrets — but it wipes them
to the literal string ``***REDACTED***`` which terraform would happily
deploy. That string MUST be replaced with a variable reference in the
real-AWS pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from localemu.export.ir import Resource, Snapshot

# Field names that hold secret material. We match exact keys, not
# substrings, to avoid pulling in benign fields like ``description``.
_SECRET_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "master_password",
        "master_user_password",
        "secret",
        "secret_string",
        "secret_value",
        "secretstring",
        "private_key",
        "privatekey",
        # ``value`` is intentionally NOT here — it's ubiquitous across AWS
        # (ECS settings, DynamoDB items, tag values, ...) and causes massive
        # false-positive secret redaction. The ``_CONDITIONAL_SECRETS`` table
        # below gates ``value`` on specific resource types where it IS secret
        # (SSM SecureString, SecretsManager).
    }
)

# Resources whose ``value`` field is secret only when their ``type`` says
# so. SSM parameters: ``value`` is secret only when ``type=SecureString``.
# SecretsManager: ``value`` is always secret regardless of type.
_CONDITIONAL_SECRETS: dict[tuple[str, str], str] = {
    ("ssm", "parameter"): "type",
}

# Resources where ``value`` is ALWAYS a secret (unconditional).
_UNCONDITIONAL_SECRET_VALUE: frozenset[tuple[str, str]] = frozenset({
    ("secretsmanager", "secret"),
})

# Sanitize a resource id into something usable as a TF variable name.
_VAR_SANITIZE = re.compile(r"[^a-z0-9_]+")


@dataclass(frozen=True)
class SecretSlot:
    """One value the deploying user must supply at apply time.

    Attributes:
        variable_name: Terraform variable / CFN parameter name.
        service: Owning service.
        resource_type: Owning resource type.
        resource_id: Owning resource id.
        attribute_path: Dotted path inside the resource's attributes
            (e.g. ``environment.variables.DB_PASSWORD``).
        sample_value: The value as collected from LocalEmu, if known.
            Used to populate ``terraform.tfvars.example``. May be ``None``
            when the redaction pass already wiped it.
    """

    variable_name: str
    service: str
    resource_type: str
    resource_id: str
    attribute_path: str
    sample_value: str | None = None


@dataclass
class SecretsExtractionResult:
    """Outcome of :func:`extract_secrets`."""

    snapshot: Snapshot
    slots: list[SecretSlot] = field(default_factory=list)


def _safe_var_name(*parts: str) -> str:
    """Build a unique-ish, syntactically-valid TF variable name."""
    joined = "_".join(parts).lower()
    cleaned = _VAR_SANITIZE.sub("_", joined).strip("_")
    if not cleaned:
        cleaned = "secret"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return f"secret_{cleaned}"


class _Sentinel:
    """Marker passed back to writers to emit ``var.<name>`` (TF) / ``Ref`` (CFN)."""

    __slots__ = ("variable_name",)

    def __init__(self, variable_name: str) -> None:
        self.variable_name = variable_name

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return f"<SecretVar {self.variable_name}>"


def _is_secret_field(
    field_name: str,
    parent_chain: tuple[str, ...],
    resource: Resource,
) -> bool:
    """Decide whether ``field_name`` (with its parent chain) holds a secret."""
    lname = field_name.lower()
    if lname in _SECRET_FIELD_NAMES:
        return True
    # ``value`` is a special case — it's secret only for specific services.
    if lname == "value":
        key = (resource.service, resource.resource_type)
        if key in _UNCONDITIONAL_SECRET_VALUE:
            return True
        cond_field = _CONDITIONAL_SECRETS.get(key)
        if cond_field is not None:
            ssm_type = str(resource.attributes.get(cond_field) or "").lower()
            return ssm_type == "securestring"
        return False
    # Lambda environment variables: pattern-match the KEY name to decide.
    # Blanket-treating every env var as a secret (the previous behavior)
    # forced operators to re-supply benign vars like ``LOG_LEVEL`` or
    # ``TABLE_NAME`` via tfvars on every deploy and broke Ref resolution
    # for vars that point at sibling resources. Match the policy in
    # ``localemu.export.redaction`` exactly.
    parents = parent_chain[:-1]
    if (
        resource.service == "lambda"
        and resource.resource_type == "function"
        and len(parents) >= 2
        and parents[-2:] == ("environment", "variables")
    ):
        return _looks_secret_by_keyname(field_name)
    return False


_SENSITIVE_KEY_PATTERNS = (
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "access_key", "private_key", "privatekey", "credential", "auth",
    "session", "jwt", "certificate", "ssh_key",
)


def _looks_secret_by_keyname(name: str) -> bool:
    lname = name.lower()
    return any(p in lname for p in _SENSITIVE_KEY_PATTERNS)


def _walk(
    value: Any,
    resource: Resource,
    chain: tuple[str, ...],
    used_names: set[str],
    slots: list[SecretSlot],
) -> Any:
    """Recursive walker. Returns a value with secrets replaced by sentinels."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            new_chain = chain + (k,)
            if isinstance(v, (str, int, float, bool)) and _is_secret_field(
                k, new_chain, resource
            ):
                base = _safe_var_name(
                    resource.service, resource.resource_type, resource.resource_id, k
                )
                name = base
                suffix = 1
                while name in used_names:
                    suffix += 1
                    name = f"{base}_{suffix}"
                used_names.add(name)
                slot = SecretSlot(
                    variable_name=name,
                    service=resource.service,
                    resource_type=resource.resource_type,
                    resource_id=resource.resource_id,
                    attribute_path=".".join(new_chain),
                    sample_value=str(v) if v != "***REDACTED***" else None,
                )
                slots.append(slot)
                out[k] = _Sentinel(name)
            else:
                out[k] = _walk(v, resource, new_chain, used_names, slots)
        return out
    if isinstance(value, list):
        return [_walk(v, resource, chain, used_names, slots) for v in value]
    return value


def extract_secrets(snapshot: Snapshot) -> SecretsExtractionResult:
    """Replace secret values in ``snapshot`` with sentinel variable refs.

    The returned snapshot is independent of the input; the input is not
    mutated. ``slots`` enumerates every variable the user must populate
    before the generated Terraform / CFN can be applied.
    """
    used_names: set[str] = set()
    slots: list[SecretSlot] = []

    new_resources: list[Resource] = []
    for r in snapshot.resources:
        new_attrs = _walk(r.attributes, r, (), used_names, slots)
        new_resources.append(
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

    return SecretsExtractionResult(
        snapshot=Snapshot(
            schema_version=snapshot.schema_version,
            exported_at=snapshot.exported_at,
            localemu_version=snapshot.localemu_version,
            resources=new_resources,
            redacted_secrets=list(snapshot.redacted_secrets),
            export_warnings=list(snapshot.export_warnings),
            sidecar_files=dict(snapshot.sidecar_files),
        ),
        slots=slots,
    )
