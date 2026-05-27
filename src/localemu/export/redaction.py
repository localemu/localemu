"""Secret redaction for exported snapshots.

Snapshots get checked into repos, mailed around, pasted into tickets. We
default to scrubbing anything that looks like a secret and let the user
opt out with ``include_secrets=True``. The redaction layer runs *after*
collection but *before* reference resolution — references do not point at
secret material, so the order does not matter semantically, but doing
redaction first keeps downstream passes simpler.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from localemu.export.ir import Resource, resource_logical_id

LOG = logging.getLogger(__name__)

REDACTED = "***REDACTED***"

# Case-insensitive substrings that strongly suggest the value is secret.
_SENSITIVE_KEY_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "privatekey",
    "credential",
    # ``auth`` used to be in this list as a bare substring, which
    # over-fired on enum / type-label keys like ``authorization_type``
    # (rendered as ``***REDACTED***`` and then rejected by the
    # ``aws_cloudwatch_event_connection`` TF schema). Narrow to the
    # patterns that actually denote a secret value.
    "auth_token",
    "authorization_header",
    "session",
    "jwt",
    "certificate",
    "ssh_key",
)

# Per-service attribute paths that are *always* redacted regardless of key
# name. Paths are dotted, rooted at ``Resource.attributes``.
_SERVICE_FORCED_PATHS: dict[tuple[str, str], tuple[str, ...]] = {
    # Note: Lambda ``environment.variables`` is intentionally NOT here.
    # Blanket-redacting every env var (including innocuous ones like
    # ``LOG_LEVEL`` or ``TABLE_NAME``) forced operators to re-supply
    # them via tfvars before each deploy and broke reference resolution
    # for vars that pointed at sibling resources. Per-key sensitivity
    # detection (via :data:`_SENSITIVE_KEY_PATTERNS`) catches the actual
    # secrets (``SECRET_TOKEN``, ``API_KEY``, ``DB_PASSWORD``, ...)
    # without nuking the whole map.
    ("ssm", "parameter"): ("value",),
    ("secretsmanager", "secret"): ("secret_string", "secret_binary"),
    ("ec2", "instance"): ("user_data",),
    ("ec2", "launch_template"): ("user_data",),
}


def _is_sensitive_key(path: str) -> bool:
    """Return ``True`` if the dotted ``path`` looks like it holds a secret.

    We only inspect the *final* path segment — matching anywhere would
    over-fire on harmless parent keys (e.g. ``auth_policy.statements``).
    """
    last = path.rsplit(".", 1)[-1].lower()
    return any(pat in last for pat in _SENSITIVE_KEY_PATTERNS)


def _redact_value(value: Any) -> Any:
    """Return a redacted stand-in preserving rough shape for debugging."""
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(b"").decode() if False else REDACTED
    if isinstance(value, dict):
        return {k: REDACTED for k in value}
    if isinstance(value, list):
        return [REDACTED for _ in value]
    return REDACTED


def _walk_and_redact(
    obj: Any,
    path: str,
    forced_prefixes: tuple[str, ...],
    redacted_paths: list[str],
) -> Any:
    """Recursively walk ``obj`` redacting sensitive leaves.

    ``forced_prefixes`` is a tuple of dotted prefixes (relative to
    ``attributes``) that should be redacted wholesale regardless of key
    name. The function returns a *new* structure; inputs are not mutated.
    """
    # Forced-path match: redact the entire subtree.
    rel = path[len("attributes.") :] if path.startswith("attributes.") else path
    if any(rel == p or rel.startswith(p + ".") for p in forced_prefixes):
        redacted_paths.append(path)
        return _redact_value(obj)

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else k
            child_rel = child_path[len("attributes.") :] if child_path.startswith(
                "attributes."
            ) else child_path
            if any(
                child_rel == p or child_rel.startswith(p + ".")
                for p in forced_prefixes
            ):
                redacted_paths.append(child_path)
                out[k] = _redact_value(v)
            elif _is_sensitive_key(child_path) and not isinstance(v, (dict, list)):
                redacted_paths.append(child_path)
                out[k] = REDACTED
            else:
                out[k] = _walk_and_redact(v, child_path, forced_prefixes, redacted_paths)
        return out
    if isinstance(obj, list):
        return [
            _walk_and_redact(item, f"{path}[{i}]", forced_prefixes, redacted_paths)
            for i, item in enumerate(obj)
        ]
    return obj


def redact_secrets(
    resource: Resource, include_secrets: bool
) -> tuple[Resource, list[str]]:
    """Return a (possibly redacted) copy of ``resource`` plus redacted paths.

    If ``include_secrets`` is ``True`` the original resource is returned
    unchanged and the list is empty. Otherwise sensitive keys and known
    per-service sensitive paths are replaced with :data:`REDACTED`.

    The returned paths are prefixed with the resource's logical ID so that
    they remain unambiguous once aggregated at the snapshot level.
    """
    if include_secrets:
        return resource, []

    forced = _SERVICE_FORCED_PATHS.get((resource.service, resource.resource_type), ())
    local_paths: list[str] = []
    new_attrs = _walk_and_redact(resource.attributes, "attributes", forced, local_paths)

    logical = resource_logical_id(resource)
    qualified = [f"{logical}.{p}" for p in local_paths]
    if qualified:
        LOG.debug("Redacted %d path(s) on %s", len(qualified), logical)

    new_resource = Resource(
        service=resource.service,
        resource_type=resource.resource_type,
        resource_id=resource.resource_id,
        account_id=resource.account_id,
        region=resource.region,
        attributes=new_attrs,
        tags=dict(resource.tags),
        created_at=resource.created_at,
    )
    return new_resource, qualified
