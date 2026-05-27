"""Secrets Manager collector — secret *metadata only*.

Walks the moto ``secretsmanager`` backend. Secret values are **never**
exported, regardless of ``include_secrets``: per the design, secrets are
re-imported via placeholder (``REPLACEME``) so the operator can re-seed
them out-of-band. Accidentally round-tripping production secrets through
an IaC artifact is a severe hazard, so this collector unconditionally
writes :data:`REDACTED` for every secret value and version payload.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

REDACTED = "***REDACTED***"


def _arn_last_segment(arn: str) -> str:
    """Return the final ``:`` or ``/`` segment of ``arn``."""
    if not isinstance(arn, str):
        return ""
    last = arn
    if ":" in last:
        last = last.rsplit(":", 1)[1]
    if "/" in last:
        last = last.rsplit("/", 1)[1]
    return last


def _parse_arn(arn: str) -> tuple[str, str, str, str] | None:
    """Parse ``arn:aws:<service>:<region>:<account>:<rest>``."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    return parts[2], parts[3], parts[4], parts[5]


def _kms_ref(kms_key_id: Any, same_account: str) -> Ref | Any:
    """Return a :class:`Ref` for a KMS key belonging to ``same_account``.

    Cross-account KMS keys are passed through as raw strings — we only
    own state for the current account and cannot re-create the key.
    """
    if not kms_key_id or not isinstance(kms_key_id, str):
        return kms_key_id
    if kms_key_id.startswith("alias/aws/"):
        return kms_key_id  # AWS-managed alias — emit verbatim.
    parsed = _parse_arn(kms_key_id)
    if parsed is not None:
        _, _, account, _ = parsed
        if account and account != same_account:
            return kms_key_id  # Different account — cannot Ref.
    key_id = _arn_last_segment(kms_key_id) or kms_key_id
    return Ref(service="kms", resource_type="key", resource_id=key_id)


def _parse_json(value: Any) -> Any:
    """Return ``value`` parsed as JSON when it is a non-empty string."""
    if not value:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


@register_collector("secretsmanager")
class SecretsManagerCollector(BaseCollector):
    """Collect Secrets Manager secret *metadata* — never plaintext values."""

    service = "secretsmanager"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Return :class:`Resource` per secret in ``account_id``/``region``.

        Uses ``.items()`` iteration over moto's BackendDict rather than
        ``.get()``/``[]`` subscript: the latter triggered lazy
        instantiation that returned a fresh empty backend even when the
        live state held secrets, so the collector saw zero resources
        despite the dashboard listing one (see ``dashboard/api.py``
        ``_iter_moto_backends`` for the canonical pattern).
        """
        resources: list[Resource] = []
        try:
            import moto.backends as moto_backends
        except Exception:  # pragma: no cover - import guard
            LOG.warning(
                "moto not importable; skipping secretsmanager export", exc_info=True
            )
            return resources

        try:
            backend_dict = moto_backends.get_backend("secretsmanager")
        except Exception:
            LOG.warning("No moto secretsmanager backend available", exc_info=True)
            return resources

        backend = None
        try:
            for acct, region_map in list(backend_dict.items()):
                if acct != account_id:
                    continue
                for reg, b in list(region_map.items()):
                    if reg == region:
                        backend = b
                        break
                break
        except Exception:
            return resources
        if backend is None:
            return resources
        self._collect_backend(backend, account_id, region, resources)
        return resources

    def _collect_backend(
        self,
        backend: Any,
        account_id: str,
        region: str,
        resources: list[Resource],
    ) -> None:
        """Walk a single account/region secretsmanager backend."""
        # moto: ``backend.secrets`` is a dict-like keyed by secret name/id.
        secrets = getattr(backend, "secrets", {}) or {}
        if hasattr(secrets, "items"):
            iterable = list(secrets.items())
        else:
            iterable = [(getattr(s, "name", None) or str(i), s) for i, s in enumerate(secrets)]

        for name, secret in iterable:
            try:
                resources.append(
                    self._build_secret_resource(account_id, region, name, secret)
                )
            except Exception:
                LOG.warning("Skipping malformed secret %s", name, exc_info=True)

    # --- builders --------------------------------------------------------

    def _build_secret_resource(
        self, account_id: str, region: str, name: str, secret: Any
    ) -> Resource:
        """Build a secret :class:`Resource` with all value fields redacted."""
        arn = _get(secret, "arn")
        secret_name = _get(secret, "name", "secret_id") or name

        kms_key_id = _get(secret, "kms_key_id", "kmsKeyId")
        rotation_enabled = _get(secret, "rotation_enabled", "rotationEnabled")
        rotation_rules = _get(secret, "rotation_rules", "rotationRules")
        rotation_lambda_arn = _get(secret, "rotation_lambda_arn", "rotationLambdaARN")
        rotation_lambda_ref: Any = rotation_lambda_arn
        if isinstance(rotation_lambda_arn, str) and rotation_lambda_arn.startswith("arn:"):
            fn = _arn_last_segment(rotation_lambda_arn)
            if fn:
                rotation_lambda_ref = Ref(
                    service="lambda", resource_type="function", resource_id=fn
                )

        replica_regions = _get(secret, "replicas", "replica_regions", "replicaRegions")
        replica_out: list[dict[str, Any]] = []
        for rep in list(replica_regions or []):
            if isinstance(rep, dict):
                replica_out.append(
                    {
                        "region": rep.get("Region") or rep.get("region"),
                        "kms_key_id": rep.get("KmsKeyId") or rep.get("kms_key_id"),
                        "status": rep.get("Status") or rep.get("status"),
                    }
                )
            else:
                replica_out.append(
                    {
                        "region": getattr(rep, "region", None),
                        "kms_key_id": getattr(rep, "kms_key_id", None),
                        "status": getattr(rep, "status", None),
                    }
                )

        resource_policy = _get(secret, "policy", "resource_policy", "resourcePolicy")

        # Version metadata WITHOUT plaintext payloads.
        versions_raw = _get(secret, "versions") or {}
        versions_meta: list[dict[str, Any]] = []
        if hasattr(versions_raw, "items"):
            version_iter = list(versions_raw.items())
        else:
            version_iter = [(getattr(v, "version_id", str(i)), v) for i, v in enumerate(versions_raw)]
        for vid, version in version_iter:
            stages = (
                _get(version, "version_stages", "versionStages", "stages") or []
            )
            versions_meta.append(
                {
                    "version_id": _get(version, "version_id", "versionId") or vid,
                    "version_stages": list(stages),
                    "created_date": str(
                        _get(version, "created_date", "createdDate") or ""
                    )
                    or None,
                    # Explicitly redact — never export plaintext values, even
                    # with include_secrets=True (per design).
                    "secret_string": REDACTED,
                    "secret_binary": REDACTED,
                }
            )

        attrs: dict[str, Any] = {
            "name": secret_name,
            "arn": arn,
            "description": _get(secret, "description"),
            "kms_key_id": _kms_ref(kms_key_id, account_id),
            "rotation_enabled": rotation_enabled,
            "rotation_lambda_arn": rotation_lambda_ref,
            "rotation_rules": rotation_rules,
            "replica_regions": replica_out,
            "resource_policy": _parse_json(resource_policy),
            "force_overwrite_replica_secret": _get(
                secret, "force_overwrite_replica_secret"
            ),
            # Per-design: placeholder on import, redacted on export.
            "secret_string": REDACTED,
            "secret_binary": REDACTED,
            "versions": versions_meta,
        }
        attrs = {k: v for k, v in attrs.items() if v not in (None, [], {})}

        # Re-assert redaction — in case a filter above stripped the sentinel.
        attrs["secret_string"] = REDACTED
        attrs["secret_binary"] = REDACTED

        tags = _normalize_tags(_get(secret, "tags"))
        return Resource(
            service="secretsmanager",
            resource_type="secret",
            resource_id=secret_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
        )


def _get(obj: Any, *keys: str) -> Any:
    """Return the first non-None attribute or dict key from ``obj``."""
    for k in keys:
        if isinstance(obj, dict):
            if k in obj and obj[k] is not None:
                return obj[k]
        else:
            v = getattr(obj, k, None)
            if v is not None:
                return v
    return None


def _normalize_tags(tags: Any) -> dict[str, str]:
    """Normalize tags to a ``dict[str, str]``."""
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        out: dict[str, str] = {}
        for item in tags:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}
