"""KMS collector.

Exports KMS customer master keys and aliases. Key *material* is never
serialised — it cannot be reproduced on a different emulator instance
anyway and emitting it into a snapshot file is a hard no.

Only a short, explicit whitelist of fields is copied off each moto Key
object. Tags are also skipped for now: KMS tags are often used as a
cheap secret store in the wild and letting them through by default
would undermine the redaction contract.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

# Whitelist of safe, non-material fields on the moto Key object.
_KEY_FIELDS = (
    "key_id",
    "arn",
    "description",
    "key_usage",
    "key_spec",
    "customer_master_key_spec",
    "origin",
    "key_manager",
    "enabled",
    "pending_window_in_days",
    "multi_region",
)


@register_collector("kms")
class KmsCollector(BaseCollector):
    """Collect KMS keys and aliases from the moto backend."""

    service = "kms"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate KMS keys and aliases for the given scope.

        LocalEmu's KMS provider holds its own ``KmsStore`` (see
        ``services/kms/models.py``) rather than moto's backend. Reading
        from ``moto.backends.get_backend('kms')`` returned an always-empty
        backend, silently dropping every key — even though the API
        correctly listed them. Walk ``kms_stores`` instead.
        """
        resources: list[Resource] = []
        try:
            from localemu.services.kms.models import kms_stores
        except Exception:
            LOG.warning("Failed to import kms_stores; skipping KMS", exc_info=True)
            return resources

        if account_id not in kms_stores:
            return resources
        try:
            backend = kms_stores[account_id][region]
        except Exception:
            LOG.warning(
                "No KMS store for %s/%s", account_id, region, exc_info=True,
            )
            return resources

        resources.extend(self._collect_keys(backend, account_id, region))
        resources.extend(self._collect_aliases(backend, account_id, region))
        return resources

    # ------------------------------------------------------------------
    def _collect_keys(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``kms:key`` resources."""
        out: list[Resource] = []
        raw = getattr(backend, "keys", None)
        if raw is None:
            return out
        for key_id, key in list(raw.items()):
            try:
                out.append(self._key_resource(key_id, key, account_id, region))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed KMS key %r", key_id, exc_info=True
                )
                continue
        return out

    def _key_resource(
        self, key_id: str, key: Any, account_id: str, region: str
    ) -> Resource:
        """Build a :class:`Resource` for a single KMS key."""
        attrs: dict[str, Any] = {}
        for field in _KEY_FIELDS:
            value = getattr(key, field, None)
            if value is not None:
                attrs[field] = value
        attrs.setdefault("key_id", str(key_id))

        # Policy is stored as a JSON string on moto keys; parse into a
        # dict so downstream writers can emit structured policy docs.
        policy = getattr(key, "policy", None)
        if isinstance(policy, str):
            try:
                attrs["policy"] = json.loads(policy)
            except (ValueError, TypeError):
                attrs["policy"] = policy
        elif isinstance(policy, dict):
            attrs["policy"] = policy

        rotation = getattr(key, "key_rotation_status", None)
        if rotation is None:
            rotation = getattr(key, "rotation_enabled", None)
        if rotation is not None:
            attrs["key_rotation_enabled"] = bool(rotation)

        # Deliberately omit: key material, grants, tags (may contain
        # sensitive info), and any ``_*`` private attributes.
        return Resource(
            service="kms",
            resource_type="key",
            resource_id=str(key_id),
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags={},
        )

    # ------------------------------------------------------------------
    def _collect_aliases(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``kms:alias`` resources."""
        out: list[Resource] = []
        aliases_map: dict[str, str] = {}
        # LocalEmu's ``KmsStore.aliases`` is ``{alias_name: KmsAlias}``
        # where ``KmsAlias.metadata`` holds ``AliasName`` + ``TargetKeyId``
        # (see ``services/kms/models.py``). The TargetKeyId may be the
        # bare key id, an ARN, or another alias — normalize to a key id.
        store_aliases = getattr(backend, "aliases", None)
        if isinstance(store_aliases, dict):
            for alias_name, target in store_aliases.items():
                meta = getattr(target, "metadata", None) or {}
                tgt = meta.get("TargetKeyId") if isinstance(meta, dict) else None
                if not tgt:
                    tgt = getattr(target, "key_id", target)
                # If the target is an ARN, extract the key id (last segment).
                tgt_s = str(tgt)
                if tgt_s.startswith("arn:") and "/" in tgt_s:
                    tgt_s = tgt_s.rsplit("/", 1)[-1]
                aliases_map[str(alias_name)] = tgt_s
        else:
            # Legacy moto layout (kept as fallback).
            raw = getattr(backend, "key_to_aliases", None)
            if isinstance(raw, dict):
                for key_id, aliases in raw.items():
                    if not aliases:
                        continue
                    for alias_name in aliases:
                        aliases_map[str(alias_name)] = str(key_id)

        for alias_name, key_id in aliases_map.items():
            try:
                if not alias_name.startswith("alias/"):
                    # KMS alias names always start with "alias/"; skip
                    # anything that doesn't match the contract.
                    continue
                out.append(
                    Resource(
                        service="kms",
                        resource_type="alias",
                        resource_id=alias_name,
                        account_id=account_id,
                        region=region,
                        attributes={
                            "name": alias_name,
                            "target_key_id": Ref(
                                service="kms",
                                resource_type="key",
                                resource_id=key_id,
                            ),
                        },
                        tags={},
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed KMS alias %r", alias_name, exc_info=True
                )
                continue
        return out
