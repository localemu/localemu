"""Resource Groups collector."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("resource_groups")
class ResourceGroupsCollector(BaseCollector):
    service = "resource_groups"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("resource-groups")[account_id][region]
        except Exception:
            LOG.warning("Resource Groups unavailable", exc_info=True); return []
        out: list[Resource] = []
        # Moto's ``ResourceGroups`` class implements ``__getitem__`` but has
        # no ``__iter__`` or ``keys()``, so ``dict(backend.groups)`` falls
        # through to Python's sequence protocol (integer indexing) and
        # moto raises ``KeyError('0')`` instead of ``IndexError`` — which
        # bubbles out of ``dict()``. Reach into the backing ``by_name``
        # dict directly; fall back to the rare ``_groups`` plain-dict
        # variant or the whole backend object so the collector is tolerant
        # of moto minor-version drift.
        raw = getattr(backend, "groups", None)
        if raw is None:
            raw = getattr(backend, "_groups", {}) or {}
        groups_map = getattr(raw, "by_name", None)
        if groups_map is None and isinstance(raw, dict):
            groups_map = raw
        if not groups_map:
            return out
        for name, grp in groups_map.items():
            try:
                attrs: dict[str, Any] = {
                    "name": getattr(grp, "name", name) or name,
                    "arn": getattr(grp, "arn", None),
                    "description": getattr(grp, "description", None),
                }
                query = getattr(grp, "resource_query", None)
                if query:
                    attrs["resource_query"] = query if isinstance(query, dict) else {"query": str(query), "type": "TAG_FILTERS_1_0"}
                attrs = {k: v for k, v in attrs.items() if v is not None}
                tags = _tags(grp)
                out.append(Resource(
                    service="resource_groups", resource_type="group",
                    resource_id=attrs["name"],
                    account_id=account_id, region=region,
                    attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping resource group %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    return {}
