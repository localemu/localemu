"""Redshift collector: clusters + subnet groups + parameter groups."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

@register_collector("redshift")
class RedshiftCollector(BaseCollector):
    service = "redshift"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("redshift")[account_id][region]
        except Exception:
            LOG.warning("Redshift unavailable", exc_info=True); return []
        out: list[Resource] = []
        clusters = getattr(backend, "clusters", {}) or {}
        for cid, cluster in dict(clusters).items():
            try:
                attrs: dict[str, Any] = {
                    "cluster_identifier": cid,
                    "node_type": getattr(cluster, "node_type", None),
                    "number_of_nodes": getattr(cluster, "number_of_nodes", None),
                    "master_username": getattr(cluster, "master_username", None),
                    "master_password": getattr(cluster, "master_password", None),  # → secret
                    "database_name": getattr(cluster, "db_name", None),
                    "cluster_type": "multi-node" if (getattr(cluster, "number_of_nodes", 1) or 1) > 1 else "single-node",
                    "skip_final_snapshot": True,
                }
                vpc_sg_ids = getattr(cluster, "vpc_security_group_ids", []) or []
                if vpc_sg_ids:
                    attrs["vpc_security_group_ids"] = vpc_sg_ids
                subnet_group = getattr(cluster, "cluster_subnet_group_name", None)
                if subnet_group:
                    attrs["cluster_subnet_group_name"] = subnet_group
                tags = _tags(cluster)
                out.append(Resource(
                    service="redshift", resource_type="cluster",
                    resource_id=cid, account_id=account_id,
                    region=region, attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping Redshift cluster %r", cid, exc_info=True)
        # Subnet groups
        subnet_groups = getattr(backend, "subnet_groups", {}) or {}
        for name, sg in dict(subnet_groups).items():
            try:
                subnet_ids = [
                    getattr(s, "subnet_identifier", None) or s
                    for s in (getattr(sg, "subnets", []) or [])
                ]
                attrs = {
                    "name": name,
                    "subnet_ids": [s for s in subnet_ids if s],
                    "description": getattr(sg, "description", None),
                }
                out.append(Resource(
                    service="redshift", resource_type="subnet_group",
                    resource_id=name, account_id=account_id,
                    region=region, attributes=attrs, tags=_tags(sg),
                ))
            except Exception:
                LOG.warning("Skipping subnet group %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
