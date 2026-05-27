"""OpenSearch collector: domains."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("opensearch")
class OpenSearchCollector(BaseCollector):
    service = "opensearch"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("opensearch")[account_id][region]
        except Exception:
            LOG.warning("OpenSearch unavailable", exc_info=True); return []
        out: list[Resource] = []
        domains = getattr(backend, "domains", {}) or {}
        for name, domain in dict(domains).items():
            try:
                attrs: dict[str, Any] = {
                    "domain_name": name,
                    "arn": getattr(domain, "arn", None),
                    "engine_version": getattr(domain, "engine_version", None),
                }
                cluster_config = getattr(domain, "cluster_config", None)
                if isinstance(cluster_config, dict):
                    attrs["cluster_config"] = [{
                        "instance_type": cluster_config.get("InstanceType", cluster_config.get("instance_type")),
                        "instance_count": cluster_config.get("InstanceCount", cluster_config.get("instance_count")),
                    }]
                ebs = getattr(domain, "ebs_options", None)
                if isinstance(ebs, dict):
                    attrs["ebs_options"] = [{
                        "ebs_enabled": bool(ebs.get("EBSEnabled", ebs.get("ebs_enabled", True))),
                        "volume_size": ebs.get("VolumeSize", ebs.get("volume_size")),
                        "volume_type": ebs.get("VolumeType", ebs.get("volume_type")),
                    }]
                access_policies = getattr(domain, "access_policies", None)
                if access_policies:
                    attrs["access_policies"] = access_policies if isinstance(access_policies, str) else str(access_policies)
                tags = _tags(domain)
                out.append(Resource(
                    service="opensearch", resource_type="domain",
                    resource_id=name, account_id=account_id,
                    region=region, attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping OpenSearch domain %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
