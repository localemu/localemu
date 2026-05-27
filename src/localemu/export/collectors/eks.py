"""EKS collector: clusters + node groups."""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


@register_collector("eks")
class EksCollector(BaseCollector):
    service = "eks"

    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("eks")[account_id][region]
        except Exception:
            LOG.warning("EKS backend unavailable", exc_info=True)
            return []

        out: list[Resource] = []
        clusters = getattr(backend, "clusters", {}) or {}
        for name, cluster in dict(clusters).items():
            try:
                out.append(self._cluster(cluster, name, account_id, region))
                nodegroups = getattr(cluster, "nodegroups", {}) or {}
                for ng_name, ng in dict(nodegroups).items():
                    try:
                        out.append(self._nodegroup(ng, ng_name, name, account_id, region))
                    except Exception:
                        LOG.warning("Skipping nodegroup %r", ng_name, exc_info=True)
            except Exception:
                LOG.warning("Skipping EKS cluster %r", name, exc_info=True)
        return out

    def _cluster(self, cluster: Any, name: str, account_id: str, region: str) -> Resource:
        role_arn = getattr(cluster, "role_arn", None)
        vpc_config = getattr(cluster, "resources_vpc_config", None) or {}
        if not isinstance(vpc_config, dict):
            vpc_config = {}
        subnet_ids = vpc_config.get("subnet_ids") or vpc_config.get("SubnetIds") or []
        sg_ids = vpc_config.get("security_group_ids") or vpc_config.get("SecurityGroupIds") or []
        attrs: dict[str, Any] = {
            "name": name,
            "arn": getattr(cluster, "arn", None),
            "version": getattr(cluster, "version", None),
            "role_arn": _role_ref(role_arn) if role_arn else None,
            "vpc_config": [{
                "subnet_ids": [
                    Ref("ec2", "subnet", s, attribute="id") for s in subnet_ids
                ] if subnet_ids else [],
                "security_group_ids": [
                    Ref("ec2", "security_group", sg, attribute="id") for sg in sg_ids
                ] if sg_ids else [],
            }],
        }
        tags = _tags(cluster)
        return Resource(
            service="eks", resource_type="cluster",
            resource_id=name, account_id=account_id,
            region=region, attributes=attrs, tags=tags,
        )

    def _nodegroup(self, ng: Any, name: str, cluster_name: str,
                   account_id: str, region: str) -> Resource:
        node_role = getattr(ng, "node_role", None) or getattr(ng, "node_role_arn", None)
        subnet_ids = getattr(ng, "subnets", []) or []
        attrs: dict[str, Any] = {
            "cluster_name": Ref("eks", "cluster", cluster_name, attribute="name"),
            "node_group_name": name,
            "arn": getattr(ng, "arn", None),
            "node_role_arn": _role_ref(node_role) if node_role else None,
            "subnet_ids": [Ref("ec2", "subnet", s, attribute="id") for s in subnet_ids] if subnet_ids else [],
            "instance_types": list(getattr(ng, "instance_types", []) or []),
            "scaling_config": [{
                "desired_size": getattr(ng, "desired_size", None) or getattr(ng, "scaling_config", {}).get("desired_size", 1),
                "min_size": getattr(ng, "min_size", None) or getattr(ng, "scaling_config", {}).get("min_size", 1),
                "max_size": getattr(ng, "max_size", None) or getattr(ng, "scaling_config", {}).get("max_size", 2),
            }],
        }
        tags = _tags(ng)
        return Resource(
            service="eks", resource_type="node_group",
            resource_id=f"{cluster_name}/{name}",
            account_id=account_id, region=region,
            attributes=attrs, tags=tags,
        )


def _role_ref(arn: str) -> Any:
    if not arn or not isinstance(arn, str):
        return arn
    name = arn.rsplit("/", 1)[-1] if "/" in arn else arn
    return Ref(service="iam", resource_type="role", resource_id=name)


def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return {str(t.get("Key", "")): str(t.get("Value", "")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
