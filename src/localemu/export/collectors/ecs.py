"""ECS collector: clusters, task definitions, services."""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


@register_collector("ecs")
class EcsCollector(BaseCollector):
    service = "ecs"

    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("ecs")[account_id][region]
        except Exception:
            LOG.warning("ECS backend unavailable", exc_info=True)
            return []

        out: list[Resource] = []
        clusters = getattr(backend, "clusters", {}) or {}
        for cluster_name, cluster in dict(clusters).items():
            try:
                out.append(self._cluster(cluster, cluster_name, account_id, region))
            except Exception:
                LOG.warning("Skipping ECS cluster %r", cluster_name, exc_info=True)

        task_defs = getattr(backend, "task_definitions", {}) or {}
        for family, revisions in dict(task_defs).items():
            if not revisions:
                continue
            # ``revisions`` is a dict keyed by revision number (int), not a
            # list. Export only the latest (highest-numbered) revision.
            if isinstance(revisions, dict):
                latest = revisions[max(revisions)]
            elif isinstance(revisions, list):
                latest = revisions[-1]
            else:
                latest = revisions
            try:
                out.append(self._task_def(latest, family, account_id, region))
            except Exception:
                LOG.warning("Skipping task def %r", family, exc_info=True)

        services = getattr(backend, "services", {}) or {}
        for svc_key, svc in dict(services).items():
            try:
                out.append(self._service(svc, account_id, region))
            except Exception:
                LOG.warning("Skipping ECS service %r", svc_key, exc_info=True)

        return out

    def _cluster(self, cluster: Any, name: str, account_id: str, region: str) -> Resource:
        attrs: dict[str, Any] = {
            "name": getattr(cluster, "name", name) or name,
            "arn": getattr(cluster, "arn", None),
        }
        settings = getattr(cluster, "settings", None)
        if settings:
            attrs["setting"] = settings if isinstance(settings, list) else [settings]
        tags = _tags(cluster)
        return Resource(
            service="ecs", resource_type="cluster",
            resource_id=attrs["name"], account_id=account_id,
            region=region, attributes=attrs, tags=tags,
        )

    def _task_def(self, td: Any, family: str, account_id: str, region: str) -> Resource:
        containers = []
        for cd in getattr(td, "container_definitions", []) or []:
            c: dict[str, Any] = {}
            if isinstance(cd, dict):
                c = dict(cd)
            else:
                for k in ("name", "image", "cpu", "memory", "memoryReservation",
                          "essential", "command", "entryPoint", "environment",
                          "portMappings", "logConfiguration", "mountPoints",
                          "volumesFrom", "healthCheck"):
                    v = getattr(cd, k, None)
                    if v is not None:
                        c[k] = v
            containers.append(c)

        attrs: dict[str, Any] = {
            "family": family,
            "arn": getattr(td, "arn", None),
            "container_definitions": containers,
            "network_mode": getattr(td, "network_mode", None),
            "requires_compatibilities": list(
                getattr(td, "requires_compatibilities", []) or []
            ),
            "cpu": getattr(td, "cpu", None),
            "memory": getattr(td, "memory", None),
        }
        task_role = getattr(td, "task_role_arn", None)
        if task_role:
            attrs["task_role_arn"] = _role_ref(task_role)
        exec_role = getattr(td, "execution_role_arn", None)
        if exec_role:
            attrs["execution_role_arn"] = _role_ref(exec_role)
        volumes = getattr(td, "volumes", None)
        if volumes:
            attrs["volume"] = volumes if isinstance(volumes, list) else [volumes]
        tags = _tags(td)
        return Resource(
            service="ecs", resource_type="task_definition",
            resource_id=family, account_id=account_id,
            region=region, attributes=attrs, tags=tags,
        )

    def _service(self, svc: Any, account_id: str, region: str) -> Resource:
        cluster_arn = getattr(svc, "cluster_arn", None) or getattr(svc, "cluster_name", None)
        task_def_arn = getattr(svc, "task_definition", None)
        attrs: dict[str, Any] = {
            "name": getattr(svc, "name", None) or getattr(svc, "service_name", None),
            "arn": getattr(svc, "arn", None),
            "cluster": cluster_arn,
            "task_definition": task_def_arn,
            "desired_count": getattr(svc, "desired_count", None),
            "launch_type": getattr(svc, "launch_type", None),
        }
        nc = getattr(svc, "network_configuration", None)
        if nc:
            attrs["network_configuration"] = nc if isinstance(nc, dict) else {"awsvpcConfiguration": {}}
        lbs = getattr(svc, "load_balancers", None)
        if lbs:
            attrs["load_balancer"] = lbs if isinstance(lbs, list) else [lbs]
        tags = _tags(svc)
        return Resource(
            service="ecs", resource_type="service",
            resource_id=attrs["name"] or "unknown",
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
        return {str(t.get("Key", t.get("key", ""))): str(t.get("Value", t.get("value", ""))) for t in raw if isinstance(t, dict)}
    return {}
