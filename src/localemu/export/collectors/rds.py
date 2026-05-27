"""RDS collector.

Enumerates the relational-database objects moto tracks under the
``rds`` backend: DB instances, Aurora clusters, subnet groups, DB
parameter groups, cluster parameter groups and option groups.

Everything else the moto backend exposes (snapshots, event
subscriptions, read-replica chains, blue/green deployments, ...) is
deliberately out of scope — none of them round-trip to a deterministic
real-AWS template, and a real RDS deployment is reconstructed from the
instance / cluster / subnet-group / parameter-group quartet this
collector emits.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _tags(tags_list: Any) -> dict[str, str]:
    """Normalise moto's ``[{"Key":..,"Value":..}]`` row list to a dict."""
    out: dict[str, str] = {}
    if not tags_list:
        return out
    for row in list(tags_list):
        if not isinstance(row, dict):
            continue
        key = row.get("Key") or row.get("key")
        value = row.get("Value") or row.get("value")
        if key is None:
            continue
        out[str(key)] = "" if value is None else str(value)
    return out


def _sg_ref(group_id: str | None) -> Ref | None:
    if not group_id:
        return None
    return Ref(
        service="ec2",
        resource_type="security_group",
        resource_id=group_id,
        attribute="id",
    )


def _subnet_ref(subnet_id: str | None) -> Ref | None:
    if not subnet_id:
        return None
    return Ref(
        service="ec2", resource_type="subnet", resource_id=subnet_id, attribute="id"
    )


def _subnet_group_ref(name: str | None) -> Ref | None:
    if not name:
        return None
    return Ref(
        service="rds",
        resource_type="db_subnet_group",
        resource_id=name,
        attribute="id",
    )


def _parameter_group_ref(name: str | None) -> Ref | None:
    if not name:
        return None
    return Ref(
        service="rds",
        resource_type="db_parameter_group",
        resource_id=name,
        attribute="id",
    )


def _cluster_parameter_group_ref(name: str | None) -> Ref | None:
    if not name:
        return None
    return Ref(
        service="rds",
        resource_type="db_cluster_parameter_group",
        resource_id=name,
        attribute="id",
    )


@register_collector("rds")
class RdsCollector(BaseCollector):
    """Enumerate RDS resources for one account/region."""

    service = "rds"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            from moto.rds import rds_backends
        except Exception:  # pragma: no cover
            LOG.warning("moto.rds unavailable; skipping RDS export", exc_info=True)
            return []

        try:
            backend = rds_backends[account_id][region]
        except Exception:
            LOG.warning(
                "No RDS backend for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        resources: list[Resource] = []
        resources.extend(self._collect_subnet_groups(backend, account_id, region))
        resources.extend(self._collect_parameter_groups(backend, account_id, region))
        resources.extend(
            self._collect_cluster_parameter_groups(backend, account_id, region)
        )
        resources.extend(self._collect_option_groups(backend, account_id, region))
        resources.extend(self._collect_db_instances(backend, account_id, region))
        resources.extend(self._collect_db_clusters(backend, account_id, region))
        return resources

    # ------------------------------------------------------------------
    # Per-type collectors
    # ------------------------------------------------------------------

    def _collect_db_instances(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for db_id, db in dict(getattr(backend, "databases", {}) or {}).items():
            try:
                # Moto stores configured values under underscore-prefixed
                # attrs (see ``DBInstance``); fall back to the public
                # attribute for keys that aren't property-backed.
                vpc_sg_ids = list(
                    getattr(db, "vpc_security_group_ids", None) or []
                )
                attrs: dict[str, Any] = {
                    "id": db_id,
                    "identifier": db_id,
                    "engine": getattr(db, "engine", None),
                    "engine_version": getattr(db, "_engine_version", None)
                    or getattr(db, "engine_version", None),
                    "instance_class": getattr(db, "db_instance_class", None),
                    "allocated_storage": getattr(db, "_allocated_storage", None)
                    or getattr(db, "allocated_storage", None),
                    "db_name": getattr(db, "_db_name", None)
                    or getattr(db, "db_name", None),
                    "username": getattr(db, "_master_username", None)
                    or getattr(db, "master_username", None),
                    "password": getattr(db, "_master_user_password", None)
                    or getattr(db, "master_user_password", None),
                    "port": getattr(db, "port", None),
                    "publicly_accessible": bool(
                        getattr(db, "publicly_accessible", False)
                    ),
                    # skip_final_snapshot is a Terraform-side toggle that
                    # AWS doesn't expose on the live instance; default to
                    # True so ``terraform destroy`` doesn't block on a
                    # snapshot prompt.
                    "skip_final_snapshot": True,
                }
                if vpc_sg_ids:
                    attrs["vpc_security_group_ids"] = [
                        _sg_ref(sid) for sid in vpc_sg_ids if sid
                    ]
                sng = getattr(db, "_db_subnet_group_name", None) or getattr(
                    db, "db_subnet_group_name", None
                )
                if sng:
                    attrs["db_subnet_group_name"] = _subnet_group_ref(sng)
                pg = getattr(db, "db_parameter_group_name", None)
                if pg:
                    attrs["parameter_group_name"] = _parameter_group_ref(pg)
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_instance",
                        resource_id=str(db_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(db, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed DB instance %r", db_id, exc_info=True)
        return out

    def _collect_db_clusters(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for cid, cluster in dict(getattr(backend, "clusters", {}) or {}).items():
            try:
                vpc_sg_ids = list(
                    getattr(cluster, "_vpc_security_group_ids", None)
                    or getattr(cluster, "vpc_security_group_ids", None)
                    or []
                )
                attrs: dict[str, Any] = {
                    "id": cid,
                    "cluster_identifier": cid,
                    "engine": getattr(cluster, "engine", None),
                    "engine_version": getattr(cluster, "engine_version", None),
                    "master_username": getattr(cluster, "master_username", None),
                    "master_password": getattr(cluster, "_master_user_password", None)
                    or getattr(cluster, "master_user_password", None),
                    "database_name": getattr(cluster, "database_name", None),
                    "skip_final_snapshot": True,
                }
                if vpc_sg_ids:
                    attrs["vpc_security_group_ids"] = [
                        _sg_ref(sid) for sid in vpc_sg_ids if sid
                    ]
                sng = getattr(cluster, "db_subnet_group_name", None)
                # Moto defaults this to the literal "default" on clusters
                # that never had an explicit subnet group assigned. Real
                # AWS creates that implicitly too, so only emit a Ref when
                # the user actually picked a subnet group.
                if sng and sng != "default":
                    attrs["db_subnet_group_name"] = _subnet_group_ref(sng)
                cpg = getattr(cluster, "db_cluster_parameter_group_name", None)
                if cpg:
                    attrs["db_cluster_parameter_group_name"] = (
                        _cluster_parameter_group_ref(cpg)
                    )
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_cluster",
                        resource_id=str(cid),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(cluster, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed DB cluster %r", cid, exc_info=True)
        return out

    def _collect_subnet_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for name, sng in dict(getattr(backend, "subnet_groups", {}) or {}).items():
            try:
                subnets = getattr(sng, "_subnets", None) or getattr(
                    sng, "subnets", None
                ) or []
                subnet_ids = [
                    getattr(s, "id", None) if not isinstance(s, str) else s
                    for s in subnets
                ]
                subnet_ids = [sid for sid in subnet_ids if sid]
                attrs: dict[str, Any] = {
                    "id": name,
                    "name": name,
                    "description": getattr(sng, "description", None)
                    or "Managed by LocalEmu export",
                }
                if subnet_ids:
                    attrs["subnet_ids"] = [
                        _subnet_ref(sid) for sid in subnet_ids
                    ]
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_subnet_group",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(sng, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed DB subnet group %r", name, exc_info=True
                )
        return out

    def _collect_parameter_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for name, pg in dict(
            getattr(backend, "db_parameter_groups", {}) or {}
        ).items():
            try:
                params = getattr(pg, "parameters", None) or {}
                parameter_list = []
                for pname, pdata in dict(params).items():
                    if not isinstance(pdata, dict):
                        continue
                    val = pdata.get("ParameterValue") or pdata.get("parameter_value")
                    if val is None:
                        continue
                    parameter_list.append({"name": pname, "value": str(val)})
                attrs: dict[str, Any] = {
                    "id": name,
                    "name": name,
                    "family": getattr(pg, "family", None),
                    "description": getattr(pg, "description", None)
                    or "Managed by LocalEmu export",
                }
                if parameter_list:
                    attrs["parameters"] = parameter_list
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_parameter_group",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(pg, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed DB parameter group %r", name, exc_info=True
                )
        return out

    def _collect_cluster_parameter_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for name, cpg in dict(
            getattr(backend, "db_cluster_parameter_groups", {}) or {}
        ).items():
            try:
                params = getattr(cpg, "parameters", None) or {}
                parameter_list = []
                for pname, pdata in dict(params).items():
                    if not isinstance(pdata, dict):
                        continue
                    val = pdata.get("ParameterValue") or pdata.get("parameter_value")
                    if val is None:
                        continue
                    parameter_list.append({"name": pname, "value": str(val)})
                attrs: dict[str, Any] = {
                    "id": name,
                    "name": name,
                    "family": getattr(cpg, "family", None),
                    "description": getattr(cpg, "description", None)
                    or "Managed by LocalEmu export",
                }
                if parameter_list:
                    attrs["parameters"] = parameter_list
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_cluster_parameter_group",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(cpg, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed DB cluster parameter group %r",
                    name,
                    exc_info=True,
                )
        return out

    def _collect_option_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for name, og in dict(getattr(backend, "option_groups", {}) or {}).items():
            try:
                attrs: dict[str, Any] = {
                    "id": name,
                    "name": name,
                    "engine_name": getattr(og, "engine_name", None),
                    "major_engine_version": getattr(
                        og, "major_engine_version", None
                    ),
                    "description": getattr(og, "description", None)
                    or "Managed by LocalEmu export",
                }
                out.append(
                    Resource(
                        service="rds",
                        resource_type="db_option_group",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(getattr(og, "_tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed DB option group %r", name, exc_info=True
                )
        return out
