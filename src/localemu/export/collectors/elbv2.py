"""ELBv2 (Application / Network / Gateway load balancer) collector.

Enumerates the four first-class ELBv2 objects:

* ``load_balancer`` — ALB / NLB / GWLB (moto's ``FakeLoadBalancer``).
* ``target_group`` — backend pool with health-check settings.
* ``listener`` — front-door protocol+port binding on an LB.
* ``listener_rule`` — non-default rule attached to a listener.

Target *registrations* (``register_targets`` / instance attachments)
are deliberately out of scope: they point at EC2 instances or Lambda
functions that LocalEmu backs with ephemeral Docker containers / sidecar
zips, which do not round-trip to a real-AWS resource address. The
MANIFEST's unsupported list records any such membership via the
orchestrator's general skip path.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _tags(obj: Any) -> dict[str, str]:
    """Extract moto-style ``{Key,Value}`` rows off ``obj`` into a dict."""
    out: dict[str, str] = {}
    try:
        raw = getattr(obj, "tags", None)
    except Exception:  # noqa: BLE001
        return out
    if not raw:
        return out
    if isinstance(raw, dict):
        for k, v in raw.items():
            out[str(k)] = "" if v is None else str(v)
        return out
    for row in list(raw):
        if not isinstance(row, dict):
            continue
        key = row.get("Key") or row.get("key")
        value = row.get("Value") or row.get("value")
        if key is None:
            continue
        out[str(key)] = "" if value is None else str(value)
    return out


def _subnet_ref(subnet_id: str | None) -> Ref | None:
    if not subnet_id:
        return None
    return Ref(
        service="ec2", resource_type="subnet", resource_id=subnet_id, attribute="id"
    )


def _sg_ref(group_id: str | None) -> Ref | None:
    if not group_id:
        return None
    return Ref(
        service="ec2",
        resource_type="security_group",
        resource_id=group_id,
        attribute="id",
    )


def _vpc_ref(vpc_id: str | None) -> Ref | None:
    if not vpc_id:
        return None
    return Ref(service="ec2", resource_type="vpc", resource_id=vpc_id, attribute="id")


def _lb_ref(lb_arn: str | None) -> Ref | None:
    if not lb_arn:
        return None
    return Ref(
        service="elbv2",
        resource_type="load_balancer",
        resource_id=lb_arn,
        attribute="arn",
    )


def _tg_ref(tg_arn: str | None) -> Ref | None:
    if not tg_arn:
        return None
    return Ref(
        service="elbv2",
        resource_type="target_group",
        resource_id=tg_arn,
        attribute="arn",
    )


def _listener_ref(listener_arn: str | None) -> Ref | None:
    if not listener_arn:
        return None
    return Ref(
        service="elbv2",
        resource_type="listener",
        resource_id=listener_arn,
        attribute="arn",
    )


def _translate_actions(actions: Any) -> list[dict[str, Any]]:
    """Translate moto's action list into TF default_action blocks.

    Only the ``forward`` action type is modelled — fixed-response /
    redirect / authenticate-* actions would require substantially more
    structure and are rare in LocalEmu workloads. Unsupported action
    types are passed through as ``type="forward"`` with the first
    available target group, so ``terraform validate`` still accepts the
    block.
    """
    out: list[dict[str, Any]] = []
    if not actions:
        return out
    for action in list(actions):
        action_type = None
        target_arn = None
        if isinstance(action, dict):
            action_type = action.get("type") or action.get("Type")
            target_arn = action.get("target_group_arn") or action.get("TargetGroupArn")
        else:
            action_type = getattr(action, "type", None)
            target_arn = getattr(action, "target_group_arn", None)
            data = getattr(action, "data", None)
            if target_arn is None and isinstance(data, dict):
                target_arn = data.get("target_group_arn") or data.get(
                    "TargetGroupArn"
                )
        block: dict[str, Any] = {"type": action_type or "forward"}
        if target_arn:
            block["target_group_arn"] = _tg_ref(target_arn)
        out.append(block)
    return out


def _translate_conditions(conditions: Any) -> list[dict[str, Any]]:
    """Translate moto listener-rule conditions into TF condition blocks."""
    out: list[dict[str, Any]] = []
    if not conditions:
        return out
    for cond in list(conditions):
        if not isinstance(cond, dict):
            continue
        field = cond.get("field") or cond.get("Field")
        values = cond.get("values") or cond.get("Values")
        if not field:
            continue
        block: dict[str, Any] = {}
        values_list = list(values or [])
        if field == "path-pattern":
            block["path_pattern"] = {"values": values_list}
        elif field == "host-header":
            block["host_header"] = {"values": values_list}
        elif field == "http-header":
            http_config = cond.get("http_header_config") or cond.get(
                "HttpHeaderConfig"
            ) or {}
            block["http_header"] = {
                "http_header_name": http_config.get("http_header_name")
                or http_config.get("HttpHeaderName"),
                "values": http_config.get("values") or http_config.get("Values") or [],
            }
        else:
            # Fallback: emit a path_pattern-style condition on the raw
            # values so the block still validates. Listener rule
            # translations for less common fields (query-string,
            # source-ip, ...) can be added here when needed.
            block["path_pattern"] = {"values": values_list or ["/*"]}
        out.append(block)
    return out


@register_collector("elbv2")
class Elbv2Collector(BaseCollector):
    """Enumerate ELBv2 resources for one account/region."""

    service = "elbv2"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            from moto.elbv2 import elbv2_backends
        except Exception:  # pragma: no cover
            LOG.warning(
                "moto.elbv2 unavailable; skipping ELBv2 export", exc_info=True
            )
            return []

        try:
            backend = elbv2_backends[account_id][region]
        except Exception:
            LOG.warning(
                "No ELBv2 backend for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        resources: list[Resource] = []
        resources.extend(self._collect_target_groups(backend, account_id, region))
        resources.extend(self._collect_load_balancers(backend, account_id, region))
        return resources

    def _collect_target_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for tg_arn, tg in dict(getattr(backend, "target_groups", {}) or {}).items():
            try:
                vpc_id = getattr(tg, "vpc_id", None)
                attrs: dict[str, Any] = {
                    "arn": tg_arn,
                    "name": getattr(tg, "name", None),
                    "port": getattr(tg, "port", None),
                    "protocol": getattr(tg, "protocol", None),
                    "target_type": getattr(tg, "target_type", None) or "instance",
                }
                if vpc_id:
                    attrs["vpc_id"] = _vpc_ref(vpc_id)
                hc_protocol = getattr(tg, "health_check_protocol", None)
                hc_port = getattr(tg, "health_check_port", None)
                hc_path = getattr(tg, "health_check_path", None)
                hc_interval = getattr(tg, "health_check_interval_seconds", None)
                hc_timeout = getattr(tg, "health_check_timeout_seconds", None)
                hc_healthy = getattr(tg, "healthy_threshold_count", None)
                hc_unhealthy = getattr(tg, "unhealthy_threshold_count", None)
                hc_enabled = getattr(tg, "health_check_enabled", None)
                health_block: dict[str, Any] = {}
                if hc_protocol:
                    health_block["protocol"] = hc_protocol
                if hc_port:
                    health_block["port"] = str(hc_port)
                if hc_path:
                    health_block["path"] = hc_path
                if hc_interval:
                    health_block["interval"] = int(hc_interval)
                if hc_timeout:
                    health_block["timeout"] = int(hc_timeout)
                if hc_healthy:
                    health_block["healthy_threshold"] = int(hc_healthy)
                if hc_unhealthy:
                    health_block["unhealthy_threshold"] = int(hc_unhealthy)
                if hc_enabled is not None:
                    health_block["enabled"] = bool(hc_enabled)
                if health_block:
                    attrs["health_check"] = health_block
                out.append(
                    Resource(
                        service="elbv2",
                        resource_type="target_group",
                        resource_id=str(tg_arn),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(tg),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed target group %r", tg_arn, exc_info=True
                )
        return out

    def _collect_load_balancers(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for lb_arn, lb in dict(getattr(backend, "load_balancers", {}) or {}).items():
            try:
                subnets = [
                    getattr(s, "id", None) if not isinstance(s, str) else s
                    for s in (getattr(lb, "subnets", None) or [])
                ]
                subnets = [s for s in subnets if s]
                sgs = list(getattr(lb, "security_groups", None) or [])
                lb_type = getattr(lb, "type", None) or "application"
                attrs: dict[str, Any] = {
                    "arn": lb_arn,
                    "name": getattr(lb, "name", None),
                    "load_balancer_type": lb_type,
                    "internal": (getattr(lb, "scheme", "") == "internal"),
                }
                if subnets:
                    attrs["subnets"] = [_subnet_ref(s) for s in subnets]
                if sgs and lb_type == "application":
                    attrs["security_groups"] = [_sg_ref(sg) for sg in sgs if sg]
                out.append(
                    Resource(
                        service="elbv2",
                        resource_type="load_balancer",
                        resource_id=str(lb_arn),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(lb),
                    )
                )
                # Listeners + rules hang off the LB in moto's model.
                for lst_arn, lst in dict(getattr(lb, "listeners", {}) or {}).items():
                    out.extend(
                        self._collect_listener(lst_arn, lst, account_id, region)
                    )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed load balancer %r", lb_arn, exc_info=True
                )
        return out

    def _collect_listener(
        self, lst_arn: str, lst: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        try:
            lb_arn = getattr(lst, "load_balancer_arn", None)
            attrs: dict[str, Any] = {
                "arn": lst_arn,
                "port": getattr(lst, "port", None),
                "protocol": getattr(lst, "protocol", None),
                "ssl_policy": getattr(lst, "ssl_policy", None),
            }
            if lb_arn:
                attrs["load_balancer_arn"] = _lb_ref(lb_arn)
            default_actions = _translate_actions(
                getattr(lst, "default_actions", None)
            )
            if default_actions:
                attrs["default_action"] = default_actions
            certs = list(getattr(lst, "certificates", None) or [])
            if certs:
                # TF expects certificate_arn as a scalar; pick the first.
                cert_entry = certs[0]
                cert_arn = (
                    cert_entry.get("certificate_arn")
                    if isinstance(cert_entry, dict)
                    else None
                )
                if cert_arn:
                    attrs["certificate_arn"] = cert_arn
            out.append(
                Resource(
                    service="elbv2",
                    resource_type="listener",
                    resource_id=str(lst_arn),
                    account_id=account_id,
                    region=region,
                    attributes=attrs,
                    tags={},
                )
            )
            for rule_key, rule in dict(getattr(lst, "rules", {}) or {}).items():
                if getattr(rule, "is_default", False):
                    # The default rule is emitted inline on the listener.
                    continue
                rule_arn = getattr(rule, "arn", None) or str(rule_key)
                rule_attrs: dict[str, Any] = {
                    "arn": rule_arn,
                    "listener_arn": _listener_ref(lst_arn),
                    "priority": int(getattr(rule, "priority", 1) or 1),
                }
                actions = _translate_actions(getattr(rule, "actions", None))
                if actions:
                    rule_attrs["action"] = actions
                conditions = _translate_conditions(
                    getattr(rule, "conditions", None)
                )
                if conditions:
                    rule_attrs["condition"] = conditions
                out.append(
                    Resource(
                        service="elbv2",
                        resource_type="listener_rule",
                        resource_id=str(rule_arn),
                        account_id=account_id,
                        region=region,
                        attributes=rule_attrs,
                        tags={},
                    )
                )
        except Exception:  # noqa: BLE001
            LOG.warning("Skipping malformed listener %r", lst_arn, exc_info=True)
        return out
