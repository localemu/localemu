"""Route53 Resolver collector: endpoints, rules, rule associations."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

@register_collector("route53resolver")
class Route53ResolverCollector(BaseCollector):
    service = "route53resolver"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("route53resolver")[account_id][region]
        except Exception:
            LOG.warning("Route53Resolver unavailable", exc_info=True); return []
        out: list[Resource] = []
        # Endpoints
        endpoints = getattr(backend, "resolver_endpoints", {}) or getattr(backend, "endpoints", {}) or {}
        for eid, ep in dict(endpoints).items():
            try:
                ip_addrs = getattr(ep, "ip_addresses", []) or []
                attrs: dict[str, Any] = {
                    "name": getattr(ep, "name", None),
                    "id": eid,
                    "arn": getattr(ep, "arn", None),
                    "direction": getattr(ep, "direction", None),
                    "security_group_ids": list(getattr(ep, "security_group_ids", []) or []),
                    "ip_address": [
                        {"subnet_id": getattr(ip, "subnet_id", None) or (ip.get("SubnetId") if isinstance(ip, dict) else None)}
                        for ip in ip_addrs
                    ] if ip_addrs else [],
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                tags = _tags(ep)
                out.append(Resource(
                    service="route53resolver", resource_type="endpoint",
                    resource_id=eid, account_id=account_id,
                    region=region, attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping resolver endpoint %r", eid, exc_info=True)
        # Rules
        rules = getattr(backend, "resolver_rules", {}) or getattr(backend, "rules", {}) or {}
        for rid, rule in dict(rules).items():
            try:
                targets = getattr(rule, "target_ips", []) or []
                attrs = {
                    "name": getattr(rule, "name", None),
                    "id": rid,
                    "arn": getattr(rule, "arn", None),
                    "domain_name": getattr(rule, "domain_name", None),
                    "rule_type": getattr(rule, "rule_type", None),
                    "resolver_endpoint_id": getattr(rule, "resolver_endpoint_id", None),
                    "target_ip": [
                        {"ip": t.get("Ip") or t.get("ip"), "port": t.get("Port") or t.get("port", 53)}
                        for t in targets if isinstance(t, dict)
                    ] if targets else None,
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                tags = _tags(rule)
                out.append(Resource(
                    service="route53resolver", resource_type="rule",
                    resource_id=rid, account_id=account_id,
                    region=region, attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping resolver rule %r", rid, exc_info=True)
        # Rule associations
        assocs = getattr(backend, "resolver_rule_associations", {}) or getattr(backend, "rule_associations", {}) or {}
        for aid, assoc in dict(assocs).items():
            try:
                attrs = {
                    "name": getattr(assoc, "name", None),
                    "id": aid,
                    "resolver_rule_id": getattr(assoc, "resolver_rule_id", None),
                    "vpc_id": getattr(assoc, "vpc_id", None),
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                out.append(Resource(
                    service="route53resolver", resource_type="rule_association",
                    resource_id=aid, account_id=account_id,
                    region=region, attributes=attrs,
                ))
            except Exception:
                LOG.warning("Skipping rule association %r", aid, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
