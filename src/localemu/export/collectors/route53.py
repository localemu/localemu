"""Route53 collector: hosted zones, record sets, health checks.

Route53 is a global service. Like IAM, we only emit when
``region == "global"``; the orchestrator calls once per account.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

_GLOBAL = "global"

# Record types that Route53 auto-creates for every zone; exporting
# these makes the deploy fail because AWS refuses to create them.
_AUTO_RECORD_TYPES = frozenset({"NS", "SOA"})


@register_collector("route53")
class Route53Collector(BaseCollector):
    """Collect Route53 hosted zones, records, and health checks."""

    service = "route53"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        if region != _GLOBAL:
            return []
        try:
            import moto.backends as moto_backends
        except Exception:
            LOG.warning("moto unavailable; skipping Route53", exc_info=True)
            return []
        try:
            backend = moto_backends.get_backend("route53")[account_id]["global"]
        except Exception:
            LOG.warning("No Route53 backend for account=%s", account_id, exc_info=True)
            return []

        resources: list[Resource] = []
        zones = getattr(backend, "zones", {}) or {}
        for zone_id, zone in dict(zones).items():
            try:
                resources.append(self._zone_resource(zone, zone_id, account_id))
                resources.extend(self._record_resources(zone, zone_id, account_id))
            except Exception:
                LOG.warning("Skipping zone %r", zone_id, exc_info=True)

        health_checks = getattr(backend, "health_checks", {}) or {}
        for hc_id, hc in dict(health_checks).items():
            try:
                resources.append(self._health_check_resource(hc, hc_id, account_id))
            except Exception:
                LOG.warning("Skipping health check %r", hc_id, exc_info=True)

        return resources

    def _zone_resource(self, zone: Any, zone_id: str, account_id: str) -> Resource:
        name = getattr(zone, "name", "")
        comment = getattr(zone, "comment", None)
        private = bool(getattr(zone, "private_zone", False))
        vpcs_raw = getattr(zone, "vpcassociations", None) or getattr(zone, "vpcs", None) or []
        vpc_blocks: list[dict[str, Any]] = []
        for v in vpcs_raw:
            vid = v.get("vpc_id") if isinstance(v, dict) else getattr(v, "vpc_id", None)
            vreg = v.get("vpc_region") if isinstance(v, dict) else getattr(v, "vpc_region", None)
            if vid:
                vpc_blocks.append({"vpc_id": vid, "vpc_region": vreg or "us-east-1"})
        attrs: dict[str, Any] = {
            "name": name,
            "zone_id": zone_id,
            "comment": comment,
            "private_zone": private,
        }
        if vpc_blocks:
            attrs["vpc"] = vpc_blocks
        tags = _tags(zone)
        return Resource(
            service="route53",
            resource_type="zone",
            resource_id=zone_id,
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags=tags,
        )

    def _record_resources(
        self, zone: Any, zone_id: str, account_id: str
    ) -> list[Resource]:
        out: list[Resource] = []
        rrsets = getattr(zone, "rrsets", None) or []
        for rr in list(rrsets):
            try:
                rr_name = getattr(rr, "name", "")
                rr_type = getattr(rr, "type_", None) or getattr(rr, "type", "")
                # Skip auto-created NS and SOA records for the zone apex.
                if rr_type in _AUTO_RECORD_TYPES:
                    continue
                ttl = getattr(rr, "ttl", None)
                records = []
                for rec in getattr(rr, "records", []) or []:
                    val = getattr(rec, "value", None) if not isinstance(rec, str) else rec
                    if val:
                        records.append(val)
                alias = getattr(rr, "alias_target", None)
                alias_block: dict[str, Any] | None = None
                if alias:
                    alias_block = {
                        "name": getattr(alias, "dns_name", None) or (alias.get("DNSName") if isinstance(alias, dict) else None),
                        "zone_id": getattr(alias, "hosted_zone_id", None) or (alias.get("HostedZoneId") if isinstance(alias, dict) else None),
                        "evaluate_target_health": bool(
                            getattr(alias, "evaluate_target_health", False)
                            if not isinstance(alias, dict)
                            else alias.get("EvaluateTargetHealth", False)
                        ),
                    }
                attrs: dict[str, Any] = {
                    "zone_id": Ref("route53", "zone", zone_id, attribute="zone_id"),
                    "name": rr_name,
                    "type": rr_type,
                }
                if alias_block:
                    attrs["alias"] = alias_block
                else:
                    if ttl is not None:
                        attrs["ttl"] = int(ttl)
                    if records:
                        attrs["records"] = records
                rid = f"{zone_id}_{rr_name}_{rr_type}"
                out.append(
                    Resource(
                        service="route53",
                        resource_type="record",
                        resource_id=rid,
                        account_id=account_id,
                        region=_GLOBAL,
                        attributes=attrs,
                    )
                )
            except Exception:
                LOG.warning("Skipping record in zone %r", zone_id, exc_info=True)
        return out

    def _health_check_resource(
        self, hc: Any, hc_id: str, account_id: str
    ) -> Resource:
        # moto's HealthCheck stores config fields as direct attributes
        # (type_, fqdn, port, ...) OR in a nested health_check_config dict,
        # depending on version. Try both shapes.
        hc_config = getattr(hc, "health_check_config", None)
        if isinstance(hc_config, dict):
            cfg = hc_config
        elif hc_config is not None and not isinstance(hc_config, dict):
            cfg = {
                k: getattr(hc_config, k, None)
                for k in (
                    "ip_address", "port", "type", "resource_path",
                    "fqdn", "request_interval", "failure_threshold",
                )
            }
        else:
            cfg = {}
        # Direct attribute fallbacks (moto route53 model stores these flat).
        def _get(ir_key: str, *candidates: str) -> Any:
            for c in candidates:
                v = cfg.get(c)
                if v is not None:
                    return v
            for c in candidates:
                v = getattr(hc, c, None)
                if v is not None:
                    return v
            return None

        attrs: dict[str, Any] = {
            "health_check_id": hc_id,
            "type": _get("type", "type", "Type", "type_"),
            "fqdn": _get("fqdn", "fqdn", "FullyQualifiedDomainName"),
            "ip_address": _get("ip_address", "ip_address", "IPAddress"),
            "port": _get("port", "port", "Port"),
            "resource_path": _get("resource_path", "resource_path", "ResourcePath"),
            "request_interval": _get("request_interval", "request_interval", "RequestInterval"),
            "failure_threshold": _get("failure_threshold", "failure_threshold", "FailureThreshold"),
        }
        # Filter None AND the literal string "None" that moto sometimes
        # returns for unset IP addresses.
        attrs = {
            k: v
            for k, v in attrs.items()
            if v is not None and str(v) != "None"
        }
        tags = _tags(hc)
        return Resource(
            service="route53",
            resource_type="health_check",
            resource_id=hc_id,
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags=tags,
        )


def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return {
            str(t.get("Key", "")): str(t.get("Value", ""))
            for t in raw
            if isinstance(t, dict) and "Key" in t
        }
    return {}
