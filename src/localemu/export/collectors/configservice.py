"""AWS Config collector: configuration recorders + rules."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("configservice")
class ConfigServiceCollector(BaseCollector):
    service = "configservice"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("config")[account_id][region]
        except Exception:
            LOG.warning("Config unavailable", exc_info=True); return []
        out: list[Resource] = []
        # Recorders
        recorders = getattr(backend, "recorders", {}) or {}
        for name, rec in dict(recorders).items():
            try:
                attrs: dict[str, Any] = {
                    "name": name,
                    "role_arn": getattr(rec, "role_arn", None),
                }
                group = getattr(rec, "recording_group", None)
                if group:
                    attrs["recording_group"] = group if isinstance(group, dict) else {}
                out.append(Resource(
                    service="configservice", resource_type="configuration_recorder",
                    resource_id=name, account_id=account_id,
                    region=region, attributes=attrs,
                ))
            except Exception:
                LOG.warning("Skipping recorder %r", name, exc_info=True)
        # Rules
        rules = getattr(backend, "rules", {}) or {}
        for name, rule in dict(rules).items():
            try:
                attrs = {
                    "name": getattr(rule, "config_rule_name", name) or name,
                    "arn": getattr(rule, "config_rule_arn", None),
                    "description": getattr(rule, "description", None),
                    "source": getattr(rule, "source", None),
                    "scope": getattr(rule, "scope", None),
                    "input_parameters": getattr(rule, "input_parameters", None),
                    "maximum_execution_frequency": getattr(rule, "maximum_execution_frequency", None),
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                out.append(Resource(
                    service="configservice", resource_type="config_rule",
                    resource_id=attrs.get("name", name),
                    account_id=account_id, region=region, attributes=attrs,
                ))
            except Exception:
                LOG.warning("Skipping config rule %r", name, exc_info=True)
        return out
