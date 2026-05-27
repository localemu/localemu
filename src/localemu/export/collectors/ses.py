"""SES collector: email identities, templates, configuration sets."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("ses")
class SesCollector(BaseCollector):
    service = "ses"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("ses")[account_id][region]
        except Exception:
            LOG.warning("SES unavailable", exc_info=True); return []
        out: list[Resource] = []
        # Email identities (v2 API)
        identities = getattr(backend, "email_identities", None) or {}
        for email, identity in dict(identities).items():
            try:
                attrs: dict[str, Any] = {"email_identity": email}
                out.append(Resource(
                    service="ses", resource_type="email_identity",
                    resource_id=email, account_id=account_id,
                    region=region, attributes=attrs, tags=_tags(identity),
                ))
            except Exception:
                LOG.warning("Skipping SES identity %r", email, exc_info=True)
        # Templates
        templates = getattr(backend, "templates", {}) or {}
        for name, tmpl in dict(templates).items():
            try:
                attrs = {
                    "name": getattr(tmpl, "template_name", name) or name,
                    "subject": getattr(tmpl, "subject_part", None) or getattr(tmpl, "subject", None),
                    "html": getattr(tmpl, "html_part", None) or getattr(tmpl, "html", None),
                    "text": getattr(tmpl, "text_part", None) or getattr(tmpl, "text", None),
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                out.append(Resource(
                    service="ses", resource_type="template",
                    resource_id=attrs.get("name", name),
                    account_id=account_id, region=region, attributes=attrs,
                ))
            except Exception:
                LOG.warning("Skipping SES template %r", name, exc_info=True)
        # Configuration sets
        config_sets = getattr(backend, "config_sets", {}) or {}
        for name, cs in dict(config_sets).items():
            try:
                attrs = {"name": name}
                out.append(Resource(
                    service="ses", resource_type="configuration_set",
                    resource_id=name, account_id=account_id,
                    region=region, attributes=attrs,
                ))
            except Exception:
                LOG.warning("Skipping SES config set %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
