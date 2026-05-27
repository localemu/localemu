"""ACM collector: enumerate certificates.

Certificates in LocalEmu (via moto) are always DNS-validated and
auto-approved. The export emits ``validation_method = "DNS"`` so the
real-AWS deploy produces a certificate that requires the user to
create DNS validation records (Route53 or external) before it becomes
ISSUED.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)


@register_collector("acm")
class AcmCollector(BaseCollector):
    """Collect ACM certificates for a single account/region."""

    service = "acm"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            import moto.backends as moto_backends
        except Exception:
            LOG.warning("moto unavailable; skipping ACM", exc_info=True)
            return []
        try:
            backend = moto_backends.get_backend("acm")[account_id][region]
        except Exception:
            LOG.warning(
                "No ACM backend for account=%s region=%s",
                account_id, region, exc_info=True,
            )
            return []

        out: list[Resource] = []
        certs = getattr(backend, "_certificates", {}) or {}
        for cert_arn, cert in dict(certs).items():
            try:
                domain = (
                    getattr(cert, "common_name", None)
                    or getattr(cert, "domain_name", None)
                )
                sans = list(getattr(cert, "subject_alternative_names", []) or [])
                # Filter out the primary domain from SANs (AWS auto-includes it).
                if domain and domain in sans:
                    sans = [s for s in sans if s != domain]
                attrs: dict[str, Any] = {
                    "arn": cert_arn,
                    "domain_name": domain,
                    "validation_method": "DNS",
                }
                if sans:
                    attrs["subject_alternative_names"] = sans
                tags = _tags(cert)
                out.append(
                    Resource(
                        service="acm",
                        resource_type="certificate",
                        resource_id=domain or cert_arn,
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=tags,
                    )
                )
            except Exception:
                LOG.warning("Skipping certificate %r", cert_arn, exc_info=True)
        return out


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
