"""CloudFront collector: distributions."""
from __future__ import annotations
import json, logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("cloudfront")
class CloudFrontCollector(BaseCollector):
    service = "cloudfront"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        # CloudFront is global but moto keys by "global"
        if region not in ("global", "us-east-1"):
            return []
        try:
            import moto.backends as mb
            backend = mb.get_backend("cloudfront")[account_id]["global"]
        except Exception:
            LOG.warning("CloudFront unavailable", exc_info=True); return []
        out: list[Resource] = []
        dists = getattr(backend, "distributions", {}) or {}
        for dist_id, dist in dict(dists).items():
            try:
                # moto's ``Distribution.distribution_config`` is an OBJECT
                # (not a dict): ``DistributionConfig`` with attributes
                # ``origins`` (list of Origin), ``default_cache_behavior``
                # (DefaultCacheBehaviour), ``geo_restriction``, ``enabled``,
                # ``comment``, etc. The previous ``.get(...)`` calls returned
                # ``None`` every time and the TF schema rejected the
                # distribution for missing ``origin`` / ``default_cache_behavior``.
                cfg = getattr(dist, "distribution_config", None)
                attrs: dict[str, Any] = {
                    "distribution_id": dist_id,
                    "arn": getattr(dist, "arn", None),
                    "domain_name": getattr(dist, "domain_name", None),
                    "enabled": bool(getattr(cfg, "enabled", True)),
                    "comment": getattr(cfg, "comment", None) or None,
                }
                origins = list(getattr(cfg, "origins", None) or [])
                if origins:
                    attrs["origin"] = [_origin_to_tf(o) for o in origins]

                dcb = getattr(cfg, "default_cache_behavior", None)
                if dcb is not None:
                    attrs["default_cache_behavior"] = [_dcb_to_tf(dcb)]

                geo = getattr(cfg, "geo_restriction", None)
                attrs["restrictions"] = [{
                    "geo_restriction": [{
                        "restriction_type": getattr(geo, "restriction_type", None) or "none",
                        "locations": list(getattr(geo, "locations", None) or []),
                    }]
                }]
                attrs["viewer_certificate"] = [{"cloudfront_default_certificate": True}]
                attrs = {k: v for k, v in attrs.items() if v is not None}
                tags = _tags(dist)
                out.append(Resource(
                    service="cloudfront", resource_type="distribution",
                    resource_id=dist_id, account_id=account_id,
                    region="global", attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping distribution %r", dist_id, exc_info=True)
        return out

def _origin_to_tf(o: Any) -> dict[str, Any]:
    """Translate a moto ``Origin`` into the TF ``origin`` block schema."""
    if isinstance(o, dict):
        getter = o.get
    else:
        def getter(k, default=None):
            return getattr(o, k, default)
    block: dict[str, Any] = {
        "domain_name": getter("DomainName") or getter("domain_name"),
        "origin_id": getter("Id") or getter("id"),
    }
    s3oc = getter("S3OriginConfig") or getter("s3_origin_config")
    if s3oc:
        oai = (s3oc.get("OriginAccessIdentity") if isinstance(s3oc, dict)
               else getattr(s3oc, "origin_access_identity", ""))
        block["s3_origin_config"] = [{"origin_access_identity": oai or ""}]
    custom = getter("CustomOriginConfig") or getter("custom_origin_config")
    if custom and not s3oc:
        if isinstance(custom, dict):
            c = custom
        else:
            c = {"HTTPPort": getattr(custom, "http_port", 80),
                 "HTTPSPort": getattr(custom, "https_port", 443),
                 "OriginProtocolPolicy": getattr(custom, "origin_protocol_policy", "http-only"),
                 "OriginSSLProtocols": {"Items": getattr(custom, "origin_ssl_protocols", ["TLSv1.2"])}}
        block["custom_origin_config"] = [{
            "http_port": c.get("HTTPPort", 80),
            "https_port": c.get("HTTPSPort", 443),
            "origin_protocol_policy": c.get("OriginProtocolPolicy", "http-only"),
            "origin_ssl_protocols": (c.get("OriginSSLProtocols") or {}).get("Items", ["TLSv1.2"]),
        }]
    return {k: v for k, v in block.items() if v is not None}


def _dcb_to_tf(dcb: Any) -> dict[str, Any]:
    """Translate a moto ``DefaultCacheBehaviour`` into the TF block schema."""
    def g(name, default=None):
        return getattr(dcb, name, default)

    methods = list(g("allowed_methods", ["GET", "HEAD"]) or ["GET", "HEAD"])
    cached = list(g("cached_methods", ["GET", "HEAD"]) or ["GET", "HEAD"])
    fwd: dict[str, Any] = {
        "query_string": bool(g("query_string", False)),
        "cookies": [{"forward": g("forward", "none") or "none"}],
    }
    headers = list(g("headers", None) or [])
    if headers:
        fwd["headers"] = headers
    return {
        "allowed_methods": methods,
        "cached_methods": cached,
        "target_origin_id": g("target_origin_id") or "",
        "viewer_protocol_policy": g("viewer_protocol_policy") or "allow-all",
        "min_ttl": int(g("min_ttl", 0) or 0),
        "forwarded_values": [fwd],
    }


def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
