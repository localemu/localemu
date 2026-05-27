"""API Gateway v2 (HTTP / WebSocket) collector: APIs + stages + routes + integrations."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

@register_collector("apigatewayv2")
class ApiGatewayV2Collector(BaseCollector):
    service = "apigatewayv2"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("apigatewayv2")[account_id][region]
        except Exception:
            LOG.warning("APIGWv2 unavailable", exc_info=True); return []
        out: list[Resource] = []
        apis = getattr(backend, "apis", {}) or {}
        for api_id, api in dict(apis).items():
            try:
                # ``_api`` below registers the resource under the api
                # NAME (not the AWS-generated id), so all child refs must
                # use the same ``api_name`` as the target resource_id —
                # otherwise the reference resolver finds nothing and
                # the literal id leaks into the TF template as
                # ``aws_apigatewayv2_api.<aws_id>.id`` (undeclared).
                api_name = getattr(api, "name", None) or api_id
                out.append(self._api(api, api_id, account_id, region))
                # Stages
                stages = getattr(api, "stages", {}) or {}
                for sname, stage in dict(stages).items():
                    try:
                        out.append(self._stage(stage, sname, api_id, api_name, account_id, region))
                    except Exception:
                        LOG.warning("Skipping stage %r", sname, exc_info=True)
                # Routes
                routes = getattr(api, "routes", {}) or {}
                for rid, route in dict(routes).items():
                    try:
                        out.append(self._route(route, rid, api_id, api_name, account_id, region))
                    except Exception:
                        LOG.warning("Skipping route %r", rid, exc_info=True)
                # Integrations
                integrations = getattr(api, "integrations", {}) or {}
                for iid, integration in dict(integrations).items():
                    try:
                        out.append(self._integration(integration, iid, api_id, api_name, account_id, region))
                    except Exception:
                        LOG.warning("Skipping integration %r", iid, exc_info=True)
            except Exception:
                LOG.warning("Skipping API %r", api_id, exc_info=True)
        return out

    def _api(self, api: Any, api_id: str, account_id: str, region: str) -> Resource:
        attrs: dict[str, Any] = {
            "api_id": api_id,
            "name": getattr(api, "name", None),
            "protocol_type": getattr(api, "protocol_type", None),
            "description": getattr(api, "description", None),
            "route_selection_expression": getattr(api, "route_selection_expression", None),
        }
        cors = getattr(api, "cors_configuration", None)
        if cors:
            attrs["cors_configuration"] = cors if isinstance(cors, dict) else {}
        attrs = {k: v for k, v in attrs.items() if v is not None}
        tags = _tags(api)
        return Resource(
            service="apigatewayv2", resource_type="api",
            resource_id=getattr(api, "name", api_id) or api_id,
            account_id=account_id, region=region,
            attributes=attrs, tags=tags,
        )

    def _stage(self, stage: Any, name: str, api_id: str, api_name: str,
               account_id: str, region: str) -> Resource:
        attrs: dict[str, Any] = {
            "api_id": Ref("apigatewayv2", "api", api_name, attribute="id"),
            "name": name,
            "auto_deploy": getattr(stage, "auto_deploy", None),
            "description": getattr(stage, "description", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        tags = _tags(stage)
        return Resource(
            service="apigatewayv2", resource_type="stage",
            resource_id=f"{api_id}/{name}",
            account_id=account_id, region=region,
            attributes=attrs, tags=tags,
        )

    def _route(self, route: Any, route_id: str, api_id: str, api_name: str,
               account_id: str, region: str) -> Resource:
        attrs: dict[str, Any] = {
            "api_id": Ref("apigatewayv2", "api", api_name, attribute="id"),
            "route_key": getattr(route, "route_key", None),
        }
        target = getattr(route, "target", None)
        if target:
            attrs["target"] = target
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="apigatewayv2", resource_type="route",
            resource_id=f"{api_id}/{route_id}",
            account_id=account_id, region=region, attributes=attrs,
        )

    def _integration(self, integ: Any, integ_id: str, api_id: str, api_name: str,
                     account_id: str, region: str) -> Resource:
        attrs: dict[str, Any] = {
            "api_id": Ref("apigatewayv2", "api", api_name, attribute="id"),
            "integration_type": getattr(integ, "integration_type", None),
            "integration_uri": getattr(integ, "integration_uri", None),
            "integration_method": getattr(integ, "integration_method", None),
            "payload_format_version": getattr(integ, "payload_format_version", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="apigatewayv2", resource_type="integration",
            resource_id=f"{api_id}/{integ_id}",
            account_id=account_id, region=region, attributes=attrs,
        )

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    return {}
