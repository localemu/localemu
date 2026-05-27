"""API Gateway (REST v1) collector.

Exports REST APIs and their nested entities. The v2 HTTP-API surface is
intentionally out of scope: it lives under the ``apigatewayv2`` service
and needs its own collector.

For each REST API we emit:

    * the API itself
    * its resources (path tree), methods, and method integrations
    * stages, deployments (metadata only), authorizers
    * API keys and usage plans (metadata, no keys/secrets)

Lambda-backed integrations and authorizers emit :class:`Ref` objects
pointing at the Lambda function so writers can stitch cross-service
references automatically.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import moto.backends as moto_backends

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

# ``arn:aws:apigateway:<region>:lambda:path/<version>/functions/<function_arn>/invocations``
_LAMBDA_INTEGRATION_RE = re.compile(
    r"arn:aws:apigateway:[^:]+:lambda:path/[^/]+/functions/"
    r"(?P<fn_arn>arn:aws:lambda:[^:]+:[^:]+:function:[^/]+)"
)
# ``arn:aws:lambda:<region>:<account>:function:<name>``
_LAMBDA_ARN_RE = re.compile(
    r"arn:aws:lambda:[^:]+:[^:]+:function:(?P<name>[^:/]+)"
)


def _lambda_ref_from_uri(uri: str | None) -> Ref | str | None:
    """Return a Lambda ``Ref`` if ``uri`` embeds one, else the original."""
    if not uri or not isinstance(uri, str):
        return uri
    match = _LAMBDA_INTEGRATION_RE.search(uri) or _LAMBDA_ARN_RE.search(uri)
    if not match:
        return uri
    fn_name_match = _LAMBDA_ARN_RE.search(match.group(0))
    if not fn_name_match:
        return uri
    return Ref(
        service="lambda",
        resource_type="function",
        resource_id=fn_name_match.group("name"),
    )


def _to_dict(obj: Any) -> dict[str, Any]:
    """Best-effort shallow dict view of a moto object."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        try:
            result = obj.to_dict()
            if isinstance(result, dict):
                return result
        except Exception:  # noqa: BLE001
            pass
    data = getattr(obj, "__dict__", None)
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not k.startswith("_")}
    return {}


@register_collector("apigateway")
class ApigatewayCollector(BaseCollector):
    """Collect API Gateway REST resources from the moto backend."""

    service = "apigateway"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate REST APIs and nested entities."""
        resources: list[Resource] = []
        try:
            backend_dict = moto_backends.get_backend("apigateway")
            backend = backend_dict[account_id][region]
        except Exception:  # noqa: BLE001
            LOG.warning(
                "API Gateway backend unavailable for %s/%s",
                account_id,
                region,
                exc_info=True,
            )
            return resources

        apis = getattr(backend, "apis", None) or {}
        for api_id, api in list(apis.items()):
            try:
                resources.extend(
                    self._collect_api(api_id, api, account_id, region)
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed REST API %r", api_id, exc_info=True
                )
                continue

        resources.extend(self._collect_api_keys(backend, account_id, region))
        resources.extend(self._collect_usage_plans(backend, account_id, region))
        return resources

    # ------------------------------------------------------------------
    def _collect_api(
        self, api_id: str, api: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Collect one REST API and all of its nested entities."""
        out: list[Resource] = []

        attrs: dict[str, Any] = {
            "name": getattr(api, "name", api_id),
        }
        for field in (
            "description",
            "binary_media_types",
            "minimum_compression_size",
            "api_key_source",
            "policy",
            "disable_execute_api_endpoint",
        ):
            value = getattr(api, field, None)
            if value is not None:
                attrs[field] = value

        # ``endpoint_configuration`` on the moto RestAPI is a dict with
        # AWS-API-shape mixed casing (``types`` lowercase, ``vpcEndpointIds``
        # camelCase). Normalize to the CFN PascalCase shape — the same dict
        # is also accepted by Terraform's ``aws_api_gateway_rest_api``
        # because TF tolerates either case for that block.
        ec = getattr(api, "endpoint_configuration", None)
        if isinstance(ec, dict):
            cleaned: dict[str, Any] = {}
            t = ec.get("types") or ec.get("Types")
            if t:
                cleaned["Types"] = list(t) if isinstance(t, (list, tuple)) else [t]
            vpc_ep = ec.get("vpcEndpointIds") or ec.get("VpcEndpointIds")
            if vpc_ep:
                cleaned["VpcEndpointIds"] = list(vpc_ep)
            # ``ipAddressType`` is a recent moto addition that real CFN
            # doesn't yet recognise; drop it rather than emit and reject.
            if cleaned:
                attrs["endpoint_configuration"] = cleaned

        tags = _normalise_tags(getattr(api, "tags", None))

        out.append(
            Resource(
                service="apigateway",
                resource_type="rest_api",
                resource_id=str(api_id),
                account_id=account_id,
                region=region,
                attributes=attrs,
                tags=tags,
            )
        )

        # Resources (path tree). Identify the root resource id so child
        # resources can ``!GetAtt rest_api.root_resource_id`` it.
        api_resources = getattr(api, "resources", None) or {}
        root_resource_id: str | None = None
        for res_id, res in list(api_resources.items()):
            path = getattr(res, "path", "")
            path_part = getattr(res, "path_part", None) or ""
            if path == "/" or path_part in ("", "/"):
                root_resource_id = str(res_id)
                break

        for res_id, res in list(api_resources.items()):
            try:
                resource = self._resource_for_rest_resource(
                    api_id, res_id, res, account_id, region,
                )
                if resource is not None:
                    # Rewrite parent_id from "rest/<root>" -> the API's
                    # root_resource_id GetAtt so the TF reference is
                    # plan-clean.
                    parent_ref = resource.attributes.get("parent_id")
                    if (
                        isinstance(parent_ref, Ref)
                        and root_resource_id
                        and parent_ref.resource_id == f"{api_id}/{root_resource_id}"
                    ):
                        resource.attributes["parent_id"] = Ref(
                            service="apigateway",
                            resource_type="rest_api",
                            resource_id=str(api_id),
                            attribute="root_resource_id",
                        )
                    out.append(resource)
                out.extend(
                    self._methods_for_resource(
                        api_id, res_id, res, account_id, region
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed API Gateway resource %r on %r",
                    res_id,
                    api_id,
                    exc_info=True,
                )
                continue

        # Deployments — required for stage refs. Without an emitted
        # deployment, ``aws_api_gateway_stage.deployment_id`` resolves
        # to an undeclared reference at terraform plan time.
        deployments = getattr(api, "deployments", None) or {}
        for dep_id, deployment in list(deployments.items()):
            try:
                out.append(self._deployment_resource(
                    api_id, dep_id, deployment, account_id, region,
                ))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed deployment %r on %r",
                    dep_id, api_id, exc_info=True,
                )

        # Stages.
        stages = getattr(api, "stages", None) or {}
        for stage_name, stage in list(stages.items()):
            try:
                out.append(
                    self._stage_resource(
                        api_id, stage_name, stage, account_id, region
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed stage %r on %r",
                    stage_name,
                    api_id,
                    exc_info=True,
                )
                continue

        # Authorizers.
        authorizers = getattr(api, "authorizers", None) or {}
        for auth_id, authorizer in list(authorizers.items()):
            try:
                out.append(
                    self._authorizer_resource(
                        api_id, auth_id, authorizer, account_id, region
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed authorizer %r on %r",
                    auth_id,
                    api_id,
                    exc_info=True,
                )
                continue

        return out

    # ------------------------------------------------------------------
    def _resource_for_rest_resource(
        self,
        api_id: str,
        res_id: str,
        res: Any,
        account_id: str,
        region: str,
    ) -> Resource | None:
        """Build a :class:`Resource` for a single REST resource (path node).

        The auto-created root ``/`` resource is NOT emitted — AWS owns it
        and rejects an explicit ``aws_api_gateway_resource`` whose
        path_part is empty / ``/``. Child resources use ``.root_resource_id``
        on the rest_api when their parent is the root.
        """
        path_part = getattr(res, "path_part", None) or ""
        path = getattr(res, "path", "")
        # Skip the root: moto stores it with path_part "" / "/" / None.
        if not path_part or path_part == "/" or path == "/":
            return None
        parent_id = getattr(res, "parent_id", None)
        attrs: dict[str, Any] = {
            # APIGW v1 refs are by ``.id``, NOT ``.arn``. Without this
            # override the resolver produced ``...rest_api.X.arn`` which
            # TF rejected as wrong type for ``rest_api_id``.
            "rest_api_id": Ref(
                service="apigateway",
                resource_type="rest_api",
                resource_id=str(api_id),
                attribute="id",
            ),
            "path": path or "/" + path_part,
            "path_part": path_part,
        }
        if parent_id:
            attrs["parent_id"] = Ref(
                service="apigateway",
                resource_type="resource",
                resource_id=f"{api_id}/{parent_id}",
                attribute="id",
            )

        return Resource(
            service="apigateway",
            resource_type="resource",
            resource_id=f"{api_id}/{res_id}",
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags={},
        )

    def _methods_for_resource(
        self,
        api_id: str,
        res_id: str,
        res: Any,
        account_id: str,
        region: str,
    ) -> list[Resource]:
        """Build method resources for one REST resource."""
        out: list[Resource] = []
        methods = getattr(res, "resource_methods", None) or {}
        for http_method, method in list(methods.items()):
            try:
                attrs: dict[str, Any] = {
                    "rest_api_id": Ref(
                        service="apigateway",
                        resource_type="rest_api",
                        resource_id=str(api_id),
                        attribute="id",
                    ),
                    "resource_id": Ref(
                        service="apigateway",
                        resource_type="resource",
                        resource_id=f"{api_id}/{res_id}",
                        attribute="id",
                    ),
                    "http_method": str(http_method),
                }
                for field in (
                    "authorization_type",
                    "authorization",
                    "api_key_required",
                    "request_parameters",
                    "request_models",
                ):
                    value = getattr(method, field, None)
                    if value is not None:
                        attrs[field] = value

                # CFN's ``AWS::ApiGateway::Method`` uses ``.Integration``
                # as an inline property — there is no standalone
                # ``AWS::ApiGateway::Integration`` type. Keep the
                # integration dict on the method's IR attributes so the
                # CFN method-builder can lift it onto Method.Integration.
                integration = (getattr(method, "method_integration", None)
                               or getattr(method, "integration", None))
                integ_dict: dict[str, Any] = {}
                if integration is not None:
                    integ_dict = self._integration_dict(integration)
                    attrs["integration"] = integ_dict

                out.append(
                    Resource(
                        service="apigateway",
                        resource_type="method",
                        resource_id=f"{api_id}/{res_id}/{http_method}",
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags={},
                    )
                )

                # Terraform takes the OPPOSITE shape: a separate
                # ``aws_api_gateway_integration`` resource per method.
                # Emit it too — the TF writer renders it via the
                # ``apigateway.integration`` TF spec; the CFN writer
                # ignores this resource type (no CFN spec → suppressed).
                if integ_dict:
                    integ_attrs = dict(integ_dict)
                    integ_attrs.update({
                        "rest_api_id": Ref(
                            service="apigateway",
                            resource_type="rest_api",
                            resource_id=str(api_id),
                            attribute="id",
                        ),
                        "resource_id": Ref(
                            service="apigateway",
                            resource_type="resource",
                            resource_id=f"{api_id}/{res_id}",
                            attribute="id",
                        ),
                        "http_method": str(http_method),
                    })
                    out.append(Resource(
                        service="apigateway",
                        resource_type="integration",
                        resource_id=f"{api_id}/{res_id}/{http_method}",
                        account_id=account_id,
                        region=region,
                        attributes=integ_attrs,
                        tags={},
                    ))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed method %s on %s/%s",
                    http_method,
                    api_id,
                    res_id,
                    exc_info=True,
                )
                continue
        return out

    def _integration_dict(self, integration: Any) -> dict[str, Any]:
        """Project a moto integration object into a plain dict."""
        data: dict[str, Any] = {}
        for field in (
            "type",
            "integration_type",
            "http_method",
            "integration_http_method",
            "request_templates",
            "passthrough_behavior",
            "timeout_in_millis",
            "cache_key_parameters",
            "content_handling",
            "credentials",
        ):
            value = getattr(integration, field, None)
            if value is not None:
                data[field] = value
        uri = getattr(integration, "uri", None)
        if uri is not None:
            data["uri"] = _lambda_ref_from_uri(uri)
        return data

    # ------------------------------------------------------------------
    def _stage_resource(
        self,
        api_id: str,
        stage_name: str,
        stage: Any,
        account_id: str,
        region: str,
    ) -> Resource:
        """Build a :class:`Resource` for a deployment stage."""
        attrs: dict[str, Any] = {
            "rest_api_id": Ref(
                service="apigateway",
                resource_type="rest_api",
                resource_id=str(api_id),
                attribute="id",
            ),
            # TF requires ``stage_name``; previous code only set ``name``
            # which the spec didn't map.
            "stage_name": stage_name,
            "name": stage_name,
        }
        for field in (
            "description",
            "variables",
            "cache_cluster_enabled",
            "cache_cluster_size",
            "tracing_enabled",
        ):
            value = getattr(stage, field, None)
            if value is not None:
                attrs[field] = value

        # deployment_id must reference the deployment resource by id.
        # moto stores it as a string on stage.deployment_id.
        deployment_id = getattr(stage, "deployment_id", None)
        if deployment_id:
            attrs["deployment_id"] = Ref(
                service="apigateway",
                resource_type="deployment",
                resource_id=f"{api_id}/{deployment_id}",
                attribute="id",
            )

        return Resource(
            service="apigateway",
            resource_type="stage",
            resource_id=f"{api_id}/{stage_name}",
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=_normalise_tags(getattr(stage, "tags", None)),
        )

    def _deployment_resource(
        self, api_id: str, dep_id: str, deployment: Any,
        account_id: str, region: str,
    ) -> Resource:
        """Build a :class:`Resource` for an APIGW v1 deployment."""
        attrs: dict[str, Any] = {
            "rest_api_id": Ref(
                service="apigateway",
                resource_type="rest_api",
                resource_id=str(api_id),
                attribute="id",
            ),
            "description": getattr(deployment, "description", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="apigateway",
            resource_type="deployment",
            resource_id=f"{api_id}/{dep_id}",
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags={},
        )

    def _authorizer_resource(
        self,
        api_id: str,
        auth_id: str,
        authorizer: Any,
        account_id: str,
        region: str,
    ) -> Resource:
        """Build a :class:`Resource` for an authorizer."""
        attrs: dict[str, Any] = {
            "rest_api_id": Ref(
                service="apigateway",
                resource_type="rest_api",
                resource_id=str(api_id),
            ),
            "name": getattr(authorizer, "name", auth_id),
        }
        for field in (
            "type",
            "identity_source",
            "identity_validation_expression",
            "authorizer_result_ttl_in_seconds",
            "provider_arns",
        ):
            value = getattr(authorizer, field, None)
            if value is not None:
                attrs[field] = value

        authorizer_uri = getattr(authorizer, "authorizer_uri", None)
        if authorizer_uri is not None:
            attrs["authorizer_uri"] = _lambda_ref_from_uri(authorizer_uri)

        return Resource(
            service="apigateway",
            resource_type="authorizer",
            resource_id=f"{api_id}/{auth_id}",
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags={},
        )

    # ------------------------------------------------------------------
    def _collect_api_keys(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Collect API keys — metadata only, never the actual key value."""
        out: list[Resource] = []
        keys = getattr(backend, "keys", None) or {}
        for key_id, api_key in list(keys.items()):
            try:
                attrs: dict[str, Any] = {
                    "name": getattr(api_key, "name", str(key_id)),
                }
                for field in ("description", "enabled"):
                    value = getattr(api_key, field, None)
                    if value is not None:
                        attrs[field] = value
                out.append(
                    Resource(
                        service="apigateway",
                        resource_type="api_key",
                        resource_id=str(key_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_normalise_tags(getattr(api_key, "tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed API key %r", key_id, exc_info=True
                )
                continue
        return out

    def _collect_usage_plans(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Collect usage plans — metadata only."""
        out: list[Resource] = []
        plans = getattr(backend, "usage_plans", None) or {}
        for plan_id, plan in list(plans.items()):
            try:
                attrs: dict[str, Any] = {
                    "name": getattr(plan, "name", str(plan_id)),
                }
                for field in ("description", "throttle", "quota", "api_stages"):
                    value = getattr(plan, field, None)
                    if value is not None:
                        attrs[field] = value
                out.append(
                    Resource(
                        service="apigateway",
                        resource_type="usage_plan",
                        resource_id=str(plan_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_normalise_tags(getattr(plan, "tags", None)),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed usage plan %r", plan_id, exc_info=True
                )
                continue
        return out


def _normalise_tags(raw: Any) -> dict[str, str]:
    """Coerce moto's varied tag shapes into a ``dict[str, str]``."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict):
                key = item.get("Key") or item.get("key")
                value = item.get("Value") or item.get("value")
                if key is not None:
                    out[str(key)] = "" if value is None else str(value)
        return out
    return {}
