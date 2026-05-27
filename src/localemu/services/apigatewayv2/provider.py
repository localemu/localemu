"""API Gateway V2 provider with real HTTP API request routing.

Wraps Moto's API Gateway V2 backend for CRUD operations and adds real
request routing when APIs are invoked. Intercepts CreateApi, CreateRoute,
CreateIntegration etc. to maintain route state, while all other operations
pass through to Moto.
"""

import logging
import threading

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import MotoOnlyDispatcher, _proxy_moto, call_moto
from localemu.services.plugins import Service

LOG = logging.getLogger(__name__)

# BUG-01 fix: Use threading.Lock + Event for thread-safe route registration
_routes_registration_lock = threading.Lock()
_routes_registered_event = threading.Event()


def _ensure_routes_registered():
    """Register V2 routes with the edge ROUTER on first use.

    Thread-safe: uses threading.Event for fast-path check and a Lock to
    serialize the one-time registration so concurrent callers never race.
    """
    if _routes_registered_event.is_set():
        return
    with _routes_registration_lock:
        if not _routes_registered_event.is_set():
            from localemu.services.apigatewayv2.router import register_v2_routes

            register_v2_routes()
            _routes_registered_event.set()


def _auto_deploy_if_enabled(context: RequestContext, api_id: str):
    """PARITY-08: When a stage has autoDeploy=true, create a deployment automatically.

    Uses the moto backend's create_deployment method if available, otherwise
    directly inserts a deployment dict into the API's deployments collection.
    """
    try:
        from moto.apigatewayv2.models import apigatewayv2_backends

        backend = apigatewayv2_backends[context.account_id][context.region]
        api = backend.apis.get(api_id)
        if not api:
            return
        for stage in api.stages.values():
            if not getattr(stage, "auto_deploy", False):
                continue
            # Prefer moto's own create_deployment so we adopt the deployment id
            # it actually allocates — generating our own short_uid and also
            # calling moto would produce two deployments with divergent ids.
            deployment = None
            deployment_id = None
            if hasattr(backend, "create_deployment"):
                deployment = backend.create_deployment(api_id, description="Auto-deployed")
                # moto returns either an object or a dict depending on version
                deployment_id = (
                    getattr(deployment, "deployment_id", None)
                    or getattr(deployment, "id", None)
                    or (deployment.get("DeploymentId") if isinstance(deployment, dict) else None)
                )
            if deployment_id is None:
                # Fallback only when moto has no create_deployment.
                from localemu.utils.strings import short_uid

                deployment_id = short_uid()
                if hasattr(api, "deployments"):
                    api.deployments[deployment_id] = {
                        "DeploymentId": deployment_id,
                        "AutoDeployed": True,
                        "Description": "Auto-deployed",
                    }
            stage.deployment_id = deployment_id
            LOG.debug(
                "Auto-deployed API %s stage %s -> deployment %s",
                api_id,
                getattr(stage, "stage_name", "$default"),
                deployment_id,
            )
    except Exception as e:
        # Keep this at debug: auto-deploy is best-effort and should never
        # surface to the caller. The CRUD path has already succeeded via moto.
        LOG.debug("Auto-deploy check failed (non-fatal): %s", e)


def _handle_create_api(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateApi: let Moto create the API, then register routes.

    AWS exposes a ``Target`` shortcut on CreateApi that auto-provisions a
    default integration + ``$default`` route + ``$default`` stage with
    autoDeploy=true, so a single ``aws apigatewayv2 create-api --target``
    yields an invokable endpoint. Moto explicitly does NOT implement
    Target (documented in its CreateApi docstring), so the convenience
    silently no-ops there: callers see an API with no stages and every
    invoke 404s. Re-implement the shortcut here.
    """
    _ensure_routes_registered()
    result = call_moto(context)
    if not result.get("ApiId"):
        return result
    LOG.info(
        "API Gateway V2 API created: %s (%s) - invoke via /_aws/execute-api-v2/%s/$default/",
        result.get("Name"), result.get("ApiId"), result.get("ApiId"),
    )

    target = request.get("Target") or context.service_request.get("Target", "")
    if not target:
        return result
    try:
        _provision_target_shortcut(context, result["ApiId"], target)
    except Exception:
        LOG.warning(
            "CreateApi --target shortcut provisioning failed for %s",
            result["ApiId"], exc_info=True,
        )
    return result


def _provision_target_shortcut(
    context: RequestContext, api_id: str, target: str,
) -> None:
    """Mirror AWS's ``aws apigatewayv2 create-api --target`` convenience.

    For a Lambda function ARN target, create an AWS_PROXY integration,
    a ``$default`` route bound to it, and a ``$default`` stage with
    auto-deploy. For an HTTP(S) URL target, create an HTTP_PROXY
    integration. ProtocolType=HTTP is assumed (the only protocol on
    which AWS exposes this shortcut).
    """
    import moto.backends as moto_backends

    backend = moto_backends.get_backend("apigatewayv2")[context.account_id][context.region]

    integration_type = "AWS_PROXY" if target.startswith("arn:") else "HTTP_PROXY"
    integration_method = "POST" if integration_type == "AWS_PROXY" else "ANY"
    payload_format = "2.0" if integration_type == "AWS_PROXY" else None

    create_kwargs = dict(
        api_id=api_id,
        connection_id=None,
        connection_type=None,
        content_handling_strategy=None,
        credentials_arn=None,
        description=None,
        integration_method=integration_method,
        integration_subtype=None,
        integration_type=integration_type,
        integration_uri=target,
        passthrough_behavior=None,
        payload_format_version=payload_format,
        request_parameters=None,
        request_templates=None,
        response_parameters=None,
        template_selection_expression=None,
        timeout_in_millis=None,
        tls_config=None,
    )
    integration = backend.create_integration(**create_kwargs)
    integration_id = getattr(integration, "integration_id", None) or integration.id

    backend.create_route(
        api_id=api_id,
        api_key_required=False,
        authorization_scopes=None,
        authorization_type=None,
        authorizer_id=None,
        model_selection_expression=None,
        operation_name=None,
        request_models=None,
        request_parameters=None,
        route_key="$default",
        route_response_selection_expression=None,
        target=f"integrations/{integration_id}",
    )
    # moto's create_stage takes (api_id, config) where config mirrors the
    # CreateStage request body (camelCase keys). $default + autoDeploy is all
    # the --target shortcut needs; the rest default inside moto's Stage model.
    backend.create_stage(
        api_id=api_id,
        config={"stageName": "$default", "autoDeploy": True},
    )
    LOG.debug(
        "Provisioned --target shortcut for api=%s target=%s (integration %s, $default stage)",
        api_id, target, integration_id,
    )
    _auto_deploy_if_enabled(context, api_id)


def _handle_create_route(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateRoute: let Moto create the route, then auto-deploy if enabled."""
    _ensure_routes_registered()
    result = call_moto(context)
    if result.get("RouteKey"):
        LOG.debug("API Gateway V2 route created: %s", result.get("RouteKey"))
    # PARITY-08: trigger auto-deploy for stages with autoDeploy=true
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_create_integration(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateIntegration: let Moto create the integration, then auto-deploy."""
    result = call_moto(context)
    if result.get("IntegrationId"):
        LOG.debug(
            "API Gateway V2 integration created: %s (%s -> %s)",
            result.get("IntegrationId"),
            result.get("IntegrationType"),
            result.get("IntegrationUri"),
        )
    # PARITY-08: trigger auto-deploy for stages with autoDeploy=true
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_update_route(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """UpdateRoute: let Moto update, then auto-deploy if enabled."""
    result = call_moto(context)
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_delete_route(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteRoute: let Moto delete, then auto-deploy if enabled."""
    result = call_moto(context)
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_update_integration(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """UpdateIntegration: let Moto update, then auto-deploy if enabled."""
    result = call_moto(context)
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_delete_integration(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteIntegration: let Moto delete, then auto-deploy if enabled."""
    result = call_moto(context)
    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    if api_id:
        _auto_deploy_if_enabled(context, api_id)
    return result


def _handle_delete_api(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteApi: let Moto delete the API, invalidate cached matchers."""
    from localemu.services.apigatewayv2.handler import (
        HttpApiHandler,
        invalidate_api_key_usage,
        invalidate_throttle_state,
    )

    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    result = call_moto(context)
    # Invalidate cached RouteMatcher + bounded in-memory state for this API
    if api_id:
        HttpApiHandler.invalidate_matcher_cache(api_id)
        invalidate_throttle_state(api_id)  # PERF-R2-03
        invalidate_api_key_usage(api_id)  # PERF-R2-04


    return result


def _handle_delete_stage(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteStage: drop throttle counters for the deleted api/stage pair (PERF-R2-03)."""
    from localemu.services.apigatewayv2.handler import invalidate_throttle_state

    api_id = request.get("ApiId") or context.service_request.get("ApiId", "")
    stage = request.get("StageName") or context.service_request.get("StageName", "")
    result = call_moto(context)
    if api_id and stage:
        invalidate_throttle_state(api_id, stage)
    return result


# Operations we intercept for logging and route registration
_INTERCEPTED_OPS = {
    "CreateApi": _handle_create_api,
    "CreateRoute": _handle_create_route,
    "UpdateRoute": _handle_update_route,
    "DeleteRoute": _handle_delete_route,
    "CreateIntegration": _handle_create_integration,
    "UpdateIntegration": _handle_update_integration,
    "DeleteIntegration": _handle_delete_integration,
    "DeleteApi": _handle_delete_api,
    "DeleteStage": _handle_delete_stage,
}


def ApiGatewayV2Dispatcher(service_model) -> DispatchTable:
    """Create a dispatch table for API Gateway V2.

    Intercepted operations go through our handlers for logging and
    route registration. All operations still use Moto for state management.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


def create_apigatewayv2_service() -> Service:
    """Create the API Gateway V2 service with request routing support."""
    from localemu.aws.spec import load_service

    service_model = load_service("apigatewayv2")
    dispatch_table = ApiGatewayV2Dispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="apigatewayv2", skeleton=skeleton)
