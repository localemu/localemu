"""API Gateway V2 request router.

Registers routes with the edge ROUTER to intercept HTTP API invocations
and dispatches them to HttpApiHandler.
"""

import json
import logging

from rolo import Request

from localemu.constants import DEFAULT_AWS_ACCOUNT_ID, AWS_REGION_US_EAST_1
from localemu.http import Response
from localemu.services.edge import ROUTER
from localemu.utils.aws.request_context import (
    extract_account_id_from_headers,
    extract_region_from_headers,
)

from .handler import HttpApiHandler

LOG = logging.getLogger(__name__)

# Internal path prefix for path-style access (when DNS resolution isn't available)
EXECUTE_API_V2_PATH = "/_aws/execute-api-v2"

# Singleton handler
_http_handler = HttpApiHandler()


def handle_v2_request(request: Request, **kwargs) -> Response:
    """Entry point for all API Gateway V2 HTTP API requests.

    Receives the request from the edge ROUTER and dispatches to HttpApiHandler.
    Differentiates between V1 (REST API) and V2 (HTTP API) by checking moto's
    API type.

    BUG-03 fix: Extract account_id and region from request headers instead
    of using hardcoded defaults. Falls back to defaults only when headers
    are absent.
    """
    api_id = kwargs.get("api_id", "")
    stage = kwargs.get("stage", "$default")
    path = kwargs.get("path", "")

    if not path.startswith("/"):
        path = f"/{path}"

    # BUG-03 fix: Determine account and region from request context
    account_id = extract_account_id_from_headers(request.headers)
    region = kwargs.get("region") or extract_region_from_headers(request.headers)

    # Check if this API is a V2 HTTP API (try extracted account first, fallback to default)
    if not _is_v2_api(api_id, account_id, region):
        # Try with default account as fallback for requests without auth headers
        if account_id != DEFAULT_AWS_ACCOUNT_ID:
            if _is_v2_api(api_id, DEFAULT_AWS_ACCOUNT_ID, region):
                account_id = DEFAULT_AWS_ACCOUNT_ID
            elif region != AWS_REGION_US_EAST_1 and _is_v2_api(
                api_id, DEFAULT_AWS_ACCOUNT_ID, AWS_REGION_US_EAST_1
            ):
                account_id = DEFAULT_AWS_ACCOUNT_ID
                region = AWS_REGION_US_EAST_1
            else:
                return Response(
                    response=json.dumps({"message": "Not Found"}),
                    status=404,
                    content_type="application/json",
                )
        else:
            return Response(
                response=json.dumps({"message": "Not Found"}),
                status=404,
                content_type="application/json",
            )

    return _http_handler.handle(
        request=request,
        api_id=api_id,
        stage=stage,
        path=path,
        account_id=account_id,
        region=region,
    )


def _is_v2_api(api_id: str, account_id: str, region: str) -> bool:
    """Check if an API ID belongs to an API Gateway V2 HTTP API."""
    try:
        from moto.apigatewayv2.models import apigatewayv2_backends

        backend = apigatewayv2_backends[account_id][region]
        return api_id in backend.apis
    except Exception:
        return False


_registered_rules = []


def register_v2_routes():
    """Register API Gateway V2 routes with the edge ROUTER.

    These routes intercept requests to HTTP APIs and route them through
    the V2 handler pipeline.
    """
    global _registered_rules

    if _registered_rules:
        return  # Already registered

    rules = [
        # Path-style access: /_aws/execute-api-v2/<api_id>/<stage>/<path>
        ROUTER.add(
            path=f"{EXECUTE_API_V2_PATH}/<api_id>/",
            endpoint=handle_v2_request,
            defaults={"path": "", "stage": "$default"},
            strict_slashes=True,
        ),
        ROUTER.add(
            path=f"{EXECUTE_API_V2_PATH}/<api_id>/<stage>/",
            endpoint=handle_v2_request,
            defaults={"path": ""},
            strict_slashes=False,
        ),
        ROUTER.add(
            path=f"{EXECUTE_API_V2_PATH}/<api_id>/<stage>/<greedy_path:path>",
            endpoint=handle_v2_request,
            strict_slashes=True,
        ),
    ]

    _registered_rules.extend(rules)
    LOG.info("API Gateway V2 routes registered (%d rules)", len(rules))


def unregister_v2_routes():
    """Remove API Gateway V2 routes from the edge ROUTER."""
    global _registered_rules
    if _registered_rules:
        ROUTER.remove(_registered_rules)
        _registered_rules = []
