"""OIDC and JWKS HTTP endpoints for Cognito user pools.

Serves:
  /<pool-id>/.well-known/jwks.json         - JWKS for token verification
  /<pool-id>/.well-known/openid-configuration - OIDC discovery document

These endpoints are registered with the edge ROUTER so JWT libraries
can fetch public keys and verify tokens issued by LocalEmu Cognito.
"""

import json
import logging

from rolo import Request

from localemu.http import Response
from localemu.services.edge import ROUTER

from .keys import private_key_to_jwk

LOG = logging.getLogger(__name__)

# Pool key store: pool_id -> (private_key, kid)
_pool_keys: dict[str, tuple] = {}


def register_pool_keys(pool_id: str, private_key, kid: str):
    """Register a pool's key pair for the JWKS endpoint."""
    _pool_keys[pool_id] = (private_key, kid)


def get_pool_keys(pool_id: str) -> tuple | None:
    """Get a pool's key pair."""
    return _pool_keys.get(pool_id)


def _handle_jwks(request: Request, **kwargs) -> Response:
    """Serve the JWKS for a Cognito user pool."""
    pool_id = kwargs.get("pool_id", "")
    keys_tuple = _pool_keys.get(pool_id)

    if not keys_tuple:
        return Response(
            response=json.dumps({"message": "Pool not found"}),
            status=404,
            content_type="application/json",
        )

    private_key, kid = keys_tuple
    jwk = private_key_to_jwk(private_key, kid)

    return Response(
        response=json.dumps({"keys": [jwk]}),
        status=200,
        content_type="application/json",
    )


def _handle_openid_configuration(request: Request, **kwargs) -> Response:
    """Serve the OIDC discovery document for a Cognito user pool."""
    pool_id = kwargs.get("pool_id", "")

    if pool_id not in _pool_keys:
        return Response(
            response=json.dumps({"message": "Pool not found"}),
            status=404,
            content_type="application/json",
        )

    # Use external_service_url so the discovery doc (and the JWKS URI it
    # advertises) is reachable from the same place clients see in the JWT
    # iss claim.
    from localemu import config as _lemu_config

    base_url = _lemu_config.external_service_url()
    issuer = f"{base_url}/{pool_id}"

    doc = {
        "authorization_endpoint": f"{base_url}/oauth2/authorize",
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code", "token"],
        "scopes_supported": ["openid", "email", "phone", "profile"],
        "subject_types_supported": ["public"],
        "token_endpoint": f"{base_url}/oauth2/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "userinfo_endpoint": f"{base_url}/oauth2/userInfo",
        "claims_supported": [
            "sub",
            "iss",
            "auth_time",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
            "cognito:username",
            "cognito:groups",
        ],
    }

    return Response(
        response=json.dumps(doc),
        status=200,
        content_type="application/json",
    )


_registered_rules = []


def register_oidc_routes():
    """Register OIDC/JWKS endpoints with the edge ROUTER."""
    global _registered_rules

    if _registered_rules:
        return

    rules = [
        ROUTER.add(
            path="/<pool_id>/.well-known/jwks.json",
            endpoint=_handle_jwks,
            methods=["GET"],
        ),
        ROUTER.add(
            path="/<pool_id>/.well-known/openid-configuration",
            endpoint=_handle_openid_configuration,
            methods=["GET"],
        ),
    ]

    _registered_rules.extend(rules)
    LOG.info("Cognito OIDC/JWKS endpoints registered")
