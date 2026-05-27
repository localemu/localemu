"""Cognito Identity Provider collector: user pools + clients."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

@register_collector("cognito")
class CognitoCollector(BaseCollector):
    service = "cognito"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("cognito-idp")[account_id][region]
        except Exception:
            LOG.warning("Cognito-IdP unavailable", exc_info=True); return []
        out: list[Resource] = []
        pools = getattr(backend, "user_pools", {}) or {}
        for pool_id, pool in dict(pools).items():
            try:
                pool_name = getattr(pool, "name", None) or pool_id
                out.append(self._pool(pool, pool_id, account_id, region))
                clients = getattr(pool, "clients", {}) or {}
                for cid, client in dict(clients).items():
                    try:
                        out.append(self._client(
                            client, cid, pool_id, pool_name,
                            account_id, region,
                        ))
                    except Exception:
                        LOG.warning("Skipping client %r", cid, exc_info=True)
            except Exception:
                LOG.warning("Skipping pool %r", pool_id, exc_info=True)
        return out

    def _pool(self, pool: Any, pool_id: str, account_id: str, region: str) -> Resource:
        name = getattr(pool, "name", None) or pool_id
        attrs: dict[str, Any] = {
            "name": name,
            "id": pool_id,
            "arn": getattr(pool, "arn", None),
            "auto_verified_attributes": list(getattr(pool, "auto_verified_attributes", []) or []),
            "username_attributes": list(getattr(pool, "username_attributes", []) or []),
            "mfa_configuration": getattr(pool, "mfa_configuration", None),
        }
        # ``schema_attributes`` on a moto pool always contains the 23 AWS-built-
        # in attributes ("sub", "email", "name", ...) even when the user defined
        # no custom attributes. The Terraform ``aws_cognito_user_pool.schema``
        # block is for *custom* attributes only — emitting the built-ins makes
        # ``terraform plan`` reject the resource. Pass through only entries
        # that look like real schema blocks (dicts with ``name`` +
        # ``attribute_data_type``), not bare strings.
        schema = getattr(pool, "schema_attributes", None)
        if isinstance(schema, list):
            custom = [
                s for s in schema
                if isinstance(s, dict) and s.get("name") and s.get("attribute_data_type")
            ]
            if custom:
                attrs["schema"] = custom
        policies = getattr(pool, "policies", None)
        if policies:
            attrs["password_policy"] = policies if isinstance(policies, dict) else None
        lc = getattr(pool, "lambda_config", None)
        if lc and isinstance(lc, dict) and any(lc.values()):
            attrs["lambda_config"] = lc
        attrs = {k: v for k, v in attrs.items() if v is not None}
        tags = _tags(pool)
        return Resource(
            service="cognito", resource_type="user_pool",
            resource_id=name, account_id=account_id,
            region=region, attributes=attrs, tags=tags,
        )

    def _client(self, client: Any, cid: str, pool_id: str, pool_name: str,
                account_id: str, region: str) -> Resource:
        name = getattr(client, "client_name", None) or cid
        # ``user_pool`` resources are registered with ``resource_id=pool_name``
        # in :meth:`_pool` above, so cross-resource refs must use the pool's
        # name — not the AWS-generated ``us-east-1_xxx`` pool id — or the
        # reference resolver finds nothing and emits a literal id, which TF
        # then rejects as "undeclared resource".
        attrs: dict[str, Any] = {
            "name": name,
            "client_id": cid,
            "user_pool_id": Ref("cognito", "user_pool", pool_name, attribute="id"),
            "explicit_auth_flows": list(getattr(client, "explicit_auth_flows", []) or []),
            "generate_secret": bool(getattr(client, "generate_secret", False)),
            "allowed_oauth_flows": list(getattr(client, "allowed_oauth_flows", []) or []),
            "allowed_oauth_scopes": list(getattr(client, "allowed_oauth_scopes", []) or []),
            "callback_urls": list(getattr(client, "callback_urls", []) or []),
            "logout_urls": list(getattr(client, "logout_urls", []) or []),
            "supported_identity_providers": list(getattr(client, "supported_identity_providers", []) or []),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="cognito", resource_type="user_pool_client",
            resource_id=name, account_id=account_id,
            region=region, attributes=attrs,
        )

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    return {}
