"""Cognito User Pool Lambda triggers.

Reads a pool's ``LambdaConfig`` (stored by moto in ``user_pool.extended_config``),
invokes the configured trigger function with the AWS-shaped event, and applies
the function's response. Supported here:

  * PreSignUp           - autoConfirmUser / autoVerifyEmail / autoVerifyPhone
  * PostConfirmation    - side-effect only (response ignored)
  * PreTokenGeneration  - claimsToAddOrOverride / claimsToSuppress merged into tokens

Triggers are best-effort: if no function is configured the call is a no-op, and
an invocation/extraction failure is logged without breaking the surrounding
Cognito operation (matching how a missing trigger degrades in practice).
"""

from __future__ import annotations

import json
import logging

LOG = logging.getLogger(__name__)


def _get_pool(account_id: str, region: str, pool_id: str):
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        return cognitoidp_backends[account_id][region].user_pools.get(pool_id)
    except Exception:
        return None


def get_lambda_config(account_id: str, region: str, pool_id: str) -> dict:
    """Return the pool's LambdaConfig dict (empty if none)."""
    pool = _get_pool(account_id, region, pool_id)
    if not pool:
        return {}
    return (getattr(pool, "extended_config", None) or {}).get("LambdaConfig") or {}


def _user_attributes(account_id: str, region: str, pool_id: str, username: str) -> dict:
    pool = _get_pool(account_id, region, pool_id)
    if not pool:
        return {}
    user = pool.users.get(username)
    if not user:
        return {}
    return {a["Name"]: a["Value"] for a in (getattr(user, "attributes", None) or [])}


def _invoke(region: str, lambda_arn: str, event: dict) -> dict | None:
    """Invoke a trigger Lambda (RequestResponse) and return its parsed response."""
    from localemu.aws.connect import connect_to

    client = connect_to(region_name=region).lambda_
    result = client.invoke(
        FunctionName=lambda_arn,
        InvocationType="RequestResponse",
        Payload=json.dumps(event).encode("utf-8"),
    )
    if result.get("FunctionError"):
        raise RuntimeError(f"trigger returned FunctionError: {result.get('FunctionError')}")
    payload = result.get("Payload")
    if not payload:
        return None
    return json.loads(payload.read())


def _build_event(
    *,
    region: str,
    pool_id: str,
    username: str,
    client_id: str,
    trigger_source: str,
    account_id: str,
    request_extra: dict | None = None,
    response_init: dict | None = None,
) -> dict:
    event = {
        "version": "1",
        "region": region,
        "userPoolId": pool_id,
        "userName": username,
        "callerContext": {"awsSdkVersion": "localemu-1.0", "clientId": client_id or ""},
        "triggerSource": trigger_source,
        "request": {
            "userAttributes": _user_attributes(account_id, region, pool_id, username)
        },
        "response": response_init or {},
    }
    if request_extra:
        event["request"].update(request_extra)
    return event


def run_pre_sign_up(
    *, account_id, region, pool_id, username, client_id, trigger_source
) -> dict | None:
    """Invoke the PreSignUp trigger; apply auto-confirm / auto-verify to the user.

    Returns the trigger response (or None if no trigger configured).
    """
    arn = get_lambda_config(account_id, region, pool_id).get("PreSignUp")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source=trigger_source,
        account_id=account_id,
        response_init={
            "autoConfirmUser": False,
            "autoVerifyEmail": False,
            "autoVerifyPhone": False,
        },
    )
    result = _invoke(region, arn, event)
    response = (result or {}).get("response", {})
    _apply_pre_sign_up_response(account_id, region, pool_id, username, response)
    return response


def _apply_pre_sign_up_response(account_id, region, pool_id, username, response: dict):
    pool = _get_pool(account_id, region, pool_id)
    if not pool:
        return
    user = pool.users.get(username)
    if not user:
        return
    if response.get("autoConfirmUser"):
        # moto tracks status as a string; CONFIRMED skips the confirmation step.
        user.status = "CONFIRMED"
    verify = []
    if response.get("autoVerifyEmail"):
        verify.append("email_verified")
    if response.get("autoVerifyPhone"):
        verify.append("phone_number_verified")
    if verify:
        attrs = {a["Name"]: a["Value"] for a in (getattr(user, "attributes", None) or [])}
        for name in verify:
            attrs[name] = "true"
        user.attributes = [{"Name": k, "Value": v} for k, v in attrs.items()]


def run_post_confirmation(
    *, account_id, region, pool_id, username, client_id, trigger_source
) -> None:
    """Invoke the PostConfirmation trigger (side-effect only; response ignored)."""
    arn = get_lambda_config(account_id, region, pool_id).get("PostConfirmation")
    if not arn:
        return
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source=trigger_source,
        account_id=account_id,
    )
    _invoke(region, arn, event)


def run_pre_token_generation(
    *, account_id, region, pool_id, username, client_id, groups
) -> tuple[dict, list[str]]:
    """Invoke the PreTokenGeneration trigger; return (claims_to_add, claims_to_suppress).

    Returns ({}, []) when no trigger is configured.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("PreTokenGeneration")
    if not arn:
        return {}, []
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="TokenGeneration_Authentication",
        account_id=account_id,
        request_extra={"groupConfiguration": {"groupsToOverride": groups or []}},
        response_init={"claimsOverrideDetails": {}},
    )
    result = _invoke(region, arn, event)
    details = ((result or {}).get("response", {}) or {}).get("claimsOverrideDetails") or {}
    claims_to_add = details.get("claimsToAddOrOverride") or {}
    claims_to_suppress = details.get("claimsToSuppress") or []
    if not isinstance(claims_to_add, dict):
        claims_to_add = {}
    if not isinstance(claims_to_suppress, list):
        claims_to_suppress = []
    return claims_to_add, claims_to_suppress
