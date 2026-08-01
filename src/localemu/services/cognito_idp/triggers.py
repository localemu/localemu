"""Cognito User Pool Lambda triggers.

Reads a pool's ``LambdaConfig`` (stored by moto in ``user_pool.extended_config``),
invokes the configured trigger function with the AWS-shaped event, and applies
the function's response. Supported here:

  * PreSignUp                    - autoConfirmUser / autoVerifyEmail / autoVerifyPhone
  * PostConfirmation             - side-effect only (response ignored)
  * PreTokenGeneration           - claimsToAddOrOverride / claimsToSuppress
  * PreAuthentication            - blocks auth when the Lambda raises ; response ignored
  * PostAuthentication           - side-effect only (response ignored)

Triggers are best-effort: if no function is configured the call is a no-op, and
an invocation/extraction failure is logged without breaking the surrounding
Cognito operation (matching how a missing trigger degrades in practice).

Exception : ``PreAuthentication``'s contract is precisely that the Lambda CAN
block sign-in by raising. ``run_pre_authentication`` propagates the
``RuntimeError`` from ``_invoke``; the provider wrapper translates it into
``NotAuthorizedException`` with the trigger's message, matching the AWS contract.
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


def get_moto_user_code(account_id, region, pool_id, username) -> str:
    """Return the code moto stamped on the user (``confirmation_code``)
    after the most recent code-send. Empty string when not present."""
    pool = _get_pool(account_id, region, pool_id)
    if not pool:
        return ""
    user = pool.users.get(username)
    if not user:
        return ""
    return getattr(user, "confirmation_code", "") or ""


def infer_delivery_medium(account_id, region, pool_id, username) -> str:
    """Pick the delivery medium AWS would use : EMAIL if the user has a
    verified email, SMS if a verified phone, else EMAIL (Cognito's
    fallback when neither is verified is still EMAIL for the
    confirmation-code path)."""
    attrs = _user_attributes(account_id, region, pool_id, username)
    if attrs.get("email"):
        return "EMAIL"
    if attrs.get("phone_number"):
        return "SMS"
    return "EMAIL"


def run_custom_message(
    *, account_id, region, pool_id, username, client_id, trigger_source,
    code_parameter,
) -> dict | None:
    """Invoke the CustomMessage trigger. Returns the response dict
    (``{smsMessage, emailMessage, emailSubject}`` overrides), or
    ``None`` if no Lambda is configured.

    Fires from every code-send path : SignUp, ResendConfirmationCode,
    ForgotPassword, AdminCreateUser, UpdateUserAttribute,
    VerifyUserAttribute, plus ``Authentication`` for MFA SMS code.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("CustomMessage")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source=trigger_source,
        account_id=account_id,
        request_extra={
            "codeParameter": "{####}",
            "usernameParameter": "{username}",
            "linkParameter": "{##Verify Email##}",
        },
        response_init={
            "smsMessage": "",
            "emailMessage": "",
            "emailSubject": "",
        },
    )
    result = _invoke(region, arn, event)
    response = (result or {}).get("response", {}) or {}
    # Substitute the {####} placeholder with the actual code so the
    # message body the user (or test) reads contains a usable value.
    code = code_parameter or ""
    out = {
        "smsMessage": (response.get("smsMessage") or "").replace("{####}", code),
        "emailMessage": (response.get("emailMessage") or "").replace("{####}", code),
        "emailSubject": (response.get("emailSubject") or ""),
    }
    return out


def run_pre_authentication(
    *, account_id, region, pool_id, username, client_id, user_not_found=False,
    validation_data=None,
) -> None:
    """Invoke the PreAuthentication trigger (response ignored).

    Fires BEFORE the password check on ``InitiateAuth`` /
    ``AdminInitiateAuth``. The Lambda has two ways to block sign-in :

    1. Raise an exception. ``_invoke`` re-raises as ``RuntimeError`` ;
       the provider wrapper catches it and returns
       ``NotAuthorizedException`` to the caller, matching the AWS contract.
    2. Return a normal response (the response shape is empty by
       contract). Auth then proceeds.

    No-op when no Lambda is configured.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("PreAuthentication")
    if not arn:
        return
    request_extra = {"userNotFound": bool(user_not_found)}
    if validation_data:
        request_extra["validationData"] = validation_data
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="PreAuthentication_Authentication",
        account_id=account_id,
        request_extra=request_extra,
    )
    _invoke(region, arn, event)


def run_post_authentication(
    *, account_id, region, pool_id, username, client_id,
    new_device_metadata=None,
) -> None:
    """Invoke the PostAuthentication trigger (side-effect only ; response
    ignored).

    Fires AFTER auth succeeds : after ``InitiateAuth`` /
    ``AdminInitiateAuth`` returns ``AuthenticationResult``, and after
    ``RespondToAuthChallenge`` / ``AdminRespondToAuthChallenge``
    returns ``AuthenticationResult``. Used by tutorials for audit
    logging and last-login bookkeeping.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("PostAuthentication")
    if not arn:
        return
    request_extra = {}
    if new_device_metadata:
        request_extra["newDeviceMetadata"] = new_device_metadata
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="PostAuthentication_Authentication",
        account_id=account_id,
        request_extra=request_extra,
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


def run_define_auth_challenge(
    *, account_id, region, pool_id, username, client_id, session_history,
    user_not_found=False,
) -> dict | None:
    """Decide the next step of a CUSTOM_AUTH flow.

    Lambda response :

      * ``challengeName`` : ``"CUSTOM_CHALLENGE"`` (or another name like
        ``"SRP_A"`` to fall back to a built-in challenge) ;
      * ``issueTokens`` : True to end the flow with auth success ;
      * ``failAuthentication`` : True to end the flow with deny.

    ``session_history`` is the list of ``{challengeName, challengeResult,
    challengeMetadata}`` accumulated across previous rounds. The first
    invocation passes an empty list.

    Returns ``None`` when no DefineAuthChallenge Lambda is configured ;
    the caller then treats CUSTOM_AUTH as unconfigured and returns the
    standard ``UnsupportedOperationException``-style error.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("DefineAuthChallenge")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="DefineAuthChallenge_Authentication",
        account_id=account_id,
        request_extra={
            "session": list(session_history or []),
            "userNotFound": bool(user_not_found),
        },
        response_init={
            "challengeName": None,
            "issueTokens": False,
            "failAuthentication": False,
        },
    )
    result = _invoke(region, arn, event)
    return (result or {}).get("response") or {}


def run_create_auth_challenge(
    *, account_id, region, pool_id, username, client_id, challenge_name,
    session_history,
) -> dict | None:
    """Produce the challenge body the client sees, plus private params
    the Verify step uses to check the answer.

    Lambda response :

      * ``publicChallengeParameters``  : echoed to the client in
        ``ChallengeParameters`` ;
      * ``privateChallengeParameters`` : stashed server-side, passed
        back to ``VerifyAuthChallengeResponse`` on the next round ;
      * ``challengeMetadata`` : an opaque string the next
        DefineAuthChallenge sees in the session entry.

    Returns ``None`` when no Lambda is configured.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("CreateAuthChallenge")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="CreateAuthChallenge_Authentication",
        account_id=account_id,
        request_extra={
            "challengeName": challenge_name,
            "session": list(session_history or []),
        },
        response_init={
            "publicChallengeParameters": {},
            "privateChallengeParameters": {},
            "challengeMetadata": "",
        },
    )
    result = _invoke(region, arn, event)
    return (result or {}).get("response") or {}


def run_verify_auth_challenge_response(
    *, account_id, region, pool_id, username, client_id,
    private_challenge_parameters, challenge_answer,
) -> dict | None:
    """Check the client's challenge answer.

    Lambda response :

      * ``answerCorrect`` : bool. Feeds back into the next
        DefineAuthChallenge as the ``challengeResult`` of the latest
        session entry.

    Returns ``None`` when no Lambda is configured.
    """
    arn = get_lambda_config(account_id, region, pool_id).get("VerifyAuthChallengeResponse")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source="VerifyAuthChallengeResponse_Authentication",
        account_id=account_id,
        request_extra={
            "privateChallengeParameters": private_challenge_parameters or {},
            "challengeAnswer": challenge_answer or "",
        },
        response_init={"answerCorrect": False},
    )
    result = _invoke(region, arn, event)
    return (result or {}).get("response") or {}


def run_user_migration(
    *, account_id, region, pool_id, username, client_id, password,
    trigger_source,
) -> dict | None:
    """Invoke the UserMigration trigger when moto reports the user does
    not exist. The Lambda's response carries the attributes for the
    new user ; we synthesise the user in moto and return the response
    so the caller can retry auth.

    Response shape (a subset of the AWS contract that LocalEmu
    actually consumes) :

      * ``userAttributes`` : dict of attribute name -> value
      * ``finalUserStatus`` : ``"CONFIRMED"`` (default) | ``"RESET_REQUIRED"``
      * ``messageAction`` : ``"SUPPRESS"`` to skip the welcome message
      * ``desiredDeliveryMediums`` : list, e.g. ``["EMAIL"]``
      * ``forceAliasCreation`` : bool

    Returns ``None`` when no trigger is configured (the caller then
    surfaces the original UserNotFoundException).
    """
    arn = get_lambda_config(account_id, region, pool_id).get("UserMigration")
    if not arn:
        return None
    event = _build_event(
        region=region,
        pool_id=pool_id,
        username=username,
        client_id=client_id,
        trigger_source=trigger_source,
        account_id=account_id,
        request_extra={
            "password": password or "",
            "validationData": {},
            "clientMetadata": {},
        },
        response_init={
            "userAttributes": None,
            "finalUserStatus": "CONFIRMED",
            "messageAction": "SUPPRESS",
            "desiredDeliveryMediums": [],
            "forceAliasCreation": False,
        },
    )
    result = _invoke(region, arn, event)
    return (result or {}).get("response") or {}


def synthesise_user_from_migration_response(
    account_id, region, pool_id, username, response: dict,
    password: str = "",
) -> bool:
    """Create the user in moto using the UserMigration response. Returns
    True when the synthesis succeeded, False on any error (the caller
    treats False as "treat the original UserNotFound as final")."""
    try:
        pool = _get_pool(account_id, region, pool_id)
        if not pool:
            return False
        attrs = response.get("userAttributes") or {}
        # Convert dict -> AWS-shape list-of-{Name,Value} ;
        # tolerate the Lambda returning the list shape directly.
        if isinstance(attrs, dict):
            attr_list = [{"Name": k, "Value": v} for k, v in attrs.items()]
        elif isinstance(attrs, list):
            attr_list = attrs
        else:
            attr_list = []
        # The user-pool carries a ``users`` dict keyed by username ;
        # moto's ``CognitoIdpUser`` is the right shape. Import lazily so
        # the trigger module stays importable when moto changes its
        # internal API.
        from moto.cognitoidp.models import CognitoIdpUser

        user = CognitoIdpUser(
            user_pool_id=pool.id,
            username=username,
            # AWS UserMigration semantics: the Lambda has already
            # validated the user against the legacy IdP using the
            # provided password. Cognito then accepts that password as
            # the new pool password (or rotates on RESET_REQUIRED).
            # We persist the password so the retry-auth call_moto
            # succeeds against the freshly-synthesised user.
            password=password or None,
            status=response.get("finalUserStatus") or "CONFIRMED",
            attributes=attr_list,
        )
        pool.users[username] = user
        return True
    except Exception:
        LOG.warning(
            "UserMigration : synthesise_user failed", exc_info=True,
        )
        return False
