"""Cognito User Pools provider with real JWT tokens.

Wraps Moto's Cognito backend for user/pool management and replaces
authentication responses with real, verifiable JWT tokens signed by
per-pool RSA keys. The JWKS endpoint serves the public keys so
applications can verify tokens using standard JWT libraries.
"""

import json
import logging
import threading
import time
import uuid
from collections import OrderedDict

from localemu import config
from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service, ServiceLifecycleHook
from localemu.state import StateVisitor

from .keys import generate_key_pair
from .oauth2 import register_oauth2_routes
from .oidc import register_oidc_routes, register_pool_keys, get_pool_keys
from .tokens import generate_access_token, generate_id_token, generate_refresh_token

LOG = logging.getLogger(__name__)

# Refresh tokens have a default lifetime of 30 days on AWS; we default to the
# same so stale entries are evicted eventually. Size cap protects memory in
# environments that churn through many tokens.
_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
_REFRESH_TOKEN_MAX_ENTRIES = 10000

# Track user subs: (account_id, pool_id, username) -> sub (UUID)
_user_subs: dict[tuple[str, str, str], str] = {}
# Track refresh tokens: token -> (account_id, region, pool_id, client_id, username, issued_at)
# OrderedDict gives us O(1) LRU-style eviction when the cap is reached.
_refresh_tokens: "OrderedDict[str, tuple[str, str, str, str, str, float]]" = OrderedDict()
# Guard concurrent access to the above module-level dicts.
_state_lock = threading.Lock()


def _evict_expired_refresh_tokens_locked() -> None:
    """Remove expired refresh tokens. Caller MUST hold _state_lock."""
    now = time.time()
    expired = [
        tok
        for tok, entry in _refresh_tokens.items()
        if now - entry[5] > _REFRESH_TOKEN_TTL_SECONDS
    ]
    for tok in expired:
        _refresh_tokens.pop(tok, None)


def _store_refresh_token_locked(
    token: str,
    account_id: str,
    region: str,
    pool_id: str,
    client_id: str,
    username: str,
) -> None:
    """Record a refresh token with TTL/size-limit enforcement. Caller holds _state_lock."""
    _evict_expired_refresh_tokens_locked()
    # Enforce a hard cap to prevent unbounded growth (e.g. token-storm abuse).
    while len(_refresh_tokens) >= _REFRESH_TOKEN_MAX_ENTRIES:
        _refresh_tokens.popitem(last=False)
    _refresh_tokens[token] = (account_id, region, pool_id, client_id, username, time.time())


def _get_or_create_sub(account_id: str, pool_id: str, username: str) -> str:
    """Get or create a stable sub (subject) UUID for a user."""
    key = (account_id, pool_id, username)
    with _state_lock:
        if key not in _user_subs:
            _user_subs[key] = str(uuid.uuid4())
        return _user_subs[key]


def _register_access_token_with_moto(
    access_token: str,
    pool_id: str,
    client_id: str,
    username: str,
    account_id: str,
    region: str,
) -> None:
    """Register a LocalEmu-issued JWT in moto's ``user_pool.access_tokens``.

    Moto's GetUser / ChangePassword / DeleteUser / UpdateUserAttributes /
    VerifyUserAttribute / ConfirmDevice / ForgetDevice / ... all gate on
    ``if access_token in user_pool.access_tokens``. Because LocalEmu mints
    its own RSA-signed JWT (so the token has a real ``iss``, ``kid``,
    proper claims, and verifies against JWKS), we have to write that JWT
    back into the moto dict - otherwise every token-taking op rejects a
    valid, freshly-issued token with ``NotAuthorizedException: Invalid
    token``. The moto value is ``(client_id, username)``.
    """
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        backend = cognitoidp_backends[account_id][region]
        pool = backend.user_pools.get(pool_id)
        if pool is not None:
            pool.access_tokens[access_token] = (client_id, username)
    except Exception:
        # Token-mint must never fail because of moto-state issues.
        LOG.debug(
            "could not register access token in moto user_pool.access_tokens",
            exc_info=True,
        )


def _get_user_email(pool_id: str, username: str, account_id: str, region: str) -> str | None:
    """Try to get user email from moto backend."""
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        backend = cognitoidp_backends[account_id][region]
        pool = backend.user_pools.get(pool_id)
        if pool:
            user = pool.users.get(username)
            if user:
                for attr in user.attributes:
                    if attr.get("Name") == "email":
                        return attr.get("Value")
    except Exception:
        pass
    return None


def _get_user_groups(pool_id: str, username: str, account_id: str, region: str) -> list[str]:
    """Get user's groups from moto backend."""
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        backend = cognitoidp_backends[account_id][region]
        pool = backend.user_pools.get(pool_id)
        if pool:
            groups = []
            for group_name, group in pool.groups.items():
                user = pool.users.get(username)
                if user and user in group.users:
                    groups.append(group_name)
            return groups
    except Exception:
        pass
    return []


def _ensure_pool_keys(pool_id: str):
    """Ensure a pool has RSA keys. Generate if missing."""
    if not get_pool_keys(pool_id):
        private_key, kid = generate_key_pair()
        register_pool_keys(pool_id, private_key, kid)
        LOG.debug("Generated RSA key pair for pool %s (kid=%s)", pool_id, kid)


# --- Lambda trigger wrappers (best-effort: a trigger error is logged and the
# surrounding Cognito operation still completes) ---


def _run_pre_sign_up(account_id, region, pool_id, username, client_id, trigger_source):
    try:
        from .triggers import run_pre_sign_up

        return run_pre_sign_up(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id, trigger_source=trigger_source,
        )
    except Exception:
        LOG.warning("Cognito PreSignUp trigger failed", exc_info=True)
        return None


def _run_post_confirmation(account_id, region, pool_id, username, client_id, trigger_source):
    try:
        from .triggers import run_post_confirmation

        run_post_confirmation(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id, trigger_source=trigger_source,
        )
    except Exception:
        LOG.warning("Cognito PostConfirmation trigger failed", exc_info=True)


def _run_custom_message(
    account_id, region, pool_id, username, client_id, trigger_source,
    delivery_medium=None,
):
    """Drive the CustomMessage trigger AND the messages.py routing.

    Always called after moto generated the code (so ``user.confirmation_code``
    is set). Reads the code, invokes the CustomMessage Lambda (if configured)
    for override message bodies, then calls ``messages.send_code`` which
    either routes through a CustomEmailSender / CustomSMSSender Lambda or
    buffers the message for the dashboard endpoint to read.

    Never raises : a failing trigger or sender does not break the
    surrounding Cognito op.
    """
    try:
        from .triggers import (
            run_custom_message, get_moto_user_code, infer_delivery_medium,
        )
        from . import messages

        code = get_moto_user_code(account_id, region, pool_id, username)
        if delivery_medium is None:
            delivery_medium = infer_delivery_medium(
                account_id, region, pool_id, username,
            )
        override = run_custom_message(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            trigger_source=trigger_source,
            code_parameter=code,
        ) or {}
        messages.send_code(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username,
            trigger_source=trigger_source,
            delivery_medium=delivery_medium,
            code_plain=code,
            override_sms_message=override.get("smsMessage", ""),
            override_email_message=override.get("emailMessage", ""),
            override_email_subject=override.get("emailSubject", ""),
        )
    except Exception:
        LOG.warning("Cognito CustomMessage trigger failed", exc_info=True)


def _run_user_migration(account_id, region, pool_id, username, client_id,
                        password, trigger_source):
    """Drive the UserMigration trigger when moto reports the user is
    unknown. On success, the user is synthesised in moto and True is
    returned so the caller can retry auth ; on failure, returns False
    and the caller propagates the original ``UserNotFoundException``."""
    try:
        from .triggers import (
            run_user_migration, synthesise_user_from_migration_response,
        )

        response = run_user_migration(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id, password=password,
            trigger_source=trigger_source,
        )
        if response is None:
            # No trigger configured.
            return False
        return synthesise_user_from_migration_response(
            account_id, region, pool_id, username, response,
            password=password or "",
        )
    except Exception:
        LOG.warning("Cognito UserMigration trigger failed", exc_info=True)
        return False


def _run_pre_authentication(account_id, region, pool_id, username, client_id,
                             user_not_found=False, validation_data=None):
    """PreAuthentication is the only trigger whose contract is "raising
    blocks the surrounding op". We translate the Lambda's exception
    into ``NotAuthorizedException``, matching the AWS contract. All other
    failure modes (transport, JSON parse, etc.) degrade quietly so a
    misconfigured trigger does not silently lock everyone out."""
    arn_present = bool(_lambda_arn_for(account_id, region, pool_id, "PreAuthentication"))
    if not arn_present:
        return
    try:
        from .triggers import run_pre_authentication

        run_pre_authentication(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            user_not_found=user_not_found, validation_data=validation_data,
        )
    except RuntimeError as exc:
        # The Lambda raised or returned FunctionError. AWS surfaces this
        # as NotAuthorizedException with the Lambda's message.
        from localemu.aws.api import CommonServiceException

        raise CommonServiceException(
            code="NotAuthorizedException",
            message=str(exc) or "PreAuthentication denied the request.",
            status_code=400,
        )
    except Exception:
        LOG.warning(
            "Cognito PreAuthentication trigger failed (non-block)",
            exc_info=True,
        )


def _run_post_authentication(account_id, region, pool_id, username, client_id,
                              new_device_metadata=None):
    try:
        from .triggers import run_post_authentication

        run_post_authentication(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            new_device_metadata=new_device_metadata,
        )
    except Exception:
        LOG.warning("Cognito PostAuthentication trigger failed", exc_info=True)


# ---------------------------------------------------------------------------
# CUSTOM_AUTH server-side session state
# ---------------------------------------------------------------------------
#
# AWS Cognito CUSTOM_AUTH carries server-side state across the
# InitiateAuth -> RespondToAuthChallenge boundary : the session token
# returned to the client is a handle to the private challenge
# parameters + the running history of (challengeName, answerCorrect)
# tuples. LocalEmu keeps this in-process. The map is best-effort
# cleaned lazily on access ; idle sessions older than the TTL are
# dropped before any new read or write so a malicious caller cannot
# hoard memory by starting a flow and abandoning it.

import threading as _threading
import time as _time
import uuid as _uuid


_CUSTOM_AUTH_SESSIONS: dict[str, dict] = {}
_CUSTOM_AUTH_LOCK = _threading.Lock()
_CUSTOM_AUTH_TTL_SECONDS = 300.0  # 5 minutes idle


def _custom_auth_cleanup_expired() -> None:
    now = _time.time()
    with _CUSTOM_AUTH_LOCK:
        for token in list(_CUSTOM_AUTH_SESSIONS):
            entry = _CUSTOM_AUTH_SESSIONS.get(token) or {}
            if now - entry.get("last_activity", now) > _CUSTOM_AUTH_TTL_SECONDS:
                _CUSTOM_AUTH_SESSIONS.pop(token, None)


def _custom_auth_create_session(
    *, account_id: str, region: str, pool_id: str, client_id: str,
    username: str,
) -> tuple[str, dict]:
    _custom_auth_cleanup_expired()
    token = _uuid.uuid4().hex
    now = _time.time()
    entry = {
        "account_id": account_id,
        "region": region,
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "history": [],
        "current_private": {},
        "current_metadata": "",
        "current_challenge_name": "",
        "created_at": now,
        "last_activity": now,
    }
    with _CUSTOM_AUTH_LOCK:
        _CUSTOM_AUTH_SESSIONS[token] = entry
    return token, entry


def _custom_auth_get_session(token: str) -> dict | None:
    _custom_auth_cleanup_expired()
    if not token:
        return None
    with _CUSTOM_AUTH_LOCK:
        entry = _CUSTOM_AUTH_SESSIONS.get(token)
        if entry is None:
            return None
        entry["last_activity"] = _time.time()
        return entry


def _custom_auth_clear_session(token: str) -> None:
    if not token:
        return
    with _CUSTOM_AUTH_LOCK:
        _CUSTOM_AUTH_SESSIONS.pop(token, None)


# ---------------------------------------------------------------------------
# CUSTOM_AUTH trigger wrappers
# ---------------------------------------------------------------------------


def _run_define_auth_challenge(account_id, region, pool_id, username, client_id,
                                session_history, user_not_found=False):
    try:
        from .triggers import run_define_auth_challenge
        return run_define_auth_challenge(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            session_history=session_history, user_not_found=user_not_found,
        )
    except Exception:
        LOG.warning("Cognito DefineAuthChallenge trigger failed", exc_info=True)
        return None


def _run_create_auth_challenge(account_id, region, pool_id, username, client_id,
                                challenge_name, session_history):
    try:
        from .triggers import run_create_auth_challenge
        return run_create_auth_challenge(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            challenge_name=challenge_name, session_history=session_history,
        )
    except Exception:
        LOG.warning("Cognito CreateAuthChallenge trigger failed", exc_info=True)
        return None


def _run_verify_auth_challenge_response(account_id, region, pool_id, username,
                                         client_id, private_challenge_parameters,
                                         challenge_answer):
    try:
        from .triggers import run_verify_auth_challenge_response
        return run_verify_auth_challenge_response(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id,
            private_challenge_parameters=private_challenge_parameters,
            challenge_answer=challenge_answer,
        )
    except Exception:
        LOG.warning(
            "Cognito VerifyAuthChallengeResponse trigger failed", exc_info=True,
        )
        return None


# ---------------------------------------------------------------------------
# CUSTOM_AUTH end-to-end driver
# ---------------------------------------------------------------------------


def _custom_auth_step(
    *, account_id: str, region: str, pool_id: str, client_id: str,
    username: str, session_history: list, user_not_found: bool = False,
) -> dict:
    """Run one DefineAuthChallenge call and, when the answer is
    CUSTOM_CHALLENGE, the follow-up CreateAuthChallenge. Returns a dict
    with keys:

      * ``terminal`` : ``"tokens"`` | ``"deny"`` | ``""`` (continue)
      * ``challenge_name``, ``public_params``, ``private_params``,
        ``challenge_metadata`` : populated when not terminal.

    Caller wires this into InitiateAuth's first step and
    RespondToAuthChallenge's nth step. Final-step termination
    (``terminal != ""``) lets the caller mint tokens or raise
    NotAuthorizedException without further trigger calls.
    """
    define = _run_define_auth_challenge(
        account_id, region, pool_id, username, client_id,
        session_history=session_history, user_not_found=user_not_found,
    ) or {}
    if define.get("failAuthentication"):
        return {"terminal": "deny"}
    if define.get("issueTokens"):
        return {"terminal": "tokens"}
    challenge_name = define.get("challengeName") or ""
    if challenge_name != "CUSTOM_CHALLENGE":
        # LocalEmu does not implement falling back to built-in
        # challenges (SRP_A, PASSWORD_VERIFIER, ...) from a CUSTOM_AUTH
        # path ; surface as deny so the user sees a clean
        # NotAuthorizedException.
        return {"terminal": "deny"}
    create = _run_create_auth_challenge(
        account_id, region, pool_id, username, client_id,
        challenge_name=challenge_name,
        session_history=session_history,
    ) or {}
    return {
        "terminal": "",
        "challenge_name": challenge_name,
        "public_params": create.get("publicChallengeParameters") or {},
        "private_params": create.get("privateChallengeParameters") or {},
        "challenge_metadata": create.get("challengeMetadata") or "",
    }


def _lambda_arn_for(account_id: str, region: str, pool_id: str, trigger: str) -> str:
    """Read one trigger ARN from the user pool's LambdaConfig. The
    sender entries (``CustomSMSSender`` / ``CustomEmailSender``) are
    structures with a ``LambdaArn`` field rather than a bare string ;
    handle both shapes."""
    try:
        from .triggers import get_lambda_config

        v = get_lambda_config(account_id, region, pool_id).get(trigger)
    except Exception:
        return ""
    if isinstance(v, dict):
        return v.get("LambdaArn") or ""
    return v or ""


def _run_pre_token_generation(account_id, region, pool_id, username, client_id, groups):
    try:
        from .triggers import run_pre_token_generation

        return run_pre_token_generation(
            account_id=account_id, region=region, pool_id=pool_id,
            username=username, client_id=client_id, groups=groups,
        )
    except Exception:
        LOG.warning("Cognito PreTokenGeneration trigger failed", exc_info=True)
        return {}, []


def _make_auth_result(
    pool_id: str,
    client_id: str,
    username: str,
    account_id: str,
    region: str,
) -> dict:
    """Build an AuthenticationResult with real JWT tokens."""
    _ensure_pool_keys(pool_id)
    keys_tuple = get_pool_keys(pool_id)
    private_key, kid = keys_tuple

    sub = _get_or_create_sub(account_id, pool_id, username)
    email = _get_user_email(pool_id, username, account_id, region)
    groups = _get_user_groups(pool_id, username, account_id, region)

    extra_claims, suppress_claims = _run_pre_token_generation(
        account_id, region, pool_id, username, client_id, groups
    )

    id_token = generate_id_token(
        pool_id=pool_id,
        region=region,
        client_id=client_id,
        username=username,
        sub=sub,
        private_key=private_key,
        kid=kid,
        email=email,
        email_verified=bool(email),
        groups=groups or None,
        extra_claims=extra_claims,
        suppress_claims=suppress_claims,
    )

    access_token = generate_access_token(
        pool_id=pool_id,
        region=region,
        client_id=client_id,
        username=username,
        sub=sub,
        private_key=private_key,
        kid=kid,
        groups=groups or None,
        extra_claims=extra_claims,
        suppress_claims=suppress_claims,
    )

    refresh_token = generate_refresh_token()
    with _state_lock:
        _store_refresh_token_locked(
            refresh_token, account_id, region, pool_id, client_id, username
        )

    _register_access_token_with_moto(
        access_token, pool_id, client_id, username, account_id, region,
    )

    return {
        "IdToken": id_token,
        "AccessToken": access_token,
        "RefreshToken": refresh_token,
        "ExpiresIn": 3600,
        "TokenType": "Bearer",
    }


# --- Intercepted operations ---


def _handle_create_user_pool(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateUserPool: let Moto create it, then generate RSA keys and register OIDC/OAuth2 routes."""
    register_oidc_routes()
    register_oauth2_routes()
    result = call_moto(context)
    pool = result.get("UserPool", {})
    pool_id = pool.get("Id")
    if pool_id:
        _ensure_pool_keys(pool_id)
        LOG.info(
            "Cognito pool %s created. JWKS: %s/%s/.well-known/jwks.json",
            pool_id,
            config.external_service_url(),
            pool_id,
        )
    return result


def _parse_json_body(context: RequestContext) -> dict:
    """Parse JSON request body (Cognito uses JSON protocol)."""
    try:
        return json.loads(context.request.data)
    except Exception:
        return {}


def _make_refresh_auth_result(
    refresh_token: str,
    account_id: str,
    region: str,
    client_id_hint: str = "",
    pool_id_hint: str = "",
) -> dict | None:
    """Consume a refresh token and issue new access + id tokens.

    Returns None if the refresh token is unknown, enabling callers to
    surface an error to the client.
    """
    with _state_lock:
        _evict_expired_refresh_tokens_locked()
        entry = _refresh_tokens.get(refresh_token)
    if not entry:
        return None

    stored_account_id, stored_region, pool_id, client_id, username, _issued_at = entry
    # Account/region must match the caller context for security.
    if stored_account_id != account_id or stored_region != region:
        return None
    if pool_id_hint and pool_id_hint != pool_id:
        return None
    if client_id_hint and client_id_hint != client_id:
        return None

    _ensure_pool_keys(pool_id)
    private_key, kid = get_pool_keys(pool_id)

    sub = _get_or_create_sub(account_id, pool_id, username)
    email = _get_user_email(pool_id, username, account_id, region)
    groups = _get_user_groups(pool_id, username, account_id, region)

    id_token = generate_id_token(
        pool_id=pool_id,
        region=region,
        client_id=client_id,
        username=username,
        sub=sub,
        private_key=private_key,
        kid=kid,
        email=email,
        email_verified=bool(email),
        groups=groups or None,
    )
    access_token = generate_access_token(
        pool_id=pool_id,
        region=region,
        client_id=client_id,
        username=username,
        sub=sub,
        private_key=private_key,
        kid=kid,
        groups=groups or None,
    )

    _register_access_token_with_moto(
        access_token, pool_id, client_id, username, account_id, region,
    )

    # Per AWS: REFRESH_TOKEN_AUTH does not return a new RefreshToken.
    return {
        "IdToken": id_token,
        "AccessToken": access_token,
        "ExpiresIn": 3600,
        "TokenType": "Bearer",
    }


def _handle_initiate_auth(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """InitiateAuth: let Moto validate, then replace tokens with real JWTs.

    Also handles REFRESH_TOKEN_AUTH / REFRESH_TOKEN flows locally by
    consuming tokens issued previously via ``_make_auth_result``.
    """
    body = _parse_json_body(context)
    auth_flow = body.get("AuthFlow", "")
    auth_params = body.get("AuthParameters", {})
    client_id = body.get("ClientId", "")

    if auth_flow in ("REFRESH_TOKEN_AUTH", "REFRESH_TOKEN"):
        refresh_token = auth_params.get("REFRESH_TOKEN", "")
        auth_result = _make_refresh_auth_result(
            refresh_token,
            context.account_id,
            context.region,
            client_id_hint=client_id,
        )
        if auth_result is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                code="NotAuthorizedException",
                message="Invalid Refresh Token.",
                status_code=400,
            )
        return {"AuthenticationResult": auth_result, "ChallengeParameters": {}}

    # PreAuthentication fires BEFORE the password check. Raising blocks
    # auth with NotAuthorizedException carrying the Lambda's message.
    username = auth_params.get("USERNAME", "")
    pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
    if pool_id and username:
        _run_pre_authentication(
            context.account_id, context.region, pool_id, username, client_id,
            validation_data=body.get("ClientMetadata"),
        )

    # CUSTOM_AUTH : if the pool has a DefineAuthChallenge Lambda and the
    # client requested CUSTOM_AUTH, drive the flow ourselves (moto's
    # CUSTOM_AUTH support is minimal). Falls back to the standard path
    # when no DefineAuthChallenge is configured.
    if auth_flow == "CUSTOM_AUTH" and pool_id and username:
        custom_result = _maybe_drive_custom_auth_initiate(
            context, pool_id, client_id, username,
        )
        if custom_result is not None:
            return custom_result

    # UserMigration : when moto reports UserNotFound for a password-bearing
    # auth flow AND the pool has a UserMigration Lambda, fire it to
    # synthesise the user, then retry.
    try:
        result = call_moto(context)
    except Exception as exc:
        if (pool_id and username and _is_user_not_found(exc)
                and auth_flow in (
                    "USER_PASSWORD_AUTH", "USER_SRP_AUTH",
                    "ADMIN_USER_PASSWORD_AUTH",
                )):
            migrated = _run_user_migration(
                context.account_id, context.region, pool_id, username,
                client_id, auth_params.get("PASSWORD", ""),
                "UserMigration_Authentication",
            )
            if migrated:
                result = call_moto(context)
            else:
                raise
        else:
            raise

    if result.get("AuthenticationResult"):
        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )
            # PostAuthentication fires only after auth actually succeeded
            # (i.e. there's an AuthenticationResult ; not on flows that
            # return a ChallengeName for the client to respond to).
            _run_post_authentication(
                context.account_id, context.region, pool_id, username, client_id,
            )

    return result


def _is_user_not_found(exc: Exception) -> bool:
    """Detect moto's UserNotFoundException across the various ways it
    surfaces (named class, code attribute, ``__class__.__name__``)."""
    name = exc.__class__.__name__
    if name in ("UserNotFoundException", "UserNotFoundError"):
        return True
    code = getattr(exc, "code", None) or getattr(exc, "error_code", None)
    return code == "UserNotFoundException"


def _handle_admin_initiate_auth(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """AdminInitiateAuth: let Moto validate, then replace tokens with real JWTs."""
    body = _parse_json_body(context)
    auth_flow = body.get("AuthFlow", "")
    pool_id = body.get("UserPoolId", "")
    client_id = body.get("ClientId", "")
    auth_params = body.get("AuthParameters", {})

    if auth_flow in ("REFRESH_TOKEN_AUTH", "REFRESH_TOKEN"):
        refresh_token = auth_params.get("REFRESH_TOKEN", "")
        auth_result = _make_refresh_auth_result(
            refresh_token,
            context.account_id,
            context.region,
            client_id_hint=client_id,
            pool_id_hint=pool_id,
        )
        if auth_result is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                code="NotAuthorizedException",
                message="Invalid Refresh Token.",
                status_code=400,
            )
        return {"AuthenticationResult": auth_result, "ChallengeParameters": {}}

    # PreAuthentication BEFORE the password check (raising blocks auth).
    username = auth_params.get("USERNAME", "")
    if pool_id and username:
        _run_pre_authentication(
            context.account_id, context.region, pool_id, username, client_id,
            validation_data=body.get("ClientMetadata"),
        )

    # CUSTOM_AUTH (admin variant) : same shape as InitiateAuth.
    if auth_flow == "CUSTOM_AUTH" and pool_id and username:
        custom_result = _maybe_drive_custom_auth_initiate(
            context, pool_id, client_id, username,
        )
        if custom_result is not None:
            return custom_result

    # UserMigration : same shape as InitiateAuth.
    try:
        result = call_moto(context)
    except Exception as exc:
        if (pool_id and username and _is_user_not_found(exc)
                and auth_flow in (
                    "USER_PASSWORD_AUTH", "USER_SRP_AUTH",
                    "ADMIN_USER_PASSWORD_AUTH",
                )):
            migrated = _run_user_migration(
                context.account_id, context.region, pool_id, username,
                client_id, auth_params.get("PASSWORD", ""),
                "UserMigration_Authentication",
            )
            if migrated:
                result = call_moto(context)
            else:
                raise
        else:
            raise

    if result.get("AuthenticationResult"):
        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )
            _run_post_authentication(
                context.account_id, context.region, pool_id, username, client_id,
            )

    return result


def _handle_respond_to_auth_challenge(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RespondToAuthChallenge: let Moto validate the challenge, then mint real JWTs.

    Covers the challenge-completion flows (SRP ``PASSWORD_VERIFIER``, SMS/TOTP
    MFA, ``NEW_PASSWORD_REQUIRED``, ...). Without this interception those flows
    return Moto's unsigned ``kid:"dummy"`` tokens, which fail JWKS verification.

    CUSTOM_AUTH continuation is driven entirely by LocalEmu : we resume
    from the ``_custom_auth_sessions`` map keyed on the client's
    ``Session`` token, fire VerifyAuthChallengeResponse, then
    DefineAuthChallenge, then either mint tokens, deny, or return the
    next CUSTOM_CHALLENGE.
    """
    body = _parse_json_body(context)
    challenge_name = body.get("ChallengeName", "")
    if challenge_name == "CUSTOM_CHALLENGE":
        return _drive_custom_auth_respond(context, body)

    result = call_moto(context)
    if result.get("AuthenticationResult"):
        client_id = body.get("ClientId", "")
        challenge_responses = body.get("ChallengeResponses", {}) or {}
        username = challenge_responses.get("USERNAME", "")
        pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )
            _run_post_authentication(
                context.account_id, context.region, pool_id, username, client_id,
            )
    return result


def _handle_admin_respond_to_auth_challenge(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """AdminRespondToAuthChallenge: like RespondToAuthChallenge, with an explicit pool id."""
    body = _parse_json_body(context)
    challenge_name = body.get("ChallengeName", "")
    if challenge_name == "CUSTOM_CHALLENGE":
        return _drive_custom_auth_respond(context, body)

    result = call_moto(context)
    if result.get("AuthenticationResult"):
        client_id = body.get("ClientId", "")
        pool_id = body.get("UserPoolId", "")
        challenge_responses = body.get("ChallengeResponses", {}) or {}
        username = challenge_responses.get("USERNAME", "")
        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )
            _run_post_authentication(
                context.account_id, context.region, pool_id, username, client_id,
            )
    return result


def _maybe_drive_custom_auth_initiate(
    context, pool_id: str, client_id: str, username: str,
):
    """Drive the FIRST step of a CUSTOM_AUTH flow.

    Returns ``None`` when no DefineAuthChallenge Lambda is configured
    (the caller then falls through to the standard path). Returns the
    InitiateAuth response dict otherwise (challenge or tokens or
    raises NotAuthorizedException).
    """
    if not _lambda_arn_for(
        context.account_id, context.region, pool_id, "DefineAuthChallenge",
    ):
        return None

    step = _custom_auth_step(
        account_id=context.account_id, region=context.region,
        pool_id=pool_id, client_id=client_id, username=username,
        session_history=[],
    )
    if step["terminal"] == "tokens":
        _run_post_authentication(
            context.account_id, context.region, pool_id, username, client_id,
        )
        return {
            "AuthenticationResult": _make_auth_result(
                pool_id=pool_id, client_id=client_id, username=username,
                account_id=context.account_id, region=context.region,
            ),
            "ChallengeParameters": {},
        }
    if step["terminal"] == "deny":
        from localemu.aws.api import CommonServiceException

        raise CommonServiceException(
            code="NotAuthorizedException",
            message="DefineAuthChallenge denied the request.",
            status_code=400,
        )
    # Continue : start a server-side session and return the
    # CUSTOM_CHALLENGE to the client.
    token, entry = _custom_auth_create_session(
        account_id=context.account_id, region=context.region,
        pool_id=pool_id, client_id=client_id, username=username,
    )
    entry["current_private"] = step["private_params"]
    entry["current_metadata"] = step["challenge_metadata"]
    entry["current_challenge_name"] = step["challenge_name"]
    return {
        "ChallengeName": "CUSTOM_CHALLENGE",
        "Session": token,
        "ChallengeParameters": dict(step["public_params"] or {}),
    }


def _drive_custom_auth_respond(context, body):
    """Drive a CUSTOM_AUTH continuation : Verify the previous answer,
    then DefineAuthChallenge for the next step. Either mints tokens,
    denies (NotAuthorizedException), or returns the next
    CUSTOM_CHALLENGE."""
    from localemu.aws.api import CommonServiceException

    session_token = body.get("Session", "") or ""
    entry = _custom_auth_get_session(session_token)
    if entry is None:
        raise CommonServiceException(
            code="NotAuthorizedException",
            message="Invalid session for the user.",
            status_code=400,
        )
    challenge_responses = body.get("ChallengeResponses", {}) or {}
    answer = challenge_responses.get("ANSWER", "")

    verify = _run_verify_auth_challenge_response(
        entry["account_id"], entry["region"], entry["pool_id"],
        entry["username"], entry["client_id"],
        private_challenge_parameters=entry["current_private"],
        challenge_answer=answer,
    ) or {}
    answer_correct = bool(verify.get("answerCorrect"))

    entry["history"].append({
        "challengeName": entry["current_challenge_name"] or "CUSTOM_CHALLENGE",
        "challengeResult": answer_correct,
        "challengeMetadata": entry["current_metadata"] or "",
    })

    step = _custom_auth_step(
        account_id=entry["account_id"], region=entry["region"],
        pool_id=entry["pool_id"], client_id=entry["client_id"],
        username=entry["username"], session_history=entry["history"],
    )
    if step["terminal"] == "tokens":
        _custom_auth_clear_session(session_token)
        _run_post_authentication(
            entry["account_id"], entry["region"], entry["pool_id"],
            entry["username"], entry["client_id"],
        )
        return {
            "AuthenticationResult": _make_auth_result(
                pool_id=entry["pool_id"], client_id=entry["client_id"],
                username=entry["username"],
                account_id=entry["account_id"], region=entry["region"],
            ),
            "ChallengeParameters": {},
        }
    if step["terminal"] == "deny":
        _custom_auth_clear_session(session_token)
        raise CommonServiceException(
            code="NotAuthorizedException",
            message="DefineAuthChallenge denied the request.",
            status_code=400,
        )
    # Another round : update the server-side session with the new
    # private params and re-issue the Session token (same value, AWS
    # contract).
    entry["current_private"] = step["private_params"]
    entry["current_metadata"] = step["challenge_metadata"]
    entry["current_challenge_name"] = step["challenge_name"]
    return {
        "ChallengeName": "CUSTOM_CHALLENGE",
        "Session": session_token,
        "ChallengeParameters": dict(step["public_params"] or {}),
    }


def _handle_sign_up(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """SignUp: let Moto handle, assign a stable sub, run the PreSignUp trigger."""
    result = call_moto(context)
    if result.get("UserSub"):
        body = _parse_json_body(context)
        client_id = body.get("ClientId", "")
        username = body.get("Username", "")
        pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
        if pool_id and username:
            sub = _get_or_create_sub(context.account_id, pool_id, username)
            result["UserSub"] = sub
            presignup = _run_pre_sign_up(
                context.account_id, context.region, pool_id, username, client_id,
                "PreSignUp_SignUp",
            )
            if presignup and presignup.get("autoConfirmUser"):
                result["UserConfirmed"] = True
            # CustomMessage : if the user was NOT auto-confirmed, moto
            # generated a confirmation code. Fire CustomMessage so the
            # tutorial's override message body lands in the buffer.
            if not result.get("UserConfirmed"):
                _run_custom_message(
                    context.account_id, context.region, pool_id, username,
                    client_id, "CustomMessage_SignUp",
                )
    return result


def _handle_confirm_sign_up(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """ConfirmSignUp: let Moto confirm, then run the PostConfirmation trigger."""
    result = call_moto(context)
    body = _parse_json_body(context)
    client_id = body.get("ClientId", "")
    username = body.get("Username", "")
    pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
    if pool_id and username:
        _run_post_confirmation(
            context.account_id, context.region, pool_id, username, client_id,
            "PostConfirmation_ConfirmSignUp",
        )
    return result


def _handle_admin_confirm_sign_up(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """AdminConfirmSignUp: let Moto confirm, then run the PostConfirmation trigger."""
    result = call_moto(context)
    body = _parse_json_body(context)
    pool_id = body.get("UserPoolId", "")
    username = body.get("Username", "")
    if pool_id and username:
        _run_post_confirmation(
            context.account_id, context.region, pool_id, username, "",
            "PostConfirmation_ConfirmSignUp",
        )
    return result


def _handle_admin_create_user(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """AdminCreateUser: let Moto handle, then run the PreSignUp + CustomMessage triggers."""
    result = call_moto(context)
    body = _parse_json_body(context)
    pool_id = body.get("UserPoolId", "")
    username = body.get("Username", "")
    if pool_id:
        _ensure_pool_keys(pool_id)
    if pool_id and username:
        _run_pre_sign_up(
            context.account_id, context.region, pool_id, username, "",
            "PreSignUp_AdminCreateUser",
        )
        # AdminCreateUser sends a temporary password. CustomMessage's
        # AdminCreateUser source lets the tutorial customize the
        # welcome message that would carry that temp password.
        _run_custom_message(
            context.account_id, context.region, pool_id, username, "",
            "CustomMessage_AdminCreateUser",
        )
    return result


def _handle_resend_confirmation_code(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """ResendConfirmationCode: let Moto regenerate the code, then fire CustomMessage."""
    result = call_moto(context)
    body = _parse_json_body(context)
    client_id = body.get("ClientId", "")
    username = body.get("Username", "")
    pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
    if pool_id and username:
        _run_custom_message(
            context.account_id, context.region, pool_id, username,
            client_id, "CustomMessage_ResendCode",
        )
    return result


def _handle_forgot_password(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """ForgotPassword: let Moto generate the reset code (stored on
    ``user.confirmation_code``), then fire CustomMessage."""
    result = call_moto(context)
    body = _parse_json_body(context)
    client_id = body.get("ClientId", "")
    username = body.get("Username", "")
    pool_id = _find_pool_for_client(client_id, context.account_id, context.region)
    if pool_id and username:
        _run_custom_message(
            context.account_id, context.region, pool_id, username,
            client_id, "CustomMessage_ForgotPassword",
        )
    return result


def _find_pool_for_client(client_id: str, account_id: str, region: str) -> str | None:
    """Find which pool a client belongs to."""
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        backend = cognitoidp_backends[account_id][region]
        for pool_id, pool in backend.user_pools.items():
            for cid, client in pool.clients.items():
                if cid == client_id:
                    return pool_id
    except Exception:
        pass
    return None


# Dispatch table configuration
_INTERCEPTED_OPS = {
    "CreateUserPool": _handle_create_user_pool,
    "InitiateAuth": _handle_initiate_auth,
    "AdminInitiateAuth": _handle_admin_initiate_auth,
    "RespondToAuthChallenge": _handle_respond_to_auth_challenge,
    "AdminRespondToAuthChallenge": _handle_admin_respond_to_auth_challenge,
    "SignUp": _handle_sign_up,
    "ConfirmSignUp": _handle_confirm_sign_up,
    "AdminConfirmSignUp": _handle_admin_confirm_sign_up,
    "AdminCreateUser": _handle_admin_create_user,
    "ResendConfirmationCode": _handle_resend_confirmation_code,
    "ForgotPassword": _handle_forgot_password,
}


def CognitoIdpDispatcher(service_model) -> DispatchTable:
    """Create dispatch table for Cognito User Pools.

    Auth operations return real JWTs. All other operations pass to Moto.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


class CognitoIdpState:
    """Bridges the dispatch-table-based provider into the state visitor API.

    The dispatch-table-based provider has no class of its own, so we attach an
    ``accept_state_visitor`` here. Underneath we delegate to the reflection
    locator so moto's backend state is picked up, and we clear our own
    module-level ``_user_subs`` / ``_refresh_tokens`` dicts at reset time via
    the lifecycle hooks declared on the Service's lifecycle_hook.
    """

    service = "cognito-idp"

    def accept_state_visitor(self, visitor: StateVisitor):
        # Only visit state containers the visitor knows how to handle (moto
        # backends + community stores via reflection). Our plain dicts are
        # cleared via the lifecycle hook attached to the Service instead.
        from localemu.state.inspect import ReflectionStateLocator

        ReflectionStateLocator(service=self.service).accept_state_visitor(visitor)


class CognitoIdpLifecycle(ServiceLifecycleHook):
    """Clears module-level token / sub state on service reset/load."""

    def on_before_state_reset(self) -> None:
        with _state_lock:
            _user_subs.clear()
            _refresh_tokens.clear()

    def on_before_state_load(self) -> None:
        with _state_lock:
            _user_subs.clear()
            _refresh_tokens.clear()


def create_cognito_idp_service() -> Service:
    """Create the Cognito User Pools service with real JWT support."""
    from localemu.aws.spec import load_service

    service_model = load_service("cognito-idp")
    dispatch_table = CognitoIdpDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    service = Service(
        name="cognito-idp",
        skeleton=skeleton,
        lifecycle_hook=CognitoIdpLifecycle(),
    )
    # Attach provider-like state holder so Service.accept_state_visitor delegates
    # to the reflection locator (which covers the moto backend).
    service._provider = CognitoIdpState()
    return service
