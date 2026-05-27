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
    back into the moto dict — otherwise every token-taking op rejects a
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

    result = call_moto(context)

    if result.get("AuthenticationResult"):
        username = auth_params.get("USERNAME", "")
        pool_id = _find_pool_for_client(client_id, context.account_id, context.region)

        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )

    return result


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

    result = call_moto(context)

    if result.get("AuthenticationResult"):
        username = auth_params.get("USERNAME", "")

        if pool_id and username:
            result["AuthenticationResult"] = _make_auth_result(
                pool_id=pool_id,
                client_id=client_id,
                username=username,
                account_id=context.account_id,
                region=context.region,
            )

    return result


def _handle_respond_to_auth_challenge(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RespondToAuthChallenge: let Moto validate the challenge, then mint real JWTs.

    Covers the challenge-completion flows (SRP ``PASSWORD_VERIFIER``, SMS/TOTP
    MFA, ``NEW_PASSWORD_REQUIRED``, ...). Without this interception those flows
    return Moto's unsigned ``kid:"dummy"`` tokens, which fail JWKS verification.
    """
    result = call_moto(context)
    if result.get("AuthenticationResult"):
        body = _parse_json_body(context)
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
    return result


def _handle_admin_respond_to_auth_challenge(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """AdminRespondToAuthChallenge: like RespondToAuthChallenge, with an explicit pool id."""
    result = call_moto(context)
    if result.get("AuthenticationResult"):
        body = _parse_json_body(context)
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
    return result


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
    """AdminCreateUser: let Moto handle, then run the PreSignUp trigger."""
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
