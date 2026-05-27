"""Cognito Hosted UI / OAuth2 endpoints.

Serves the endpoints the OIDC discovery document advertises:

  GET  /oauth2/authorize   - hosted login page; on submit issues an auth code
                             and redirects to the client's redirect_uri
  POST /oauth2/token       - authorization_code / refresh_token / client_credentials
  GET  /oauth2/userInfo    - returns the user's claims for a valid access token

Tokens are the same real RS256 JWTs minted for the SDK auth flows (reused via
the provider's token helpers), so a token obtained through the hosted UI
verifies against the pool JWKS exactly like one from InitiateAuth.
"""

from __future__ import annotations

import html
import json
import logging
import time
import urllib.parse
import uuid
from collections import OrderedDict

from rolo import Request

from localemu.http import Response
from localemu.services.edge import ROUTER

LOG = logging.getLogger(__name__)

# code -> dict(account_id, region, pool_id, client_id, username, redirect_uri, scope, exp)
_auth_codes: "OrderedDict[str, dict]" = OrderedDict()
_CODE_TTL = 300
_CODE_MAX = 10000


# --------------------------------------------------------------------------
# moto backend lookups
# --------------------------------------------------------------------------


def _find_client(client_id: str):
    """Locate (account_id, region, pool_id, pool, client) for a client id."""
    try:
        from moto.cognitoidp.models import cognitoidp_backends

        for account_id in list(cognitoidp_backends.keys()):
            regions = cognitoidp_backends[account_id]
            for region in list(regions.keys()):
                backend = regions[region]
                for pool_id, pool in backend.user_pools.items():
                    client = pool.clients.get(client_id)
                    if client:
                        return account_id, region, pool_id, pool, client
    except Exception:
        LOG.debug("oauth2 client lookup failed", exc_info=True)
    return None


def _client_field(client, *names):
    cfg = getattr(client, "extended_config", None) or {}
    for n in names:
        if n in cfg:
            return cfg[n]
    return None


def _status_str(user) -> str:
    status = getattr(user, "status", "")
    return getattr(status, "value", status) if status is not None else ""


def _validate_credentials(pool, username: str, password: str) -> bool:
    user = pool.users.get(username) if pool else None
    if not user:
        return False
    if _status_str(user) != "CONFIRMED":
        return False
    return getattr(user, "password", None) == password


# --------------------------------------------------------------------------
# auth code store
# --------------------------------------------------------------------------


def _issue_code(data: dict) -> str:
    code = uuid.uuid4().hex
    now = time.time()
    # evict expired + cap size
    for k in [k for k, v in _auth_codes.items() if v["exp"] < now]:
        _auth_codes.pop(k, None)
    while len(_auth_codes) >= _CODE_MAX:
        _auth_codes.popitem(last=False)
    data["exp"] = now + _CODE_TTL
    _auth_codes[code] = data
    return code


def _consume_code(code: str) -> dict | None:
    data = _auth_codes.pop(code, None)
    if not data or data["exp"] < time.time():
        return None
    return data


# --------------------------------------------------------------------------
# /oauth2/authorize  (hosted login page)
# --------------------------------------------------------------------------

_LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font-family:sans-serif;max-width:340px;margin:60px auto">
<h2>Sign in</h2>
{error}
<form method="post" action="/oauth2/authorize">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="response_type" value="{response_type}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <p><input name="username" placeholder="username" style="width:100%;padding:8px"></p>
  <p><input name="password" type="password" placeholder="password" style="width:100%;padding:8px"></p>
  <p><button type="submit" style="width:100%;padding:8px">Sign in</button></p>
</form></body></html>"""


def _render_login(params: dict, error: str = "") -> Response:
    page = _LOGIN_PAGE.format(
        error=f'<p style="color:#c00">{html.escape(error)}</p>' if error else "",
        client_id=html.escape(params.get("client_id", "")),
        redirect_uri=html.escape(params.get("redirect_uri", "")),
        response_type=html.escape(params.get("response_type", "code")),
        scope=html.escape(params.get("scope", "openid")),
        state=html.escape(params.get("state", "")),
    )
    return Response(response=page, status=200, content_type="text/html; charset=utf-8")


def _redirect(location: str) -> Response:
    return Response(status=302, headers={"Location": location})


def _handle_authorize(request: Request, **kwargs) -> Response:
    if request.method == "GET":
        params = {k: request.args.get(k, "") for k in
                  ("client_id", "redirect_uri", "response_type", "scope", "state")}
        if not params["client_id"]:
            return _json(400, {"error": "invalid_request", "error_description": "client_id required"})
        return _render_login(params)

    # POST: credentials submitted
    form = request.form
    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    state = form.get("state", "")
    scope = form.get("scope", "openid")
    response_type = form.get("response_type", "code")
    username = form.get("username", "")
    password = form.get("password", "")

    located = _find_client(client_id)
    if not located:
        return _json(400, {"error": "invalid_client"})
    account_id, region, pool_id, pool, client = located

    callbacks = _client_field(client, "CallbackURLs") or []
    if callbacks and redirect_uri not in callbacks:
        return _json(400, {"error": "redirect_mismatch"})

    if not _validate_credentials(pool, username, password):
        return _render_login(
            {"client_id": client_id, "redirect_uri": redirect_uri,
             "response_type": response_type, "scope": scope, "state": state},
            error="Incorrect username or password.",
        )

    code = _issue_code({
        "account_id": account_id, "region": region, "pool_id": pool_id,
        "client_id": client_id, "username": username,
        "redirect_uri": redirect_uri, "scope": scope,
    })
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={code}"
    if state:
        location += f"&state={urllib.parse.quote(state)}"
    return _redirect(location)


# --------------------------------------------------------------------------
# /oauth2/token
# --------------------------------------------------------------------------


def _handle_token(request: Request, **kwargs) -> Response:
    form = request.form
    grant_type = form.get("grant_type", "")

    if grant_type == "authorization_code":
        code = form.get("code", "")
        data = _consume_code(code)
        if not data:
            return _json(400, {"error": "invalid_grant"})
        if form.get("redirect_uri") and form.get("redirect_uri") != data["redirect_uri"]:
            return _json(400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
        from .provider import _make_auth_result

        result = _make_auth_result(
            pool_id=data["pool_id"], client_id=data["client_id"],
            username=data["username"], account_id=data["account_id"], region=data["region"],
        )
        return _json(200, _token_response(result, data["scope"]))

    if grant_type == "refresh_token":
        located = _find_client(form.get("client_id", ""))
        if not located:
            return _json(400, {"error": "invalid_client"})
        account_id, region, _pool_id, _pool, _client = located
        from .provider import _make_refresh_auth_result

        result = _make_refresh_auth_result(
            form.get("refresh_token", ""), account_id, region,
            client_id_hint=form.get("client_id", ""),
        )
        if not result:
            return _json(400, {"error": "invalid_grant"})
        return _json(200, _token_response(result, form.get("scope", "")))

    if grant_type == "client_credentials":
        located = _find_client(form.get("client_id", ""))
        if not located:
            return _json(400, {"error": "invalid_client"})
        account_id, region, pool_id, _pool, _client = located
        from .keys import generate_key_pair  # noqa: F401  (ensure key module importable)
        from .provider import _ensure_pool_keys
        from .oidc import get_pool_keys
        from .tokens import generate_access_token

        _ensure_pool_keys(pool_id)
        private_key, kid = get_pool_keys(pool_id)
        scopes = (form.get("scope") or "").split() or None
        access = generate_access_token(
            pool_id=pool_id, region=region, client_id=form.get("client_id"),
            username=form.get("client_id"), sub=form.get("client_id"),
            private_key=private_key, kid=kid, scopes=scopes,
        )
        from .provider import _register_access_token_with_moto

        _register_access_token_with_moto(
            access, pool_id, form.get("client_id"), form.get("client_id"), account_id, region
        )
        return _json(200, {"access_token": access, "token_type": "Bearer", "expires_in": 3600})

    return _json(400, {"error": "unsupported_grant_type"})


def _token_response(result: dict, scope: str) -> dict:
    body = {
        "access_token": result["AccessToken"],
        "id_token": result.get("IdToken"),
        "token_type": "Bearer",
        "expires_in": result.get("ExpiresIn", 3600),
    }
    if result.get("RefreshToken"):
        body["refresh_token"] = result["RefreshToken"]
    if scope:
        body["scope"] = scope
    return {k: v for k, v in body.items() if v is not None}


# --------------------------------------------------------------------------
# /oauth2/userInfo
# --------------------------------------------------------------------------


def _handle_userinfo(request: Request, **kwargs) -> Response:
    auth = request.headers.get("Authorization", "")
    from .verify import TokenVerificationError, verify_cognito_token

    try:
        claims = verify_cognito_token(auth, allowed_token_uses=("access",))
    except TokenVerificationError:
        return Response(
            status=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            response=json.dumps({"error": "invalid_token"}),
            content_type="application/json",
        )

    username = claims.get("username") or claims.get("cognito:username") or ""
    located = _find_client(claims.get("client_id", ""))
    info = {"sub": claims.get("sub"), "username": username}
    if located:
        _account_id, _region, _pool_id, pool, _client = located
        user = pool.users.get(username)
        for attr in getattr(user, "attributes", None) or []:
            name, value = attr.get("Name"), attr.get("Value")
            if name in ("email", "email_verified", "phone_number", "phone_number_verified", "name"):
                info[name] = value
    return _json(200, {k: v for k, v in info.items() if v is not None})


# --------------------------------------------------------------------------


def _json(status: int, body: dict) -> Response:
    return Response(response=json.dumps(body), status=status, content_type="application/json")


_registered = []


def register_oauth2_routes():
    """Register the /oauth2/* endpoints with the edge ROUTER (idempotent)."""
    global _registered
    if _registered:
        return
    _registered = [
        ROUTER.add(path="/oauth2/authorize", endpoint=_handle_authorize, methods=["GET", "POST"]),
        ROUTER.add(path="/oauth2/token", endpoint=_handle_token, methods=["POST"]),
        ROUTER.add(path="/oauth2/userInfo", endpoint=_handle_userinfo, methods=["GET", "POST"]),
    ]
    LOG.info("Cognito OAuth2 / hosted-UI endpoints registered")
