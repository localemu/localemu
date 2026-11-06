"""Real signature verification for ``sts:AssumeRoleWithWebIdentity`` tokens,
plus a LocalEmu-only way to mint a validly-signed test token for a
registered OIDC provider without needing a real external identity provider.

Real AWS verifies a web-identity token's signature against the JWKS of the
OIDC provider registered via ``iam:CreateOpenIDConnectProvider`` (fetched
from the provider's own well-known URL). LocalEmu previously accepted any
token structurally, including an unsigned/garbage-signature one, as long as
the trust policy's ``Principal: {Federated: ...}`` matched by string - this
module closes that gap for any provider that is actually registered.

For a provider LocalEmu has never minted a local test token for, we fetch
the real JWKS over HTTPS exactly like AWS does. For local lab/test use where
reaching the real provider isn't desired (or possible), ``mint_test_token``
below generates a per-provider RSA keypair on first use and signs with it;
``verify_web_identity_token`` checks that local keypair first, so a token it
minted verifies without any network access.
"""

from __future__ import annotations

import logging
import threading
import time

import jwt as pyjwt

from localemu.services.cognito_idp.keys import (
    generate_key_pair,
    private_key_to_jwk,
    private_key_to_pem,
)

LOG = logging.getLogger(__name__)

# provider_arn -> (private_key, kid). Lazily created by mint_test_token;
# a provider nobody has minted a local token for has no entry here, and
# verification falls through to fetching its real JWKS over HTTPS.
_LOCAL_KEYPAIRS: dict[str, tuple] = {}
_LOCK = threading.Lock()

_JWKS_FETCH_TIMEOUT_SECONDS = 3
_JWKS_CACHE_TTL_SECONDS = 300
_jwks_cache: dict[str, tuple[float, dict]] = {}  # url -> (fetched_at, jwks)


def _get_or_create_local_keypair(provider_arn: str):
    with _LOCK:
        pair = _LOCAL_KEYPAIRS.get(provider_arn)
        if pair is None:
            pair = generate_key_pair()
            _LOCAL_KEYPAIRS[provider_arn] = pair
        return pair


def local_jwks_for_provider(provider_arn: str) -> dict | None:
    """The JWKS LocalEmu would serve for this provider, or None if no local
    test token has ever been minted for it (nothing to verify against)."""
    with _LOCK:
        pair = _LOCAL_KEYPAIRS.get(provider_arn)
    if pair is None:
        return None
    private_key, kid = pair
    return {"keys": [private_key_to_jwk(private_key, kid)]}


def _provider_url_from_arn(provider_arn: str) -> str | None:
    """Pull the registered URL straight out of the provider's own ARN -
    ``arn:aws:iam::<account>:oidc-provider/<url>`` - matching exactly how
    moto builds it (``OpenIDConnectProvider.arn`` in
    ``moto/iam/models.py``), so this needs no backend lookup at all."""
    marker = ":oidc-provider/"
    idx = provider_arn.find(marker)
    if idx == -1:
        return None
    return provider_arn[idx + len(marker):]


def mint_test_token(provider_arn: str, claims: dict) -> str:
    """Sign ``claims`` with a LocalEmu-generated per-provider keypair.

    LocalEmu-only convenience for lab/test use: it lets a trust policy that
    references a real external OIDC provider (e.g.
    ``token.actions.githubusercontent.com``) be exercised locally with a
    token that passes real signature verification, without needing a real workflow run at
    that provider. Not something real AWS offers - this exists purely so a
    local security lab can demonstrate the *authorization* risk (an overly
    broad trust condition) without having to fake the *cryptography* too.

    ``iss`` is always forced to the registered provider's own URL,
    overriding anything the caller passed in ``claims`` - a real OIDC
    token's issuer is never caller-controlled either, and
    ``AssumeRoleWithWebIdentity``'s whole provider-lookup chain (issuer ->
    registered provider -> signature check -> trust-policy issuer match)
    depends on it being present and correct. Omitting ``iss`` (an easy
    mistake when hand-building test claims) used to produce a token that
    could never match any ``Federated`` principal, no matter how permissive
    the trust policy's condition (e.g. ``repo:*``) was.
    """
    claims = dict(claims)
    url = _provider_url_from_arn(provider_arn)
    if url:
        claims["iss"] = f"https://{url}"
    private_key, kid = _get_or_create_local_keypair(provider_arn)
    headers = {"kid": kid}
    return pyjwt.encode(claims, private_key_to_pem(private_key), algorithm="RS256", headers=headers)


def _fetch_real_jwks(issuer_host: str) -> dict | None:
    cached = _jwks_cache.get(issuer_host)
    if cached and (time.time() - cached[0]) < _JWKS_CACHE_TTL_SECONDS:
        return cached[1]

    import requests

    for url in (
        f"https://{issuer_host}/.well-known/jwks.json",
        f"https://{issuer_host}/.well-known/openid-configuration",
    ):
        try:
            resp = requests.get(url, timeout=_JWKS_FETCH_TIMEOUT_SECONDS)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            continue
        if "keys" in data:
            _jwks_cache[issuer_host] = (time.time(), data)
            return data
        jwks_uri = data.get("jwks_uri")
        if jwks_uri:
            try:
                resp = requests.get(jwks_uri, timeout=_JWKS_FETCH_TIMEOUT_SECONDS)
                resp.raise_for_status()
                jwks = resp.json()
                _jwks_cache[issuer_host] = (time.time(), jwks)
                return jwks
            except Exception:
                continue
    return None


def verify_web_identity_token(token: str, provider) -> dict | None:
    """Verify ``token``'s signature and expiry against ``provider``'s JWKS.

    ``provider`` is a moto ``OpenIDConnectProvider`` (has ``.arn`` and
    ``.url``, the registered issuer host/path). Returns the decoded claims
    on success, or ``None`` on any verification failure (missing/invalid
    signature, expired, no reachable key) - the caller denies on ``None``.
    """
    try:
        unverified_header = pyjwt.get_unverified_header(token)
    except Exception:
        return None
    kid = unverified_header.get("kid")

    jwks = local_jwks_for_provider(provider.arn) or _fetch_real_jwks(provider.url)
    if not jwks:
        LOG.debug("No JWKS available (local or remote) for OIDC provider %s", provider.arn)
        return None

    matching_jwks = [k for k in jwks.get("keys", []) if k.get("kid") == kid] if kid else jwks.get("keys", [])
    if not matching_jwks and len(jwks.get("keys", [])) == 1:
        matching_jwks = jwks["keys"]
    if not matching_jwks:
        LOG.debug("No matching JWKS key (kid=%s) for OIDC provider %s", kid, provider.arn)
        return None

    for jwk in matching_jwks:
        try:
            public_key = pyjwt.PyJWK.from_dict(jwk).key
            return pyjwt.decode(
                token, public_key, algorithms=["RS256", "RS384", "RS512"],
                options={"verify_aud": False},
            )
        except Exception:
            continue
    return None
