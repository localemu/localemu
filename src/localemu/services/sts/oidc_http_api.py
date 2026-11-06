"""HTTP endpoint for minting a locally-verifiable test token for a
registered OIDC provider. Mounted by :mod:`localemu.services.sts.plugins`
at ``/_localemu/api/oidc/mint-token``.

LocalEmu-only testing convenience (see ``oidc_local.mint_test_token`` for
why this exists): a security lab can register a role that trusts a real
external OIDC provider (e.g. ``token.actions.githubusercontent.com``) and
then get a token that passes real verification against LocalEmu's own records for
that provider, without needing a real workflow run at the real provider.
"""

from __future__ import annotations

import logging

from localemu.http import Response

LOG = logging.getLogger(__name__)


def _error(code: str, message: str, status: int) -> Response:
    resp = Response()
    resp.status_code = status
    resp.set_json({"error": code, "message": message})
    return resp


class OidcMintTokenResource:
    """``POST /_localemu/api/oidc/mint-token``.

    Request body: ``{"provider_arn": "...", "claims": {"sub": "...", ...}}``.
    Response body: ``{"token": "<jwt>"}``.
    """

    def on_post(self, request):
        try:
            body = request.get_json(force=True) or {}
        except Exception:
            return _error("invalid_json", "Body must be valid JSON.", 400)

        provider_arn = body.get("provider_arn")
        claims = body.get("claims")
        if not provider_arn or not isinstance(claims, dict):
            return _error(
                "invalid_request",
                "'provider_arn' (string) and 'claims' (object) are required.",
                400,
            )

        try:
            from localemu.services.sts.oidc_local import mint_test_token

            token = mint_test_token(provider_arn, claims)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the caller
            LOG.error("OIDC test-token minting failed", exc_info=True)
            return _error("internal_error", f"Minting failed: {type(exc).__name__}", 500)

        return {"token": token}
