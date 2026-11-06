"""Plux hook: wires the OIDC test-token-minting endpoint into the internal
API router at ``/_localemu/api/oidc/mint-token``.

Follows the same registration pattern as ``localemu.export.plugins:register``.
"""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def register_oidc_mint_token() -> None:
    """Register :class:`OidcMintTokenResource` on the internal APIs router."""
    try:
        from localemu.http import Resource
        from localemu.services.internal import get_internal_apis
        from localemu.services.sts.oidc_http_api import OidcMintTokenResource

        router = get_internal_apis()
        router.add(Resource("/_localemu/api/oidc/mint-token", OidcMintTokenResource()))
        LOG.info("LocalEmu OIDC test-token endpoint registered at /_localemu/api/oidc/mint-token")
    except Exception:
        LOG.error("Failed to register LocalEmu OIDC test-token endpoint", exc_info=True)


__all__ = ["register_oidc_mint_token"]
