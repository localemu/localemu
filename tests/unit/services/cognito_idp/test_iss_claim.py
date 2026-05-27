"""Cognito JWT ``iss`` claim must respect LOCALEMU_HOST.

The issuer URL is what JWT verifiers fetch the JWKS from. Hardcoding
``http://localhost:4566`` breaks every verifier that runs anywhere other
than the same loopback interface as LocalEmu — Lambda containers reaching
LocalEmu through ``host.docker.internal``, API tests running on a CI
runner that talks to a docker-compose service name, etc.

The fix threads :func:`localemu.config.external_service_url` through both
``tokens.generate_{id,access}_token`` and the ``/.well-known/openid-
configuration`` document, so iss + jwks_uri stay consistent and remain
fetchable from the same network position as the JWT consumer.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest

from localemu.services.cognito_idp import tokens
from localemu.services.cognito_idp.keys import generate_key_pair


@pytest.fixture(scope="module")
def keypair():
    return generate_key_pair()


class TestIssClaim:
    def test_default_localhost(self, keypair, monkeypatch):
        # default LOCALEMU_HOST resolves to localhost:4566 — the iss must
        # remain compatible with the historical value when no override.
        monkeypatch.delenv("LOCALEMU_HOST", raising=False)
        from localemu import config as _lemu_config

        expected_base = _lemu_config.external_service_url()
        token = tokens.generate_id_token(
            pool_id="us-east-1_abc123",
            region="us-east-1",
            client_id="client-foo",
            username="alice",
            sub="00000000-0000-0000-0000-000000000001",
            private_key=keypair[0],
            kid="kid-1",
        )
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert claims["iss"] == f"{expected_base}/us-east-1_abc123"

    def test_iss_honors_external_service_url_override(self, keypair, monkeypatch):
        # Simulate a deployment where the gateway is reachable as
        # https://localemu.dev.example.com on a non-default port — that
        # value MUST end up in the iss claim, else off-host verifiers fail.
        import localemu.config as _lemu_config

        monkeypatch.setattr(
            _lemu_config,
            "external_service_url",
            lambda *a, **kw: "https://localemu.dev.example.com:8443",
        )
        token = tokens.generate_id_token(
            pool_id="us-east-1_pool",
            region="us-east-1",
            client_id="client-bar",
            username="bob",
            sub="00000000-0000-0000-0000-000000000002",
            private_key=keypair[0],
            kid="kid-2",
        )
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert claims["iss"] == "https://localemu.dev.example.com:8443/us-east-1_pool"

    def test_access_token_iss_matches_id_token_iss(self, keypair, monkeypatch):
        import localemu.config as _lemu_config

        monkeypatch.setattr(
            _lemu_config,
            "external_service_url",
            lambda *a, **kw: "http://cognito-le.test:4566",
        )
        id_tok = tokens.generate_id_token(
            pool_id="us-east-1_match",
            region="us-east-1",
            client_id="c",
            username="u",
            sub="s",
            private_key=keypair[0],
            kid="k",
        )
        access_tok = tokens.generate_access_token(
            pool_id="us-east-1_match",
            region="us-east-1",
            client_id="c",
            username="u",
            sub="s",
            private_key=keypair[0],
            kid="k",
        )
        id_iss = pyjwt.decode(id_tok, options={"verify_signature": False})["iss"]
        ac_iss = pyjwt.decode(access_tok, options={"verify_signature": False})["iss"]
        assert id_iss == ac_iss == "http://cognito-le.test:4566/us-east-1_match"
