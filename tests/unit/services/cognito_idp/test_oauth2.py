"""Unit tests for the Cognito OAuth2 / hosted-UI helpers (no server)."""

from __future__ import annotations

import time

import pytest

from localemu.services.cognito_idp import oauth2


@pytest.fixture(autouse=True)
def _clear_codes():
    oauth2._auth_codes.clear()
    yield
    oauth2._auth_codes.clear()


class FakeUser:
    def __init__(self, password="New-Pass-1!", status="CONFIRMED"):
        self.password = password
        self.status = status
        self.attributes = [{"Name": "email", "Value": "u@example.com"}]


class FakePool:
    def __init__(self, users=None):
        self.users = users or {"alice": FakeUser()}


def test_code_issue_and_consume_once():
    code = oauth2._issue_code({"username": "alice"})
    data = oauth2._consume_code(code)
    assert data["username"] == "alice"
    # second consume fails (single-use)
    assert oauth2._consume_code(code) is None


def test_expired_code_rejected():
    code = oauth2._issue_code({"username": "alice"})
    oauth2._auth_codes[code]["exp"] = time.time() - 1  # force expiry
    assert oauth2._consume_code(code) is None


def test_validate_credentials():
    pool = FakePool()
    assert oauth2._validate_credentials(pool, "alice", "New-Pass-1!") is True
    assert oauth2._validate_credentials(pool, "alice", "wrong") is False
    assert oauth2._validate_credentials(pool, "ghost", "x") is False


def test_validate_credentials_requires_confirmed():
    pool = FakePool(users={"bob": FakeUser(status="UNCONFIRMED")})
    assert oauth2._validate_credentials(pool, "bob", "New-Pass-1!") is False


def test_token_response_shape():
    result = {
        "AccessToken": "a",
        "IdToken": "i",
        "RefreshToken": "r",
        "ExpiresIn": 3600,
    }
    body = oauth2._token_response(result, scope="openid email")
    assert body["access_token"] == "a"
    assert body["id_token"] == "i"
    assert body["refresh_token"] == "r"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "openid email"


def test_login_page_renders_hidden_fields():
    resp = oauth2._render_login(
        {"client_id": "cli", "redirect_uri": "https://app/cb",
         "response_type": "code", "scope": "openid", "state": "xyz"}
    )
    body = resp.get_data(as_text=True) if hasattr(resp, "get_data") else str(resp.response)
    assert 'name="client_id" value="cli"' in body
    assert 'name="redirect_uri" value="https://app/cb"' in body
    assert 'name="state" value="xyz"' in body
    assert "<form" in body and "password" in body
