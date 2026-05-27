"""Unit tests for the export HTTP endpoint.

The endpoint lives at ``/_localemu/api/export`` and is intentionally
restrictive: secrets may only be requested from localhost and with an
auth token. Tests here pin the contract.
"""

from __future__ import annotations

import importlib

import pytest


def _load_export_resource():
    for candidate in (
        "localemu.export.http_api",
        "localemu.http.export",
        "localemu.dashboard.export",
    ):
        try:
            mod = importlib.import_module(candidate)
        except ImportError:
            continue
        for name in ("ExportResource", "export_resource", "resource", "bp"):
            r = getattr(mod, name, None)
            if r is not None:
                return r, mod
    pytest.skip("ExportResource not present yet")


def _build_test_client(resource_obj) -> "object":
    """Wrap ``resource_obj`` in a Werkzeug test client.

    We try several common shapes: a Flask app, a Werkzeug WSGI callable,
    or a bare resource class we can attach to a minimal app.
    """
    werkzeug = pytest.importorskip("werkzeug")
    from werkzeug.test import Client
    from werkzeug.wrappers import Response

    # Flask app?
    if hasattr(resource_obj, "wsgi_app") or hasattr(resource_obj, "test_client"):
        return resource_obj.test_client()
    # WSGI callable directly?
    if callable(resource_obj):
        return Client(resource_obj, Response)
    pytest.skip("unable to build a test client for the export resource")


@pytest.fixture
def http_client():
    resource_obj, _mod = _load_export_resource()
    return _build_test_client(resource_obj)


def test_json_format_ok(http_client) -> None:
    resp = http_client.get("/_localemu/api/export?format=json")
    # Accept 200 OK; the body should be JSON-ish.
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_data(as_text=True)
    assert body.lstrip().startswith("{") or body.lstrip().startswith("[")


def test_invalid_format_returns_400(http_client) -> None:
    resp = http_client.get("/_localemu/api/export?format=nosuch")
    assert resp.status_code == 400


def test_secrets_without_auth_forbidden(http_client) -> None:
    resp = http_client.get("/_localemu/api/export?format=json&include_secrets=true")
    assert resp.status_code == 403


def test_secrets_with_auth_allowed(http_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALEMU_EXPORT_AUTH_TOKEN", "test-token")
    resp = http_client.get(
        "/_localemu/api/export?format=json&include_secrets=true",
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200


def test_secrets_non_loopback_denied(http_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALEMU_EXPORT_AUTH_TOKEN", "t")
    resp = http_client.get(
        "/_localemu/api/export?format=json&include_secrets=true",
        headers={"Authorization": "Bearer t", "X-Forwarded-For": "8.8.8.8"},
        environ_overrides={"REMOTE_ADDR": "8.8.8.8"},
    )
    assert resp.status_code == 403


def test_content_type_json(http_client) -> None:
    resp = http_client.get("/_localemu/api/export?format=json")
    assert resp.status_code == 200
    ctype = resp.headers.get("Content-Type", "")
    assert "json" in ctype.lower()


def test_content_disposition_attachment(http_client) -> None:
    resp = http_client.get("/_localemu/api/export?format=json")
    disp = resp.headers.get("Content-Disposition", "")
    # A downloadable attachment is the UX contract.
    assert "attachment" in disp.lower() or "filename" in disp.lower()
