"""Unit tests for the dashboard's write-action CSRF/Origin gate.

Covers the fix for the reported gap: EXTRA_CORS_ALLOWED_ORIGINS (the same
env var the global CORS enforcer already honors) is now also respected
here, so a custom hostname / reverse proxy only needs to be allow-listed
once, not via two separate, inconsistently-documented mechanisms.
"""
from __future__ import annotations

from types import SimpleNamespace

from localemu.dashboard.plugins import _dashboard_origin_ok


def _req(origin: str | None):
    headers = {"Origin": origin} if origin else {}
    return SimpleNamespace(headers=headers)


def test_no_origin_header_is_allowed():
    """Not a browser fetch (curl, CLI) - nothing to check."""
    assert _dashboard_origin_ok(_req(None)) is True


def test_loopback_origin_is_allowed():
    assert _dashboard_origin_ok(_req("http://localhost:4566")) is True
    assert _dashboard_origin_ok(_req("http://127.0.0.1:4566")) is True


def test_arbitrary_origin_is_rejected_by_default():
    assert _dashboard_origin_ok(_req("http://my.domain:4567")) is False


def test_extra_cors_allowed_origins_unblocks_custom_hostname(monkeypatch):
    monkeypatch.setenv("EXTRA_CORS_ALLOWED_ORIGINS", "http://my.domain:4567")
    assert _dashboard_origin_ok(_req("http://my.domain:4567")) is True


def test_extra_cors_allowed_origins_is_comma_separated(monkeypatch):
    monkeypatch.setenv(
        "EXTRA_CORS_ALLOWED_ORIGINS", "http://a.example:1,http://my.domain:4567,http://b.example:2",
    )
    assert _dashboard_origin_ok(_req("http://my.domain:4567")) is True


def test_extra_cors_allowed_origins_does_not_allow_unlisted_hosts(monkeypatch):
    monkeypatch.setenv("EXTRA_CORS_ALLOWED_ORIGINS", "http://my.domain:4567")
    assert _dashboard_origin_ok(_req("http://evil.example")) is False


def test_matching_is_by_hostname_not_full_origin_string(monkeypatch):
    """A different scheme/port on the same host still matches - this gate
    cares about the hostname being trusted, same granularity the global
    CORS enforcer's EXTRA_CORS_ALLOWED_ORIGINS is documented to provide."""
    monkeypatch.setenv("EXTRA_CORS_ALLOWED_ORIGINS", "http://my.domain:4567")
    assert _dashboard_origin_ok(_req("https://my.domain:9999")) is True
