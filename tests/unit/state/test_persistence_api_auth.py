"""Auth-gating tests for the ``/_localemu/state/*`` REST endpoints.

The state save/load/status endpoints used to accept any caller, so
an attacker who could reach the LocalEmu gateway (which inside a
Docker container binds to 0.0.0.0:4566 by default) could wipe every
backend's state via a single POST. The gating logic now requires
either a loopback origin or explicit ``PERSISTENCE_API_OPEN=1`` opt-in.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from localemu.dashboard.plugins import (
    _is_loopback_request,
    _persistence_api_enabled,
)


def _req(remote_addr: str | None) -> SimpleNamespace:
    return SimpleNamespace(remote_addr=remote_addr)


class TestIsLoopbackRequest:
    @pytest.mark.parametrize("addr", ["127.0.0.1", "127.0.0.5", "::1"])
    def test_loopback_addresses_are_trusted(self, addr):
        assert _is_loopback_request(_req(addr)) is True

    @pytest.mark.parametrize(
        "addr",
        [
            "10.0.0.5",
            "192.168.1.100",
            "172.17.0.2",  # default Docker bridge address space
            "203.0.113.7",  # TEST-NET-3
            "2001:db8::1",
        ],
    )
    def test_non_loopback_addresses_are_rejected(self, addr):
        assert _is_loopback_request(_req(addr)) is False

    @pytest.mark.parametrize("addr", [None, "", "   ", "not-an-ip"])
    def test_missing_or_malformed_addr_is_rejected(self, addr):
        assert _is_loopback_request(_req(addr)) is False


class TestPersistenceApiEnabled:
    def test_loopback_accepted_without_env_var(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        assert _persistence_api_enabled(_req("127.0.0.1")) is True

    def test_remote_rejected_without_env_var(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        assert _persistence_api_enabled(_req("203.0.113.7")) is False

    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE"])
    def test_remote_accepted_when_opt_in(self, monkeypatch, value):
        monkeypatch.setenv("PERSISTENCE_API_OPEN", value)
        assert _persistence_api_enabled(_req("203.0.113.7")) is True

    @pytest.mark.parametrize("value", ["0", "false", "no", ""])
    def test_remote_still_rejected_for_falsy_opt_in(self, monkeypatch, value):
        monkeypatch.setenv("PERSISTENCE_API_OPEN", value)
        assert _persistence_api_enabled(_req("10.0.0.5")) is False


class TestEndpointGating:
    """End-to-end-ish: exercise the resource classes that
    :func:`_register_persistence_endpoints` builds, confirming each one
    short-circuits with a 403 when the caller isn't authorized."""

    def _build_resources(self):
        from localemu.dashboard import plugins

        captured = []

        class _RecordingRouter:
            def add(self, resource):
                captured.append(resource)

        plugins._register_persistence_endpoints(_RecordingRouter())
        # save, load, status
        return captured

    def test_save_endpoint_rejects_remote_caller(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        save_res, _load, _status = self._build_resources()
        resp = save_res.obj.on_post(_req("203.0.113.7"))
        assert resp.status_code == 403

    def test_load_endpoint_rejects_remote_caller(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        _save, load_res, _status = self._build_resources()
        resp = load_res.obj.on_post(_req("203.0.113.7"))
        assert resp.status_code == 403

    def test_status_endpoint_rejects_remote_caller(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        _save, _load, status_res = self._build_resources()
        resp = status_res.obj.on_get(_req("203.0.113.7"))
        assert resp.status_code == 403

    def test_save_endpoint_runs_for_loopback_caller(self, monkeypatch):
        monkeypatch.delenv("PERSISTENCE_API_OPEN", raising=False)
        save_res, _load, _status = self._build_resources()
        with patch("localemu.state.persistence.SaveOrchestrator") as mock_orch:
            mock_orch.return_value.save.return_value = {"saved": ["s3"]}
            resp = save_res.obj.on_post(_req("127.0.0.1"))
        assert resp.status_code == 200
        mock_orch.return_value.save.assert_called_once()
