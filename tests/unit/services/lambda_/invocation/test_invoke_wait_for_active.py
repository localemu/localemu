"""Regression tests for the Pending -> Active wait in lambda_service.invoke.

The provider used to fail any Invoke that arrived while the function was
still in Pending state, which made back-to-back create-function/invoke
scripts brittle (the typical ~300 ms warm-up is enough to race).

The fix wraps the version-manager lookup in a short polling loop bounded
by ``LAMBDA_INVOKE_WAIT_FOR_ACTIVE_SECONDS`` (default 5 s; 0 disables and
restores strict AWS-parity behavior).
"""

from __future__ import annotations

import time
import types
from unittest import mock

from localemu import config
from localemu.aws.api.lambda_ import State
from localemu.services.lambda_.invocation.lambda_service import LambdaService


def _service_with(version_manager_appears_after: float | None):
    """Build a minimal LambdaService stub.

    ``version_manager_appears_after`` controls when the in-memory version
    manager "registers": ``None`` means never (deadline must expire);
    otherwise the lookup succeeds after this many seconds.
    """
    service = LambdaService.__new__(LambdaService)
    t0: dict[str, float] = {}
    mgr = mock.Mock(name="version_manager")
    em = mock.Mock(name="event_manager")

    def get_version(arn):
        t0.setdefault("t", time.monotonic())
        if (
            version_manager_appears_after is not None
            and time.monotonic() - t0["t"] >= version_manager_appears_after
        ):
            return mgr
        raise ValueError(f"Could not find version '{arn}'")

    service.get_lambda_version_manager = get_version  # type: ignore[attr-defined]
    service.get_lambda_event_manager = lambda arn: em  # type: ignore[attr-defined]
    return service, mgr, em


def _function_in_state(state: State):
    cfg = types.SimpleNamespace(state=types.SimpleNamespace(state=state))
    version = types.SimpleNamespace(config=cfg)
    return types.SimpleNamespace(versions={"$LATEST": version})


class TestAwaitActiveVersionManager:
    def test_returns_manager_when_pending_clears_within_deadline(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_INVOKE_WAIT_FOR_ACTIVE_SECONDS", 2.0)
        service, mgr, em = _service_with(version_manager_appears_after=0.2)
        function = _function_in_state(State.Pending)
        vm, ev, state, err = service._await_active_version_manager(
            "arn:lambda:fn", function, "$LATEST"
        )
        assert err is None
        assert vm is mgr and ev is em

    def test_raises_after_deadline_when_still_pending(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_INVOKE_WAIT_FOR_ACTIVE_SECONDS", 0.2)
        service, *_ = _service_with(version_manager_appears_after=None)
        function = _function_in_state(State.Pending)
        vm, ev, state, err = service._await_active_version_manager(
            "arn:lambda:fn", function, "$LATEST"
        )
        assert err is not None
        assert state == State.Pending
        assert vm is None and ev is None

    def test_zero_disables_wait_for_strict_aws_parity(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_INVOKE_WAIT_FOR_ACTIVE_SECONDS", 0.0)
        # Would succeed in 500ms if we waited; should not.
        service, *_ = _service_with(version_manager_appears_after=0.5)
        function = _function_in_state(State.Pending)
        t0 = time.monotonic()
        vm, ev, state, err = service._await_active_version_manager(
            "arn:lambda:fn", function, "$LATEST"
        )
        assert err is not None
        assert time.monotonic() - t0 < 0.1

    def test_fails_fast_when_state_is_failed(self, monkeypatch):
        # Failed should bypass the wait entirely (Docker missing, etc.).
        monkeypatch.setattr(config, "LAMBDA_INVOKE_WAIT_FOR_ACTIVE_SECONDS", 5.0)
        service, *_ = _service_with(version_manager_appears_after=None)
        function = _function_in_state(State.Failed)
        t0 = time.monotonic()
        vm, ev, state, err = service._await_active_version_manager(
            "arn:lambda:fn", function, "$LATEST"
        )
        assert err is not None
        assert state == State.Failed
        assert time.monotonic() - t0 < 0.5
