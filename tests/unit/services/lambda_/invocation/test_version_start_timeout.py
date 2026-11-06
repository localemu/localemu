"""Regression test: a version whose ``prepare_version`` (Docker image
pull / runtime init) hangs past ``LAMBDA_VERSION_START_TIMEOUT_SECONDS``
must be forced to ``State.Failed`` with a clear reason, not left in
``Pending`` forever.

Root cause this guards: ``LambdaVersionManager.start()`` used to call
``prepare_version`` with no timeout at all - a slow/stuck docker pull
left the version (and therefore the function) stuck in Pending
indefinitely, which in turn made UpdateFunctionConfiguration fail
("cannot be updated if an old one is not running") with no way out.
"""

from __future__ import annotations

import time
import types
from unittest import mock

from localemu import config
from localemu.aws.api.lambda_ import State
from localemu.services.lambda_.invocation.version_manager import LambdaVersionManager


def _bare_manager() -> LambdaVersionManager:
    mgr = LambdaVersionManager.__new__(LambdaVersionManager)
    mgr.function_version = types.SimpleNamespace(
        qualified_arn="arn:aws:lambda:us-east-1:000000000000:function:f:$LATEST",
        config=types.SimpleNamespace(capacity_provider_config=None, internal_revision="rev1"),
        id=types.SimpleNamespace(qualifier="$LATEST"),
    )
    mgr.function_arn = mgr.function_version.qualified_arn
    mgr.log_handler = mock.Mock(start_subscriber=mock.Mock())
    return mgr


class TestVersionStartTimeout:
    def test_prepare_version_timeout_raises(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_VERSION_START_TIMEOUT_SECONDS", 0.2)
        mgr = _bare_manager()
        slow_executor = mock.Mock()
        slow_executor.prepare_version = lambda fv: time.sleep(2)
        monkeypatch.setattr(
            "localemu.services.lambda_.invocation.version_manager.get_runtime_executor",
            lambda: slow_executor,
        )

        start = time.monotonic()
        try:
            mgr._prepare_version_with_timeout()
            raised = False
        except TimeoutError:
            raised = True
        elapsed = time.monotonic() - start

        assert raised, "expected a TimeoutError, prepare_version hung past the ceiling"
        assert elapsed < 1.0, "must not wait for the full 2s hang"

    def test_start_moves_to_failed_on_timeout_not_stuck_pending(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_VERSION_START_TIMEOUT_SECONDS", 0.2)
        mgr = _bare_manager()
        slow_executor = mock.Mock()
        slow_executor.prepare_version = lambda fv: time.sleep(2)
        monkeypatch.setattr(
            "localemu.services.lambda_.invocation.version_manager.get_runtime_executor",
            lambda: slow_executor,
        )

        state = mgr.start()

        assert state.state == State.Failed
        assert "did not finish within" in (state.reason or "")

    def test_fast_prepare_still_reports_active(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_VERSION_START_TIMEOUT_SECONDS", 5.0)
        mgr = _bare_manager()
        fast_executor = mock.Mock()
        fast_executor.prepare_version = lambda fv: None
        monkeypatch.setattr(
            "localemu.services.lambda_.invocation.version_manager.get_runtime_executor",
            lambda: fast_executor,
        )

        state = mgr.start()

        assert state.state == State.Active

    def test_zero_disables_ceiling_waits_for_real_completion(self, monkeypatch):
        monkeypatch.setattr(config, "LAMBDA_VERSION_START_TIMEOUT_SECONDS", 0)
        mgr = _bare_manager()
        calls = []
        fast_executor = mock.Mock()
        fast_executor.prepare_version = lambda fv: calls.append(1)
        monkeypatch.setattr(
            "localemu.services.lambda_.invocation.version_manager.get_runtime_executor",
            lambda: fast_executor,
        )

        mgr._prepare_version_with_timeout()

        assert calls == [1]
