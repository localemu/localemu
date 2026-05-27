"""PipeManager singleton — registration, removal, stop_all."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from localemu.services.pipes.pipe_manager import (
    PipeManager,
    _reset_singleton_for_tests,
)


@pytest.fixture(autouse=True)
def _isolate():
    _reset_singleton_for_tests()
    yield
    _reset_singleton_for_tests()


def _mock_worker(arn: str = "arn:aws:pipes:us-east-1:000000000000:pipe/p1"):
    w = MagicMock()
    w.pipe_arn = arn
    return w


class TestPipeManager:
    def test_singleton_returns_same_instance(self):
        a = PipeManager.instance()
        b = PipeManager.instance()
        assert a is b

    def test_register_get_remove(self):
        mgr = PipeManager.instance()
        worker = _mock_worker()
        mgr.register(worker)
        assert mgr.get(worker.pipe_arn) is worker
        assert mgr.remove(worker.pipe_arn) is worker
        assert mgr.get(worker.pipe_arn) is None

    def test_remove_missing_returns_none(self):
        assert PipeManager.instance().remove("nope") is None

    def test_register_replaces_and_stops_existing(self):
        mgr = PipeManager.instance()
        old = _mock_worker()
        new = _mock_worker()
        mgr.register(old)
        mgr.register(new)
        old.stop.assert_called_once()
        assert mgr.get(old.pipe_arn) is new

    def test_register_same_object_does_not_stop_itself(self):
        mgr = PipeManager.instance()
        worker = _mock_worker()
        mgr.register(worker)
        mgr.register(worker)  # idempotent
        worker.stop.assert_not_called()

    def test_stop_all_drains_registry(self):
        mgr = PipeManager.instance()
        w1 = _mock_worker("arn:aws:pipes:us-east-1:000000000000:pipe/a")
        w2 = _mock_worker("arn:aws:pipes:us-east-1:000000000000:pipe/b")
        mgr.register(w1)
        mgr.register(w2)
        mgr.stop_all()
        w1.stop.assert_called_once()
        w2.stop.assert_called_once()
        assert mgr.all() == []
