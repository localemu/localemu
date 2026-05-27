"""PipeWorker — lifecycle transitions on create/start/stop/delete."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.aws.api.pipes import PipeState
from localemu.services.pipes.pipe_worker import PipeWorker


def _fake_poller():
    p = MagicMock()
    # Hand the worker an immediately-empty poll so the loop spends
    # negligible time inside poll_events before yielding to the shutdown
    # event.
    from localemu.services.lambda_.event_source_mapping.pollers.poller import (
        EmptyPollResultsException,
    )

    p.poll_events.side_effect = EmptyPollResultsException(
        service="sqs", source_arn="arn:aws:sqs:us-east-1:000000000000:q",
    )
    return p


def _worker(desired_running: bool = True) -> PipeWorker:
    return PipeWorker(
        pipe_arn="arn:aws:pipes:us-east-1:000000000000:pipe/p",
        pipe_name="p",
        account_id="000000000000",
        region="us-east-1",
        poller=_fake_poller(),
        desired_running=desired_running,
    )


class TestCreate:
    def test_create_with_desired_running_starts_poller(self):
        worker = _worker(desired_running=True)
        with patch.object(worker, "_sync_state_to_moto"):
            worker.create()
            assert worker._poller_thread is not None
            assert worker._poller_thread.is_alive()
            worker.stop()

    def test_create_with_stopped_does_not_start_poller(self):
        worker = _worker(desired_running=False)
        with patch.object(worker, "_sync_state_to_moto"):
            worker.create()
            assert worker._poller_thread is None
            assert worker.current_state == PipeState.STOPPED


class TestStop:
    def test_stop_transitions_to_stopped(self):
        worker = _worker(desired_running=True)
        with patch.object(worker, "_sync_state_to_moto"):
            worker.create()
            worker.stop()
        assert worker.current_state == PipeState.STOPPED
        assert worker.desired_running is False


class TestStartIdempotent:
    def test_double_start_does_not_spawn_two_threads(self):
        """Hold the poller's first call so the thread stays alive for the
        duration of the second start; that's the only race condition the
        idempotency guard is supposed to protect against."""
        import threading
        from localemu.services.lambda_.event_source_mapping.pollers.poller import (
            EmptyPollResultsException,
        )

        block = threading.Event()
        called = threading.Event()

        def slow_poll():
            called.set()
            block.wait(timeout=2.0)
            raise EmptyPollResultsException(
                service="sqs",
                source_arn="arn:aws:sqs:us-east-1:000000000000:q",
            )

        worker = _worker(desired_running=True)
        worker.poller.poll_events.side_effect = slow_poll
        with patch.object(worker, "_sync_state_to_moto"):
            worker.start()
            assert called.wait(timeout=2.0), "first poll never ran"
            first_thread = worker._poller_thread
            worker.start()  # second start while the first is alive
            assert worker._poller_thread is first_thread
            block.set()
            worker.stop()


class TestDelete:
    def test_delete_signals_shutdown_and_marks_state(self):
        worker = _worker(desired_running=True)
        with patch.object(worker, "_sync_state_to_moto"):
            worker.start()
            worker.delete()
        assert worker.current_state == PipeState.DELETING
        assert worker._shutdown_event.is_set()
