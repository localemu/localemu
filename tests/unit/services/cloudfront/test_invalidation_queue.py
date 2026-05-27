"""Unit tests for the CloudFront invalidation completion queue."""

from __future__ import annotations

from localemu.services.cloudfront.invalidation_queue import InvalidationQueue


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


def _make_queue(clock: FakeClock):
    """Return a queue plus captured set_status / purge callbacks."""
    status_log: list[tuple] = []
    purge_log: list[tuple] = []

    def _set_status(acct, region, dist_id, inv_id, status):
        status_log.append((acct, region, dist_id, inv_id, status))

    def _purge(acct, region, dist_id, paths):
        purge_log.append((acct, region, dist_id, tuple(paths)))

    queue = InvalidationQueue(
        set_status=_set_status, purge=_purge, clock=clock,
    )
    return queue, status_log, purge_log


class TestEnqueue:
    def test_enqueue_marks_in_progress_immediately(self):
        clock = FakeClock()
        queue, status_log, _ = _make_queue(clock)
        queue.enqueue(
            account_id="a", region="us-east-1",
            distribution_id="E1", invalidation_id="I1",
            paths=["/*"], delay_seconds=5.0,
        )
        assert status_log == [("a", "us-east-1", "E1", "I1", "InProgress")]

    def test_completion_fires_after_delay(self):
        clock = FakeClock()
        queue, status_log, _ = _make_queue(clock)
        queue.enqueue(
            account_id="a", region="us-east-1",
            distribution_id="E1", invalidation_id="I1",
            paths=["/images/*"], delay_seconds=5.0,
        )
        clock.advance(4.999)
        assert queue.tick() == 0
        clock.advance(0.001)
        assert queue.tick() == 1
        # Two set_status calls: InProgress at enqueue, Completed at tick
        statuses = [entry[-1] for entry in status_log]
        assert statuses == ["InProgress", "Completed"]

    def test_purge_callback_fires_before_completed_flip(self):
        clock = FakeClock()
        order: list[str] = []

        def _set_status(acct, region, dist_id, inv_id, status):
            order.append(f"status:{status}")

        def _purge(acct, region, dist_id, paths):
            order.append(f"purge:{list(paths)}")

        q = InvalidationQueue(
            set_status=_set_status, purge=_purge, clock=clock,
        )
        q.enqueue(
            account_id="a", region="r", distribution_id="E1", invalidation_id="I1",
            paths=["/*"], delay_seconds=1.0,
        )
        clock.advance(1.0)
        q.tick()
        # Purge must precede Completed so cache is empty before any client
        # observing Completed does a GetObject expecting fresh content.
        assert order == ["status:InProgress", "purge:['/*']", "status:Completed"]


class TestDefaultPurge:
    def test_absent_purge_is_noop(self):
        clock = FakeClock()
        status_log: list = []

        queue = InvalidationQueue(
            set_status=lambda *a: status_log.append(a),
            purge=None,
            clock=clock,
        )
        queue.enqueue(
            account_id="a", region="r", distribution_id="E1", invalidation_id="I1",
            paths=["/*"], delay_seconds=0.0,
        )
        assert queue.tick() == 1
        # No crash; only InProgress + Completed status calls observed.
        assert [s[-1] for s in status_log] == ["InProgress", "Completed"]


class TestErrorResilience:
    def test_purge_exception_still_marks_completed(self, caplog):
        clock = FakeClock()
        status_log: list = []

        def _purge(*args, **kwargs):
            raise RuntimeError("cache layer exploded")

        queue = InvalidationQueue(
            set_status=lambda *a: status_log.append(a),
            purge=_purge, clock=clock,
        )
        queue.enqueue(
            account_id="a", region="r", distribution_id="E1", invalidation_id="I1",
            paths=["/*"], delay_seconds=0.0,
        )
        import logging
        with caplog.at_level(logging.ERROR,
                             logger="localemu.services.cloudfront.invalidation_queue"):
            queue.tick()
        # Even though purge raised, status must flip to Completed so the user
        # polling `wait invalidation-completed` is not stuck forever.
        assert [s[-1] for s in status_log] == ["InProgress", "Completed"]
        assert any("purge" in rec.message.lower() for rec in caplog.records)

    def test_set_status_exception_on_completed_is_logged(self, caplog):
        clock = FakeClock()

        def _set_status(acct, region, dist_id, inv_id, status):
            if status == "Completed":
                raise RuntimeError("backend vanished")

        queue = InvalidationQueue(
            set_status=_set_status, purge=None, clock=clock,
        )
        queue.enqueue(
            account_id="a", region="r", distribution_id="E1", invalidation_id="I1",
            paths=["/*"], delay_seconds=0.0,
        )
        import logging
        with caplog.at_level(logging.ERROR,
                             logger="localemu.services.cloudfront.invalidation_queue"):
            # Swallows the exception — no raise propagated
            queue.tick()
        assert any("Completed" in rec.message for rec in caplog.records)


class TestBackgroundWorker:
    def test_start_shutdown_is_clean(self):
        status_log: list = []
        queue = InvalidationQueue(
            set_status=lambda *a: status_log.append(a),
        )
        queue.start()
        try:
            queue.enqueue(
                account_id="a", region="r", distribution_id="E1",
                invalidation_id="I1", paths=["/*"],
                delay_seconds=0.0,
            )
            import time
            deadline = time.monotonic() + 2.0
            while len(status_log) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(status_log) >= 2
            assert status_log[-1][-1] == "Completed"
        finally:
            queue.shutdown(timeout=2.0)
