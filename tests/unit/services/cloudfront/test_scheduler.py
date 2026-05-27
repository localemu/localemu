"""Unit tests for the CloudFront distribution deployment scheduler.

The scheduler is intentionally decoupled from moto — it takes a ``flip``
callback and a ``clock`` function — so every test here can drive time
deterministically without a background thread.
"""

from __future__ import annotations

import pytest

from localemu.services.cloudfront.scheduler import DeploymentScheduler


class FakeClock:
    """Monotonic clock under test control."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


def _make_scheduler(clock: FakeClock) -> tuple[DeploymentScheduler, list[tuple[str, str, str]]]:
    """Return a scheduler whose flip calls are captured in a list."""
    fires: list[tuple[str, str, str]] = []

    def _flip(dist_id: str, account_id: str, region: str) -> None:
        fires.append((dist_id, account_id, region))

    return DeploymentScheduler(flip=_flip, clock=clock), fires


class TestBasicScheduling:
    def test_fire_at_exact_target_time(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="000000000000",
            region="us-east-1", delay_seconds=5.0,
        )
        clock.advance(4.999)
        assert scheduler.tick() == 0
        assert fires == []
        clock.advance(0.001)
        assert scheduler.tick() == 1
        assert fires == [("E1", "000000000000", "us-east-1")]

    def test_fires_in_target_time_order(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E2", account_id="a", region="r", delay_seconds=10.0,
        )
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=5.0,
        )
        scheduler.schedule_deploy(
            distribution_id="E3", account_id="a", region="r", delay_seconds=20.0,
        )
        clock.advance(100.0)
        scheduler.tick()
        # Fires in target-time order regardless of schedule order
        assert [f[0] for f in fires] == ["E1", "E2", "E3"]

    def test_zero_delay_fires_immediately(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=0.0,
        )
        # No advance — still at clock=0
        assert scheduler.tick() == 1

    def test_negative_delay_clamped_to_zero(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=-100.0,
        )
        assert scheduler.tick() == 1


class TestSupersession:
    def test_second_schedule_for_same_distribution_supersedes_first(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=5.0,
        )
        # Before the first fires, schedule again — the first should be cancelled.
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=10.0,
        )
        clock.advance(6.0)
        assert scheduler.tick() == 0  # first entry is stale now
        clock.advance(5.0)
        assert scheduler.tick() == 1  # second entry fires
        assert fires == [("E1", "a", "r")]

    def test_distinct_distributions_do_not_interfere(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=5.0,
        )
        scheduler.schedule_deploy(
            distribution_id="E2", account_id="a", region="r", delay_seconds=5.0,
        )
        clock.advance(5.0)
        scheduler.tick()
        assert sorted(f[0] for f in fires) == ["E1", "E2"]

    def test_cancel_drops_pending_flip(self):
        clock = FakeClock()
        scheduler, fires = _make_scheduler(clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=5.0,
        )
        scheduler.cancel("E1", "a", "r")
        clock.advance(10.0)
        assert scheduler.tick() == 0
        assert fires == []


class TestFlipErrorHandling:
    def test_flip_exception_is_logged_not_raised(self, caplog):
        clock = FakeClock()

        def _raising_flip(*args, **kwargs):
            raise RuntimeError("moto backend exploded")

        scheduler = DeploymentScheduler(flip=_raising_flip, clock=clock)
        scheduler.schedule_deploy(
            distribution_id="E1", account_id="a", region="r", delay_seconds=1.0,
        )
        clock.advance(2.0)
        # Must not raise; logs an exception instead.
        import logging
        with caplog.at_level(logging.ERROR, logger="localemu.services.cloudfront.scheduler"):
            scheduler.tick()
        assert any("flip" in rec.message.lower() for rec in caplog.records)


class TestBackgroundWorker:
    """Light real-thread test to verify start/shutdown lifecycle."""

    def test_start_shutdown_is_clean(self):
        fires: list = []
        scheduler = DeploymentScheduler(
            flip=lambda *a: fires.append(a),
        )  # real clock
        scheduler.start()
        try:
            scheduler.schedule_deploy(
                distribution_id="E1", account_id="a", region="r", delay_seconds=0.0,
            )
            # Poll briefly for the flip to fire via the real worker.
            import time
            deadline = time.monotonic() + 2.0
            while not fires and time.monotonic() < deadline:
                time.sleep(0.01)
            assert fires, "flip callback did not fire within 2s"
        finally:
            scheduler.shutdown(timeout=2.0)
