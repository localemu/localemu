"""SchedulerJobScheduler — registry mutations, polling tick, lifecycle.

The polling loop is timing-sensitive so we drive it deterministically
in tests by calling ``_tick`` directly rather than waiting on the
background thread. Each test resets the process-wide singleton via
``_reset_singleton_for_tests`` to keep state isolation tight.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.scheduler.job_scheduler import (
    ScheduledJob,
    SchedulerJobScheduler,
    _reset_singleton_for_tests,
)


@pytest.fixture(autouse=True)
def _isolate():
    _reset_singleton_for_tests()
    yield
    _reset_singleton_for_tests()


def _fake_schedule(
    *,
    name: str = "s1",
    group_name: str = "default",
    expression: str = "rate(30 seconds)",
    tz: str = "UTC",
    target_arn: str = "arn:aws:lambda:us-east-1:000000000000:function:foo",
    state: str = "ENABLED",
    action: str = "NONE",
    flex_minutes: int = 0,
    start_date=None,
    end_date=None,
) -> SimpleNamespace:
    """Mock the subset of moto's ``Schedule`` attributes the job
    scheduler reads. Using SimpleNamespace keeps tests independent of
    moto internals — when moto changes its constructor signature, we
    don't have to chase it through every test."""
    flex = (
        {"Mode": "FLEXIBLE", "MaximumWindowInMinutes": flex_minutes}
        if flex_minutes > 0
        else {"Mode": "OFF"}
    )
    arn = f"arn:aws:scheduler:us-east-1:000000000000:schedule/{group_name}/{name}"
    return SimpleNamespace(
        arn=arn,
        name=name,
        group_name=group_name,
        schedule_expression=expression,
        schedule_expression_timezone=tz,
        target={
            "Arn": target_arn,
            "RoleArn": "arn:aws:iam::000000000000:role/r",
        },
        state=state,
        flexible_time_window=flex,
        action_after_completion=action,
        start_date=start_date,
        end_date=end_date,
    )


class TestAddRemove:
    def test_add_registers_and_computes_next_fire(self):
        scheduler = SchedulerJobScheduler.instance()
        sched = _fake_schedule(expression="rate(5 minutes)")
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        assert sched.arn in scheduler._jobs
        job = scheduler._jobs[sched.arn]
        assert job.next_fire is not None
        assert job.next_fire > datetime.now(timezone.utc)

    def test_remove_clears_registration(self):
        scheduler = SchedulerJobScheduler.instance()
        sched = _fake_schedule()
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        scheduler.remove_schedule(sched.arn)
        assert sched.arn not in scheduler._jobs

    def test_remove_group_clears_only_matching_schedules(self):
        scheduler = SchedulerJobScheduler.instance()
        keep = _fake_schedule(name="keeper", group_name="keep")
        drop1 = _fake_schedule(name="d1", group_name="drop")
        drop2 = _fake_schedule(name="d2", group_name="drop")
        for sched in (keep, drop1, drop2):
            scheduler.add_schedule(sched, "000000000000", "us-east-1")
        scheduler.remove_group("000000000000", "us-east-1", "drop")
        assert keep.arn in scheduler._jobs
        assert drop1.arn not in scheduler._jobs
        assert drop2.arn not in scheduler._jobs


class TestTickDispatch:
    """The tick logic must:
        * pick only ENABLED schedules whose next_fire is in the past
        * skip currently_dispatching ones (re-entry guard)
        * submit each to the executor exactly once
    """

    def test_due_schedule_is_dispatched_exactly_once(self):
        scheduler = SchedulerJobScheduler.instance()
        scheduler._ensure_running()
        sched = _fake_schedule(expression="rate(10 seconds)")
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        # Pull next_fire into the past so the tick selects it.
        job.next_fire = datetime.now(timezone.utc) - timedelta(seconds=1)

        with patch("localemu.services.scheduler.target_invoker.invoke") as mock_invoke:
            scheduler._tick()
            # Dispatch is async on the executor — wait for completion.
            scheduler._executor.shutdown(wait=True)
            scheduler._executor = None  # avoid the shutdown double-up

        assert mock_invoke.call_count == 1
        kw = mock_invoke.call_args.kwargs
        assert kw["schedule_arn"] == sched.arn
        assert kw["account_id"] == "000000000000"
        assert kw["region"] == "us-east-1"

    def test_disabled_schedule_is_not_dispatched(self):
        scheduler = SchedulerJobScheduler.instance()
        scheduler._ensure_running()
        sched = _fake_schedule(state="DISABLED")
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        job.next_fire = datetime.now(timezone.utc) - timedelta(seconds=1)

        with patch("localemu.services.scheduler.target_invoker.invoke") as mock_invoke:
            scheduler._tick()
            scheduler._executor.shutdown(wait=True)
            scheduler._executor = None

        mock_invoke.assert_not_called()

    def test_currently_dispatching_short_circuits_reentry(self):
        scheduler = SchedulerJobScheduler.instance()
        scheduler._ensure_running()
        sched = _fake_schedule()
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        job.next_fire = datetime.now(timezone.utc) - timedelta(seconds=1)
        job.currently_dispatching = True  # pretend a dispatch is in flight

        with patch("localemu.services.scheduler.target_invoker.invoke") as mock_invoke:
            scheduler._tick()

        mock_invoke.assert_not_called()


class TestOneShotCompletion:
    def test_at_one_shot_records_fired_once(self):
        scheduler = SchedulerJobScheduler.instance()
        scheduler._ensure_running()
        # at() must be in the future for the initial registration to
        # produce a non-None next_fire; we then rewind it for the tick.
        sched = _fake_schedule(
            expression="at(2099-01-01T00:00:00)",
            action="NONE",
        )
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        job.next_fire = datetime.now(timezone.utc) - timedelta(seconds=1)

        with patch("localemu.services.scheduler.target_invoker.invoke"):
            scheduler._tick()
            scheduler._executor.shutdown(wait=True)
            scheduler._executor = None

        assert job.fired_once is True
        assert sched.arn in scheduler._jobs  # NOT deleted (action=NONE)

    def test_at_one_shot_with_action_delete_removes_registration(self):
        scheduler = SchedulerJobScheduler.instance()
        scheduler._ensure_running()
        sched = _fake_schedule(
            expression="at(2099-01-01T00:00:00)",
            action="DELETE",
        )
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        job.next_fire = datetime.now(timezone.utc) - timedelta(seconds=1)

        with patch("localemu.services.scheduler.target_invoker.invoke"), patch.object(
            SchedulerJobScheduler, "_delete_from_moto"
        ) as mock_delete:
            scheduler._tick()
            scheduler._executor.shutdown(wait=True)
            scheduler._executor = None

        assert sched.arn not in scheduler._jobs
        mock_delete.assert_called_once()


class TestRetryCap:
    """``MaximumRetryAttempts`` from the AWS-side default is 185; the
    job scheduler must cap that to a local-dev-sane value or a single
    failure would tie up a dispatch worker for hours."""

    def test_default_is_capped(self):
        scheduler = SchedulerJobScheduler.instance()
        sched = _fake_schedule()
        sched.target = {**sched.target, "RetryPolicy": {"MaximumRetryAttempts": 185}}
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        job = scheduler._jobs[sched.arn]
        assert job.target["RetryPolicy"]["MaximumRetryAttempts"] <= 5

    def test_caller_under_cap_is_respected(self):
        scheduler = SchedulerJobScheduler.instance()
        sched = _fake_schedule()
        sched.target = {**sched.target, "RetryPolicy": {"MaximumRetryAttempts": 2}}
        scheduler.add_schedule(sched, "000000000000", "us-east-1")
        assert (
            scheduler._jobs[sched.arn].target["RetryPolicy"]["MaximumRetryAttempts"] == 2
        )


class TestRebuildFromBackends:
    def test_clears_then_repopulates(self):
        scheduler = SchedulerJobScheduler.instance()
        # Seed a stale registration that must NOT survive the rebuild.
        old = _fake_schedule(name="stale")
        scheduler.add_schedule(old, "000000000000", "us-east-1")
        assert old.arn in scheduler._jobs

        # Mock the moto backend traversal to look like one fresh schedule.
        fresh = _fake_schedule(name="fresh")
        fake_group = SimpleNamespace(schedules={"fresh": fresh})
        fake_backend = SimpleNamespace(schedule_groups={"default": fake_group})
        fake_backends = {"000000000000": {"us-east-1": fake_backend}}

        with patch.dict(
            "moto.scheduler.models.scheduler_backends",
            fake_backends,
            clear=True,
        ):
            scheduler.rebuild_from_backends()

        assert old.arn not in scheduler._jobs
        assert fresh.arn in scheduler._jobs
