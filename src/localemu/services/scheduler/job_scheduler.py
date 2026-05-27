"""Background polling thread that fires registered EventBridge Scheduler
schedules at their next computed instant.

One thread per process — every schedule across every account+region is
multiplexed through a single 1-second tick. Dispatch runs on a small
thread pool so a slow target never blocks the loop. The job-registry
mirrors the live moto backends and is rebuilt on every state load /
reset so persisted schedules survive process restarts.
"""

from __future__ import annotations

import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from localemu.services.scheduler.expression import (
    InvalidScheduleExpression,
    compute_next_fire,
    is_one_shot,
)
from localemu.services.scheduler import target_invoker

LOG = logging.getLogger(__name__)


# Cap the (otherwise 185) AWS-default MaximumRetryAttempts to a sane local
# value. process_event already implements exponential backoff and 185
# retries blocks the dispatch worker for hours per failure.
_MAX_LOCAL_RETRIES = 5

# Tick frequency. rate(N seconds) needs second-level resolution; AWS itself
# guarantees no better than ±1s so this lines up.
_TICK_SECONDS = 1.0

# Dispatch pool. Sized so a few hundred dormant schedules can each fire
# the same second without serialising.
_DISPATCH_WORKERS = 32


@dataclass
class ScheduledJob:
    """In-memory bookkeeping for one schedule.

    Source of truth for state/expression/target stays in the moto backend
    — we only mirror what the polling loop needs to make a dispatch
    decision. ``rebuild_from_backends`` keeps these in sync.
    """

    arn: str
    name: str
    group_name: str
    account_id: str
    region: str
    schedule_expression: str
    schedule_expression_timezone: str | None
    target: dict[str, Any]
    state: str = "ENABLED"
    action_after_completion: str = "NONE"
    flex_minutes: int = 0
    start_date: datetime | None = None
    end_date: datetime | None = None
    next_fire: datetime | None = None
    currently_dispatching: bool = False
    # Set once a one-shot at(...) has fired so we never re-dispatch.
    fired_once: bool = False


class SchedulerJobScheduler:
    """Process-wide singleton that owns the polling thread + dispatch pool."""

    _instance: "SchedulerJobScheduler | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._jobs: dict[str, ScheduledJob] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None

    # ------------------------------------------------------------------
    # Singleton / lifecycle
    # ------------------------------------------------------------------
    @classmethod
    def instance(cls) -> "SchedulerJobScheduler":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = SchedulerJobScheduler()
        return cls._instance

    @classmethod
    def start(cls) -> "SchedulerJobScheduler":
        inst = cls.instance()
        inst._ensure_running()
        return inst

    @classmethod
    def shutdown(cls) -> None:
        if cls._instance is None:
            return
        cls._instance._stop()

    def _ensure_running(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._executor = ThreadPoolExecutor(
                max_workers=_DISPATCH_WORKERS,
                thread_name_prefix="scheduler-dispatch",
            )
            self._thread = threading.Thread(
                target=self._loop,
                name="scheduler-tick",
                daemon=True,
            )
            self._thread.start()

    def _stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            thread = self._thread
            executor = self._executor
            self._thread = None
            self._executor = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        if executor is not None:
            executor.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Registry operations (called by provider patches + state hooks)
    # ------------------------------------------------------------------
    def add_schedule(self, schedule, account_id: str, region: str) -> None:
        """Register a moto ``Schedule`` (or anything with the same attrs)."""
        job = self._build_job(schedule, account_id, region)
        with self._lock:
            self._jobs[job.arn] = job
        self._ensure_running()
        LOG.debug(
            "Scheduler registered %s (next_fire=%s, state=%s)",
            job.arn, job.next_fire, job.state,
        )

    def remove_schedule(self, schedule_arn: str) -> None:
        with self._lock:
            self._jobs.pop(schedule_arn, None)

    def remove_group(self, account_id: str, region: str, group_name: str) -> None:
        with self._lock:
            to_drop = [
                arn for arn, job in self._jobs.items()
                if job.account_id == account_id
                and job.region == region
                and job.group_name == group_name
            ]
            for arn in to_drop:
                self._jobs.pop(arn, None)

    def clear_all(self) -> None:
        with self._lock:
            self._jobs.clear()

    def rebuild_from_backends(self) -> None:
        """Walk every moto scheduler backend and re-register every schedule.

        Called on cold start, snapshot restore, and state reset. The
        scheduler module is imported lazily because moto.scheduler.models
        is loaded on first use and isn't always available at import time.
        """
        try:
            from moto.scheduler.models import scheduler_backends
        except ImportError:
            return
        with self._lock:
            self._jobs.clear()
        for account_id, regions in scheduler_backends.items():
            for region, backend in regions.items():
                for group in getattr(backend, "schedule_groups", {}).values():
                    for schedule in getattr(group, "schedules", {}).values():
                        try:
                            self.add_schedule(schedule, account_id, region)
                        except Exception:
                            LOG.warning(
                                "Could not rebuild schedule %s after state load",
                                getattr(schedule, "arn", "?"),
                                exc_info=True,
                            )

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------
    def _loop(self) -> None:
        LOG.info("Scheduler polling loop started")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                LOG.exception("Scheduler tick failed")
            self._stop_event.wait(timeout=_TICK_SECONDS)
        LOG.info("Scheduler polling loop stopped")

    def _tick(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            due = [
                job for job in self._jobs.values()
                if job.state == "ENABLED"
                and job.next_fire is not None
                and job.next_fire <= now
                and not job.currently_dispatching
                and not (job.end_date is not None and now > job.end_date)
                and not (job.fired_once and is_one_shot(job.schedule_expression))
            ]
            for job in due:
                job.currently_dispatching = True
        if not due:
            return
        LOG.debug("Scheduler dispatching %d due job(s)", len(due))
        executor = self._executor
        if executor is None:
            # Race with shutdown — clear flags and exit cleanly.
            with self._lock:
                for job in due:
                    job.currently_dispatching = False
            return
        for job in due:
            executor.submit(self._dispatch_and_advance, job, now)

    def _dispatch_and_advance(self, job: ScheduledJob, fire_at: datetime) -> None:
        try:
            target_invoker.invoke(
                schedule_arn=job.arn,
                schedule_name=job.name,
                target=job.target,
                account_id=job.account_id,
                region=job.region,
            )
        except Exception:
            LOG.warning("Scheduler dispatch failed for %s", job.arn, exc_info=True)
        finally:
            self._after_dispatch(job, fire_at)

    def _after_dispatch(self, job: ScheduledJob, fire_at: datetime) -> None:
        with self._lock:
            job.currently_dispatching = False
            if is_one_shot(job.schedule_expression):
                job.fired_once = True
                if job.action_after_completion == "DELETE":
                    self._jobs.pop(job.arn, None)
                    self._delete_from_moto(job)
                return
            # Recurring schedules: compute the NEXT fire after the one
            # that just executed, NOT after now — otherwise a slow
            # dispatch could shift the cadence forward.
            try:
                next_fire = compute_next_fire(
                    job.schedule_expression,
                    job.schedule_expression_timezone,
                    after=fire_at,
                    flex_minutes=job.flex_minutes,
                    jitter_seconds=_jitter(job.flex_minutes),
                )
            except InvalidScheduleExpression:
                LOG.warning(
                    "Could not advance schedule %s — invalid expression %r",
                    job.arn, job.schedule_expression,
                )
                self._jobs.pop(job.arn, None)
                return
            job.next_fire = next_fire
            if next_fire is None:
                # at(...) past its time; nothing more to do.
                return

    def _delete_from_moto(self, job: ScheduledJob) -> None:
        """Drop a schedule from the moto backend (used after a one-shot
        with ActionAfterCompletion=DELETE fires)."""
        try:
            from moto.scheduler.models import scheduler_backends

            backend = scheduler_backends[job.account_id][job.region]
            backend.delete_schedule(name=job.name, group_name=job.group_name)
        except Exception:
            LOG.debug(
                "Could not delete completed schedule %s from moto backend",
                job.arn, exc_info=True,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _build_job(self, schedule, account_id: str, region: str) -> ScheduledJob:
        flex = (schedule.flexible_time_window or {}).get("Mode", "OFF")
        flex_minutes = 0
        if flex == "FLEXIBLE":
            flex_minutes = int(
                (schedule.flexible_time_window or {}).get("MaximumWindowInMinutes", 0)
            )
        target = dict(schedule.target or {})
        # Apply our local retry cap so a single failure doesn't tie up a
        # dispatch worker for hours.
        retry_policy = dict(target.get("RetryPolicy") or {})
        retry_policy["MaximumRetryAttempts"] = min(
            _MAX_LOCAL_RETRIES,
            int(retry_policy.get("MaximumRetryAttempts", _MAX_LOCAL_RETRIES)),
        )
        target["RetryPolicy"] = retry_policy

        start_date = _parse_iso(schedule.start_date)
        end_date = _parse_iso(schedule.end_date)
        now = datetime.now(timezone.utc)
        after = max(now, start_date) if start_date is not None else now
        try:
            next_fire = compute_next_fire(
                schedule.schedule_expression,
                schedule.schedule_expression_timezone,
                after=after,
                flex_minutes=flex_minutes,
                jitter_seconds=_jitter(flex_minutes),
            )
        except InvalidScheduleExpression:
            LOG.warning(
                "Schedule %s has invalid expression %r — not registered",
                schedule.arn, schedule.schedule_expression,
            )
            next_fire = None
        return ScheduledJob(
            arn=schedule.arn,
            name=schedule.name,
            group_name=schedule.group_name,
            account_id=account_id,
            region=region,
            schedule_expression=schedule.schedule_expression,
            schedule_expression_timezone=schedule.schedule_expression_timezone,
            target=target,
            state=schedule.state,
            action_after_completion=getattr(schedule, "action_after_completion", "NONE")
                or "NONE",
            flex_minutes=flex_minutes,
            start_date=start_date,
            end_date=end_date,
            next_fire=next_fire,
        )


def _jitter(flex_minutes: int) -> float:
    """Compute one jitter offset for a single fire occurrence.

    Drawn fresh per call so two schedules with the same flex window don't
    line up on the same second. Returns 0 when the window is OFF.
    """
    if flex_minutes <= 0:
        return 0.0
    return random.uniform(0, flex_minutes * 60.0)


def _parse_iso(value) -> datetime | None:
    """Parse an ISO 8601 string from the moto backend into a tz-aware
    datetime. Returns ``None`` for empty input — moto uses '' as the
    sentinel for "field not set"."""
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    try:
        # moto sometimes hands us a bare ISO string, sometimes with 'Z'.
        text = value.rstrip("Z")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _reset_singleton_for_tests() -> None:
    """Test-only helper — drops the singleton so each test starts clean.

    Production callers must NOT use this; the polling thread expects to
    be the only owner of moto schedule registrations within a process.
    """
    with SchedulerJobScheduler._instance_lock:
        if SchedulerJobScheduler._instance is not None:
            SchedulerJobScheduler._instance._stop()
        SchedulerJobScheduler._instance = None
