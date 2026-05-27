"""Pure-function tests for scheduler expression parsing + next-fire math.

Every supported expression form (``at(...)``, ``rate(N <unit>)``,
``cron(...)``) and every rate unit (``second``/``seconds``/``minute``/
``minutes``/``hour``/``hours``/``day``/``days``) must round-trip through
:func:`compute_next_fire` without surprise. Negative cases (singular vs
plural mismatch, past one-shot, bad expression) must raise the
documented exception so the provider can map it to the AWS-shaped
``ValidationException``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from localemu.services.scheduler.expression import (
    InvalidScheduleExpression,
    compute_next_fire,
    is_one_shot,
    validate_schedule_expression,
)


NOW = datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc)


class TestValidate:
    @pytest.mark.parametrize(
        "expr",
        [
            "rate(1 minute)",
            "rate(5 minutes)",
            "rate(30 seconds)",
            "rate(1 hour)",
            "rate(2 hours)",
            "rate(1 day)",
            "rate(7 days)",
            "cron(0 12 * * ? *)",
            "cron(*/5 * * * ? *)",
            "at(2026-12-31T23:59:59)",
        ],
    )
    def test_accepts_valid(self, expr):
        validate_schedule_expression(expr)  # must not raise

    @pytest.mark.parametrize(
        "expr,why",
        [
            ("rate(1 minutes)", "singular value must use singular unit"),
            ("rate(5 minute)", "plural value must use plural unit"),
            ("rate(0 seconds)", "zero values rejected"),
            ("rate(10 fortnight)", "unknown unit"),
            ("at(garbage)", "malformed iso"),
            ("cron(0 12)", "too few cron fields"),
            ("", "empty"),
            (None, "non-string"),
        ],
    )
    def test_rejects_invalid(self, expr, why):
        with pytest.raises(InvalidScheduleExpression):
            validate_schedule_expression(expr)


class TestRateSeconds:
    def test_advances_by_exactly_n_seconds(self):
        nf = compute_next_fire("rate(10 seconds)", "UTC", NOW)
        assert nf == NOW + timedelta(seconds=10)

    def test_one_second_singular(self):
        nf = compute_next_fire("rate(1 second)", "UTC", NOW)
        assert nf == NOW + timedelta(seconds=1)


class TestRateMinutes:
    def test_advances_by_exactly_n_minutes(self):
        nf = compute_next_fire("rate(15 minutes)", "UTC", NOW)
        assert nf == NOW + timedelta(minutes=15)


class TestAtExpression:
    def test_future_returns_that_instant(self):
        nf = compute_next_fire("at(2026-06-01T08:00:00)", "UTC", NOW)
        assert nf == datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)

    def test_past_returns_none(self):
        # NOW is 2026-05-18T12:00:00Z; 2024 is in the past.
        assert compute_next_fire("at(2024-01-01T00:00:00)", "UTC", NOW) is None

    def test_honors_timezone(self):
        """at(...) is wall-clock in the schedule's timezone; an 08:00 PDT
        target is 15:00Z, NOT 08:00Z."""
        nf = compute_next_fire(
            "at(2026-06-01T08:00:00)", "America/Los_Angeles", NOW
        )
        # In June, LA is UTC-7. 08:00 LA = 15:00 UTC.
        assert nf == datetime(2026, 6, 1, 15, 0, 0, tzinfo=timezone.utc)

    def test_is_one_shot(self):
        assert is_one_shot("at(2026-06-01T08:00:00)") is True
        assert is_one_shot("rate(5 minutes)") is False
        assert is_one_shot("cron(0 12 * * ? *)") is False


class TestCron:
    def test_daily_noon_utc(self):
        nf = compute_next_fire("cron(0 12 * * ? *)", "UTC", NOW)
        # NOW is exactly 12:00:00 — next noon is tomorrow.
        assert nf == NOW + timedelta(days=1)

    def test_drops_year_field_for_python_crontab_compat(self):
        # 6-field cron expressions are the AWS form; the 6th field (year)
        # is silently dropped because python-crontab doesn't honour it.
        # Confirm we don't crash and return a sensible next fire.
        nf = compute_next_fire("cron(0 12 * * ? 2026)", "UTC", NOW)
        assert nf == NOW + timedelta(days=1)

    def test_5_field_cron_works_directly(self):
        nf = compute_next_fire("cron(0 12 * * ?)", "UTC", NOW)
        assert nf == NOW + timedelta(days=1)


class TestTzAwareness:
    def test_after_must_be_tz_aware(self):
        naive = datetime(2026, 5, 18, 12, 0, 0)
        with pytest.raises(ValueError):
            compute_next_fire("rate(5 minutes)", "UTC", naive)


class TestJitter:
    def test_deterministic_jitter_seconds_are_added(self):
        nf = compute_next_fire(
            "rate(10 seconds)", "UTC", NOW, jitter_seconds=2.5,
        )
        assert nf == NOW + timedelta(seconds=12.5)
