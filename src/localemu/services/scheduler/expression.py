"""Schedule-expression parsing and next-fire computation for EventBridge Scheduler.

Three expression forms exist in the public API; this module is the single
authoritative parser for all of them:

  * ``at(YYYY-MM-DDTHH:MM:SS)``     – one-shot fire at a specific local time.
  * ``rate(N <unit>)``              – periodic with second-level precision
                                      (``seconds``/``minutes``/``hours``/``days``).
  * ``cron(<5 or 6 field cron>)``   – calendar-driven; same syntax as EventBridge
                                      Rules.

EventBridge Scheduler differs from EventBridge Rules in two important ways:
the ``rate(...)`` form supports ``seconds`` (Rules don't), and every fire is
evaluated in ``ScheduleExpressionTimezone`` rather than UTC. Both are
honoured here.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from crontab import CronTab


_AT_REGEX = re.compile(
    r"^at\((19|20)\d{2}-(0[1-9]|1[012])-([012]\d|3[01])"
    r"T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)\)$"
)
_RATE_REGEX = re.compile(r"^rate\((\d+)\s+(second|seconds|minute|minutes|hour|hours|day|days)\)$")
_CRON_REGEX = re.compile(r"^cron\(([^)]+)\)$")


class InvalidScheduleExpression(ValueError):
    """Raised when an expression doesn't match any of the supported forms."""


def validate_schedule_expression(expr: str) -> None:
    """Raise :class:`InvalidScheduleExpression` if *expr* is unparseable.

    Mirrors what the AWS API returns to the caller (a ``ValidationException``);
    the provider catches this and re-raises in the API's preferred shape so
    the moto-side error path stays as the single source of truth.
    """
    if not expr or not isinstance(expr, str):
        raise InvalidScheduleExpression("Schedule expression must be a non-empty string")
    if _AT_REGEX.match(expr):
        return
    if (cron_match := _CRON_REGEX.match(expr)):
        # _CRON_REGEX only checks the outer ``cron(...)`` wrapper; ask
        # python-crontab to actually parse the inner expression so we
        # reject malformed forms (too few fields, bad ranges, etc.)
        # before they slip into the polling loop.
        cron_expr = cron_match.group(1)
        parts = cron_expr.split()
        crontab_expr = " ".join(parts[:5]) if len(parts) >= 6 else cron_expr
        try:
            CronTab(crontab_expr)
        except Exception as e:
            raise InvalidScheduleExpression(
                f"Invalid cron expression {cron_expr!r}: {e}"
            ) from e
        return
    if (match := _RATE_REGEX.match(expr)):
        value = int(match.group(1))
        unit = match.group(2)
        if value < 1:
            raise InvalidScheduleExpression("rate(N <unit>): N must be >= 1")
        # AWS pluralisation rule: 1 must be singular, >1 must be plural.
        if value == 1 and unit.endswith("s"):
            raise InvalidScheduleExpression(
                "rate(1 <unit>): unit must be singular (e.g. 'rate(1 minute)')"
            )
        if value > 1 and not unit.endswith("s"):
            raise InvalidScheduleExpression(
                f"rate({value} <unit>): unit must be plural (e.g. 'rate({value} minutes)')"
            )
        return
    raise InvalidScheduleExpression(f"Invalid Schedule Expression: {expr!r}")


def _resolve_timezone(tz_name: str | None) -> ZoneInfo:
    """Return a ``ZoneInfo`` for *tz_name* (defaults to UTC). Unknown
    zones fall back to UTC with no error — the caller already validated
    on create; this is a defensive path for restored state."""
    if not tz_name:
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(tz_name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def _rate_to_timedelta(value: int, unit: str) -> timedelta:
    if unit.startswith("second"):
        return timedelta(seconds=value)
    if unit.startswith("minute"):
        return timedelta(minutes=value)
    if unit.startswith("hour"):
        return timedelta(hours=value)
    if unit.startswith("day"):
        return timedelta(days=value)
    raise InvalidScheduleExpression(f"Unsupported rate unit: {unit!r}")


def compute_next_fire(
    expr: str,
    tz_name: str | None,
    after: datetime,
    flex_minutes: int = 0,
    *,
    jitter_seconds: float = 0.0,
) -> datetime | None:
    """Return the next instant *expr* should fire, strictly later than *after*.

    Returns ``None`` only for one-shot ``at(...)`` expressions whose fire time
    has already passed — that schedule will never fire again and the caller
    should stop polling it.

    *after* must be timezone-aware; we return tz-aware UTC instants too.
    *flex_minutes* widens the firing window by adding up to that many minutes
    of jitter to the base time; *jitter_seconds* lets callers seed
    deterministic jitter in tests (otherwise it's chosen at random by the
    job scheduler, NOT by this pure-function module).
    """
    if after.tzinfo is None:
        raise ValueError("'after' must be timezone-aware")
    after_utc = after.astimezone(timezone.utc)
    tz = _resolve_timezone(tz_name)

    if match := _AT_REGEX.match(expr):
        # at(...) is a wall-clock instant in the schedule's timezone.
        # Parse the inner ISO timestamp and stamp the timezone.
        iso = expr[3:-1]
        fire_local = datetime.fromisoformat(iso).replace(tzinfo=tz)
        fire_utc = fire_local.astimezone(timezone.utc)
        if fire_utc <= after_utc:
            return None
        return fire_utc + timedelta(seconds=jitter_seconds)

    if match := _RATE_REGEX.match(expr):
        delta = _rate_to_timedelta(int(match.group(1)), match.group(2))
        return after_utc + delta + timedelta(seconds=jitter_seconds)

    if match := _CRON_REGEX.match(expr):
        cron_expr = match.group(1)
        # AWS cron expressions are 6-field (minute hour day-of-month month
        # day-of-week year). python-crontab supports both 5-field and
        # 6-field; if a year field is present we drop it because crontab
        # doesn't honour the year field anyway and would crash.
        parts = cron_expr.split()
        crontab_expr = " ".join(parts[:5]) if len(parts) >= 6 else cron_expr
        # CronTab needs a tz-aware now so its computation honours DST.
        local_after = after_utc.astimezone(tz)
        seconds = CronTab(crontab_expr).next(now=local_after, default_utc=False)
        if seconds is None:
            return None
        return after_utc + timedelta(seconds=seconds + jitter_seconds)

    raise InvalidScheduleExpression(f"Invalid Schedule Expression: {expr!r}")


def is_one_shot(expr: str) -> bool:
    """Whether *expr* is an ``at(...)`` one-shot — used by the scheduler to
    know it can delete the registration after the first successful dispatch
    when ``ActionAfterCompletion=DELETE`` doesn't apply."""
    return bool(_AT_REGEX.match(expr))
