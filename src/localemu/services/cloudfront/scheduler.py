"""Simulated CloudFront distribution deployment clock.

Real AWS takes seconds-to-minutes to flip a distribution from ``InProgress``
to ``Deployed``. Code that does not poll status before hitting the edge then
fails only in prod. Hard-coding ``Deployed`` locally (moto's behaviour)
hides that bug. We strike a middle ground: flip to ``Deployed`` after a
short, configurable delay so the ``wait_until_deployed`` pattern works
deterministically without a 15-minute real-AWS wait.

The scheduler runs a single background worker driven by a min-heap keyed on
target wake time, so N pending transitions cost O(1) memory per transition
and O(log N) wake cost. Transitions are idempotent: scheduling a new
transition for the same distribution supersedes any pending entry.

The caller injects a ``flip`` callback so this module has zero coupling to
moto — the caller passes a function that mutates the distribution's status
field on the shared backend. That separation keeps the scheduler unit-
testable without a live moto backend.
"""

from __future__ import annotations

import heapq
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

LOG = logging.getLogger(__name__)


FlipCallback = Callable[[str, str, str], None]
"""``flip(distribution_id, account_id, region)`` — mutate the backend status."""


@dataclass(order=True)
class _PendingFlip:
    target_time: float
    # Tie-breaker so heapq doesn't try to compare the non-comparable payload.
    seq: int
    # The actual fields — ``field(compare=False)`` keeps them out of ordering.
    distribution_id: str = field(compare=False)
    account_id: str = field(compare=False)
    region: str = field(compare=False)
    generation: int = field(compare=False)
    # Short label for operator logs, e.g. "deploy" / "invalidation".
    kind: str = field(compare=False, default="deploy")


class DeploymentScheduler:
    """Single-worker heap-based scheduler for distribution status flips.

    Usage::

        scheduler = DeploymentScheduler(flip=my_flip_function)
        scheduler.start()
        scheduler.schedule_deploy(distribution_id="E123", account_id="000000000000",
                                   region="us-east-1", delay_seconds=10)
        ...
        scheduler.shutdown()

    The scheduler can be constructed and used without ``start()`` for a
    ``clock=lambda: now`` injected time source — handy for unit tests that
    step time manually via ``tick()``.
    """

    def __init__(self, flip: FlipCallback, *, clock: Callable[[], float] = time.monotonic):
        self._flip = flip
        self._clock = clock
        self._heap: list[_PendingFlip] = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        # Per-distribution generation counter so a second schedule_deploy()
        # on the same distribution supersedes the first one — we accept the
        # entry from the heap only if its generation still matches.
        self._generations: dict[tuple[str, str, str], int] = {}
        self._seq = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._worker is not None:
            return
        self._worker = threading.Thread(
            target=self._run, name="cloudfront-scheduler", daemon=True,
        )
        self._worker.start()

    def shutdown(self, *, timeout: float | None = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
            self._worker = None

    def schedule_deploy(
        self,
        *,
        distribution_id: str,
        account_id: str,
        region: str,
        delay_seconds: float,
        kind: str = "deploy",
    ) -> None:
        """Schedule ``flip(distribution_id, account_id, region)`` in ``delay_seconds``.

        Subsequent calls for the same ``(distribution_id, account_id, region)``
        invalidate any pending entry — only the latest call fires.
        """
        key = (distribution_id, account_id, region)
        with self._lock:
            self._generations[key] = self._generations.get(key, 0) + 1
            self._seq += 1
            entry = _PendingFlip(
                target_time=self._clock() + max(0.0, delay_seconds),
                seq=self._seq,
                distribution_id=distribution_id,
                account_id=account_id,
                region=region,
                generation=self._generations[key],
                kind=kind,
            )
            heapq.heappush(self._heap, entry)
        self._wake.set()

    def cancel(self, distribution_id: str, account_id: str, region: str) -> None:
        """Invalidate any pending flip for the given distribution (e.g. on delete).

        We never remove entries from the heap directly — incrementing the
        generation is cheaper and keeps the heap invariant intact. Stale
        entries are ignored on pop.
        """
        key = (distribution_id, account_id, region)
        with self._lock:
            self._generations[key] = self._generations.get(key, 0) + 1

    def tick(self) -> int:
        """Process any due entries and return the count of fires.

        Exposed for unit tests that drive the clock manually. Production code
        goes through the worker thread instead.
        """
        return self._drain_due()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain_due()
            sleep_for = self._seconds_until_next()
            if sleep_for is None:
                # No pending work — block until a new schedule arrives.
                self._wake.wait()
                self._wake.clear()
            else:
                # Bound the wait so a schedule with an earlier target that
                # arrived while we were between _drain_due and _wake still
                # gets serviced on time; the ``schedule_deploy`` setter also
                # signals _wake for the common path.
                self._wake.wait(timeout=min(sleep_for, 1.0))
                self._wake.clear()

    def _seconds_until_next(self) -> float | None:
        with self._lock:
            if not self._heap:
                return None
            now = self._clock()
            return max(0.0, self._heap[0].target_time - now)

    def _drain_due(self) -> int:
        fired = 0
        while True:
            entry = self._pop_if_due()
            if entry is None:
                return fired
            # Drop stale entries whose generation has moved on.
            key = (entry.distribution_id, entry.account_id, entry.region)
            with self._lock:
                current_gen = self._generations.get(key, 0)
            if entry.generation != current_gen:
                continue
            try:
                self._flip(entry.distribution_id, entry.account_id, entry.region)
                fired += 1
            except Exception:
                LOG.exception(
                    "cloudfront scheduler: flip(%s, %s, %s) failed; the "
                    "distribution status may be stuck in InProgress and will "
                    "require operator intervention.",
                    entry.distribution_id, entry.account_id, entry.region,
                )

    def _pop_if_due(self) -> _PendingFlip | None:
        with self._lock:
            if not self._heap:
                return None
            if self._heap[0].target_time > self._clock():
                return None
            return heapq.heappop(self._heap)
