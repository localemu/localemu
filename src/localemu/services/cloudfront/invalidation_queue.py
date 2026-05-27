"""Async lifecycle for CloudFront invalidations.

Moto stores invalidations with ``Status=completed`` immediately. Real AWS
goes ``InProgress`` for a few seconds. This queue:

  1. On ``CreateInvalidation`` — records the invalidation as ``InProgress``
     (via the caller-provided ``set_status`` hook).
  2. After a configurable delay, flips status to ``Completed``.
  3. Invokes an optional ``purge`` callback at the moment of completion so
     the Phase 2 cache layer can evict matching entries.

Intentionally independent from :class:`.scheduler.DeploymentScheduler`:
invalidations are distribution-scoped child resources with independent
completion semantics, and decoupling keeps both classes small and
single-purpose.
"""

from __future__ import annotations

import heapq
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

LOG = logging.getLogger(__name__)


StatusSetter = Callable[[str, str, str, str, str], None]
"""``set_status(account_id, region, distribution_id, invalidation_id, status)``."""

PurgeCallback = Callable[[str, str, str, list[str]], None]
"""``purge(account_id, region, distribution_id, paths)``.

Paths are the raw path patterns from the invalidation request, including
wildcards. Phase 2 cache layer is responsible for matching them.
"""


@dataclass(order=True)
class _PendingCompletion:
    target_time: float
    seq: int
    account_id: str = field(compare=False)
    region: str = field(compare=False)
    distribution_id: str = field(compare=False)
    invalidation_id: str = field(compare=False)
    paths: list[str] = field(compare=False, default_factory=list)


class InvalidationQueue:
    """Schedules invalidation completion callbacks.

    Phase 1 only drives the status flip; the purge callback defaults to a
    no-op so the data plane can plug in later without a breaking change.
    """

    def __init__(
        self,
        *,
        set_status: StatusSetter,
        purge: PurgeCallback | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._set_status = set_status
        self._purge = purge or (lambda *args, **kwargs: None)
        self._clock = clock
        self._heap: list[_PendingCompletion] = []
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._seq = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._worker is not None:
            return
        self._worker = threading.Thread(
            target=self._run, name="cloudfront-invalidation-queue", daemon=True,
        )
        self._worker.start()

    def shutdown(self, *, timeout: float | None = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
            self._worker = None

    def enqueue(
        self,
        *,
        account_id: str,
        region: str,
        distribution_id: str,
        invalidation_id: str,
        paths: list[str],
        delay_seconds: float,
    ) -> None:
        """Mark invalidation InProgress now; schedule Completed after delay."""
        self._set_status(account_id, region, distribution_id, invalidation_id, "InProgress")
        with self._lock:
            self._seq += 1
            heapq.heappush(
                self._heap,
                _PendingCompletion(
                    target_time=self._clock() + max(0.0, delay_seconds),
                    seq=self._seq,
                    account_id=account_id,
                    region=region,
                    distribution_id=distribution_id,
                    invalidation_id=invalidation_id,
                    paths=list(paths),
                ),
            )
        self._wake.set()

    def tick(self) -> int:
        """Drive any due completions and return the count fired. Test hook."""
        return self._drain_due()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain_due()
            sleep_for = self._seconds_until_next()
            if sleep_for is None:
                self._wake.wait()
                self._wake.clear()
            else:
                self._wake.wait(timeout=min(sleep_for, 1.0))
                self._wake.clear()

    def _seconds_until_next(self) -> float | None:
        with self._lock:
            if not self._heap:
                return None
            return max(0.0, self._heap[0].target_time - self._clock())

    def _drain_due(self) -> int:
        fired = 0
        while True:
            entry = self._pop_if_due()
            if entry is None:
                return fired
            try:
                self._purge(
                    entry.account_id, entry.region,
                    entry.distribution_id, entry.paths,
                )
            except Exception:
                LOG.exception(
                    "cloudfront invalidation purge callback raised; continuing "
                    "to mark invalidation %s Completed so the user's wait loop "
                    "isn't stuck.",
                    entry.invalidation_id,
                )
            try:
                self._set_status(
                    entry.account_id, entry.region,
                    entry.distribution_id, entry.invalidation_id,
                    "Completed",
                )
                fired += 1
            except Exception:
                LOG.exception(
                    "cloudfront: failed to flip invalidation %s to Completed",
                    entry.invalidation_id,
                )

    def _pop_if_due(self) -> _PendingCompletion | None:
        with self._lock:
            if not self._heap:
                return None
            if self._heap[0].target_time > self._clock():
                return None
            return heapq.heappop(self._heap)
