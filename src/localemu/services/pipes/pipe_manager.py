"""Process-wide registry of running ``PipeWorker`` instances.

One :class:`PipeWorker` exists per pipe ARN; the manager owns the
mapping and serialises lifecycle transitions (start / stop / update /
delete) so concurrent API calls against the same pipe never race.

The manager itself is intentionally thin — all the source-polling and
target-dispatch logic lives on the workers. This is the same shape as
:class:`localemu.services.lambda_.event_source_mapping.esm_worker.EsmWorker`
+ its surrounding manager pattern, so the two stay easy to compare.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from localemu.services.pipes.pipe_worker import PipeWorker

LOG = logging.getLogger(__name__)


class PipeManager:
    """Singleton dict[pipe_arn, PipeWorker]."""

    _instance: "PipeManager | None" = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._workers: dict[str, "PipeWorker"] = {}
        self._lock = threading.RLock()

    @classmethod
    def instance(cls) -> "PipeManager":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = PipeManager()
        return cls._instance

    # ------------------------------------------------------------------
    # Registry API
    # ------------------------------------------------------------------
    def get(self, pipe_arn: str) -> Optional["PipeWorker"]:
        with self._lock:
            return self._workers.get(pipe_arn)

    def register(self, worker: "PipeWorker") -> None:
        with self._lock:
            existing = self._workers.get(worker.pipe_arn)
            if existing is not None and existing is not worker:
                # A new worker is taking over the same ARN — make sure
                # the old one is fully stopped first or both will poll
                # the same source.
                existing.stop()
            self._workers[worker.pipe_arn] = worker

    def remove(self, pipe_arn: str) -> Optional["PipeWorker"]:
        with self._lock:
            return self._workers.pop(pipe_arn, None)

    def all(self) -> list["PipeWorker"]:
        with self._lock:
            return list(self._workers.values())

    def stop_all(self) -> None:
        for worker in self.all():
            try:
                worker.stop()
            except Exception:
                LOG.warning(
                    "Failed to stop pipe %s during shutdown",
                    worker.pipe_arn, exc_info=True,
                )
        with self._lock:
            self._workers.clear()


def _reset_singleton_for_tests() -> None:
    """Test-only helper — drops the singleton so each test starts clean.

    Production code MUST NOT call this; running tests use it from a
    fixture so per-test state doesn't leak across the polling-thread
    boundary.
    """
    with PipeManager._instance_lock:
        if PipeManager._instance is not None:
            PipeManager._instance.stop_all()
        PipeManager._instance = None
