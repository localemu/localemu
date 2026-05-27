"""Snapshot replay runner.

:class:`ImportRunner` ties the pieces together:

1. Topologically sorts the snapshot into waves (see
   :mod:`localemu.export.importer.dep_sort`).
2. For each wave, dispatches the resources to handlers in parallel via a
   :class:`concurrent.futures.ThreadPoolExecutor` (real concurrency —
   v1 claimed it but was serial).
3. Collects honest per-resource outcomes into :class:`ImportResult` —
   ``applied`` really means *created*, ``skipped`` really means
   *intentionally not created*, ``failed`` really means *tried and
   failed*.

Handlers may need access to the enclosing snapshot (Lambda pulls code
bytes from ``sidecar_files``). Rather than threading the snapshot
through every handler signature — which would force churn every time a
handler learns it needs another piece of snapshot metadata — we expose
it via a :class:`contextvars.ContextVar`, ``_CURRENT_SNAPSHOT``, set for
the duration of :meth:`ImportRunner.run`. ``ContextVar`` is async- and
thread-safe and integrates cleanly with ``ThreadPoolExecutor`` when we
propagate the context explicitly.
"""

from __future__ import annotations

import contextvars
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.dep_sort import CycleError, group_by_level
from localemu.export.importer.handlers import HANDLERS
from localemu.export.ir import Resource, Snapshot

LOG = logging.getLogger(__name__)

_CURRENT_SNAPSHOT: contextvars.ContextVar[Snapshot | None] = contextvars.ContextVar(
    "localemu_import_current_snapshot", default=None
)


class ImportMode(Enum):
    """Behavior when a resource already exists on the target."""

    SKIP_EXISTING = "skip-existing"
    FAIL_ON_EXISTING = "fail-on-existing"
    REPLACE = "replace"


@dataclass
class ImportResult:
    """Per-resource outcome accounting. Counts never lie.

    Attributes:
        applied: Resource IDs that were actually created.
        skipped: ``(resource_id, reason)`` for resources intentionally
            not created (e.g. they already exist in
            ``SKIP_EXISTING`` mode).
        failed: ``(resource_id, error_message)`` for create attempts that
            failed.
        total: Total resources considered (equals
            ``len(applied) + len(skipped) + len(failed)`` plus any
            handler-unsupported resources).
    """

    applied: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    total: int = 0

    @property
    def planned(self) -> int:
        """Total resources considered this run.

        Equivalent to ``total`` but named to match the common summary
        vocabulary callers use when describing a dry-run (planned vs.
        applied). Tests rely on this attribute to distinguish an
        honest "I would create N resources" dry-run report from the
        applied/skipped/failed triad that a live run produces.
        """
        return self.total


OnError = Literal["continue", "stop"]


class ImportRunner:
    """Replay a :class:`Snapshot` against a target using a :class:`ClientFactory`.

    The runner supports two construction shapes:

    1. **Snapshot-bound**: ``ImportRunner(snapshot, client_factory, ...)`` —
       the snapshot and factory are captured at construction time and
       ``run()`` is invoked with no arguments.
    2. **Factory-less / deferred**: ``ImportRunner(dry_run=True, ...)`` (or
       any combination of keyword-only options) and then
       ``run(snapshot)``. This shape is convenient for CLI callers and
       dry-run planning where no network client is ever needed; ``run()``
       accepts an explicit snapshot in that case.

    A ``ClientFactory`` can also be supplied later via
    :attr:`client_factory`. Real (non-dry-run) replays still require one.
    """

    def __init__(
        self,
        snapshot: Snapshot | None = None,
        client_factory: ClientFactory | None = None,
        *,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "us-east-1",
        mode: ImportMode = ImportMode.SKIP_EXISTING,
        dry_run: bool = False,
        on_error: OnError = "continue",
        max_workers: int = 8,
    ) -> None:
        if on_error not in ("continue", "stop"):
            raise ValueError(f"on_error must be 'continue' or 'stop', got {on_error!r}")
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._snapshot = snapshot
        # Allow the caller to pass loose connection parameters instead of a
        # pre-built factory (CLI / ad-hoc callers). We construct the factory
        # lazily so dry-run planning never touches boto3 / credentials.
        self._client_factory = client_factory
        self._endpoint_url = endpoint_url
        self._access_key = access_key
        self._secret_key = secret_key
        self._default_region = region
        self._mode = mode
        self._dry_run = dry_run
        self._on_error = on_error
        self._max_workers = max_workers

    # ---- factory accessor ------------------------------------------------
    @property
    def client_factory(self) -> ClientFactory:
        """Return the configured :class:`ClientFactory`, building one on demand.

        Lazy instantiation is load-bearing for dry-run: constructing a
        ``ClientFactory`` triggers boto3 credential resolution, which a
        dry-run explicitly must not do.
        """
        if self._client_factory is None:
            self._client_factory = ClientFactory(
                endpoint_url=self._endpoint_url,
                access_key=self._access_key,
                secret_key=self._secret_key,
                region=self._default_region,
            )
        return self._client_factory

    def run(self, snapshot: Snapshot | None = None) -> ImportResult:
        """Execute the replay.

        ``snapshot`` may be supplied either at construction time (original
        API) or as an argument here. Supplying it in both places is an
        error — ambiguous intent.
        """
        if snapshot is not None and self._snapshot is not None and snapshot is not self._snapshot:
            raise ValueError(
                "snapshot supplied to both ImportRunner(...) and .run(); "
                "pass it in exactly one place"
            )
        active_snapshot = snapshot if snapshot is not None else self._snapshot
        if active_snapshot is None:
            raise ValueError(
                "no snapshot to import: pass one to ImportRunner(...) or .run()"
            )
        # Re-bind so the rest of the method (which reads ``self._snapshot``)
        # sees the correct snapshot for this call without changing the
        # method signature of the internal helpers.
        self._snapshot = active_snapshot
        result = ImportResult(total=len(self._snapshot.resources))

        try:
            waves = group_by_level(self._snapshot)
        except CycleError as exc:
            LOG.error("%s", exc)
            for r in exc.resources:
                result.failed.append((r.resource_id, f"dependency cycle: {exc}"))
            return result

        token = _CURRENT_SNAPSHOT.set(self._snapshot)
        try:
            for wave_idx, wave in enumerate(waves):
                LOG.info(
                    "import wave %d/%d: %d resources", wave_idx + 1, len(waves), len(wave)
                )
                stop_requested = self._run_wave(wave, result)
                if stop_requested and self._on_error == "stop":
                    LOG.error("on_error=stop — aborting after wave %d", wave_idx + 1)
                    break
        finally:
            _CURRENT_SNAPSHOT.reset(token)

        return result

    def _run_wave(self, wave: list[Resource], result: ImportResult) -> bool:
        """Execute a single wave concurrently. Returns True if any handler failed."""
        any_failed = False
        # ``min(len(wave), self._max_workers)`` keeps the pool right-sized
        # for small waves (no point in 8 threads for 2 resources).
        workers = max(1, min(len(wave), self._max_workers))
        ctx = contextvars.copy_context()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_resource = {
                pool.submit(ctx.run, self._invoke_handler, resource): resource
                for resource in wave
            }
            for future in as_completed(future_to_resource):
                resource = future_to_resource[future]
                try:
                    outcome = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    LOG.exception("handler crashed for %s", resource.resource_id)
                    result.failed.append((resource.resource_id, f"handler crashed: {exc}"))
                    any_failed = True
                    continue
                self._record(outcome, resource, result)
                if outcome[0] == "failed":
                    any_failed = True

        return any_failed

    def _invoke_handler(self, resource: Resource) -> tuple[str, str, str | None]:
        key = (resource.service, resource.resource_type)
        handler = HANDLERS.get(key)
        if handler is None:
            return ("skipped", resource.resource_id, f"unsupported resource type {key}")

        if self._dry_run:
            LOG.info(
                "[dry-run] would import %s:%s:%s (mode=%s)",
                resource.service,
                resource.resource_type,
                resource.resource_id,
                self._mode.value,
            )

        try:
            # In dry-run we must never construct a client — the factory
            # would pull credentials from the environment. Pass a typed
            # ``None`` and rely on handlers to short-circuit on dry_run.
            factory = None if self._dry_run else self.client_factory
            return handler(resource, factory, self._mode, self._dry_run)
        except Exception as exc:
            LOG.exception("handler raised for %s", resource.resource_id)
            return ("failed", resource.resource_id, f"handler exception: {exc}")

    def _record(
        self,
        outcome: tuple[str, str, str | None],
        resource: Resource,
        result: ImportResult,
    ) -> None:
        status, rid, detail = outcome
        if status == "applied":
            result.applied.append(rid)
            LOG.info("applied %s:%s:%s", resource.service, resource.resource_type, rid)
        elif status == "skipped":
            result.skipped.append((rid, detail or "skipped"))
            LOG.info(
                "skipped %s:%s:%s (%s)",
                resource.service,
                resource.resource_type,
                rid,
                detail,
            )
        elif status == "failed":
            result.failed.append((rid, detail or "unknown error"))
            LOG.error(
                "failed %s:%s:%s (%s)",
                resource.service,
                resource.resource_type,
                rid,
                detail,
            )
        else:
            # Unknown status — treat as failure so we don't lie in the summary.
            result.failed.append((rid, f"handler returned unknown status {status!r}"))
