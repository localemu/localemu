"""Export orchestrator.

Fans collectors out across a thread pool, enforces a real per-service
timeout, aggregates results into a :class:`Snapshot`, then runs the
redaction and reference-resolution passes. Timeouts and collector
exceptions are converted into ``export_warnings`` — partial exports are
explicitly better than aborted ones.
"""

from __future__ import annotations

import concurrent.futures
import datetime as _dt
import logging
import traceback
from typing import TYPE_CHECKING

from localemu.export import SCHEMA_VERSION
from localemu.export.ir import Resource, Snapshot
from localemu.export.redaction import redact_secrets
from localemu.export.references import resolve_references

if TYPE_CHECKING:
    from localemu.export.collectors import BaseCollector

LOG = logging.getLogger(__name__)

# Default account id used when none can be inferred. Matches LocalEmu's
# documented default moto account.
_DEFAULT_ACCOUNT_ID = "000000000000"
_DEFAULT_REGION = "us-east-1"


def _localemu_version() -> str:
    """Return the running LocalEmu version string, or ``"unknown"``."""
    try:
        from localemu.version import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - defensive
        LOG.debug("Could not import localemu.version", exc_info=True)
        return "unknown"


def _now_iso() -> str:
    """Return current UTC time as an ISO 8601 string (``Z`` suffix)."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Orchestrator:
    """Run registered collectors and assemble the final snapshot.

    The orchestrator itself is stateless beyond the registry snapshot it
    captures at :meth:`export` time; concurrent exports are safe but
    redundant.
    """

    def __init__(self, max_workers: int = 8) -> None:
        """Create an orchestrator.

        Args:
            max_workers: Size of the collector thread pool. Collectors are
                I/O-bound (reading moto state), so a modest pool suffices.
        """
        self._max_workers = max_workers

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def export(
        self,
        services: list[str] | None,
        regions: list[str] | None,
        include_data: bool,
        include_secrets: bool,
        timeout_per_service: int = 30,
    ) -> Snapshot:
        """Run the export and return a :class:`Snapshot`.

        Args:
            services: Service names to include. ``None`` means all
                registered collectors.
            regions: Regions to export. ``None`` means a single default
                region (``us-east-1``) — multi-region discovery lives in a
                later phase.
            include_data: Forwarded to collectors; when ``True`` bulk
                payloads (S3 bodies etc.) are harvested into
                ``snapshot.sidecar_files``.
            include_secrets: When ``False`` (the default), sensitive
                attributes are replaced with ``***REDACTED***`` and the
                dotted paths are recorded in ``snapshot.redacted_secrets``.
            timeout_per_service: Hard per-collector wall-clock budget in
                seconds. Enforced via ``Future.result(timeout=...)``.

        Never raises for a collector-level failure — those are converted
        into ``export_warnings``. Only genuinely unrecoverable conditions
        (e.g. the registry itself blowing up) propagate.
        """
        # Imported lazily to keep package import cost low.
        from localemu.export.collectors import CollectorRegistry

        registry = CollectorRegistry.instance().get_all()
        if services is not None:
            selected = {
                name: cls for name, cls in registry.items() if name in set(services)
            }
            missing = sorted(set(services) - set(registry))
        else:
            selected = registry
            missing = []

        effective_regions = list(regions) if regions else [_DEFAULT_REGION]
        account_id = _DEFAULT_ACCOUNT_ID

        # IAM (and a handful of other partition-global services) live under
        # the magic ``"global"`` region in moto. The IAM collector
        # explicitly returns ``[]`` for any other region, so without
        # injecting ``"global"`` into the per-collector schedule for those
        # services we silently lose every IAM role/user/policy.
        # Per-collector region overrides keep regional services unaffected.
        _GLOBAL_SERVICES: set[str] = {"iam", "route53", "cloudfront"}

        snapshot = Snapshot(
            schema_version=SCHEMA_VERSION,
            exported_at=_now_iso(),
            localemu_version=_localemu_version(),
        )

        for m in missing:
            msg = f"no collector registered for service {m!r}"
            LOG.warning(msg)
            snapshot.export_warnings.append(msg)

        if not selected:
            LOG.info("No collectors to run; returning empty snapshot")
            return snapshot

        # Run all (service, region) pairs concurrently.
        #
        # NB: we deliberately do NOT use ``with ThreadPoolExecutor(...)``
        # here. Its ``__exit__`` blocks on ``shutdown(wait=True)`` until
        # every submitted task finishes — which would defeat
        # ``timeout_per_service``: a hung collector in a ``time.sleep``
        # cannot be preempted, so the ``with`` block would swallow the
        # timeout and keep the caller waiting for the full sleep. We
        # manage the pool explicitly and tear it down with
        # ``wait=False, cancel_futures=True`` so abandoned tasks are
        # cancelled if still queued and otherwise left to die with the
        # interpreter.
        pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="localemu-export",
        )
        try:
            future_to_key: dict[concurrent.futures.Future, tuple[str, str]] = {}
            for service_name, collector_cls in selected.items():
                regions_for_service = (
                    ["global"]
                    if service_name in _GLOBAL_SERVICES
                    else effective_regions
                )
                for region in regions_for_service:
                    fut = pool.submit(
                        self._run_one,
                        collector_cls,
                        account_id,
                        region,
                        include_data,
                    )
                    future_to_key[fut] = (service_name, region)

            for fut, (service_name, region) in future_to_key.items():
                try:
                    collected, sidecars = fut.result(
                        timeout=timeout_per_service
                    )
                except concurrent.futures.TimeoutError:
                    # Best-effort cancel; running collectors cannot be
                    # pre-empted in Python, but we at least stop future
                    # scheduling of this unit.
                    fut.cancel()
                    msg = (
                        f"collector {service_name!r} timed out after "
                        f"{timeout_per_service}s in region {region}"
                    )
                    LOG.warning(msg)
                    snapshot.export_warnings.append(msg)
                    continue
                except Exception as exc:  # noqa: BLE001 — intentionally broad
                    msg = (
                        f"collector {service_name!r} failed in region "
                        f"{region}: {exc!r}"
                    )
                    LOG.warning(msg, exc_info=True)
                    snapshot.export_warnings.append(
                        f"{msg}\n{traceback.format_exc()}"
                    )
                    continue

                # Merge sidecars even when ``collected`` is empty — a
                # collector might still produce auxiliary content that
                # downstream renderers need.
                if sidecars:
                    snapshot.sidecar_files.update(sidecars)
                if not collected:
                    continue
                snapshot.resources.extend(collected)
        finally:
            # Don't wait — hung collectors would otherwise keep us here
            # past ``timeout_per_service``. ``cancel_futures=True`` clears
            # anything still in the queue.
            pool.shutdown(wait=False, cancel_futures=True)

        # Redaction pass.
        redacted_resources: list[Resource] = []
        for r in snapshot.resources:
            new_r, paths = redact_secrets(r, include_secrets=include_secrets)
            redacted_resources.append(new_r)
            snapshot.redacted_secrets.extend(paths)
        snapshot.resources = redacted_resources

        # Reference resolution pass.
        snapshot = resolve_references(snapshot)
        return snapshot

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run_one(
        collector_cls: "type[BaseCollector]",
        account_id: str,
        region: str,
        include_data: bool,
    ) -> tuple[list[Resource], dict[str, bytes]]:
        """Instantiate a collector and invoke :meth:`collect`.

        Returns the resource list AND any sidecar files the collector
        accumulated on its instance (e.g. Lambda zip bytes). Kept as a
        static method so it can be submitted directly to the executor
        without closing over ``self`` (avoids accidental shared state
        between worker threads).
        """
        instance = collector_cls()
        resources = list(instance.collect(account_id, region, include_data))
        sidecars = dict(getattr(instance, "sidecar_files", {}) or {})
        return resources, sidecars
