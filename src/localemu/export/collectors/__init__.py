"""Collector registry and base class.

A *collector* is a per-service class that knows how to enumerate resources
from LocalEmu's in-memory state and convert them into :class:`Resource`
IR objects. Collectors are registered with :class:`CollectorRegistry`
(typically via the :func:`register_collector` decorator) and consumed by
the :class:`~localemu.export.orchestrator.Orchestrator`.

Real collectors live under ``localemu.export.collectors.<service>`` and
are added in phases P2-P4; this module only provides the registration
machinery.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from typing import Callable

from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for per-service collectors.

    Subclasses must set the ``service`` class attribute (the AWS service
    name, e.g. ``"s3"``) and implement :meth:`collect`.
    """

    service: str = ""

    @abstractmethod
    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate resources for ``account_id`` / ``region``.

        Args:
            account_id: AWS account id to export.
            region: AWS region to export.
            include_data: If ``True``, include bulk data payloads (S3 object
                bodies, DynamoDB items, ...) as sidecar content. If
                ``False``, only metadata is collected.
        Returns:
            List of :class:`Resource` IR objects. Empty list if the service
            has no resources in this account/region.
        """
        raise NotImplementedError


class CollectorRegistry:
    """Process-wide registry of collector classes.

    Use :meth:`instance` to get the singleton. The registry is thread-safe
    — registration can happen at import time from multiple plugin loaders.
    """

    _singleton: "CollectorRegistry | None" = None
    _singleton_lock = threading.Lock()

    def __init__(self) -> None:
        self._collectors: dict[str, type[BaseCollector]] = {}
        self._lock = threading.Lock()

    @classmethod
    def instance(cls) -> "CollectorRegistry":
        """Return the module-level singleton, creating it on first use."""
        if cls._singleton is None:
            with cls._singleton_lock:
                if cls._singleton is None:
                    cls._singleton = cls()
        return cls._singleton

    def register(self, service_name: str, collector_cls: type[BaseCollector]) -> None:
        """Register ``collector_cls`` under ``service_name``.

        Duplicate registrations replace the previous entry and log a
        warning — this is typically only hit during test reloads.
        """
        with self._lock:
            if service_name in self._collectors:
                LOG.warning(
                    "Collector for service %r already registered; replacing",
                    service_name,
                )
            self._collectors[service_name] = collector_cls

    def get_all(self) -> dict[str, type[BaseCollector]]:
        """Return a snapshot copy of the registered collectors."""
        with self._lock:
            return dict(self._collectors)


def register_collector(
    service_name: str,
) -> Callable[[type[BaseCollector]], type[BaseCollector]]:
    """Class decorator: register a collector under ``service_name``."""

    def _wrap(cls: type[BaseCollector]) -> type[BaseCollector]:
        CollectorRegistry.instance().register(service_name, cls)
        return cls

    return _wrap


# Real collectors are registered in P2-P4. We eagerly import every
# per-service collector module here so their ``@register_collector``
# decorators fire on package import — without this side-effect import the
# orchestrator's ``CollectorRegistry.instance().get_all()`` returns an
# empty dict and ``localemu export`` silently produces a zero-resource
# snapshot. Each module is small and import-cheap, so the loaded-by-default
# cost is negligible compared to the foot-gun of an empty export.
def _autoregister_collectors() -> None:
    """Import every per-service collector so its decorator runs.

    Failure to import a single collector (e.g. an upstream API change
    breaking one module) must not poison the whole export — we log and
    continue so the remaining services still register.
    """
    import importlib
    import pkgutil

    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{__name__}.{module_info.name}")
        except Exception:  # noqa: BLE001 — defensive
            LOG.warning(
                "Failed to import collector module %r; that service "
                "will not be exported.",
                module_info.name,
                exc_info=True,
            )


_autoregister_collectors()
