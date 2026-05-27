"""Inert no-op metrics shim — no counters are ever reported.

The original LocalStack-era ``LabeledCounter`` class incremented in-memory
counts that were aggregated and POSTed to an external metrics endpoint on a
periodic schedule. That entire pipeline has been removed.

The classes below preserve the public API used by per-service ``analytics.py``
files (``LabeledCounter(namespace=..., name=..., labels=...)`` declarations and
``counter.labels(**kw).increment()`` call sites) so the existing instrumentation
points become no-ops without requiring source-wide edits.
"""

from __future__ import annotations


class _NoOpLabel:
    def increment(self, *args, **kwargs) -> None:
        return None

    def record(self, *args, **kwargs) -> None:
        return None


_NOOP_LABEL = _NoOpLabel()


class LabeledCounter:
    """No-op replacement for the former LocalStack labeled counter.

    Accepts and ignores any additional keyword arguments (``schema_version``,
    etc.) so historical call sites declared in services/*/analytics.py modules
    keep working without modification.
    """

    def __init__(self, namespace: str = "", name: str = "", labels=None, **_ignored) -> None:
        self.namespace = namespace
        self.name = name
        self.labels_keys = list(labels or [])

    def labels(self, *args, **kwargs):
        return _NOOP_LABEL


class Counter(LabeledCounter):
    """No-op replacement for the former LocalStack unlabeled counter."""

    def increment(self, *args, **kwargs) -> None:
        return None


class MetricRegistry:
    """No-op replacement for the former metrics registry. Always empty."""

    def collect(self) -> list:
        return []


class MetricRegistryKey:
    """Placeholder kept for back-compat. Unused in the no-op implementation."""
