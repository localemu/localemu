"""LocalEmu infrastructure export / import package.

This package implements the infrastructure export feature: it walks the
running LocalEmu state and produces a portable, reference-resolved
`Snapshot` object (see :mod:`localemu.export.ir`) that downstream writers
(Terraform, CloudFormation, etc. — added in later phases) can turn into
real IaC artifacts.

Public API:
    - :data:`SCHEMA_VERSION` — current snapshot schema version string.
    - :func:`export_snapshot` — orchestrated export entry point.
    - :func:`import_snapshot` — inverse operation (stub until later phase).
"""

from __future__ import annotations

SCHEMA_VERSION = "2.0"

__all__ = [
    "SCHEMA_VERSION",
    "export_snapshot",
    "import_snapshot",
]


def export_snapshot(
    services: list[str] | None = None,
    regions: list[str] | None = None,
    include_data: bool = False,
    include_secrets: bool = False,
    timeout_per_service: int = 30,
):
    """Run an orchestrated export and return a :class:`Snapshot`.

    Thin convenience wrapper around :class:`Orchestrator.export`. Kept at
    package level so callers do not need to know the orchestrator class.
    """
    from localemu.export.orchestrator import Orchestrator

    return Orchestrator().export(
        services=services,
        regions=regions,
        include_data=include_data,
        include_secrets=include_secrets,
        timeout_per_service=timeout_per_service,
    )


def import_snapshot(snapshot):  # pragma: no cover - implemented in later phase
    """Import a previously exported snapshot back into LocalEmu.

    Placeholder — the real implementation lands in a later phase. We keep
    the symbol reserved here so the public API surface is stable.
    """
    raise NotImplementedError("import_snapshot is implemented in a later phase")
