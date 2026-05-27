"""Snapshot importer: replays an exported :class:`Snapshot` against a target.

The importer consumes the same IR the exporter produces (see
:mod:`localemu.export.ir`) and re-creates the resources on a live AWS
endpoint — either a LocalEmu instance or real AWS. The public surface is
intentionally small:

* :class:`ImportRunner` orchestrates the replay.
* :class:`ImportMode` selects the behavior when a resource already exists
  (skip / fail / replace).
* :class:`ImportResult` captures *what actually happened* per resource, so
  callers can render honest summaries (no "applied" counts that were
  actually skips — a lesson from the v1 importer).
"""

from __future__ import annotations

from localemu.export.importer.replay import ImportMode, ImportResult, ImportRunner

__all__ = ["ImportMode", "ImportResult", "ImportRunner"]
