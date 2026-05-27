"""Format writers and readers for exported LocalEmu snapshots.

Each format module is responsible for serializing a :class:`Snapshot`
(see :mod:`localemu.export.ir`) to a concrete on-disk artifact and, where
applicable, reading it back.
"""

from __future__ import annotations

from localemu.export.formats.json_format import JsonReader, JsonWriter
from localemu.export.formats.terraform import TerraformWriter


class CfnWriter:  # pragma: no cover - placeholder for a later phase
    """Placeholder CloudFormation writer; real implementation lands later."""


__all__ = ["JsonWriter", "JsonReader", "TerraformWriter", "CfnWriter"]
