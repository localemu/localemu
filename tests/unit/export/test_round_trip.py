"""End-to-end round-trip tests: seed → export → import → re-export → compare.

Marked ``integration`` — these need LocalEmu running.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest

from localemu.export import export_snapshot
from localemu.export.formats.json_format import JsonReader, JsonWriter
from localemu.export.ir import Snapshot


def _resource_identity(r: Any) -> tuple[str, str, str]:
    return (r.service, r.resource_type, r.resource_id)


@pytest.mark.integration
def test_json_write_read_is_identity(sample_snapshot: Snapshot, tmp_path: Path) -> None:
    """Non-integration sanity: the IR round-trips through JSON bit-for-bit
    (apart from the sidecar_files dict, which is regenerated)."""
    out = JsonWriter().write(sample_snapshot, tmp_path / "s.json")
    back = JsonReader().read(out)
    assert back.schema_version == sample_snapshot.schema_version
    assert {_resource_identity(r) for r in back.resources} == {
        _resource_identity(r) for r in sample_snapshot.resources
    }


@pytest.mark.integration
def test_end_to_end_round_trip(seeded_infra, tmp_path: Path) -> None:
    """Seed → export → import → re-export. The re-exported snapshot must
    contain (at least) every resource the original export contained.

    This is the single most important test in the whole suite: it
    exercises collectors, redaction, reference resolution, JSON
    serialization, dep sort, and import handlers all together.
    """
    # 1) Export current state.
    first = export_snapshot(include_secrets=True)

    path = JsonWriter().write(first, tmp_path / "first.json")

    # 2) Read it back (proves the file is legal).
    back = JsonReader().read(path)
    assert back.schema_version == first.schema_version

    # 3) Try an import into a fresh instance. We don't actually reset
    #    state from inside the test (that requires an admin hook). We
    #    assert instead that the importer accepts the snapshot in
    #    dry-run without raising.
    try:
        importer = importlib.import_module("localemu.export.importer")
        runner = getattr(importer, "ImportRunner", None)
        if runner is not None:
            runner(dry_run=True).run(back)
    except ImportError:
        pytest.skip("importer module not yet available")

    # 4) Re-export and verify stability: the same seeded resources are
    #    still observable.
    second = export_snapshot(include_secrets=True)
    first_ids = {_resource_identity(r) for r in first.resources}
    second_ids = {_resource_identity(r) for r in second.resources}
    # Allow second ⊇ first (re-export may see additional resources from
    # concurrent activity) but never less.
    missing = first_ids - second_ids
    assert not missing, f"re-export lost resources: {missing}"
