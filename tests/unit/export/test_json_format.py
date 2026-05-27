"""Unit tests for :mod:`localemu.export.formats.json_format`."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from localemu.export.formats.json_format import (
    IncompatibleSnapshotVersion,
    JsonReader,
    JsonWriter,
    SnapshotFormatError,
)
from localemu.export.ir import Ref, Resource, Snapshot


def _write_read(snapshot: Snapshot, tmp_path: Path) -> Snapshot:
    writer = JsonWriter()
    out_path = writer.write(snapshot, tmp_path / "snap.json")
    return JsonReader().read(out_path)


def test_emits_valid_json(sample_snapshot: Snapshot, tmp_path: Path) -> None:
    writer = JsonWriter()
    out = writer.write(sample_snapshot, tmp_path / "s.json")
    assert out.exists()
    # The file itself must parse as JSON.
    with out.open() as fh:
        json.load(fh)


def test_bytes_roundtrip(tmp_path: Path) -> None:
    r = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"code_blob": b"\x00\x01\x02binary"},
    )
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=[r],
    )
    back = _write_read(snap, tmp_path)
    assert back.resources[0].attributes["code_blob"] == b"\x00\x01\x02binary"


def test_ref_roundtrip(tmp_path: Path) -> None:
    ref = Ref(service="iam", resource_type="role", resource_id="r", attribute="arn")
    r = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"role": ref},
    )
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=[r],
    )
    back = _write_read(snap, tmp_path)
    role_val = back.resources[0].attributes["role"]
    assert isinstance(role_val, Ref)
    assert role_val == ref


def test_reader_rejects_wrong_major_version(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "schema_version": "9.9",
                "exported_at": "2026-01-01T00:00:00Z",
                "localemu_version": "test",
                "resources": [],
            }
        )
    )
    with pytest.raises(IncompatibleSnapshotVersion):
        JsonReader().read(bad)


def test_reader_rejects_missing_schema_version(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"resources": []}))
    with pytest.raises(SnapshotFormatError):
        JsonReader().read(bad)


def test_reader_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        JsonReader().read(tmp_path / "missing.json")


def test_deterministic_output(sample_snapshot: Snapshot, tmp_path: Path) -> None:
    w = JsonWriter()
    p1 = w.write(sample_snapshot, tmp_path / "a.json")
    p2 = w.write(sample_snapshot, tmp_path / "b.json")
    assert p1.read_bytes() == p2.read_bytes()


def test_zip_archive_when_sidecars_present(tmp_path: Path) -> None:
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        sidecar_files={"lambda/fn.zip": b"PK\x03\x04stub"},
    )
    out = JsonWriter().write(snap, tmp_path / "s.zip")
    assert zipfile.is_zipfile(out)
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "snapshot.json" in names
        assert "lambda/fn.zip" in names


def test_zip_roundtrip_restores_sidecars(tmp_path: Path) -> None:
    payload = b"hello-bytes"
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        sidecar_files={"s3/unit/bucket/key": payload},
    )
    back = _write_read(snap, tmp_path)
    assert back.sidecar_files["s3/unit/bucket/key"] == payload


def test_zip_rejects_non_bytes_sidecar(tmp_path: Path) -> None:
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        sidecar_files={"bad": "not-bytes"},  # type: ignore[dict-item]
    )
    with pytest.raises(TypeError):
        JsonWriter().write(snap, tmp_path / "x.zip")


def test_plain_json_when_no_sidecars(sample_snapshot: Snapshot, tmp_path: Path) -> None:
    out = JsonWriter().write(sample_snapshot, tmp_path / "s.json")
    # No sidecars → plain JSON, not a zip.
    assert not zipfile.is_zipfile(out)


def test_snapshot_roundtrip_equal(sample_snapshot: Snapshot, tmp_path: Path) -> None:
    back = _write_read(sample_snapshot, tmp_path)
    assert back.schema_version == sample_snapshot.schema_version
    assert len(back.resources) == len(sample_snapshot.resources)
    # Resource identity by (service, type, id).
    orig_keys = {(r.service, r.resource_type, r.resource_id) for r in sample_snapshot.resources}
    back_keys = {(r.service, r.resource_type, r.resource_id) for r in back.resources}
    assert orig_keys == back_keys


def test_reader_rejects_sidecar_index_mismatch(tmp_path: Path) -> None:
    # Construct a zip whose snapshot.json declares a sidecar that's missing.
    p = tmp_path / "bad.zip"
    body = {
        "schema_version": "2.0",
        "exported_at": "2026-01-01T00:00:00Z",
        "localemu_version": "test",
        "resources": [],
        "redacted_secrets": [],
        "export_warnings": [],
        "sidecar_index": ["missing.bin"],
    }
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("snapshot.json", json.dumps(body))
    with pytest.raises(SnapshotFormatError):
        JsonReader().read(p)


def test_plain_resource_equality_after_roundtrip(simple_resource: Resource, tmp_path: Path) -> None:
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=[simple_resource],
    )
    back = _write_read(snap, tmp_path)
    r = back.resources[0]
    assert r.service == simple_resource.service
    assert r.resource_id == simple_resource.resource_id
    assert r.attributes == simple_resource.attributes
