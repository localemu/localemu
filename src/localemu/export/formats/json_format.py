"""JSON (and JSON-in-ZIP) format writer / reader for LocalEmu snapshots.

A :class:`~localemu.export.ir.Snapshot` may contain arbitrary binary
sidecar payloads (Lambda deployment zips, S3 object bodies, ...). We
support two on-disk layouts:

* **Plain ``.json``** — used when ``snapshot.sidecar_files`` is empty.
  The whole snapshot is a single, human-editable JSON document.
* **``.zip`` archive** — used when sidecars are present. The archive
  contains a top-level ``snapshot.json`` plus every sidecar file at its
  logical path (``lambda/fn.zip``, ``s3/bucket/key``, ...). Sidecars are
  referenced from the JSON by path, *not* embedded as base64, so large
  payloads don't balloon the JSON document.
"""

from __future__ import annotations

import base64
import datetime as _dt
import io
import json
import zipfile
from decimal import Decimal
from pathlib import Path
from typing import Any

from localemu.export.ir import Ref, Resource, Snapshot

SUPPORTED_MAJOR_VERSION = "2"
SNAPSHOT_JSON_NAME = "snapshot.json"


class IncompatibleSnapshotVersion(ValueError):
    """Raised when a snapshot's schema version is not readable by this code."""


class SnapshotFormatError(ValueError):
    """Raised when a snapshot file is structurally invalid."""


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


class _SnapshotJsonEncoder(json.JSONEncoder):
    """JSON encoder that knows how to serialize LocalEmu IR value types.

    Unknown types raise :class:`TypeError` — we deliberately refuse to
    silently coerce via ``str()`` because that loses type information the
    reader would need to reconstruct the original value.
    """

    def default(self, o: Any) -> Any:  # noqa: D401 - stdlib signature
        if isinstance(o, Ref):
            return {
                "@@ref": {
                    "service": o.service,
                    "type": o.resource_type,
                    "id": o.resource_id,
                    "attr": o.attribute,
                }
            }
        if isinstance(o, (bytes, bytearray, memoryview)):
            raw = bytes(o)
            return {
                "__bytes_b64__": base64.b64encode(raw).decode("ascii"),
                "size": len(raw),
            }
        if isinstance(o, _dt.datetime):
            # Always emit with a timezone designator if present; naive
            # datetimes are serialized as-is (caller's responsibility).
            return o.isoformat()
        if isinstance(o, _dt.date):
            return o.isoformat()
        if isinstance(o, Decimal):
            # Preserve int-ness so round-tripping doesn't introduce .0
            if o == o.to_integral_value():
                return int(o)
            return float(o)
        if isinstance(o, (set, frozenset)):
            # Sort for determinism; mixed-type sets fall back to string sort.
            try:
                return sorted(o)
            except TypeError:
                return sorted(o, key=repr)
        raise TypeError(
            f"Object of type {type(o).__name__} is not JSON serializable "
            f"by LocalEmu's snapshot encoder"
        )


def _decode_hook(obj: dict[str, Any]) -> Any:
    """``object_hook`` for :func:`json.load` that restores IR types."""
    if "@@ref" in obj and len(obj) == 1:
        r = obj["@@ref"]
        try:
            return Ref(
                service=r["service"],
                resource_type=r["type"],
                resource_id=r["id"],
                attribute=r.get("attr", "arn"),
            )
        except KeyError as e:
            raise SnapshotFormatError(
                f"Malformed @@ref marker, missing key: {e.args[0]}"
            ) from e
    if "__bytes_b64__" in obj:
        try:
            return base64.b64decode(obj["__bytes_b64__"], validate=True)
        except (ValueError, TypeError) as e:
            raise SnapshotFormatError(
                f"Malformed __bytes_b64__ marker: {e}"
            ) from e
    return obj


# ---------------------------------------------------------------------------
# Resource <-> dict
# ---------------------------------------------------------------------------


def _encode_resource(r: Resource) -> dict[str, Any]:
    """Convert a :class:`Resource` to a plain JSON-compatible dict."""
    return {
        "service": r.service,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "account_id": r.account_id,
        "region": r.region,
        "attributes": r.attributes,
        "tags": r.tags,
        "created_at": r.created_at,
    }


def _decode_resource(d: dict[str, Any]) -> Resource:
    """Inverse of :func:`_encode_resource`; validates required fields."""
    required = ("service", "resource_type", "resource_id", "account_id", "region")
    for key in required:
        if key not in d:
            raise SnapshotFormatError(
                f"Resource missing required field '{key}' "
                f"(resource_id={d.get('resource_id', '?')})"
            )
    return Resource(
        service=d["service"],
        resource_type=d["resource_type"],
        resource_id=d["resource_id"],
        account_id=d["account_id"],
        region=d["region"],
        attributes=d.get("attributes", {}) or {},
        tags=d.get("tags", {}) or {},
        created_at=d.get("created_at"),
    )


def _snapshot_to_dict(snapshot: Snapshot) -> dict[str, Any]:
    """Serialize a :class:`Snapshot` to a JSON-ready dict (no sidecars)."""
    return {
        "schema_version": snapshot.schema_version,
        "exported_at": snapshot.exported_at,
        "localemu_version": snapshot.localemu_version,
        "resources": [_encode_resource(r) for r in snapshot.resources],
        "redacted_secrets": list(snapshot.redacted_secrets),
        "export_warnings": list(snapshot.export_warnings),
        # Sidecar *contents* live outside the JSON (in the zip) — we only
        # record their logical paths here so the reader knows what to
        # expect and can detect truncated archives.
        "sidecar_index": sorted(snapshot.sidecar_files.keys()),
    }


def _snapshot_from_dict(
    data: dict[str, Any], sidecars: dict[str, bytes] | None = None
) -> Snapshot:
    """Reconstruct a :class:`Snapshot` from a parsed JSON dict."""
    if "schema_version" not in data:
        raise SnapshotFormatError(
            "Snapshot JSON missing required field 'schema_version'"
        )
    version = str(data["schema_version"])
    major = version.split(".", 1)[0]
    if major != SUPPORTED_MAJOR_VERSION:
        raise IncompatibleSnapshotVersion(
            f"Snapshot schema_version={version!r} is not compatible with "
            f"this LocalEmu build (supports major {SUPPORTED_MAJOR_VERSION}.x)."
        )

    for key in ("exported_at", "localemu_version"):
        if key not in data:
            raise SnapshotFormatError(
                f"Snapshot JSON missing required field '{key}'"
            )

    raw_resources = data.get("resources", [])
    if not isinstance(raw_resources, list):
        raise SnapshotFormatError(
            "Snapshot field 'resources' must be a list, "
            f"got {type(raw_resources).__name__}"
        )
    resources = [_decode_resource(r) for r in raw_resources]

    # Cross-check sidecar index against the files we actually got.
    sidecars = dict(sidecars or {})
    declared = set(data.get("sidecar_index", []) or [])
    actual = set(sidecars.keys())
    missing = declared - actual
    if missing:
        raise SnapshotFormatError(
            f"Snapshot declares sidecar files not present in archive: "
            f"{sorted(missing)}"
        )

    return Snapshot(
        schema_version=version,
        exported_at=data["exported_at"],
        localemu_version=data["localemu_version"],
        resources=resources,
        redacted_secrets=list(data.get("redacted_secrets", []) or []),
        export_warnings=list(data.get("export_warnings", []) or []),
        sidecar_files=sidecars,
    )


# ---------------------------------------------------------------------------
# Public writer / reader
# ---------------------------------------------------------------------------


def _resolve_output_path(output: Path, has_sidecars: bool, exported_at: str) -> Path:
    """Pick a concrete output file path given a user-supplied target."""
    # Normalize the timestamp to a filename-safe slug.
    stamp = exported_at.replace(":", "").replace("-", "").replace(".", "")
    suffix = ".zip" if has_sidecars else ".json"
    if output.is_dir():
        return output / f"localemu-export-{stamp}{suffix}"
    return output


class JsonWriter:
    """Writes a :class:`Snapshot` to a ``.json`` file or ``.zip`` archive."""

    def write(self, snapshot: Snapshot, output: Path) -> Path:
        """Serialize ``snapshot`` to ``output`` and return the final path.

        If ``output`` is a directory, a timestamped filename is generated
        inside it; otherwise ``output`` is used verbatim (and its suffix
        is left to the caller — we don't second-guess it).
        """
        output = Path(output)
        has_sidecars = bool(snapshot.sidecar_files)
        final_path = _resolve_output_path(output, has_sidecars, snapshot.exported_at)
        final_path.parent.mkdir(parents=True, exist_ok=True)

        snapshot_dict = _snapshot_to_dict(snapshot)

        if has_sidecars:
            self._write_zip(final_path, snapshot_dict, snapshot.sidecar_files)
        else:
            self._write_json(final_path, snapshot_dict)
        return final_path

    @staticmethod
    def _write_json(path: Path, snapshot_dict: dict[str, Any]) -> None:
        """Stream the snapshot dict to ``path`` as pretty JSON."""
        with path.open("w", encoding="utf-8") as fh:
            json.dump(
                snapshot_dict,
                fh,
                cls=_SnapshotJsonEncoder,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            fh.write("\n")

    @staticmethod
    def _write_zip(
        path: Path,
        snapshot_dict: dict[str, Any],
        sidecars: dict[str, bytes],
    ) -> None:
        """Write a zip archive containing ``snapshot.json`` + sidecars."""
        # We buffer the JSON in memory (it fits easily; sidecars are the
        # heavyweights and those are streamed byte-for-byte).
        json_text = json.dumps(
            snapshot_dict,
            cls=_SnapshotJsonEncoder,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        with zipfile.ZipFile(
            path, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            zf.writestr(SNAPSHOT_JSON_NAME, json_text)
            for logical_path in sorted(sidecars.keys()):
                payload = sidecars[logical_path]
                if not isinstance(payload, (bytes, bytearray)):
                    raise TypeError(
                        f"Sidecar '{logical_path}' must be bytes, "
                        f"got {type(payload).__name__}"
                    )
                zf.writestr(logical_path, bytes(payload))


class JsonReader:
    """Reads a snapshot previously written by :class:`JsonWriter`."""

    def read(self, path: Path) -> Snapshot:
        """Load a ``.json`` or ``.zip`` snapshot from ``path``."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Snapshot file not found: {path}")

        if zipfile.is_zipfile(path):
            return self._read_zip(path)
        return self._read_json(path)

    @staticmethod
    def _read_json(path: Path) -> Snapshot:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh, object_hook=_decode_hook)
        if not isinstance(data, dict):
            raise SnapshotFormatError(
                f"Snapshot JSON root must be an object, got {type(data).__name__}"
            )
        return _snapshot_from_dict(data, sidecars=None)

    @staticmethod
    def _read_zip(path: Path) -> Snapshot:
        with zipfile.ZipFile(path, mode="r") as zf:
            names = set(zf.namelist())
            if SNAPSHOT_JSON_NAME not in names:
                raise SnapshotFormatError(
                    f"Zip archive {path} does not contain {SNAPSHOT_JSON_NAME}"
                )
            with zf.open(SNAPSHOT_JSON_NAME, "r") as jf:
                # json.load needs text; wrap in a TextIOWrapper.
                with io.TextIOWrapper(jf, encoding="utf-8") as tf:
                    data = json.load(tf, object_hook=_decode_hook)
            if not isinstance(data, dict):
                raise SnapshotFormatError(
                    "Snapshot JSON root must be an object, "
                    f"got {type(data).__name__}"
                )
            sidecars: dict[str, bytes] = {}
            for name in names:
                if name == SNAPSHOT_JSON_NAME:
                    continue
                # Skip directory entries that some zip tools emit.
                if name.endswith("/"):
                    continue
                sidecars[name] = zf.read(name)
        return _snapshot_from_dict(data, sidecars=sidecars)


__all__ = [
    "JsonWriter",
    "JsonReader",
    "IncompatibleSnapshotVersion",
    "SnapshotFormatError",
]
