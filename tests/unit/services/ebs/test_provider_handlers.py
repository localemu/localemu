"""Unit tests for the EBS provider's per-operation handlers.

The block-store has its own unit tests (``test_block_store.py``); these
tests focus on the *boundary* between the AWS protocol runtime and the
block store — the layer that the previous PR-005 ship missed and that
let a real bug land in production.

Concretely:

* ``BlockData`` in the EBS spec is declared ``streaming=True``. The
  request-parser surfaces it as a stream-like wrapper (``_InputStream``
  in botocore terms). The handler **must** ``.read()`` from it before
  writing to disk; the previous implementation treated it as bytes and
  crashed with ``memoryview: a bytes-like object is required, not
  '_InputStream'``.
* The ``GetSnapshotBlock`` response shape's ``BlockData`` is also
  streaming, so the serializer expects a file-like object — bytes
  would crash the serializer the same way.

These tests simulate the streaming shapes without booting LocalEmu or
boto3.
"""
from __future__ import annotations

import base64
import hashlib
import io

import pytest

from localemu.services.ebs import block_store
from localemu.services.ebs.provider import (
    _coerce_block_data_to_bytes,
    _get_snapshot_block,
    _list_snapshot_blocks,
    _put_snapshot_block,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path):
    block_store.set_root(tmp_path / "ebs")
    block_store._locks.clear()
    yield
    block_store.reset_for_tests()


class _InputStreamLike:
    """Stand-in for botocore's ``_InputStream``.

    The real type lives at ``botocore.parsers._InputStream``; importing
    private internals is fragile so we duck-type it here. The handler
    only requires ``.read()``.
    """

    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self, *args, **kwargs) -> bytes:
        return self._buf.read(*args, **kwargs)


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


# ---------------------------------------------------------------------------
# _coerce_block_data_to_bytes covers every shape the runtime might emit
# ---------------------------------------------------------------------------


def test_coerce_none_yields_empty_bytes():
    assert _coerce_block_data_to_bytes(None) == b""


def test_coerce_bytes_passthrough():
    assert _coerce_block_data_to_bytes(b"raw") == b"raw"


def test_coerce_bytearray_to_bytes():
    assert _coerce_block_data_to_bytes(bytearray(b"raw")) == b"raw"


def test_coerce_memoryview_to_bytes():
    mv = memoryview(b"raw")
    assert _coerce_block_data_to_bytes(mv) == b"raw"


def test_coerce_input_stream_like_reads_full_payload():
    """The exact shape PR-005 user reported: an _InputStream wrapper."""
    stream = _InputStreamLike(b"hello-streamed-bytes")
    assert _coerce_block_data_to_bytes(stream) == b"hello-streamed-bytes"


def test_coerce_bytesio_reads_full_payload():
    buf = io.BytesIO(b"another-shape")
    assert _coerce_block_data_to_bytes(buf) == b"another-shape"


def test_coerce_base64_string_decodes():
    encoded = base64.b64encode(b"\x00\x01\x02").decode("ascii")
    assert _coerce_block_data_to_bytes(encoded) == b"\x00\x01\x02"


def test_coerce_unknown_type_raises_typeerror():
    with pytest.raises(TypeError):
        _coerce_block_data_to_bytes(12345)


# ---------------------------------------------------------------------------
# _put_snapshot_block end-to-end with a stream payload
# ---------------------------------------------------------------------------


def test_put_snapshot_block_reads_streaming_input_and_stores_bytes():
    """The PR-005 reproduction at unit scope.

    Without the streaming read, this test fails with
    ``TypeError: a bytes-like object is required, not '_InputStreamLike'``
    inside the hashing step of the block store — matching the bug
    report's symptom verbatim.
    """
    block_store.create_snapshot(
        snapshot_id="snap-rt", owner_id="o", volume_size_gib=1,
    )
    payload = b"streamed-block-payload" * 100
    response = _put_snapshot_block(
        context=None,  # not consulted by the handler
        request={
            "SnapshotId": "snap-rt",
            "BlockIndex": 7,
            "BlockData": _InputStreamLike(payload),
            "Checksum": _sha256_b64(payload),
            "ChecksumAlgorithm": "SHA256",
        },
    )
    assert response["Checksum"] == _sha256_b64(payload)
    # And the bytes really landed on disk.
    data, record = block_store.get_snapshot_block(
        snapshot_id="snap-rt", block_index=7,
    )
    assert data == payload
    assert record.data_length == len(payload)


def test_put_snapshot_block_accepts_raw_bytes_too():
    block_store.create_snapshot(
        snapshot_id="snap-b", owner_id="o", volume_size_gib=1,
    )
    payload = b"raw-bytes-block"
    response = _put_snapshot_block(
        context=None,
        request={
            "SnapshotId": "snap-b",
            "BlockIndex": 0,
            "BlockData": payload,
            "Checksum": _sha256_b64(payload),
            "ChecksumAlgorithm": "SHA256",
        },
    )
    assert response["Checksum"] == _sha256_b64(payload)


# ---------------------------------------------------------------------------
# _get_snapshot_block returns a file-like for the streaming output shape
# ---------------------------------------------------------------------------


def test_get_snapshot_block_returns_file_like_block_data():
    """The serializer expects ``.read()`` on the output BlockData.

    Returning raw bytes would crash the EBS spec serializer with the
    same shape mismatch the input side hit, so we wrap in a BytesIO.
    """
    block_store.create_snapshot(
        snapshot_id="snap-g", owner_id="o", volume_size_gib=1,
    )
    payload = b"to-be-read-back"
    block_store.put_snapshot_block(
        snapshot_id="snap-g", block_index=0, block_data=payload,
    )
    resp = _get_snapshot_block(
        context=None,
        request={"SnapshotId": "snap-g", "BlockIndex": 0, "BlockToken": "x"},
    )
    body = resp["BlockData"]
    assert hasattr(body, "read"), (
        "BlockData on GetSnapshotBlock output must be a file-like "
        "object — the AWS spec declares it streaming=True and the "
        "serializer rejects raw bytes."
    )
    assert body.read() == payload
    assert resp["DataLength"] == len(payload)
    assert resp["Checksum"] == _sha256_b64(payload)


# ---------------------------------------------------------------------------
# Round-trip via the actual provider handlers (no boto3 involved)
# ---------------------------------------------------------------------------


def test_full_round_trip_through_handlers_with_streaming_input():
    """Start -> Put (streamed) -> List -> Get (file-like out)."""
    from localemu.services.ebs.provider import _complete_snapshot, _start_snapshot

    # Start
    from localemu.services.ebs import block_store as bs
    snap_id = "snap-full"
    bs.create_snapshot(
        snapshot_id=snap_id, owner_id="o", volume_size_gib=1, status="pending",
    )

    payload_a = b"block-A" * 10
    payload_b = b"block-B" * 10

    # Put twice, both via streaming
    _put_snapshot_block(
        context=None,
        request={
            "SnapshotId": snap_id, "BlockIndex": 0,
            "BlockData": _InputStreamLike(payload_a),
            "Checksum": _sha256_b64(payload_a), "ChecksumAlgorithm": "SHA256",
        },
    )
    _put_snapshot_block(
        context=None,
        request={
            "SnapshotId": snap_id, "BlockIndex": 1,
            "BlockData": _InputStreamLike(payload_b),
            "Checksum": _sha256_b64(payload_b), "ChecksumAlgorithm": "SHA256",
        },
    )

    # Complete
    done = _complete_snapshot(context=None, request={"SnapshotId": snap_id})
    assert done["Status"] == "completed"

    # List
    listed = _list_snapshot_blocks(
        context=None, request={"SnapshotId": snap_id},
    )
    indexes = sorted(b["BlockIndex"] for b in listed["Blocks"])
    assert indexes == [0, 1]

    # Get
    got_a = _get_snapshot_block(
        context=None,
        request={"SnapshotId": snap_id, "BlockIndex": 0, "BlockToken": "x"},
    )
    assert got_a["BlockData"].read() == payload_a
    got_b = _get_snapshot_block(
        context=None,
        request={"SnapshotId": snap_id, "BlockIndex": 1, "BlockToken": "x"},
    )
    assert got_b["BlockData"].read() == payload_b
