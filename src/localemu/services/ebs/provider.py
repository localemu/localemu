"""LocalEmu EBS direct-API provider.

Overrides moto's in-memory ``EBSBackend`` for the data-plane
operations so blocks survive process restart and are visible across
all snapshot-creation paths:

* ``StartSnapshot`` -> creates a pending block-store entry.
* ``PutSnapshotBlock`` -> writes a block to disk, returns
  ``BlockToken`` + ``Checksum``.
* ``CompleteSnapshot`` -> marks the snapshot ``completed``.
* ``GetSnapshotBlock`` -> reads a block back, returns bytes +
  ``BlockToken`` + ``Checksum``.
* ``ListSnapshotBlocks`` -> returns the list of blocks + tokens.
* ``ListChangedBlocks`` -> diffs two snapshots.

All other operations fall through to moto so existing functionality
isn't affected.

The provider is created lazily via :func:`create_ebs_service`, which
also installs the EC2 ↔ block-store bridge (see
:mod:`localemu.services.ebs.moto_bridge`).
"""
from __future__ import annotations

import base64
import io as _io
import logging
import uuid
from typing import Any

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.ebs import block_store
from localemu.services.ebs.block_store import (
    BlockNotFoundError,
    SnapshotNotFoundError,
)
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Operation handlers
# ---------------------------------------------------------------------------


def _start_snapshot(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:StartSnapshot`` — open a new snapshot for block writes.

    AWS semantics: the snapshot is in ``pending`` state until
    ``CompleteSnapshot`` arrives. We mirror that. Idempotency on
    ``ClientToken`` is a future enhancement; for now each call mints
    a new snapshot via moto, then registers it in the block store.
    """
    # Delegate the moto side first so the EC2 snapshot id, volume,
    # description, tags etc. land in the EC2 backend with the right
    # shape. Moto's ``start_snapshot`` returns the new EBS-snapshot
    # mirror object too, but we ignore that and use the block-store.
    moto_response = call_moto(context)
    snapshot_id = moto_response.get("SnapshotId")
    if not snapshot_id:
        return moto_response

    volume_size = int(request.get("VolumeSize") or 1)
    description = request.get("Description") or ""
    parent_snapshot_id = request.get("ParentSnapshotId")

    block_store.create_snapshot(
        snapshot_id=snapshot_id,
        owner_id=str(context.account_id or "000000000000"),
        volume_size_gib=volume_size,
        parent_snapshot_id=parent_snapshot_id,
        description=description,
        status="pending",
    )
    # Echo a richer response back so callers get the block-store
    # snapshot id + status (matches AWS).
    moto_response.setdefault("Status", "pending")
    moto_response.setdefault("BlockSize", block_store.BLOCK_SIZE_BYTES)
    moto_response.setdefault("VolumeSize", volume_size)
    moto_response.setdefault("StartTime", moto_response.get("StartTime"))
    return moto_response


def _put_snapshot_block(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:PutSnapshotBlock`` — write one block."""
    snapshot_id = request["SnapshotId"]
    block_index = int(request["BlockIndex"])
    raw = _coerce_block_data_to_bytes(request.get("BlockData"))
    checksum = request.get("Checksum")
    checksum_algorithm = (request.get("ChecksumAlgorithm") or "SHA256").upper()

    try:
        record = block_store.put_snapshot_block(
            snapshot_id=snapshot_id,
            block_index=block_index,
            block_data=raw,
            checksum=checksum,
            checksum_algorithm=checksum_algorithm,
        )
    except SnapshotNotFoundError as exc:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            str(exc),
            status_code=404,
        )
    return {
        "Checksum": record.checksum,
        "ChecksumAlgorithm": record.checksum_algorithm,
    }


def _complete_snapshot(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:CompleteSnapshot`` — mark the snapshot ``completed``."""
    snapshot_id = request["SnapshotId"]
    try:
        block_store.update_snapshot_status(snapshot_id, "completed")
    except FileNotFoundError:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            f"snapshot {snapshot_id!r} not found",
            status_code=404,
        )
    return {"Status": "completed"}


def _get_snapshot_block(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:GetSnapshotBlock`` — read one block back."""
    snapshot_id = request["SnapshotId"]
    block_index = int(request["BlockIndex"])
    try:
        data, record = block_store.get_snapshot_block(
            snapshot_id=snapshot_id,
            block_index=block_index,
        )
    except SnapshotNotFoundError as exc:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            str(exc),
            status_code=404,
        )
    except BlockNotFoundError as exc:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            str(exc),
            status_code=404,
        )
    return {
        "DataLength": record.data_length,
        # The output ``BlockData`` shape is declared streaming=True in
        # the AWS EBS spec, so the serializer expects a file-like
        # object with ``.read()``. Passing bytes here crashes the
        # serializer with the same kind of ``a bytes-like object is
        # required`` shape mismatch we hit on the input side.
        "BlockData": _io.BytesIO(data),
        "Checksum": record.checksum,
        "ChecksumAlgorithm": record.checksum_algorithm,
    }


def _coerce_block_data_to_bytes(value) -> bytes:
    """Normalise the ``BlockData`` input across all shapes the runtime emits.

    The AWS EBS service-2 spec marks ``BlockData`` as ``streaming=True``,
    so the protocol parser surfaces it as a file-like wrapper
    (``botocore`` calls these ``_InputStream`` objects, but any stream
    with ``.read()`` qualifies). Inline test fixtures and the older
    LocalEmu test paths sometimes pass raw bytes, base64 strings, or
    ``bytearray``; we accept all four shapes.

    Returns the canonical ``bytes`` payload to hand off to the block
    store. ``None`` is treated as an empty block (matches AWS's
    documented "you can write a zero-length block").
    """
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if hasattr(value, "read"):
        # botocore _InputStream, BytesIO, urllib3's BodyReader, etc.
        return value.read()
    if isinstance(value, str):
        # Some inline test paths submit base64; falling through to
        # bytes-from-string would corrupt binary payloads. The
        # PutSnapshotBlock spec says blob, which boto encodes as
        # base64 only on the JSON protocol — strings here are
        # base64.
        try:
            return base64.b64decode(value, validate=False)
        except Exception:
            return value.encode("utf-8")
    raise TypeError(
        f"PutSnapshotBlock: unsupported BlockData type {type(value).__name__!r}"
    )


def _list_snapshot_blocks(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:ListSnapshotBlocks`` — enumerate the blocks."""
    snapshot_id = request["SnapshotId"]
    try:
        records = block_store.list_snapshot_blocks(snapshot_id)
        meta = block_store.read_snapshot_meta(snapshot_id)
    except SnapshotNotFoundError as exc:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            str(exc),
            status_code=404,
        )

    return {
        "Blocks": [
            {"BlockIndex": r.block_index, "BlockToken": r.block_token}
            for r in records
        ],
        "ExpiryTime": None,  # AWS sends an expiry; we never expire tokens.
        "VolumeSize": meta.volume_size_gib,
        "BlockSize": meta.block_size,
    }


def _list_changed_blocks(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """``ebs:ListChangedBlocks`` — diff two snapshots' tokens."""
    first = request.get("FirstSnapshotId")
    second = request["SecondSnapshotId"]
    try:
        changed = block_store.diff_snapshots(first, second) if first else []
        meta = block_store.read_snapshot_meta(second)
    except SnapshotNotFoundError as exc:
        from localemu.aws.api import CommonServiceException
        raise CommonServiceException(
            "ResourceNotFoundException",
            str(exc),
            status_code=404,
        )
    return {
        "ChangedBlocks": [
            {"BlockIndex": idx,
             "FirstBlockToken": tok1,
             "SecondBlockToken": tok2}
            for (idx, tok1, tok2) in changed
        ],
        "ExpiryTime": None,
        "VolumeSize": meta.volume_size_gib,
        "BlockSize": meta.block_size,
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


_INTERCEPTED_OPS = {
    "StartSnapshot": _start_snapshot,
    "PutSnapshotBlock": _put_snapshot_block,
    "CompleteSnapshot": _complete_snapshot,
    "GetSnapshotBlock": _get_snapshot_block,
    "ListSnapshotBlocks": _list_snapshot_blocks,
    "ListChangedBlocks": _list_changed_blocks,
}


def EbsDispatcher(service_model) -> DispatchTable:
    """Intercept the direct-API operations; everything else -> moto."""
    table: DispatchTable = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


def create_ebs_service() -> Service:
    """Build the EBS service. Installs the moto bridge on first call."""
    from localemu.aws.spec import load_service
    from localemu.services.ebs.moto_bridge import apply_patches

    apply_patches()
    service_model = load_service("ebs")
    return Service(
        name="ebs",
        skeleton=Skeleton(service_model, EbsDispatcher(service_model)),
    )
