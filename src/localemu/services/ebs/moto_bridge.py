"""Bridge moto's EC2 backend into the LocalEmu EBS block store.

Real AWS exposes a single volume/snapshot identity space across both
the EC2 API (``ec2:CreateSnapshot``, ``ec2:CreateVolume``,
``ec2:DeleteSnapshot``, ``ec2:DeleteVolume``) and the EBS direct API
(``ebs:ListSnapshotBlocks``, ``ebs:GetSnapshotBlock``,
``ebs:StartSnapshot``, ``ebs:PutSnapshotBlock``, etc.). Moto's two
backends (``moto.ec2`` and ``moto.ebs``) maintain separate dicts and
do not bridge: a snapshot created via ``ec2:CreateSnapshot`` is
invisible to ``ebs:ListSnapshotBlocks``, causing a 500 InternalError
(``KeyError`` inside ``EBSBackend.list_snapshot_blocks``).

This module wires that bridge:

* Every ``ec2:CreateSnapshot`` now also creates a block-store entry
  for the snapshot. If the source volume had block data (from
  previous ``PutSnapshotBlock`` writes flowing through the volume's
  backing store), those blocks are copied into the snapshot so a
  later ``GetSnapshotBlock`` / a restored volume returns the same
  bytes — matching real AWS's copy-on-snapshot semantics.

* Every ``ec2:CreateVolume`` with ``SnapshotId`` inherits the source
  snapshot's blocks into the new volume's backing store, so reads
  through the EBS direct API on the restored volume's later snapshots
  see the data again.

* Every ``ec2:DeleteSnapshot`` / ``ec2:DeleteVolume`` removes the
  matching block-store directory so disk doesn't grow without bound.

Patches are applied once per process via :func:`apply_patches`
(idempotent) — called from :mod:`localemu.services.providers` when
the EBS service is first asked to start.
"""
from __future__ import annotations

import logging

from localemu.services.ebs import block_store

LOG = logging.getLogger(__name__)


_APPLIED = False


def apply_patches() -> None:
    """Install the moto-ec2 → block-store hooks. Idempotent.

    Wraps ``EC2Backend.create_snapshot`` /
    ``EC2Backend.create_volume`` / ``EC2Backend.delete_snapshot`` /
    ``EC2Backend.delete_volume`` so the block store stays in sync
    with moto's EC2 model on every relevant mutation.
    """
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    from moto.ec2.models.elastic_block_store import EBSBackend as _EC2EbsBackend

    # Save the originals so we can re-enter them. We do NOT use the
    # ``@patch`` helper here (which is set up for boto/botocore method
    # interception) because we're patching plain Python methods on a
    # mutable class with no decorator-friendly contract — straight
    # assignment is clearest.
    original_create_snapshot = _EC2EbsBackend.create_snapshot
    original_create_volume = _EC2EbsBackend.create_volume
    original_delete_snapshot = _EC2EbsBackend.delete_snapshot
    original_delete_volume = _EC2EbsBackend.delete_volume

    def _patched_create_snapshot(
        self, volume_id, description, owner_id=None, from_ami=None,
    ):
        snapshot = original_create_snapshot(
            self, volume_id, description, owner_id=owner_id, from_ami=from_ami,
        )
        try:
            owner = owner_id or getattr(self, "account_id", "000000000000")
            volume_size_gib = int(getattr(snapshot.volume, "size", 0) or 0)
            block_store.create_snapshot(
                snapshot_id=snapshot.id,
                owner_id=str(owner),
                volume_size_gib=volume_size_gib,
                parent_snapshot_id=None,
                description=description or "",
                status="completed",
            )
            # Copy source-volume's blocks into the snapshot (snapshot of
            # a volume that had content returns that content via the EBS
            # direct API later).
            block_store.copy_volume_to_snapshot(
                volume_id=volume_id,
                snapshot_id=snapshot.id,
            )
        except Exception as exc:
            # Failing the block-store mirror must NOT fail the EC2
            # CreateSnapshot call itself — that's user-visible API.
            # We log so the regression is observable.
            LOG.warning(
                "block-store mirror failed for ec2:CreateSnapshot(%s -> %s): %s",
                volume_id, snapshot.id, exc, exc_info=True,
            )
        return snapshot

    def _patched_create_volume(
        self, size, zone_name,
        snapshot_id=None, encrypted=False, kms_key_id=None,
        volume_type=None, iops=None, throughput=None,
        multi_attach_enabled=None,
    ):
        volume = original_create_volume(
            self, size, zone_name,
            snapshot_id=snapshot_id, encrypted=encrypted, kms_key_id=kms_key_id,
            volume_type=volume_type, iops=iops, throughput=throughput,
            multi_attach_enabled=multi_attach_enabled,
        )
        try:
            owner = getattr(self, "account_id", "000000000000")
            size_gib = int(getattr(volume, "size", 0) or 0)
            block_store.create_volume(
                volume_id=volume.id,
                owner_id=str(owner),
                size_gib=size_gib,
                source_snapshot_id=snapshot_id,
            )
            if snapshot_id:
                block_store.copy_snapshot_to_volume(
                    snapshot_id=snapshot_id,
                    volume_id=volume.id,
                )
        except Exception as exc:
            LOG.warning(
                "block-store mirror failed for ec2:CreateVolume(snap=%s -> %s): %s",
                snapshot_id, volume.id, exc, exc_info=True,
            )
        return volume

    def _patched_delete_snapshot(self, snapshot_id):
        result = original_delete_snapshot(self, snapshot_id)
        try:
            block_store.delete_snapshot(snapshot_id)
        except Exception as exc:
            LOG.debug("block-store delete_snapshot(%s) failed: %s", snapshot_id, exc)
        return result

    def _patched_delete_volume(self, volume_id):
        result = original_delete_volume(self, volume_id)
        try:
            block_store.delete_volume(volume_id)
        except Exception as exc:
            LOG.debug("block-store delete_volume(%s) failed: %s", volume_id, exc)
        return result

    _EC2EbsBackend.create_snapshot = _patched_create_snapshot
    _EC2EbsBackend.create_volume = _patched_create_volume
    _EC2EbsBackend.delete_snapshot = _patched_delete_snapshot
    _EC2EbsBackend.delete_volume = _patched_delete_volume

    LOG.info("LocalEmu EBS moto-bridge patches applied")
