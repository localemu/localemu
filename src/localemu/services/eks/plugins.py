"""EKS lifecycle hooks.

When ``PERSISTENCE=1``, both shutdown and startup hooks switch to the
stop-don't-delete path: ``k3d cluster stop`` preserves the k3s SQLite/etcd
state, all PVC data (in the server container's writable layer), and the
CA + port bindings. ``EksProvider.on_after_state_load`` then reconciles
the moto record set with whatever k3d still has on disk.

Without persistence the legacy blanket-delete hooks run exactly as before.
"""

from __future__ import annotations

import logging

from localemu import config
from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_shutdown()
def cleanup_eks_clusters():
    """Tear down (or stop, under persistence) the k3d EKS clusters."""
    try:
        from localemu.services.eks.provider import _cluster_manager

        if not _cluster_manager:
            return
        if config.PERSISTENCE:
            _cluster_manager.shutdown_all()
        else:
            _cluster_manager.cleanup_all()
    except Exception as e:
        LOG.debug("EKS cluster cleanup on shutdown skipped: %s", e)


@hooks.on_infra_start()
def cleanup_orphaned_eks_clusters():
    """Remove orphaned k3d clusters from previous crashes on startup.

    Under persistence this is a no-op: ``EksProvider.on_after_state_load``
    performs the authoritative moto ↔ k3d reconciliation (including
    deleting real orphans). Without persistence the legacy nuke-everything
    behaviour runs.
    """
    if config.PERSISTENCE:
        return
    try:
        import json
        import subprocess

        result = subprocess.run(
            ["k3d", "cluster", "list", "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            clusters = json.loads(result.stdout or "[]")
            for cluster in clusters:
                name = cluster.get("name", "")
                if name.startswith("localemu-eks-"):
                    try:
                        subprocess.run(
                            ["k3d", "cluster", "delete", name],
                            capture_output=True, timeout=30,
                        )
                        LOG.info("Cleaned up orphaned EKS cluster: %s", name)
                    except Exception:
                        pass
    except Exception:
        pass  # k3d not installed — skip
