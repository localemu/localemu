"""ECS Docker backend plugin.

Handles cleanup of Docker task containers on LocalEmu shutdown,
and orphan recovery on startup.

When ``PERSISTENCE=1`` the shutdown path stops containers WITHOUT
removing them, and the startup orphan-cleanup path is skipped — the
authoritative reconciliation happens in
``EcsStateLifecycleHook.on_after_state_load`` where we have both moto
state and the live Docker snapshot in hand. When persistence is off,
the legacy nuke-everything behaviour is preserved.
"""

import logging

from localemu import config
from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_shutdown()
def cleanup_ecs_docker():
    """Tear down (or stop, under persistence) the ECS Docker containers."""
    from localemu.services.ecs.provider import _task_manager

    if not _task_manager:
        return
    if config.PERSISTENCE:
        _task_manager.stop_all_for_persistence()
    else:
        _task_manager.cleanup_all()


@hooks.on_infra_start()
def cleanup_orphaned_ecs_containers():
    """Remove orphaned ECS containers from previous crashes on startup.

    Under persistence this is a no-op: ``on_after_state_load`` performs
    the authoritative reconciliation with moto state. Without persistence
    we fall back to the legacy blanket-delete.
    """
    if config.PERSISTENCE:
        return
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT

        containers = DOCKER_CLIENT.list_containers(
            filter=["name=localemu-ecs-"], all=True,
        )
        for c in containers:
            name = c.get("name") or c.get("id") or ""
            if not name:
                continue
            try:
                DOCKER_CLIENT.remove_container(name, force=True)
                LOG.info("Cleaned up orphaned ECS container: %s", name)
            except Exception:
                pass
    except Exception:
        LOG.debug("Orphan ECS cleanup skipped", exc_info=True)
