"""RDS Docker backend plugin.

Handles cleanup of Docker database containers on LocalEmu shutdown.

When ``PERSISTENCE=1`` the shutdown path stops containers without removing
them so ``RdsProvider.on_after_state_load`` can resume them in place on
the next ``localemu start``. When persistence is off, the legacy destructive
cleanup is preserved so short-lived CI runs behave as they did before.
"""

import logging

from localemu import config
from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_shutdown()
def cleanup_rds_docker():
    """Tear down (or stop, under persistence) the RDS Docker containers."""
    from localemu.services.rds.provider import _db_manager

    if not _db_manager:
        return
    if config.PERSISTENCE:
        _db_manager.shutdown_all()
    else:
        _db_manager.cleanup_all()
