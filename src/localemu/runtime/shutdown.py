import logging
import threading
from collections.abc import Callable
from typing import Any

from localemu.runtime import hooks
from localemu.utils.functions import call_safe

LOG = logging.getLogger(__name__)

SERVICE_SHUTDOWN_PRIORITY = -10
"""Shutdown hook priority for shutting down service plugins."""


class ShutdownHandlers:
    """
    Register / unregister shutdown handlers. All registered shutdown handlers should execute as fast as possible.
    Blocking shutdown handlers will block infra shutdown.
    """

    def __init__(self):
        self._callbacks = []
        self._lock = threading.Lock()
        # Guard against double-execution of shutdown handlers
        self._ran = False

    def register(self, shutdown_handler: Callable[[], Any]) -> None:
        """
        Register shutdown handler. Handler should not block or take more than a couple seconds.

        :param shutdown_handler: Callable without parameters
        """
        with self._lock:
            self._callbacks.append(shutdown_handler)

    def unregister(self, shutdown_handler: Callable[[], Any]) -> None:
        """
        Unregister a handler. Idempotent operation.

        :param shutdown_handler: Shutdown handler which was previously registered
        """
        with self._lock:
            try:
                self._callbacks.remove(shutdown_handler)
            except ValueError:
                pass

    def run(self) -> None:
        """
        Execute shutdown handlers in reverse order of registration.
        Should only be called once, on shutdown.

        Idempotent — subsequent calls are no-ops. Without this guard
        two on_infra_shutdown hooks that both invoke ``run()`` (or any code
        path that retriggers shutdown) would re-execute every callback,
        leading to duplicate side effects (double stop, double close, etc.).
        """
        with self._lock:
            if self._ran:
                return
            self._ran = True
            callbacks = list(self._callbacks)

        for callback in reversed(callbacks):
            call_safe(callback)


SHUTDOWN_HANDLERS = ShutdownHandlers()
"""Shutdown handlers run with default priority in an on_infra_shutdown hook."""

ON_AFTER_SERVICE_SHUTDOWN_HANDLERS = ShutdownHandlers()
"""Shutdown handlers that are executed after all services have been shut down."""


@hooks.on_infra_shutdown()
def run_shutdown_handlers():
    SHUTDOWN_HANDLERS.run()


@hooks.on_infra_shutdown(priority=SERVICE_SHUTDOWN_PRIORITY)
def shutdown_services():
    # TODO: this belongs into the shutdown procedure of a `Platform` or `RuntimeContainer` class.
    from localemu.services.plugins import SERVICE_PLUGINS

    LOG.info("[shutdown] Stopping all services")
    SERVICE_PLUGINS.stop_all_services()


@hooks.on_infra_shutdown(priority=SERVICE_SHUTDOWN_PRIORITY - 10)
def run_on_after_service_shutdown_handlers():
    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.run()
