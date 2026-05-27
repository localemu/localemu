"""Persistence wiring for the SubnetAllocator and AddressIndex.

Provides ``load_addressing_state()`` and ``save_addressing_state()``
helpers that read/write the two state files under ``~/.localemu/data/``.

The save side is registered on the SHUTDOWN_HANDLERS chain at the same
priority as the moto save (``state/persistence.py:937-947``), so it runs
before service teardown. The load side is called from
``Ec2Provider.on_after_state_load`` before the addressing reconciler
walks Docker.

Failure-tolerant: missing or corrupt files are logged and skipped; the
reconciler will rebuild from Docker + labels on next startup.
"""
from __future__ import annotations

import logging
import os
import threading

from localemu import config
from localemu.services.ec2.docker.address_index import get_address_index
from localemu.services.ec2.docker.subnet_allocator import get_subnet_allocator

LOG = logging.getLogger(__name__)

ALLOCATOR_FILENAME = "subnet_allocator.state"
INDEX_FILENAME = "address_index.state"

_save_handler_registered = False
_register_lock = threading.Lock()


def _data_dir() -> str:
    """Return the LocalEmu data directory (~/.localemu/data by default)."""
    dirs = getattr(config, "dirs", None)
    if dirs is not None and getattr(dirs, "data", None):
        return dirs.data
    return os.path.expanduser("~/.localemu/data")


def allocator_state_path() -> str:
    return os.path.join(_data_dir(), ALLOCATOR_FILENAME)


def index_state_path() -> str:
    return os.path.join(_data_dir(), INDEX_FILENAME)


def load_addressing_state() -> tuple[bool, bool]:
    """Load both state files. Returns (allocator_loaded, index_loaded)."""
    a_path = allocator_state_path()
    i_path = index_state_path()
    a_loaded = get_subnet_allocator().load_from_file(a_path)
    i_loaded = get_address_index().load_from_file(i_path)
    if a_loaded or i_loaded:
        LOG.info(
            "addressing_persistence: loaded allocator=%s index=%s",
            a_loaded, i_loaded,
        )
    return a_loaded, i_loaded


def save_addressing_state() -> None:
    """Save both state files. Tolerates errors per-file."""
    try:
        get_subnet_allocator().save_to_file(allocator_state_path())
    except Exception:
        LOG.warning(
            "addressing_persistence: failed to save allocator state",
            exc_info=True,
        )
    try:
        get_address_index().save_to_file(index_state_path())
    except Exception:
        LOG.warning(
            "addressing_persistence: failed to save address index",
            exc_info=True,
        )


def register_save_handler() -> None:
    """Register save_addressing_state on the SHUTDOWN_HANDLERS chain.

    Idempotent. Safe to call from multiple places; only the first call
    actually registers.
    """
    global _save_handler_registered
    with _register_lock:
        if _save_handler_registered:
            return
        if not config.PERSISTENCE:
            # No persistence requested; skip registration entirely so
            # we don't write state files the user doesn't want.
            return
        try:
            from localemu.runtime.shutdown import SHUTDOWN_HANDLERS
            SHUTDOWN_HANDLERS.register(save_addressing_state)
            _save_handler_registered = True
            LOG.debug("addressing_persistence: save handler registered")
        except Exception:
            LOG.warning(
                "addressing_persistence: cannot register save handler",
                exc_info=True,
            )


def _reset_for_tests() -> None:
    """Drop the registration flag. ONLY for tests."""
    global _save_handler_registered
    with _register_lock:
        _save_handler_registered = False
