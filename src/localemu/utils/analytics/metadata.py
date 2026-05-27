"""Inert no-op client-metadata shim — no machine fingerprint, no persistence.

The original LocalStack-era implementation here wrote a salted persistent
machine fingerprint to ``~/.cache/localemu/machine.json`` and shipped a
``ClientMetadata`` dataclass populated with the user's API key/auth token
and host details, intended for inclusion in telemetry events. Both behaviors
have been removed.

What remains is a minimal ``get_client_metadata()`` that returns the build
version (read from ``localemu.constants.VERSION``) so the internal info
endpoint (``services/internal.py``) keeps working. Nothing is written to
disk and nothing leaves the machine.
"""

from __future__ import annotations

from dataclasses import dataclass

from localemu.constants import VERSION


@dataclass
class ClientMetadata:
    """Minimal client metadata. Used only by the local /info endpoint."""

    version: str = VERSION


def get_client_metadata() -> ClientMetadata:
    """Return inert client metadata. No machine fingerprint, no network, no disk write."""
    return ClientMetadata()
