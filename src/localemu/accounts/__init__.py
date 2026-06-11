"""Central account registry shared across all services.

The registry is the canonical list of AWS account IDs known to this LocalEmu
instance. It is populated:

* implicitly, every time the auth chain resolves a new 12-digit account ID
  from an inbound access key (via :class:`AccountIdEnricher`);
* explicitly, via the Organizations service when ``CreateAccount`` runs;
* explicitly, via the admin endpoint ``POST /_localemu/api/accounts``.

The registry is used by the dashboard, by the admin endpoint, and by the
cross-account resource-policy evaluator to resolve "which account owns
this access key / this resource".
"""

from .registry import (
    AccountRecord,
    AccountRegistry,
    accounts_stores,
    get_registry,
)

__all__ = [
    "AccountRecord",
    "AccountRegistry",
    "accounts_stores",
    "get_registry",
]
