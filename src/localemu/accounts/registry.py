"""Central account registry.

Stores the canonical list of accounts that this LocalEmu instance knows
about. Mirrors the shape of ``Organizations.Account`` so the dashboard,
the admin endpoint and the Organizations service can all consume the same
records without conversion.

The records live in the ``_universal`` slot of an :class:`AccountRegionBundle`,
so they are shared across all account-bucketed services and across all
regions. Persistence ships them through dill as a single dict; see
:mod:`localemu.state.registry`.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable

from localemu.constants import DEFAULT_AWS_ACCOUNT_ID
from localemu.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
)

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


# --------------------------------------------------------------------------
# Record
# --------------------------------------------------------------------------


@dataclass
class AccountRecord:
    """One account known to this LocalEmu instance.

    Field names match ``Organizations.Account`` so the record can be
    serialized straight into an Organizations API response without
    transformation.
    """

    Id: str
    Arn: str
    Email: str
    Name: str
    Status: str = "ACTIVE"           # ACTIVE | SUSPENDED | PENDING_CLOSURE
    JoinedMethod: str = "CREATED"    # CREATED | INVITED | IMPLICIT
    JoinedTimestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


class AccountsStore(BaseStore):
    """Cross-account store holding the registry of known accounts.

    The actual data lives in a single dict keyed by 12-digit account ID,
    declared as a :class:`CrossAccountAttribute` so it sits in the
    ``_universal`` slot and is shared across every account/region pair
    that touches the bundle.
    """

    # account_id -> AccountRecord
    accounts: dict = CrossAccountAttribute(default=dict)


# AccountRegionBundle requires a real botocore service name for region
# validation. "organizations" is the natural home for this registry; the
# bundle is shared cross-account by design (CrossAccountAttribute), so the
# specific account/region used as the access path does not matter — the
# data is in ``_universal``. We pass ``validate=False`` because
# Organizations is a global service whose valid-region list doesn't
# include the "us-east-1" we use as the access path; the cross-account
# attribute path bypasses the region semantic anyway.
accounts_stores = AccountRegionBundle("organizations", AccountsStore, validate=False)


# --------------------------------------------------------------------------
# Registry facade
# --------------------------------------------------------------------------


def _account_arn(account_id: str, org_id: str | None = None) -> str:
    """Return the AWS Organizations-style account ARN.

    Outside an organization the ARN omits the ``o-XXXX/`` org segment; the
    Organizations provider rewrites this when an org exists.
    """

    if org_id:
        return f"arn:aws:organizations::{account_id}:account/{org_id}/{account_id}"
    return f"arn:aws:organizations::{account_id}:account/{account_id}"


class AccountRegistry:
    """Thin facade over :data:`accounts_stores` for ergonomic access.

    All operations are thread-safe; mutating methods take an explicit
    re-entrant lock. The registry is a singleton — fetch it via
    :func:`get_registry`.
    """

    _lock = threading.RLock()

    def _store(self) -> AccountsStore:
        # Any account/region path returns a store whose ``accounts`` dict
        # lives in the shared ``_universal`` slot; we use the default
        # account as the access path purely for the lookup.
        return accounts_stores[DEFAULT_AWS_ACCOUNT_ID]["us-east-1"]

    def _accounts(self) -> dict[str, AccountRecord]:
        return self._store().accounts

    # ---- read paths --------------------------------------------------------

    def list(self) -> list[AccountRecord]:
        with self._lock:
            return list(self._accounts().values())

    def get(self, account_id: str) -> AccountRecord | None:
        with self._lock:
            return self._accounts().get(account_id)

    def __contains__(self, account_id: str) -> bool:
        return self.get(account_id) is not None

    # ---- write paths -------------------------------------------------------

    def ensure(
        self,
        account_id: str,
        *,
        email: str | None = None,
        name: str | None = None,
        joined_method: str = "IMPLICIT",
        org_id: str | None = None,
    ) -> AccountRecord:
        """Insert an :class:`AccountRecord` if missing, return the canonical record.

        Idempotent. Called by the auth chain on every inbound request, so
        it must be cheap and side-effect-free for the common already-present
        case.
        """
        if not _ACCOUNT_ID_RE.match(account_id):
            raise ValueError(f"{account_id!r} is not a valid 12-digit AWS account ID")

        with self._lock:
            existing = self._accounts().get(account_id)
            if existing is not None:
                return existing
            record = AccountRecord(
                Id=account_id,
                Arn=_account_arn(account_id, org_id),
                Email=email or f"{account_id}@localemu.local",
                Name=name or f"account-{account_id}",
                JoinedMethod=joined_method,
            )
            self._accounts()[account_id] = record
            return record

    def create(
        self,
        account_id: str,
        *,
        email: str | None = None,
        name: str | None = None,
        org_id: str | None = None,
    ) -> AccountRecord:
        """Explicit account creation via the admin API.

        Raises ``ValueError`` if the account already exists. Differs from
        :meth:`ensure` only in that re-creating is treated as a caller bug,
        not an idempotent no-op.
        """
        if not _ACCOUNT_ID_RE.match(account_id):
            raise ValueError(f"{account_id!r} is not a valid 12-digit AWS account ID")

        with self._lock:
            if account_id in self._accounts():
                raise ValueError(f"Account {account_id} already exists")
            record = AccountRecord(
                Id=account_id,
                Arn=_account_arn(account_id, org_id),
                Email=email or f"{account_id}@localemu.local",
                Name=name or f"account-{account_id}",
                JoinedMethod="CREATED",
            )
            self._accounts()[account_id] = record
            return record

    def suspend(self, account_id: str) -> AccountRecord | None:
        """Mark the account ``SUSPENDED`` without wiping its resources.

        Mirrors what real AWS Organizations does to closed accounts: the
        resources still exist for 90 days for billing recovery; LocalEmu
        keeps them indefinitely.
        """
        with self._lock:
            record = self._accounts().get(account_id)
            if record is None:
                return None
            record.Status = "SUSPENDED"
            return record

    def delete(self, account_id: str) -> bool:
        """Remove the record from the registry. Resources in other services
        are NOT touched (mirrors real AWS account closure semantics).
        Returns True if the record was removed, False if it didn't exist.
        """
        with self._lock:
            return self._accounts().pop(account_id, None) is not None

    def update_arn(self, account_id: str, org_id: str) -> None:
        """Recompute the Arn when an account joins or leaves an organization."""
        with self._lock:
            record = self._accounts().get(account_id)
            if record is None:
                return
            record.Arn = _account_arn(account_id, org_id)


# Singleton accessor — kept as a module-level function so callers can patch
# the underlying store in tests without dragging the class.
_REGISTRY = AccountRegistry()


def get_registry() -> AccountRegistry:
    """Return the process-wide :class:`AccountRegistry`."""
    return _REGISTRY


def all_account_ids() -> Iterable[str]:
    """Convenience for callers that just want the IDs (e.g. dashboard)."""
    return [rec.Id for rec in _REGISTRY.list()]
