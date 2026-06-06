"""Per-account-region AWS Backup state for the bits moto doesn't model.

This carries the protected-resource index and the BackupSelection records.
Plan / Vault state still lives in moto.
"""

from __future__ import annotations

from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class BackupStore(BaseStore):
    # {selection_id (uuid str): dict shaped like AWS BackupSelection}.
    selections: dict = LocalAttribute(default=dict)
    # {resource_arn: dict shaped like AWS ProtectedResource}.
    # Populated lazily when ``CreateBackupSelection`` references an ARN.
    protected_resources: dict = LocalAttribute(default=dict)


backup_stores = AccountRegionBundle("backup", BackupStore)
