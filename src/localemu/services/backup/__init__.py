"""AWS Backup partial-backend overlay.

Moto already implements ``CreateBackupPlan`` / ``CreateBackupVault`` /
``List*`` / ``Get*`` for plans and vaults. This package adds the missing
read side that scanners hit (``DescribeProtectedResource``,
``ListProtectedResources``) plus the missing write (``CreateBackupSelection``)
so the full plan -> selection -> protected-resource chain is observable.
"""
