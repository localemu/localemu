"""Moto AWS Backup overlay: register the missing URL routes + handlers.

Moto's ``backup`` URL router has no entries for ``/resources`` (which the
``ListProtectedResources`` and ``DescribeProtectedResource`` calls hit) or
for ``/backup/plans/<plan-id>/selections`` (``CreateBackupSelection``).
A request to any of those today fails with::

    InternalFailure: No moto route for service backup on path /resources/...

Real AWS returns ``200 {Results: []}`` for ListProtectedResources on a new
account, ``400 ResourceNotFoundException`` for DescribeProtectedResource on
an un-backed-up ARN, and a normal 200 for CreateBackupSelection. We add the
URL routes here and override ``BackupResponse`` with the three handler
methods so the wire-level shape matches AWS.

Idempotent: ``apply_patches`` checks a module-level flag and is safe to
call from multiple plugin entry points.
"""

from __future__ import annotations

import json
from urllib.parse import unquote

_APPLIED = False


def _backup_store(account_id: str, region: str):
    from localemu.services.backup.models import backup_stores

    return backup_stores[account_id][region]


def apply_patches() -> None:
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    from moto.backup import urls as _urls
    from moto.backup.responses import BackupResponse

    # ----- URL routes the scanner / SDK hit -----
    # Use the same capture-group names that botocore emits for these
    # operations (camelCase ``resourceArn`` and ``backupPlanId``) so that
    # ``self._get_param("resourceArn")`` inside the handler resolves via
    # the URI match. The matching for the operation name is done from
    # botocore's service-2.json patterns, not from these; the
    # registrations below only ensure that the URL reaches a Response.
    extra_paths = {
        "{0}/resources/?$": _urls.response.dispatch,
        "{0}/resources/(?P<resourceArn>[^/]+)$": _urls.response.dispatch,
        "{0}/backup/plans/(?P<backupPlanId>[^/]+)/selections/?$": (
            _urls.response.dispatch
        ),
        "{0}/backup/plans/(?P<backupPlanId>[^/]+)/selections/(?P<selectionId>[^/]+)/?$": (
            _urls.response.dispatch
        ),
    }
    _urls.url_paths.update(extra_paths)

    # ----- handler methods (added to the live BackupResponse class) -----

    def describe_protected_resource(self):
        """GET /resources/<resourceArn>.

        Returns 200 with the protected-resource record, or 400
        ``ResourceNotFoundException`` if the ARN has no entry. AWS uses
        HTTP 400 for Backup not-found, not 404.

        botocore exposes the path parameter as ``resourceArn`` (camelCase);
        ``self._get_param`` resolves it via ``self.uri_match.group``.
        """
        arn_raw = self._get_param("resourceArn") or ""
        arn = unquote(arn_raw)
        store = _backup_store(self.current_account, self.region)
        rec = store.protected_resources.get(arn)
        if rec is None:
            # 400 + typed error body matches AWS Backup's not-found shape.
            headers = {
                "status": 400,
                "X-Amzn-ErrorType": "ResourceNotFoundException",
                "Content-Type": "application/json",
            }
            body = json.dumps(
                {
                    "__type": "ResourceNotFoundException",
                    "Message": f"Resource {arn} not found.",
                }
            )
            return 400, headers, body
        return json.dumps(rec)

    def list_protected_resources(self) -> str:
        """GET /resources/."""
        store = _backup_store(self.current_account, self.region)
        results = list(store.protected_resources.values())
        return json.dumps({"Results": results})

    def create_backup_selection(self) -> str:
        """PUT /backup/plans/<backupPlanId>/selections."""
        import time
        import uuid

        plan_id = self._get_param("backupPlanId") or self._get_param("plan_id") or ""
        try:
            body = json.loads(self.body or "{}")
        except Exception:
            body = {}
        sel = body.get("BackupSelection") or {}
        selection_id = str(uuid.uuid4())
        creation_date = time.time()

        store = _backup_store(self.current_account, self.region)
        record = {
            "SelectionId": selection_id,
            "BackupPlanId": plan_id,
            "SelectionName": sel.get("SelectionName"),
            "IamRoleArn": sel.get("IamRoleArn"),
            "Resources": sel.get("Resources") or [],
            "NotResources": sel.get("NotResources") or [],
            "ListOfTags": sel.get("ListOfTags") or [],
            "Conditions": sel.get("Conditions") or {},
            "CreatorRequestId": body.get("CreatorRequestId"),
            "CreationDate": creation_date,
        }
        store.selections[selection_id] = record

        # Materialize protected-resource entries for any explicit ARN in
        # ``Resources``. A real implementation derives type from the ARN
        # service segment; we mirror the AWS shape and pull a friendly
        # ResourceType from the ARN's service:resource-class. Lazy so an
        # empty selection costs nothing.
        for resource_arn in record["Resources"]:
            res_type = _guess_resource_type(resource_arn)
            store.protected_resources[resource_arn] = {
                "ResourceArn": resource_arn,
                "ResourceType": res_type,
                "ResourceName": resource_arn.split("/")[-1],
                "LastBackupTime": creation_date,
            }

        return json.dumps(
            {
                "SelectionId": selection_id,
                "BackupPlanId": plan_id,
                "CreationDate": creation_date,
            }
        )

    BackupResponse.describe_protected_resource = describe_protected_resource
    BackupResponse.list_protected_resources = list_protected_resources
    BackupResponse.create_backup_selection = create_backup_selection


def _guess_resource_type(arn: str) -> str:
    """Map an ARN to AWS Backup's ResourceType taxonomy.

    Examples:
        arn:aws:ec2:...:instance/i-xxx          -> EC2
        arn:aws:rds:...:db:my-db                 -> RDS
        arn:aws:dynamodb:...:table/foo           -> DynamoDB
        arn:aws:s3:::my-bucket                   -> S3
        arn:aws:efs:...:file-system/fs-xxx       -> EFS

    Falls back to the uppercased service segment when unrecognized.
    """
    try:
        parts = arn.split(":")
        service = parts[2] if len(parts) > 2 else ""
        resource = parts[5] if len(parts) > 5 else ""
        mapping = {
            "ec2": "EC2",
            "rds": "RDS",
            "dynamodb": "DynamoDB",
            "s3": "S3",
            "efs": "EFS",
            "fsx": "FSx",
            "storage-gateway": "Storage Gateway",
            "docdb": "DocumentDB",
            "neptune": "Neptune",
            "redshift": "Redshift",
        }
        if service in mapping:
            return mapping[service]
        if service == "rds" and resource.startswith("cluster"):
            return "Aurora"
        return service.upper() if service else "Unknown"
    except Exception:
        return "Unknown"
