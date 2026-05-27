"""S3 import handlers.

Only bucket-level configuration is replayed here; object data lives in
sidecar files and is restored by a separate pass when the user opts in
(not part of MVP). Region handling follows boto3's quirk: for
``us-east-1`` the ``CreateBucketConfiguration`` must be *omitted*
entirely, otherwise the API returns ``InvalidLocationConstraint``.
"""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.handlers import register_handler
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)


def _bucket_exists(client, bucket: str) -> bool:  # type: ignore[no-untyped-def]
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            return False
        # 403 means bucket exists but we can't access it — treat as exists.
        if code in ("403", "Forbidden"):
            return True
        raise


def _create_bucket(client, bucket: str, region: str) -> None:  # type: ignore[no-untyped-def]
    kwargs: dict[str, object] = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    client.create_bucket(**kwargs)


def _delete_bucket(client, bucket: str) -> None:  # type: ignore[no-untyped-def]
    # Empty the bucket first — S3 refuses to delete a non-empty bucket.
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = []
        for v in page.get("Versions", []) or []:
            objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []) or []:
            objects.append({"Key": m["Key"], "VersionId": m["VersionId"]})
        if objects:
            client.delete_objects(Bucket=bucket, Delete={"Objects": objects, "Quiet": True})
    client.delete_bucket(Bucket=bucket)


@register_handler("s3", "bucket")
def handle_bucket(
    resource: Resource,
    client_factory: ClientFactory,
    mode: object,
    dry_run: bool,
) -> tuple[str, str, str | None]:
    from localemu.export.importer.replay import ImportMode  # local to avoid cycle

    assert isinstance(mode, ImportMode)
    bucket = resource.resource_id

    # Early-return for dry-run BEFORE we touch the client factory — the
    # test-suite pins the invariant that a dry-run must not construct any
    # boto3 client (credential resolution is an observable side-effect).
    if dry_run:
        return ("applied", bucket, "dry-run")

    client = client_factory.get_client("s3", resource.region)

    try:
        exists = _bucket_exists(client, bucket)
    except ClientError as exc:
        return ("failed", bucket, f"head_bucket failed: {exc}")

    if exists:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", bucket, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", bucket, "already exists and mode=fail-on-existing")
        # REPLACE
        try:
            _delete_bucket(client, bucket)
        except ClientError as exc:
            return ("failed", bucket, f"delete before replace failed: {exc}")

    try:
        _create_bucket(client, bucket, resource.region)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists") and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", bucket, f"already exists ({code})")
        return ("failed", bucket, f"{code}: {exc}")

    # Best-effort application of sub-configurations. Failures here are
    # logged but do not fail the resource — the bucket itself was created.
    tags = resource.tags
    if tags:
        try:
            client.put_bucket_tagging(
                Bucket=bucket,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]},
            )
        except ClientError as exc:
            LOG.warning("put_bucket_tagging failed for %s: %s", bucket, exc)

    versioning = resource.attributes.get("versioning")
    if isinstance(versioning, dict) and versioning.get("Status") in ("Enabled", "Suspended"):
        try:
            client.put_bucket_versioning(
                Bucket=bucket,
                VersioningConfiguration={"Status": versioning["Status"]},
            )
        except ClientError as exc:
            LOG.warning("put_bucket_versioning failed for %s: %s", bucket, exc)

    return ("applied", bucket, None)
