"""Regression test for the ``check_bucket_exists`` patch.

Problem: moto's ``Trail.check_bucket_exists`` consults moto's own S3
backend. LocalEmu's S3 is NOT moto-backed (it's our own provider with
its own store), so a bucket that exists per ``s3api list-buckets`` was
invisible to moto's CloudTrail — ``CreateTrail`` failed with
``S3BucketDoesNotExistException`` even though the bucket clearly existed.

The fix rewires the check to consult LocalEmu's ``s3_stores`` first,
falling back to moto only if the bucket isn't in LocalEmu's store.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_s3_store():
    """Clear LocalEmu's S3 store before and after each test."""
    from localemu.services.s3.models import s3_stores
    snapshot = dict(s3_stores)
    s3_stores.clear()
    yield
    s3_stores.clear()
    s3_stores.update(snapshot)


def _patched_trail(bucket_name: str, account_id: str = "000000000000"):
    """Build a minimal Trail-shaped object the patched check can run against.
    We don't need the full moto machinery — just the attributes the check
    uses: ``account_id``, ``partition``, and ``bucket_name``."""
    from moto.cloudtrail.models import Trail

    t = Trail.__new__(Trail)
    t.account_id = account_id
    t.partition = "aws"
    t.bucket_name = bucket_name
    return t


class TestPatchInstallation:
    def test_patch_is_installed_at_service_creation(self):
        """``create_cloudtrail_service`` installs the patch on Trail."""
        from moto.cloudtrail.models import Trail
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        # Force fresh patch install.
        create_cloudtrail_service()
        assert getattr(Trail.check_bucket_exists, "_le_patched", False) is True

    def test_patch_is_idempotent(self):
        """Calling the installer twice must not wrap twice."""
        from moto.cloudtrail.models import Trail
        from localemu.services.cloudtrail.provider import _patch_moto_bucket_check

        _patch_moto_bucket_check()
        first = Trail.check_bucket_exists
        _patch_moto_bucket_check()
        assert Trail.check_bucket_exists is first


class TestBucketCheck:
    def test_accepts_bucket_in_localemu_store(self):
        """A bucket present in s3_stores must pass the check."""
        from localemu.services.cloudtrail.provider import _patch_moto_bucket_check
        from localemu.services.s3.models import s3_stores

        _patch_moto_bucket_check()

        store = s3_stores["000000000000"]["us-east-1"]
        store.buckets["my-real-bucket"] = object()   # sentinel

        trail = _patched_trail("my-real-bucket")
        trail.check_bucket_exists()  # must not raise

    def test_rejects_unknown_bucket(self):
        """A bucket missing from both LocalEmu and moto must still error."""
        from moto.cloudtrail.models import S3BucketDoesNotExistException
        from localemu.services.cloudtrail.provider import _patch_moto_bucket_check

        _patch_moto_bucket_check()

        trail = _patched_trail("bucket-that-does-not-exist-anywhere")
        with pytest.raises(S3BucketDoesNotExistException) as ei:
            trail.check_bucket_exists()
        assert "bucket-that-does-not-exist-anywhere" in str(ei.value)
