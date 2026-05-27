"""Regression test for B3 — CreateTrail / UpdateTrail must validate the
``KmsKeyId`` against LocalEmu's native KMS store and raise a CloudTrail-
shaped ``KmsKeyNotFoundException`` when the key is absent.
"""

from __future__ import annotations

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.cloudtrail.provider import _validate_kms_key_id


@pytest.fixture(autouse=True)
def _isolate_kms_store():
    from localemu.services.kms.models import kms_stores
    snapshot = dict(kms_stores)
    kms_stores.clear()
    yield
    kms_stores.clear()
    kms_stores.update(snapshot)


def _seed_key(account_id: str, region: str, key_id: str):
    """Seed a minimal KMS key in the native store. The validator only
    looks at ``store.keys[key_id]`` membership, so a sentinel value is
    sufficient."""
    from localemu.services.kms.models import kms_stores

    kms_stores[account_id][region].keys[key_id] = object()


class TestKmsValidation:
    def test_none_or_empty_passes(self):
        # A trail with no KmsKeyId configured is valid.
        _validate_kms_key_id(None, "000000000000", "us-east-1")  # type: ignore[arg-type]
        _validate_kms_key_id("", "000000000000", "us-east-1")

    def test_unknown_key_id_raises_kms_key_not_found(self):
        with pytest.raises(CommonServiceException) as ei:
            _validate_kms_key_id(
                "00000000-1111-2222-3333-444444444444",
                "000000000000",
                "us-east-1",
            )
        assert ei.value.code == "KmsKeyNotFoundException"
        assert ei.value.status_code == 400
        assert ei.value.sender_fault is True

    def test_known_key_id_passes(self):
        key_id = "00000000-1111-2222-3333-444444444444"
        _seed_key("000000000000", "us-east-1", key_id)
        _validate_kms_key_id(key_id, "000000000000", "us-east-1")

    def test_key_arn_with_matching_region_passes(self):
        key_id = "00000000-1111-2222-3333-444444444444"
        _seed_key("000000000000", "us-east-1", key_id)
        _validate_kms_key_id(
            f"arn:aws:kms:us-east-1:000000000000:key/{key_id}",
            "000000000000",
            "us-east-1",
        )

    def test_key_arn_with_region_mismatch_raises(self):
        key_id = "00000000-1111-2222-3333-444444444444"
        _seed_key("000000000000", "eu-west-1", key_id)
        with pytest.raises(CommonServiceException) as ei:
            _validate_kms_key_id(
                f"arn:aws:kms:eu-west-1:000000000000:key/{key_id}",
                "000000000000",
                "us-east-1",
            )
        assert ei.value.code == "KmsKeyNotFoundException"

    def test_unknown_alias_raises(self):
        with pytest.raises(CommonServiceException) as ei:
            _validate_kms_key_id(
                "alias/does-not-exist", "000000000000", "us-east-1"
            )
        assert ei.value.code == "KmsKeyNotFoundException"


class TestCreateTrailIntegration:
    """B3 end-to-end — the CreateTrail intercept calls _validate_kms_key_id
    before handing off to moto."""

    def test_create_trail_rejects_bogus_kms_key(self):
        from localemu.aws.api import RequestContext
        from localemu.services.cloudtrail.provider import _handle_create_trail

        from localemu.http.request import Request
        ctx = RequestContext(Request(method="POST", path="/", body=b""))
        ctx.account_id = "000000000000"
        ctx.region = "us-east-1"

        with pytest.raises(CommonServiceException) as ei:
            _handle_create_trail(
                ctx,
                {
                    "Name": "trail-with-bad-kms",
                    "S3BucketName": "doesnt-matter",
                    "KmsKeyId": "00000000-0000-0000-0000-000000000000",
                },
            )
        assert ei.value.code == "KmsKeyNotFoundException"
