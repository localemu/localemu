"""Unit tests for the CloudFront provider's OAC/OAI binding bookkeeping.

The binding registry is consumed by the Phase 2 S3 data-plane guard: when
a bucket is locked behind an OAC, direct S3 reads from outside our
CloudFront router must be denied.
"""

from __future__ import annotations

from localemu.services.cloudfront.models import get_cloudfront_store
from localemu.services.cloudfront.provider import CloudFrontProvider


ACCT = "000000000000"


def _reset_store():
    """Wipe the cloudfront store for a clean test."""
    store = get_cloudfront_store(ACCT)
    store.oac_bucket_bindings.clear()
    store.oai_bucket_bindings.clear()


def _distribution_response(origins):
    return {
        "Distribution": {
            "DistributionConfig": {
                "Origins": {"Items": origins},
            },
        },
    }


class TestRegisterFromConfig:
    """Direct ``_register_origin_bindings_from_config`` path — the one actually
    used at runtime because moto doesn't preserve OriginAccessControlId on
    round-trip. Register straight from the caller's request payload.
    """

    def setup_method(self):
        _reset_store()

    def test_from_config_extracts_oac(self):
        provider = CloudFrontProvider()
        provider._register_origin_bindings_from_config(
            {
                "Origins": {"Items": [{
                    "DomainName": "config-bucket.s3.amazonaws.com",
                    "OriginAccessControlId": "OACX",
                }]},
            },
            ACCT,
        )
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings == {"arn:aws:s3:::config-bucket": {"OACX"}}

    def test_from_config_handles_empty_config(self):
        provider = CloudFrontProvider()
        provider._register_origin_bindings_from_config({}, ACCT)
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings == {}
        assert store.oai_bucket_bindings == {}


class TestRegisterOriginBindings:
    def setup_method(self):
        _reset_store()

    def test_s3_origin_with_oac_registers_binding(self):
        provider = CloudFrontProvider()
        response = _distribution_response([{
            "DomainName": "my-bucket.s3.amazonaws.com",
            "OriginAccessControlId": "OAC1",
        }])
        provider._register_origin_bindings(response, ACCT)
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings == {
            "arn:aws:s3:::my-bucket": {"OAC1"},
        }

    def test_s3_origin_with_regional_domain_registers(self):
        provider = CloudFrontProvider()
        response = _distribution_response([{
            "DomainName": "my-bucket.s3.us-west-2.amazonaws.com",
            "OriginAccessControlId": "OAC2",
        }])
        provider._register_origin_bindings(response, ACCT)
        store = get_cloudfront_store(ACCT)
        assert "arn:aws:s3:::my-bucket" in store.oac_bucket_bindings
        assert store.oac_bucket_bindings["arn:aws:s3:::my-bucket"] == {"OAC2"}

    def test_multiple_oacs_on_same_bucket_accumulate(self):
        provider = CloudFrontProvider()
        provider._register_origin_bindings(
            _distribution_response([{
                "DomainName": "shared.s3.amazonaws.com",
                "OriginAccessControlId": "OAC1",
            }]),
            ACCT,
        )
        provider._register_origin_bindings(
            _distribution_response([{
                "DomainName": "shared.s3.amazonaws.com",
                "OriginAccessControlId": "OAC2",
            }]),
            ACCT,
        )
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings["arn:aws:s3:::shared"] == {"OAC1", "OAC2"}

    def test_legacy_oai_format_is_parsed(self):
        provider = CloudFrontProvider()
        response = _distribution_response([{
            "DomainName": "legacy-bucket.s3.amazonaws.com",
            "S3OriginConfig": {
                "OriginAccessIdentity": "origin-access-identity/cloudfront/E12345",
            },
        }])
        provider._register_origin_bindings(response, ACCT)
        store = get_cloudfront_store(ACCT)
        assert store.oai_bucket_bindings == {
            "arn:aws:s3:::legacy-bucket": {"E12345"},
        }

    def test_custom_origin_does_not_create_s3_binding(self):
        """An HTTP origin pointing at a user-controlled domain should not
        spuriously be treated as an S3 bucket binding."""
        provider = CloudFrontProvider()
        response = _distribution_response([{
            "DomainName": "origin.example.com",
            "CustomOriginConfig": {"HTTPPort": 80},
        }])
        provider._register_origin_bindings(response, ACCT)
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings == {}
        assert store.oai_bucket_bindings == {}

    def test_missing_origins_section_is_tolerated(self):
        provider = CloudFrontProvider()
        provider._register_origin_bindings({"Distribution": {}}, ACCT)
        store = get_cloudfront_store(ACCT)
        assert store.oac_bucket_bindings == {}
        assert store.oai_bucket_bindings == {}


class TestDropBindings:
    def setup_method(self):
        _reset_store()

    def test_drop_oac_removes_entries_but_leaves_others(self):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings = {
            "arn:aws:s3:::a": {"OAC1", "OAC2"},
            "arn:aws:s3:::b": {"OAC2"},
        }
        provider = CloudFrontProvider()
        provider._drop_oac_bindings(oac_id="OAC2", account_id=ACCT)
        assert store.oac_bucket_bindings == {"arn:aws:s3:::a": {"OAC1"}}

    def test_drop_oac_removes_empty_bucket_entries(self):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings = {"arn:aws:s3:::only": {"OAC1"}}
        provider = CloudFrontProvider()
        provider._drop_oac_bindings(oac_id="OAC1", account_id=ACCT)
        assert store.oac_bucket_bindings == {}

    def test_drop_oai_removes_legacy_bindings(self):
        store = get_cloudfront_store(ACCT)
        store.oai_bucket_bindings = {"arn:aws:s3:::legacy": {"E12345"}}
        provider = CloudFrontProvider()
        provider._drop_oai_bindings(oai_id="E12345", account_id=ACCT)
        assert store.oai_bucket_bindings == {}


class TestConfigReaders:
    def test_propagation_seconds_defaults_to_10(self, monkeypatch):
        from localemu.services.cloudfront.provider import _propagation_seconds
        monkeypatch.delenv("CLOUDFRONT_PROPAGATION_SECONDS", raising=False)
        assert _propagation_seconds() == 10

    def test_propagation_seconds_respects_env(self, monkeypatch):
        from localemu.services.cloudfront.provider import _propagation_seconds
        monkeypatch.setenv("CLOUDFRONT_PROPAGATION_SECONDS", "30")
        assert _propagation_seconds() == 30

    def test_propagation_seconds_rejects_negative(self, monkeypatch):
        from localemu.services.cloudfront.provider import _propagation_seconds
        monkeypatch.setenv("CLOUDFRONT_PROPAGATION_SECONDS", "-5")
        assert _propagation_seconds() == 0

    def test_propagation_seconds_falls_back_on_garbage(self, monkeypatch, caplog):
        from localemu.services.cloudfront.provider import _propagation_seconds
        monkeypatch.setenv("CLOUDFRONT_PROPAGATION_SECONDS", "not-a-number")
        import logging
        with caplog.at_level(logging.WARNING,
                             logger="localemu.services.cloudfront.provider"):
            assert _propagation_seconds() == 10
        assert any("not an int" in rec.message for rec in caplog.records)

    def test_invalidation_seconds_defaults_to_5(self, monkeypatch):
        from localemu.services.cloudfront.provider import _invalidation_seconds
        monkeypatch.delenv("CLOUDFRONT_INVALIDATION_SECONDS", raising=False)
        assert _invalidation_seconds() == 5


class TestArnBuilder:
    def test_distribution_arn_shape(self):
        from localemu.services.iam_enforcement.arn_builder import build_resource_arn
        arn = build_resource_arn(
            "cloudfront", "GetDistribution",
            {"Id": "E1XYZ"}, "us-east-1", "000000000000",
        )
        assert arn == "arn:aws:cloudfront::000000000000:distribution/E1XYZ"

    def test_distribution_arn_from_distributionid(self):
        from localemu.services.iam_enforcement.arn_builder import build_resource_arn
        arn = build_resource_arn(
            "cloudfront", "GetDistribution",
            {"DistributionId": "E1XYZ"}, "us-east-1", "000000000000",
        )
        assert arn == "arn:aws:cloudfront::000000000000:distribution/E1XYZ"

    def test_wildcard_when_no_id(self):
        from localemu.services.iam_enforcement.arn_builder import build_resource_arn
        arn = build_resource_arn(
            "cloudfront", "ListDistributions",
            {}, "us-east-1", "000000000000",
        )
        assert arn == "arn:aws:cloudfront::000000000000:*"

    def test_passthrough_existing_arn(self):
        from localemu.services.iam_enforcement.arn_builder import build_resource_arn
        full = "arn:aws:cloudfront::000000000000:distribution/E2"
        arn = build_resource_arn(
            "cloudfront", "GetDistribution",
            {"Id": full}, "us-east-1", "000000000000",
        )
        assert arn == full
