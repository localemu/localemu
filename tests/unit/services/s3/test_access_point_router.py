"""Unit tests for the S3 access-point detection / resolution helpers.

The router runs early in the gateway request chain ; these tests
exercise its pure-Python pieces (regex detection, op-incompatibility
set, helper utilities) without spinning up a live LocalEmu instance.
The hostname-rewrite handler and the end-to-end resolution path are
exercised live in ``tests/e2e/test_s3_access_point_data_plane.py``.
"""

from __future__ import annotations

import pytest

from localemu.services.s3 import access_point_router as router


# --------------------------------------------------------------------------
# Detection : ARN, alias, host, LocalEmu-hybrid
# --------------------------------------------------------------------------


class TestDetectFromArn:
    def test_valid_ap_arn(self):
        form, fields = router.detect_access_point(
            "arn:aws:s3:us-east-1:000000000000:accesspoint/vault-ap", None,
        )
        assert form == "arn"
        assert fields["account"] == "000000000000"
        assert fields["region"] == "us-east-1"
        assert fields["name"] == "vault-ap"

    def test_mrap_arn_with_empty_region_is_flagged(self):
        # MRAP is out of scope for 1.1.0 ; the resolver raises a typed
        # error, but the detector reports the form so the handler can
        # surface the right AWS error.
        form, _ = router.detect_access_point(
            "arn:aws:s3::000000000000:accesspoint/global-ap", None,
        )
        assert form == "arn_mrap"

    def test_non_ap_arn_returns_none(self):
        assert router.detect_access_point(
            "arn:aws:s3:::just-a-bucket", None,
        ) is None

    def test_bare_bucket_name_returns_none_when_no_ap_record(self):
        # ``my-bucket`` could in theory be the LocalEmu-hybrid form
        # ``<name>-<account>`` ; without a matching AP record the
        # detector should fall through.
        assert router.detect_access_point("my-bucket", None) is None


class TestDetectFromAlias:
    def test_valid_alias(self):
        alias = "vault-ap-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-s3alias"
        form, fields = router.detect_access_point(alias, None)
        assert form == "alias"
        assert fields["name"] == "vault-ap"
        # 34 hex chars
        assert len(fields["rnd"]) == 34

    def test_ext_alias_for_fsx_is_detected_with_ext_flag(self):
        # FSx-backed APs (``-ext-s3alias`` suffix) are out of scope ;
        # the detector reports the form so the resolver can raise a
        # typed unsupported error.
        alias = "vault-ap-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ext-s3alias"
        form, fields = router.detect_access_point(alias, None)
        assert form == "alias"
        assert fields.get("ext") == "-ext"

    def test_non_alias_with_s3alias_suffix_does_not_match(self):
        # Random text + suffix doesn't have the 34-hex middle.
        assert router.detect_access_point(
            "vault-ap-short-s3alias", None,
        ) is None


class TestDetectFromHost:
    def test_official_aws_hostname(self):
        host = "vault-ap-000000000000.s3-accesspoint.us-east-1.amazonaws.com"
        form, fields = router.detect_access_point(None, host)
        assert form == "host"
        assert fields["name"] == "vault-ap"
        assert fields["account"] == "000000000000"
        assert fields["region"] == "us-east-1"

    def test_official_aws_hostname_with_port_in_localhost(self):
        # LocalEmu accepts the localhost variant so contract tests in a
        # CI that points the SDK at LocalEmu still match.
        host = "vault-ap-000000000000.s3-accesspoint.us-east-1.localhost:4566"
        form, _ = router.detect_access_point(None, host)
        assert form == "host"

    def test_regular_s3_host_returns_none(self):
        assert router.detect_access_point(
            None, "data-vault.s3.us-east-1.amazonaws.com",
        ) is None


# --------------------------------------------------------------------------
# AP-incompatible operation set
# --------------------------------------------------------------------------


class TestIncompatibleOps:
    @pytest.mark.parametrize("op", [
        "CreateBucket", "DeleteBucket", "ListBuckets",
        "PutBucketReplication", "PutBucketVersioning",
        "PutBucketEncryption", "PutBucketWebsite", "PutBucketPolicy",
        "PutBucketTagging", "PutBucketLogging", "PutBucketAcl",
        "PutBucketCors", "PutBucketNotificationConfiguration",
        "PutBucketLifecycleConfiguration", "DeleteBucketLifecycle",
        "PutBucketInventoryConfiguration",
        "PutBucketMetricsConfiguration",
        "PutBucketAnalyticsConfiguration",
        "PutBucketIntelligentTieringConfiguration",
        "PutBucketOwnershipControls",
        "PutObjectLockConfiguration", "GetObjectLockConfiguration",
        "PutPublicAccessBlock", "GetPublicAccessBlock",
        "DeletePublicAccessBlock",
    ])
    def test_op_in_deny_set(self, op):
        assert op in router.AP_INCOMPATIBLE_OPS

    @pytest.mark.parametrize("op", [
        # Operations that real AWS allows through an AP
        "GetObject", "PutObject", "DeleteObject", "HeadObject",
        "ListObjectsV2", "ListObjects", "ListObjectVersions",
        "CopyObject", "CreateMultipartUpload",
        "UploadPart", "CompleteMultipartUpload",
        "AbortMultipartUpload", "ListMultipartUploads", "ListParts",
        "GetObjectAcl", "PutObjectAcl",
        "GetObjectTagging", "PutObjectTagging", "DeleteObjectTagging",
        "GetObjectAttributes",
        "HeadBucket", "GetBucketAcl", "GetBucketPolicy",
        "GetBucketLocation", "GetBucketCors",
        "GetBucketNotificationConfiguration",
    ])
    def test_op_not_in_deny_set(self, op):
        assert op not in router.AP_INCOMPATIBLE_OPS


# --------------------------------------------------------------------------
# AccessPointContext dataclass
# --------------------------------------------------------------------------


class TestAccessPointContext:
    def test_dataclass_carries_every_field(self):
        ctx = router.AccessPointContext(
            arn="arn:aws:s3:us-east-1:000000000000:accesspoint/x",
            account="000000000000", region="us-east-1", name="x",
            network_origin="Internet", vpc_id=None,
            policy=None, underlying_bucket="data-vault",
        )
        assert ctx.arn.endswith("accesspoint/x")
        assert ctx.network_origin == "Internet"
        assert ctx.underlying_bucket == "data-vault"

    def test_vpc_origin_carries_vpc_id(self):
        ctx = router.AccessPointContext(
            arn="arn:aws:s3:us-east-1:000000000000:accesspoint/y",
            account="000000000000", region="us-east-1", name="y",
            network_origin="VPC", vpc_id="vpc-aaaa1111",
            policy=None, underlying_bucket="b",
        )
        assert ctx.network_origin == "VPC"
        assert ctx.vpc_id == "vpc-aaaa1111"


# --------------------------------------------------------------------------
# Error types raised on bad / unsupported inputs
# --------------------------------------------------------------------------


class TestResolverErrorTypes:
    def test_mrap_arn_raises_mrap_unsupported(self):
        with pytest.raises(router.AccessPointMrapUnsupported):
            router.resolve_access_point(
                "arn:aws:s3::000000000000:accesspoint/global-ap", None,
            )

    def test_fsx_alias_raises_fsx_unsupported(self):
        alias = "fsx-ap-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ext-s3alias"
        with pytest.raises(router.AccessPointFsxUnsupported):
            router.resolve_access_point(alias, None)

    def test_unknown_ap_arn_raises_not_found(self):
        with pytest.raises(router.AccessPointNotFound):
            router.resolve_access_point(
                "arn:aws:s3:us-east-1:000000000000:accesspoint/does-not-exist",
                None,
            )

    def test_non_ap_input_returns_none(self):
        # Returns None (not an exception) for normal bucket-style addressing.
        assert router.resolve_access_point("data-vault", None) is None
