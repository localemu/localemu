"""Unit tests for router helpers that don't need the rolo ROUTER installed."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from localemu.services.cloudfront.data import router


class TestCacheKeyConstruction:
    def test_same_request_produces_same_key(self):
        k1 = router._build_cache_key(
            path="/foo/bar", query_string="", behavior={}, headers={},
        )
        k2 = router._build_cache_key(
            path="/foo/bar", query_string="", behavior={}, headers={},
        )
        assert k1 == k2

    def test_query_string_order_invariant(self):
        k1 = router._build_cache_key(
            path="/p", query_string="a=1&b=2", behavior={}, headers={},
        )
        k2 = router._build_cache_key(
            path="/p", query_string="b=2&a=1", behavior={}, headers={},
        )
        assert k1 == k2, "query string permutations must hit the same cache entry"

    def test_distinct_queries_produce_distinct_keys(self):
        k1 = router._build_cache_key(
            path="/p", query_string="a=1", behavior={}, headers={},
        )
        k2 = router._build_cache_key(
            path="/p", query_string="a=2", behavior={}, headers={},
        )
        assert k1 != k2

    def test_path_normalization(self):
        k1 = router._build_cache_key(
            path="foo//bar", query_string="", behavior={}, headers={},
        )
        k2 = router._build_cache_key(
            path="/foo/bar", query_string="", behavior={}, headers={},
        )
        assert k1 == k2


class TestNormalizedUri:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("", "/"),
            ("foo", "/foo"),
            ("/foo", "/foo"),
            ("foo//bar", "/foo/bar"),
            ("///a///b", "/a/b"),
        ],
    )
    def test_normalize(self, raw, expected):
        assert router._normalized_uri_for_cache(raw) == expected


class TestTtl:
    def test_default_ttl_from_behavior(self):
        assert router._default_ttl({"DefaultTTL": 60}) == 60

    def test_ttl_defaults_to_zero_on_missing(self):
        assert router._default_ttl({}) == 0

    def test_ttl_clamps_negative(self):
        assert router._default_ttl({"DefaultTTL": -1}) == 0

    def test_ttl_rejects_non_int(self):
        assert router._default_ttl({"DefaultTTL": "not a number"}) == 0


class TestPickOrigin:
    def test_target_id_match(self):
        origins = [{"Id": "a"}, {"Id": "b"}]
        assert router._pick_origin(origins, "b") == {"Id": "b"}

    def test_fallback_to_sole_origin_when_id_missing(self):
        """If there's only one origin, use it even if TargetOriginId doesn't match.
        Covers distributions where TargetOriginId was set to a stale value."""
        origins = [{"Id": "only"}]
        assert router._pick_origin(origins, "nonexistent") == {"Id": "only"}

    def test_returns_none_when_none_match_and_multiple_origins(self):
        origins = [{"Id": "a"}, {"Id": "b"}]
        assert router._pick_origin(origins, "c") is None

    def test_empty_origins_returns_none(self):
        assert router._pick_origin([], "a") is None


class TestOwnerAccountId:
    def test_extracts_from_arn(self):
        dist = SimpleNamespace(arn="arn:aws:cloudfront::123456789012:distribution/E1")
        assert router._owner_account_id(dist) == "123456789012"

    def test_falls_back_on_malformed_arn(self):
        dist = SimpleNamespace(arn="not-an-arn")
        assert router._owner_account_id(dist) == "000000000000"

    def test_falls_back_on_missing_arn(self):
        dist = SimpleNamespace()
        assert router._owner_account_id(dist) == "000000000000"


class TestOriginsOf:
    def test_projects_moto_origin_with_oac(self):
        moto_origin = SimpleNamespace(
            id="s3-origin", domain_name="b.s3.amazonaws.com", origin_path="",
            origin_access_control_id="OACX", s3_access_identity="",
            custom_origin=None, custom_headers=[],
        )
        dist = SimpleNamespace(
            distribution_config=SimpleNamespace(origins=[moto_origin]),
        )
        result = router._origins_of(dist)
        assert result == [{
            "Id": "s3-origin",
            "DomainName": "b.s3.amazonaws.com",
            "OriginPath": "",
            "OriginAccessControlId": "OACX",
        }]

    def test_projects_legacy_oai(self):
        moto_origin = SimpleNamespace(
            id="s3-origin", domain_name="b.s3.amazonaws.com", origin_path="",
            origin_access_control_id="",
            s3_access_identity="origin-access-identity/cloudfront/E12345",
            custom_origin=None, custom_headers=[],
        )
        dist = SimpleNamespace(
            distribution_config=SimpleNamespace(origins=[moto_origin]),
        )
        result = router._origins_of(dist)
        assert result[0]["S3OriginConfig"] == {
            "OriginAccessIdentity": "origin-access-identity/cloudfront/E12345",
        }

    def test_projects_custom_origin(self):
        custom = SimpleNamespace(http_port=80, https_port=443,
                                 protocol_policy="https-only", read_timeout=30)
        moto_origin = SimpleNamespace(
            id="custom", domain_name="origin.example.com", origin_path="/v1",
            origin_access_control_id="", s3_access_identity="",
            custom_origin=custom, custom_headers=[],
        )
        dist = SimpleNamespace(
            distribution_config=SimpleNamespace(origins=[moto_origin]),
        )
        result = router._origins_of(dist)
        assert result[0]["CustomOriginConfig"] == {
            "HTTPPort": 80, "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only", "OriginReadTimeout": 30,
        }
        assert result[0]["OriginPath"] == "/v1"
