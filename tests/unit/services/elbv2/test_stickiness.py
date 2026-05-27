"""Tests for ELBv2 ``lb_cookie`` stickiness — the pure helpers and the
moto attribute reader.

End-to-end pinning under a real HTTP listener is exercised by the
ALB-stickiness E2E in tests/e2e/.
"""
from __future__ import annotations

import time
from unittest import mock

import boto3
import pytest
from moto import mock_aws

from localemu.services.elbv2 import stickiness as sk


class TestParseAwsalbCookie:
    def test_single_cookie(self):
        assert sk.parse_awsalb_cookie("AWSALB=abc123") == "abc123"

    def test_multiple_cookies(self):
        assert sk.parse_awsalb_cookie(
            "session=foo; AWSALB=mytarget; tz=UTC",
        ) == "mytarget"

    def test_missing_returns_none(self):
        assert sk.parse_awsalb_cookie("session=foo") is None
        assert sk.parse_awsalb_cookie("") is None

    def test_empty_value_returns_none(self):
        assert sk.parse_awsalb_cookie("AWSALB=") is None


class TestBuildSetCookie:
    def test_http_omits_secure(self):
        cookie = sk.build_set_cookie("opaque", 3600, secure=False)
        assert "AWSALB=opaque" in cookie
        assert "Path=/" in cookie
        assert "Max-Age=3600" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" not in cookie

    def test_https_includes_secure(self):
        cookie = sk.build_set_cookie("opaque", 3600, secure=True)
        assert "Secure" in cookie

    def test_clamps_negative_duration(self):
        cookie = sk.build_set_cookie("opaque", -10, secure=False)
        assert "Max-Age=1" in cookie


class TestFreshCookieId:
    def test_has_enough_entropy(self):
        ids = {sk.fresh_cookie_id() for _ in range(100)}
        assert len(ids) == 100  # all distinct

    def test_url_safe(self):
        for _ in range(20):
            i = sk.fresh_cookie_id()
            assert all(c.isalnum() or c in "-_" for c in i), i


class TestStickyStore:
    def test_remember_then_lookup(self):
        s = sk.StickyStore()
        s.remember("c1", "i-A:80", duration=60)
        pin = s.lookup("c1")
        assert pin is not None
        assert pin.target_key == "i-A:80"

    def test_lookup_unknown_returns_none(self):
        assert sk.StickyStore().lookup("unknown") is None

    def test_lookup_empty_cookie_returns_none(self):
        assert sk.StickyStore().lookup("") is None

    def test_expired_pin_is_dropped(self):
        s = sk.StickyStore()
        s.remember("c1", "i-A:80", duration=60)
        # Force expiry by mutating the stored pin
        s.pins["c1"].expires_at = time.time() - 1
        assert s.lookup("c1") is None
        # And it's been evicted from the store
        assert "c1" not in s.pins

    def test_forget(self):
        s = sk.StickyStore()
        s.remember("c1", "i-A:80", duration=60)
        s.forget("c1")
        assert s.lookup("c1") is None


class TestParseTargetGroupArn:
    def test_extracts_account_and_region(self):
        arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web/abcd"
        assert sk.parse_target_group_arn(arn) == ("123456789012", "us-east-1")

    def test_unparseable_returns_empty(self):
        assert sk.parse_target_group_arn("not-an-arn") == ("", "")
        assert sk.parse_target_group_arn("") == ("", "")


class TestReadStickinessConfigAgainstMoto:
    @mock_aws
    def test_disabled_by_default(self):
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        # Need a minimal LB topology — create a VPC+subnet first
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
        )["Subnet"]
        tg = elbv2.create_target_group(
            Name="tg-sticky-off", Protocol="HTTP", Port=80,
            VpcId=vpc["VpcId"], TargetType="ip",
        )["TargetGroups"][0]
        cfg = sk.read_stickiness_config(tg["TargetGroupArn"])
        assert cfg.enabled is False
        assert cfg.type == "lb_cookie"

    @mock_aws
    def test_enabled_lb_cookie_reads_duration(self):
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")
        tg = elbv2.create_target_group(
            Name="tg-sticky-on", Protocol="HTTP", Port=80,
            VpcId=vpc["VpcId"], TargetType="ip",
        )["TargetGroups"][0]
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg["TargetGroupArn"],
            Attributes=[
                {"Key": "stickiness.enabled", "Value": "true"},
                {"Key": "stickiness.type", "Value": "lb_cookie"},
                {"Key": "stickiness.lb_cookie.duration_seconds", "Value": "7200"},
            ],
        )
        cfg = sk.read_stickiness_config(tg["TargetGroupArn"])
        assert cfg.enabled is True
        assert cfg.type == "lb_cookie"
        assert cfg.cookie_duration == 7200

    def test_invalid_arn_falls_back_to_disabled(self):
        cfg = sk.read_stickiness_config("not-an-arn")
        assert cfg.enabled is False

    def test_missing_moto_backend_is_safe(self):
        # ARN looks well-formed but the account/region has no TG —
        # moto returns no backend; we must not crash.
        arn = "arn:aws:elasticloadbalancing:us-east-1:999999999999:targetgroup/nope/abcd"
        with mock.patch(
            "moto.backends.get_backend",
            side_effect=KeyError("no such backend"),
        ):
            cfg = sk.read_stickiness_config(arn)
        assert cfg.enabled is False
