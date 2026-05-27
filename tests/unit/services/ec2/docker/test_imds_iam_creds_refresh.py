"""Tests for the IMDS IAM-credentials auto-refresh path.

Closes audit bug #15: previously, ``_get_iam_credentials`` returned a
static dict cached at instance create time. The cached set carries a
6-hour Expiration, after which AWS SDK clients (boto3, awscli, the
Go/Java SDKs, cloud-init) re-poll IMDS and get the SAME stale dict
back. Long-running workloads inside an EC2 instance then hit
ExpiredToken on every AWS API call.

The fix: on each IMDS IAM-creds request, if the cached set is
within 15 minutes of expiry (or already expired), call STS
AssumeRole again to mint a fresh 6-hour session and update the
cache in place.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import boto3
import pytest
from moto import mock_aws

from localemu.services.ec2.docker.imds import (
    _CRED_REFRESH_WINDOW_SECONDS,
    _refresh_iam_credentials_if_needed,
)


def _mk_role(role_name: str) -> str:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
    )
    return f"arn:aws:iam::123456789012:role/{role_name}"


class TestRefreshLogic:
    def test_no_role_returns_none(self):
        meta = {"instance_id": "i-1", "account_id": "123456789012",
                "region": "us-east-1"}
        assert _refresh_iam_credentials_if_needed(meta) is None

    def test_no_role_with_cached_creds_returns_cached(self):
        """Edge: role removed but cache lingers — return whatever's
        cached without trying to re-mint (no role name to assume)."""
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1",
            "iam_credentials": {"AccessKeyId": "old", "Token": "old"},
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result == {"AccessKeyId": "old", "Token": "old"}

    @mock_aws
    def test_fresh_cache_is_not_refreshed(self):
        """When Expiration is well in the future, the cached set is
        returned verbatim and no STS call is made."""
        _mk_role("test-role-fresh")
        future = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "test-role-fresh",
            "iam_credentials": {
                "Code": "Success", "AccessKeyId": "AKIA-CACHED-1",
                "SecretAccessKey": "secret-cached", "Token": "token-cached",
                "Expiration": future,
            },
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result["AccessKeyId"] == "AKIA-CACHED-1"
        # Cache untouched
        assert meta["iam_credentials"]["AccessKeyId"] == "AKIA-CACHED-1"

    @mock_aws
    def test_near_expiry_triggers_refresh(self):
        """When Expiration is within the refresh window, a fresh
        STS AssumeRole is issued and the cache is updated."""
        _mk_role("test-role-stale")
        near_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "test-role-stale",
            "iam_credentials": {
                "Code": "Success", "AccessKeyId": "AKIA-OLD",
                "SecretAccessKey": "secret-old", "Token": "token-old",
                "Expiration": near_expiry,
            },
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result["AccessKeyId"] != "AKIA-OLD", (
            "Near-expiry creds should have been re-minted"
        )
        # Cache mutated in place
        assert meta["iam_credentials"]["AccessKeyId"] == result["AccessKeyId"]
        # Fresh Expiration is far in the future
        new_expiry = datetime.fromisoformat(result["Expiration"])
        remaining = (new_expiry - datetime.now(timezone.utc)).total_seconds()
        assert remaining > _CRED_REFRESH_WINDOW_SECONDS

    @mock_aws
    def test_already_expired_triggers_refresh(self):
        _mk_role("test-role-expired")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "test-role-expired",
            "iam_credentials": {
                "Code": "Success", "AccessKeyId": "AKIA-EXPIRED",
                "SecretAccessKey": "secret-expired", "Token": "token-expired",
                "Expiration": past,
            },
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result["AccessKeyId"] != "AKIA-EXPIRED"

    @mock_aws
    def test_malformed_expiration_triggers_refresh(self):
        """Defensive: a bad Expiration string shouldn't crash — treat
        as needing refresh."""
        _mk_role("test-role-bad")
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "test-role-bad",
            "iam_credentials": {
                "Code": "Success", "AccessKeyId": "AKIA-BAD",
                "SecretAccessKey": "secret", "Token": "tok",
                "Expiration": "not-an-iso-string",
            },
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result["AccessKeyId"] != "AKIA-BAD"

    @mock_aws
    def test_no_cache_at_all_mints_first_set(self):
        """A role with no cached credentials triggers the initial
        mint — useful for late-attached instance profiles."""
        _mk_role("test-role-virgin")
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "test-role-virgin",
            # no iam_credentials key at all
        }
        result = _refresh_iam_credentials_if_needed(meta)
        assert result is not None
        assert "AccessKeyId" in result
        assert result["AccessKeyId"].startswith(("AKIA", "ASIA"))

    def test_sts_failure_falls_back_to_cached(self):
        """When STS re-mint raises, return whatever's cached rather
        than 404'ing — better to serve stale creds than break the
        instance's SDK calls outright."""
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        meta = {
            "instance_id": "i-1", "account_id": "123456789012",
            "region": "us-east-1", "iam_role_name": "any-role",
            "iam_credentials": {
                "Code": "Success", "AccessKeyId": "AKIA-STALE",
                "SecretAccessKey": "secret", "Token": "tok",
                "Expiration": future,
            },
        }
        with mock.patch(
            "localemu.services.ec2.docker.imds._mint_iam_credentials",
            return_value=None,
        ):
            result = _refresh_iam_credentials_if_needed(meta)
        assert result["AccessKeyId"] == "AKIA-STALE"
