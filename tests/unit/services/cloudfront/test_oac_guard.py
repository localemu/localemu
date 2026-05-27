"""Unit tests for the CloudFront OAC/OAI S3 guard handler.

Exercises the handler's ``__call__`` directly with synthetic contexts.
The handler is installed in the gateway chain by ``aws/app.py`` — that
wiring is covered by the Phase 2 E2E suite.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu.services.cloudfront.auth import oac_guard
from localemu.services.cloudfront.models import get_cloudfront_store


ACCT = "000000000000"


def _ctx(
    bucket: str,
    service_name: str = "s3",
    operation_name: str = "GetObject",
    headers: dict | None = None,
    account: str = ACCT,
    service_request: dict | None = None,
):
    request = SimpleNamespace(headers=(headers or {}))
    svc = SimpleNamespace(service_name=service_name) if service_name else None
    op = SimpleNamespace(name=operation_name) if operation_name else None
    req_body = service_request if service_request is not None else {"Bucket": bucket}
    return SimpleNamespace(
        request=request,
        service=svc,
        operation=op,
        service_request=req_body,
        account_id=account,
    )


def _reset_store():
    store = get_cloudfront_store(ACCT)
    store.oac_bucket_bindings.clear()
    store.oai_bucket_bindings.clear()


def _run(guard: oac_guard.OACGuard, ctx):
    """Invoke the handler with a MagicMock chain / response."""
    guard(chain=MagicMock(), context=ctx, response=MagicMock())


class TestOACGuardBehavior:
    def setup_method(self):
        _reset_store()

    def test_unlocked_bucket_is_allowed(self):
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("open-bucket"))  # must not raise

    def test_oac_locked_blocks_direct_getobject(self):
        from localemu.aws.api import CommonServiceException
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        with pytest.raises(CommonServiceException) as excinfo:
            _run(guard, _ctx("locked"))
        assert excinfo.value.code == "AccessDenied"
        assert excinfo.value.status_code == 403

    def test_oac_locked_blocks_headobject(self):
        from localemu.aws.api import CommonServiceException
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        with pytest.raises(CommonServiceException):
            _run(guard, _ctx("locked", operation_name="HeadObject"))

    def test_oai_locked_blocks_direct_read(self):
        from localemu.aws.api import CommonServiceException
        store = get_cloudfront_store(ACCT)
        store.oai_bucket_bindings["arn:aws:s3:::legacy-locked"] = {"E1"}
        guard = oac_guard.OACGuard()
        with pytest.raises(CommonServiceException):
            _run(guard, _ctx("legacy-locked"))

    def test_cloudfront_marker_header_allows_request(self):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        ctx = _ctx("locked", headers={oac_guard._DISTRIBUTION_HEADER: "E1XYZ"})
        _run(guard, ctx)  # must not raise

    def test_marker_is_case_insensitive(self):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        ctx = _ctx("locked", headers={oac_guard._DISTRIBUTION_HEADER.lower(): "E1"})
        _run(guard, ctx)


class TestShortCircuits:
    """Guard must return immediately on every non-applicable request."""

    def setup_method(self):
        _reset_store()

    def test_non_s3_service_is_ignored(self):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("locked", service_name="dynamodb"))  # must not raise

    def test_write_operation_is_not_guarded(self):
        """OAC is a read-path protection; writes (PutObject etc.) pass
        through even on locked buckets — they would fail on AWS for a
        different reason (IAM), handled by the enforcement handler."""
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("locked", operation_name="PutObject"))  # must not raise

    def test_no_service_no_op(self):
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("x", service_name=None))  # must not raise

    def test_no_operation_no_op(self):
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("x", operation_name=None))  # must not raise

    def test_missing_bucket_is_noop(self):
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("", service_request={}))  # must not raise


class TestEnvOverride:
    def setup_method(self):
        _reset_store()

    def test_disable_flag_skips_check(self, monkeypatch):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        monkeypatch.setenv("CLOUDFRONT_OAC_ENFORCE", "0")
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("locked"))  # must not raise

    @pytest.mark.parametrize("val", ["0", "false", "FALSE", "no", "off"])
    def test_various_off_values(self, monkeypatch, val):
        store = get_cloudfront_store(ACCT)
        store.oac_bucket_bindings["arn:aws:s3:::locked"] = {"OAC1"}
        monkeypatch.setenv("CLOUDFRONT_OAC_ENFORCE", val)
        guard = oac_guard.OACGuard()
        _run(guard, _ctx("locked"))


class TestSingleton:
    def test_get_handler_is_idempotent(self):
        h1 = oac_guard.get_handler()
        h2 = oac_guard.get_handler()
        assert h1 is h2
