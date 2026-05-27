"""Regression test for B5 — GetTrailStatus must return the real S3
log-delivery state recorded by the delivery thread, not moto's
``utcnow()`` lie.

The provider exposes ``_record_delivery_attempt`` so the delivery thread
(or a test) can publish delivery outcomes into a shared state dict keyed
by ``(account_id, region, trail_name)``. ``_handle_get_trail_status``
then overlays those values onto moto's response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from localemu.aws.api import RequestContext
from localemu.services.cloudtrail.provider import (
    _clear_delivery_state,
    _handle_get_trail_status,
    _record_delivery_attempt,
)


@pytest.fixture(autouse=True)
def _reset_state():
    _clear_delivery_state()
    yield
    _clear_delivery_state()


def _ctx(account="000000000000", region="us-east-1") -> RequestContext:
    # RequestContext requires a ``request``; an empty Request suffices for
    # the fields this code path reads.
    from localemu.http.request import Request

    c = RequestContext(Request(method="POST", path="/", body=b""))
    c.account_id = account
    c.region = region
    return c


class FakeBackend:
    def __init__(self, trails):
        self.trails = trails


class TestGetTrailStatusRealDelivery:
    def test_no_delivery_recorded_returns_empty(self):
        """A freshly-created trail with no delivery attempts yet must
        not return moto's synthetic ``utcnow()`` in ``LatestDeliveryTime``.
        The overlay replaces it with ``None``/empty-string."""
        trail_name = "my-trail"
        moto_response = {
            "IsLogging": True,
            "LatestDeliveryTime": datetime.now(timezone.utc),  # moto's lie
            "LatestDeliveryError": "some-stale-moto-value",
            "LatestDeliveryAttemptTime": "2020-01-01T00:00:00Z",
            "LatestDeliveryAttemptSucceeded": "true",
        }
        fake_backends = [
            ("000000000000", "us-east-1", FakeBackend({trail_name: object()})),
        ]
        with patch(
            "localemu.services.cloudtrail.provider._proxy_moto",
            return_value=moto_response,
        ), patch(
            "localemu.dashboard.api._iter_moto_backends",
            return_value=fake_backends,
        ):
            out = _handle_get_trail_status(
                _ctx(), {"Name": trail_name}
            )

        assert out["LatestDeliveryTime"] is None
        assert out["LatestDeliveryError"] == ""
        assert out["LatestDeliveryAttemptTime"] == ""
        assert out["LatestDeliveryAttemptSucceeded"] == ""
        # Moto's other fields must be preserved untouched.
        assert out["IsLogging"] is True

    def test_recorded_success_is_surfaced(self):
        trail_name = "my-trail"
        when = datetime(2026, 4, 15, 12, 34, 56, tzinfo=timezone.utc)
        _record_delivery_attempt(
            "000000000000", "us-east-1", trail_name,
            success=True, when=when,
        )

        fake_backends = [
            ("000000000000", "us-east-1", FakeBackend({trail_name: object()})),
        ]
        with patch(
            "localemu.services.cloudtrail.provider._proxy_moto",
            return_value={"IsLogging": True},
        ), patch(
            "localemu.dashboard.api._iter_moto_backends",
            return_value=fake_backends,
        ):
            out = _handle_get_trail_status(
                _ctx(), {"Name": trail_name}
            )

        assert out["LatestDeliveryTime"] == when
        assert out["LatestDeliveryError"] == ""
        assert out["LatestDeliveryAttemptTime"] == "2026-04-15T12:34:56Z"
        assert out["LatestDeliveryAttemptSucceeded"] == "true"

    def test_recorded_failure_is_surfaced(self):
        trail_name = "my-trail"
        when = datetime(2026, 4, 15, 9, 0, 0, tzinfo=timezone.utc)
        _record_delivery_attempt(
            "000000000000", "us-east-1", trail_name,
            success=False, error="NoSuchBucket", when=when,
        )

        fake_backends = [
            ("000000000000", "us-east-1", FakeBackend({trail_name: object()})),
        ]
        with patch(
            "localemu.services.cloudtrail.provider._proxy_moto",
            return_value={"IsLogging": True},
        ), patch(
            "localemu.dashboard.api._iter_moto_backends",
            return_value=fake_backends,
        ):
            out = _handle_get_trail_status(
                _ctx(), {"Name": trail_name}
            )

        # Failure does not advance LatestDeliveryTime.
        assert out["LatestDeliveryTime"] is None
        assert out["LatestDeliveryError"] == "NoSuchBucket"
        assert out["LatestDeliveryAttemptTime"] == "2026-04-15T09:00:00Z"
        assert out["LatestDeliveryAttemptSucceeded"] == "false"

    def test_arn_name_is_normalized_to_bare_trail_name(self):
        """``GetTrailStatus.Name`` may be the trail ARN; the overlay must
        still find the delivery state recorded by bare trail name."""
        trail_name = "my-trail"
        when = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
        _record_delivery_attempt(
            "000000000000", "us-east-1", trail_name,
            success=True, when=when,
        )

        fake_backends = [
            ("000000000000", "us-east-1", FakeBackend({trail_name: object()})),
        ]
        with patch(
            "localemu.services.cloudtrail.provider._proxy_moto",
            return_value={"IsLogging": True},
        ), patch(
            "localemu.dashboard.api._iter_moto_backends",
            return_value=fake_backends,
        ):
            out = _handle_get_trail_status(
                _ctx(),
                {
                    "Name": (
                        f"arn:aws:cloudtrail:us-east-1:000000000000:trail/{trail_name}"
                    ),
                },
            )
        assert out["LatestDeliveryTime"] == when
