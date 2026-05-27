"""F1 regression: CloudTrail service stops its S3 delivery thread cleanly.

Before the fix, ``create_cloudtrail_service()`` returned a bare
``Service`` with no lifecycle hook. The S3 delivery background thread
was only stopped at interpreter shutdown, not on service restart.

The fix installs ``CloudTrailLifecycleHook`` whose ``on_before_stop``
calls ``_stop_s3_log_delivery``. This test verifies that stopping the
service does shut the thread down.
"""

from __future__ import annotations

import threading
import time

import pytest


@pytest.fixture(autouse=True)
def _isolate_delivery_thread():
    """Ensure we start and end each test with no delivery thread running."""
    from localemu.services.cloudtrail import provider

    provider._stop_s3_log_delivery()
    yield
    provider._stop_s3_log_delivery()


class TestCloudTrailLifecycle:
    def test_service_has_lifecycle_hook(self):
        from localemu.services.cloudtrail.provider import (
            CloudTrailLifecycleHook,
            create_cloudtrail_service,
        )

        service = create_cloudtrail_service()
        assert isinstance(service.lifecycle_hook, CloudTrailLifecycleHook)

    def test_on_before_stop_terminates_delivery_thread(self):
        from localemu.services.cloudtrail import provider
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        service = create_cloudtrail_service()
        # Delivery thread should be running after creation.
        thread = provider._s3_delivery_thread
        assert thread is not None
        assert thread.is_alive()

        # Stopping the service must terminate the thread.
        service.stop()
        # Give the thread a short grace period to exit its wait().
        for _ in range(50):
            if provider._s3_delivery_thread is None and not thread.is_alive():
                break
            time.sleep(0.05)
        assert not thread.is_alive(), (
            "CloudTrail S3 delivery thread did not stop on service.stop()"
        )
        assert provider._s3_delivery_thread is None

    def test_stop_is_idempotent(self):
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        service = create_cloudtrail_service()
        service.stop()
        # Second stop must not raise.
        service.stop()

    def test_on_before_stop_does_not_touch_other_threads(self):
        """Regression: stopping CloudTrail must not affect unrelated
        threads the process is running."""
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        sentinel_stop = threading.Event()
        sentinel = threading.Thread(
            target=sentinel_stop.wait, name="sentinel-thread", daemon=True,
        )
        sentinel.start()

        try:
            service = create_cloudtrail_service()
            service.stop()
            assert sentinel.is_alive()
        finally:
            sentinel_stop.set()
            sentinel.join(timeout=1)
