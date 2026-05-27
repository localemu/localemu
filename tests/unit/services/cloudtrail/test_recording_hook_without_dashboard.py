"""F2 regression: CloudTrail recording hook is installed by the
CloudTrail service itself, not by the dashboard plugin.

Before the fix, ``_activity_handler`` was defined as a closure inside
``dashboard.plugins.register_dashboard``. If the dashboard plugin was
not loaded, no handler was appended to
``run_custom_response_handlers.handlers`` — so ``LookupEvents`` quietly
returned nothing and the S3 delivery thread wrote empty log files.

The fix moves registration into the CloudTrail service's lifecycle so
CloudTrail is self-sufficient.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _restore_response_handlers():
    from localemu.aws.handlers import run_custom_response_handlers
    snapshot = list(run_custom_response_handlers.handlers)
    yield
    run_custom_response_handlers.handlers[:] = snapshot


def _recorder_is_registered() -> bool:
    from localemu.aws.handlers import run_custom_response_handlers
    return any(
        getattr(h, "_le_handler_tag", None) == "cloudtrail-activity-recorder"
        for h in run_custom_response_handlers.handlers
    )


class TestRecordingHookWithoutDashboard:
    def test_creating_cloudtrail_service_installs_recording_hook(self):
        """The CloudTrail service must install the hook itself — no
        dashboard import involved."""
        from localemu.aws.handlers import run_custom_response_handlers
        from localemu.services.cloudtrail.recording_hook import (
            unregister_recording_hook,
        )
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        # Start clean: no recorder registered.
        unregister_recording_hook()
        assert not _recorder_is_registered()

        service = create_cloudtrail_service()
        try:
            assert _recorder_is_registered(), (
                "create_cloudtrail_service must register the recording hook"
            )
        finally:
            service.stop()

    def test_stopping_service_removes_recording_hook(self):
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        service = create_cloudtrail_service()
        assert _recorder_is_registered()
        service.stop()
        assert not _recorder_is_registered(), (
            "CloudTrail service.stop() must remove its recording hook"
        )

    def test_hook_is_named_module_level_function_not_closure(self):
        """F3 (companion check): the handler must be a real module-level
        function carrying the ``_le_handler_tag`` attribute, not a
        closure captured by the dashboard plugin."""
        from localemu.services.cloudtrail.recording_hook import (
            cloudtrail_activity_handler,
        )
        # Module-level function has a stable ``__qualname__`` without a
        # ``<locals>`` segment (closures produce ``register_dashboard.<locals>.<name>``).
        assert "<locals>" not in cloudtrail_activity_handler.__qualname__
        assert getattr(cloudtrail_activity_handler, "_le_handler_tag", None) == (
            "cloudtrail-activity-recorder"
        )
