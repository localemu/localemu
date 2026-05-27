"""F3 regression: recording-hook registration is idempotent across
repeated calls and across re-imports of the hook module.

The original ``register_dashboard()`` guarded duplicate registration
with ``if _activity_handler not in run_custom_response_handlers.handlers``.
Because ``_activity_handler`` was a local closure, a second invocation
of ``register_dashboard`` created a *new* function object, so ``not in``
was always true and the handler was appended a second time.

The fix tags the module-level handler with a string attribute
``_le_handler_tag = "cloudtrail-activity-recorder"`` and uses that tag
for deduplication — survives reloads, fresh imports, any scenario that
produces a fresh function object.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _restore_response_handlers():
    from localemu.aws.handlers import run_custom_response_handlers
    snapshot = list(run_custom_response_handlers.handlers)
    yield
    run_custom_response_handlers.handlers[:] = snapshot


def _count_recorders() -> int:
    from localemu.aws.handlers import run_custom_response_handlers
    return sum(
        1 for h in run_custom_response_handlers.handlers
        if getattr(h, "_le_handler_tag", None) == "cloudtrail-activity-recorder"
    )


class TestIdempotentRegistration:
    def test_register_twice_installs_only_once(self):
        from localemu.services.cloudtrail.recording_hook import (
            register_recording_hook,
            unregister_recording_hook,
        )

        unregister_recording_hook()
        register_recording_hook()
        register_recording_hook()
        register_recording_hook()
        assert _count_recorders() == 1

    def test_register_dashboard_twice_installs_only_once(self):
        """Dashboard's ``register_dashboard`` now delegates to the named
        CloudTrail hook. Calling it twice must not duplicate."""
        from localemu.dashboard.plugins import register_dashboard
        from localemu.services.cloudtrail.recording_hook import (
            unregister_recording_hook,
        )

        unregister_recording_hook()
        register_dashboard()
        register_dashboard()
        assert _count_recorders() == 1

    def test_mixed_cloudtrail_plus_dashboard_registration(self):
        """Both CloudTrail and the dashboard may call register — the
        total count of active recorders must still be exactly 1."""
        from localemu.dashboard.plugins import register_dashboard
        from localemu.services.cloudtrail.recording_hook import (
            register_recording_hook,
            unregister_recording_hook,
        )

        unregister_recording_hook()
        register_recording_hook()
        register_dashboard()
        register_recording_hook()
        register_dashboard()
        assert _count_recorders() == 1

    def test_reimport_does_not_duplicate(self):
        """Simulate a hot reload: re-import the module and register again.
        Because we dedupe on the string tag, not the function object,
        the freshly-imported function must still be recognised."""
        import importlib

        from localemu.services.cloudtrail import recording_hook
        from localemu.services.cloudtrail.recording_hook import (
            register_recording_hook,
            unregister_recording_hook,
        )

        unregister_recording_hook()
        register_recording_hook()
        assert _count_recorders() == 1

        importlib.reload(recording_hook)
        recording_hook.register_recording_hook()
        # The reloaded module has a different function object, but the
        # tag string matches — still exactly one registration.
        assert _count_recorders() == 1
