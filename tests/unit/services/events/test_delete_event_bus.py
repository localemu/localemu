"""Regression tests for EventBridge DeleteEventBus / DeleteRule.

Before the fix, both handlers called ``store.TAGS.pop(arn, None)``, but
``TaggingService`` has no ``.pop()`` method. The call raised
``AttributeError`` after partially mutating the store — the bus was
already removed from ``store.event_buses``. The exception propagated up,
botocore saw it, applied its default retry policy, and on retry hit
``ResourceNotFoundException`` because the bus was now gone. That was
the error the user actually saw — masking the real bug entirely.

The fix uses ``TaggingService.del_resource(arn)`` (the real API; no-op
safe on missing arns). These tests lock the correct behaviour in at
the unit level so a regression fails CI before shipping.
"""

from __future__ import annotations

import pytest

from localemu.services.events.provider import (
    EventsProvider,
    ResourceNotFoundException,
    ValidationException,
    events_stores,
)
from localemu.utils.tagging import TaggingService


@pytest.fixture(autouse=True)
def _isolate_events_stores():
    """Each test starts from a clean ``events_stores`` global — otherwise
    the provider's module-level state leaks between tests."""
    snapshot = dict(events_stores)
    events_stores.clear()
    yield
    events_stores.clear()
    events_stores.update(snapshot)


# -----------------------------------------------------------------------
# 1) TaggingService API contract — the exact shape the fix depends on.
# -----------------------------------------------------------------------
class TestTaggingServiceContract:

    def test_del_resource_removes_tags(self):
        svc = TaggingService()
        svc.tag_resource("arn-x", [{"Key": "k", "Value": "v"}])
        assert svc.list_tags_for_resource("arn-x")["Tags"]
        svc.del_resource("arn-x")
        assert svc.list_tags_for_resource("arn-x")["Tags"] == []

    def test_del_resource_is_noop_on_missing_arn(self):
        svc = TaggingService()
        svc.del_resource("arn-never-tagged")  # must not raise

    def test_tagging_service_has_no_pop(self):
        """``.pop()`` was the source of the original bug. If someone ever
        adds a ``pop`` method that happens to work, they should still
        audit every call site that used to reach for it — so this guard
        fails on purpose rather than silently drifting."""
        assert not hasattr(TaggingService, "pop"), (
            "TaggingService.pop would revive the pattern that caused the "
            "DeleteEventBus/DeleteRule bug — prefer del_resource(arn)."
        )


# -----------------------------------------------------------------------
# 2) DeleteEventBus — atomic, idempotent, correct errors.
# -----------------------------------------------------------------------
class TestDeleteEventBusCleanup:

    def _setup(self):
        provider = EventsProvider()

        class _Ctx:
            region = "us-east-1"
            account_id = "000000000000"

        ctx = _Ctx()
        provider.create_event_bus(ctx, name="reg-bus")
        return provider, ctx

    def test_delete_removes_bus_from_store(self):
        provider, ctx = self._setup()
        store = provider.get_store(ctx.region, ctx.account_id)
        assert "reg-bus" in store.event_buses

        provider.delete_event_bus(ctx, name="reg-bus")

        assert "reg-bus" not in store.event_buses

    def test_delete_is_safe_on_tagged_bus(self):
        """Regression: a tagged bus used to crash the cleanup path."""
        provider, ctx = self._setup()
        arn = "arn:aws:events:us-east-1:000000000000:event-bus/reg-bus"
        store = provider.get_store(ctx.region, ctx.account_id)
        store.TAGS.tag_resource(arn, [{"Key": "Env", "Value": "test"}])

        provider.delete_event_bus(ctx, name="reg-bus")  # must not raise

        assert "reg-bus" not in store.event_buses
        assert store.TAGS.list_tags_for_resource(arn)["Tags"] == []

    def test_delete_default_bus_raises_validation(self):
        provider, ctx = self._setup()
        with pytest.raises(ValidationException):
            provider.delete_event_bus(ctx, name="default")

    def test_delete_missing_bus_raises_not_found(self):
        provider, ctx = self._setup()
        with pytest.raises(ResourceNotFoundException):
            provider.delete_event_bus(ctx, name="never-created")


# -----------------------------------------------------------------------
# 3) DeleteRule — same class of bug was present on line 804.
# -----------------------------------------------------------------------
class TestDeleteRuleCleanup:

    def _setup_with_rule(self):
        provider = EventsProvider()

        class _Ctx:
            region = "us-east-1"
            account_id = "000000000000"

        ctx = _Ctx()
        provider.create_event_bus(ctx, name="reg-bus")
        provider.put_rule(
            ctx,
            name="reg-rule",
            event_bus_name="reg-bus",
            event_pattern='{"source":["foo"]}',
        )
        return provider, ctx

    def test_delete_rule_removes_rule_from_bus(self):
        provider, ctx = self._setup_with_rule()
        store = provider.get_store(ctx.region, ctx.account_id)
        bus = store.event_buses["reg-bus"]
        assert "reg-rule" in bus.rules

        provider.delete_rule(ctx, name="reg-rule", event_bus_name="reg-bus")

        assert "reg-rule" not in bus.rules

    def test_delete_rule_is_safe_on_tagged_rule(self):
        provider, ctx = self._setup_with_rule()
        rule_arn = "arn:aws:events:us-east-1:000000000000:rule/reg-bus/reg-rule"
        store = provider.get_store(ctx.region, ctx.account_id)
        store.TAGS.tag_resource(rule_arn, [{"Key": "Owner", "Value": "team"}])

        provider.delete_rule(ctx, name="reg-rule", event_bus_name="reg-bus")

        assert store.TAGS.list_tags_for_resource(rule_arn)["Tags"] == []
