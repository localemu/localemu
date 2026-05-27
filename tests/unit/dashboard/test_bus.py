"""Unit tests for the dashboard event bus.

Covers:
- Publish/subscribe fan-out
- Tag-based filtering
- ETag generation counter
- Backpressure: overflow drops oldest + sentinel
- ``is_mutating`` classifier
"""
from __future__ import annotations

import queue as _q

import pytest

from localemu.dashboard.bus import (
    HEARTBEAT_INTERVAL_SECONDS,
    MAX_QUEUED_EVENTS,
    Bus,
    is_mutating,
    publish_activity,
    publish_count,
    publish_resource_changed,
)


class TestPublishSubscribe:
    def test_subscriber_receives_published_event(self):
        b = Bus()
        sub = b.subscribe()
        b.publish("foo", ["t1"], {"x": 1})
        evt = sub.queue.get(timeout=1.0)
        assert evt.kind == "foo"
        assert evt.payload == {"x": 1}
        assert "t1" in evt.tags
        assert "*" in evt.tags  # wildcard always added

    def test_tag_filter_excludes_unrelated_events(self):
        b = Bus()
        sub = b.subscribe(("resources:lambda",))
        b.publish("activity", ["activity"], {})
        with pytest.raises(_q.Empty):
            sub.queue.get(timeout=0.1)
        b.publish("resource", ["resources:lambda"], {})
        evt = sub.queue.get(timeout=1.0)
        assert evt.kind == "resource"

    def test_multiple_subscribers_each_get_event(self):
        b = Bus()
        a = b.subscribe()
        c = b.subscribe()
        b.publish("activity", [], {})
        assert a.queue.get(timeout=0.5).kind == "activity"
        assert c.queue.get(timeout=0.5).kind == "activity"

    def test_unsubscribe_removes_from_fanout(self):
        b = Bus()
        sub = b.subscribe()
        b.unsubscribe(sub)
        b.publish("foo", ["x"], {})
        with pytest.raises(_q.Empty):
            sub.queue.get(timeout=0.1)


class TestGenerationCounter:
    def test_etag_bumps_on_publish(self):
        b = Bus()
        before = b.generation("count")
        b.publish("count", ["count"], {"service": "lambda", "count": 1})
        after = b.generation("count")
        assert after == before + 1
        # The wildcard tag is also bumped.
        assert b.generation("*") == before + 1

    def test_per_service_tag_is_independent(self):
        b = Bus()
        b.publish("resource", ["resources:lambda"], {})
        b.publish("resource", ["resources:s3"], {})
        # Each per-service tag advances exactly once.
        assert b.generation("resources:lambda") == 1
        assert b.generation("resources:s3") == 1
        # The wildcard advances on every publish.
        assert b.generation("*") == 2

    def test_etag_for_returns_quoted_weak_etag(self):
        b = Bus()
        b.publish("x", ["g"], {})
        et = b.etag_for("g")
        assert et.startswith('W/"g')
        assert et.endswith('"')


class TestBackpressure:
    def test_overflow_drops_oldest_and_inserts_sentinel(self):
        b = Bus()
        sub = b.subscribe()
        # Fill past the cap so a drop happens.
        for i in range(MAX_QUEUED_EVENTS + 5):
            b.publish("activity", ["a"], {"i": i})
        assert sub.dropped >= 1
        # Drain the queue and confirm the sentinel event appears.
        kinds: list[str] = []
        while not sub.queue.empty():
            evt = sub.queue.get_nowait()
            kinds.append(evt.kind)
        assert "dropped" in kinds


class TestHelpers:
    def test_publish_activity_helper(self, monkeypatch):
        # Replace the singleton with a fresh bus so the test is isolated.
        from localemu.dashboard import bus as bus_module

        b = Bus()
        monkeypatch.setattr(bus_module, "_bus", b)
        sub = b.subscribe()
        publish_activity(
            service="lambda",
            operation="Invoke",
            status=200,
            request_id="rid-1",
            account_id="0",
            region="us-east-1",
            source_ip="127.0.0.1",
        )
        evt = sub.queue.get(timeout=1.0)
        assert evt.kind == "activity"
        assert evt.payload["service"] == "lambda"
        assert "service:lambda" in evt.tags

    def test_publish_resource_changed_helper(self, monkeypatch):
        from localemu.dashboard import bus as bus_module

        b = Bus()
        monkeypatch.setattr(bus_module, "_bus", b)
        sub = b.subscribe()
        publish_resource_changed(service="s3", operation="CreateBucket", resource_id="b1")
        evt = sub.queue.get(timeout=1.0)
        assert evt.kind == "resource"
        assert "resources:s3" in evt.tags
        assert "count:s3" in evt.tags

    def test_publish_count_helper(self, monkeypatch):
        from localemu.dashboard import bus as bus_module

        b = Bus()
        monkeypatch.setattr(bus_module, "_bus", b)
        sub = b.subscribe()
        publish_count("lambda", 5)
        evt = sub.queue.get(timeout=1.0)
        assert evt.kind == "count"
        assert evt.payload == {"service": "lambda", "count": 5}


class TestIsMutating:
    @pytest.mark.parametrize("op", [
        "CreateBucket", "DeleteFunction", "PutItem", "UpdateTable",
        "AttachInternetGateway", "Subscribe", "Publish", "Invoke",
        "RotateSecret", "ReplicateKey", "ImportKeyMaterial",
        "RunInstances", "TerminateInstances",
    ])
    def test_mutating_ops(self, op):
        assert is_mutating(op)

    @pytest.mark.parametrize("op", [
        "GetObject", "ListBuckets", "DescribeInstances", "HeadBucket",
        "GetSecretValue", "GetParameters",
    ])
    def test_read_only_ops(self, op):
        assert not is_mutating(op)


class TestShutdown:
    def test_shutdown_enqueues_closed_event_to_each_subscriber(self):
        b = Bus()
        sub_a = b.subscribe(name="a")
        sub_b = b.subscribe(name="b")

        b.shutdown()

        evt_a = sub_a.queue.get(timeout=1.0)
        evt_b = sub_b.queue.get(timeout=1.0)
        assert evt_a.kind == "closed"
        assert evt_b.kind == "closed"
        assert evt_a.payload.get("reason") == "infra shutdown"

    def test_shutdown_is_safe_with_no_subscribers(self):
        b = Bus()
        # Must not raise even when nobody is subscribed.
        b.shutdown()

    def test_shutdown_does_not_block_publishers(self):
        # If shutdown happens before a publisher's call lands, the
        # publisher must still complete without raising. The closed
        # sentinel arrives ahead of any later events; both end up in
        # the queue.
        b = Bus()
        sub = b.subscribe()
        b.shutdown()
        b.publish(kind="activity", tags=("s3",), payload={"x": 1})

        first = sub.queue.get(timeout=1.0)
        second = sub.queue.get(timeout=1.0)
        assert first.kind == "closed"
        assert second.kind == "activity"
