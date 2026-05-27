"""Regression tests for the CloudTrail S3 log-delivery thread (D1–D7).

These correspond to the seven defects closed on 2026-04-15:

* **D1** Cursor keyed by ``(account_id, region, trail_name)`` so trails
  sharing a name across accounts/regions maintain independent cursors.
* **D2** Cursor is a monotonic ``event_time`` (datetime), so redelivery
  is avoided even when the cursor event has aged out of the 500-event
  recent window.
* **D3** Client bundle is cached by ``(account_id, region)`` — the same
  object is returned across cycles instead of leaking sockets.
* **D4** Iteration snapshots the trails dict so concurrent ``CreateTrail``
  cannot raise ``RuntimeError``.
* **D5** Per-iteration exceptions are logged at WARNING level (not
  silently swallowed) while the loop keeps going.
* **D6** Stop-then-start yields a fresh Event — the new thread's first
  ``wait()`` honors the full 60s timeout instead of spinning.
* **D7** ``_start_s3_log_delivery`` registers the shutdown handler
  exactly once, regardless of how many times it is called.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.cloudtrail import provider as ct_provider


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------
@dataclass
class FakeEvent:
    """Stand-in for CloudTrailEvent with only the attributes the delivery
    cycle reads."""

    event_id: str
    event_time: datetime
    aws_region: str

    def to_cloudtrail_event_json(self) -> str:
        return '{"eventID": "%s"}' % self.event_id


def _trail(name="trail-1", *, bucket="bkt", logging=True):
    return SimpleNamespace(
        trail_name=name,
        s3_bucket_name=bucket,
        s3_key_prefix="",
        is_logging=logging,
        kms_key_id=None,
        sns_topic_name=None,
        partition="aws",
        topic_arn=None,
    )


class FakeStore:
    def __init__(self, events):
        self._events = list(events)

    def get_recent(self, limit=500):
        # newest-first, as the real store returns
        return list(self._events[:limit])


@pytest.fixture(autouse=True)
def _reset_provider_state():
    """Ensure each test starts with a clean cursor/client cache/shutdown flag."""
    ct_provider._run_delivery_cycle._last_delivered = {}  # type: ignore[attr-defined]
    ct_provider._clear_delivery_client_cache()
    ct_provider._s3_delivery_shutdown_registered = False
    ct_provider._s3_delivery_stop = threading.Event()
    yield
    # best-effort teardown
    if ct_provider._s3_delivery_thread and ct_provider._s3_delivery_thread.is_alive():
        ct_provider._stop_s3_log_delivery()


# ---------------------------------------------------------------------------
# D1 — cursor keyed by (account_id, region, trail_name)
# ---------------------------------------------------------------------------
def test_d1_same_trail_name_across_accounts_and_regions_have_independent_cursors():
    """Two trails named ``audit`` in different (account, region) pairs must
    each deliver their own events without one trail's cursor masking the
    other."""
    now = datetime.now(timezone.utc)
    # Two events in two different regions; delivery to trail in region-A
    # must NOT advance the cursor for trail in region-B.
    evt_a = FakeEvent("evt-a", now, "us-east-1")
    evt_b = FakeEvent("evt-b", now, "eu-west-1")
    store = FakeStore([evt_a, evt_b])

    trail_a = _trail(name="audit", bucket="bkt-a")
    trail_b = _trail(name="audit", bucket="bkt-b")
    backend_a = SimpleNamespace(trails={"audit": trail_a})
    backend_b = SimpleNamespace(trails={"audit": trail_b})

    clients = SimpleNamespace(s3=MagicMock(), sns=MagicMock())

    with patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
         patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=store), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[
             ("111111111111", "us-east-1", backend_a),
             ("222222222222", "eu-west-1", backend_b),
         ]):
        ct_provider._run_delivery_cycle(threading.Event())

    # Both trails should have delivered exactly once, each to its own bucket.
    buckets_written = [call.kwargs["Bucket"] for call in clients.s3.put_object.call_args_list]
    assert "bkt-a" in buckets_written
    assert "bkt-b" in buckets_written
    assert clients.s3.put_object.call_count == 2

    # The cursor dict must contain BOTH composite keys, not one shared key.
    cursors = ct_provider._run_delivery_cycle._last_delivered
    assert ("111111111111", "us-east-1", "audit") in cursors
    assert ("222222222222", "eu-west-1", "audit") in cursors


# ---------------------------------------------------------------------------
# D2 — idempotent when cursor event ages out of the 500-event window
# ---------------------------------------------------------------------------
def test_d2_no_redelivery_when_cursor_event_ages_out():
    """Simulate: cycle 1 delivers a batch. Between cycles the event store
    rotates so the cursor event is no longer in ``get_recent``'s output,
    but newer events after the cursor time are still present. The next
    cycle must NOT redeliver the older events."""
    t0 = datetime.now(timezone.utc)
    # Cycle 1: events [e2, e1] (newest first, both older than next batch)
    e1 = FakeEvent("e1", t0, "us-east-1")
    e2 = FakeEvent("e2", t0 + timedelta(seconds=1), "us-east-1")

    trail = _trail(name="t1", bucket="bkt")
    backend = SimpleNamespace(trails={"t1": trail})
    clients = SimpleNamespace(s3=MagicMock(), sns=MagicMock())

    cycle1_store = FakeStore([e2, e1])
    with patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
         patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=cycle1_store), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[
             ("000000000000", "us-east-1", backend),
         ]):
        ct_provider._run_delivery_cycle(threading.Event())

    assert clients.s3.put_object.call_count == 1
    first_body = clients.s3.put_object.call_args.kwargs["Body"]

    # Cycle 2: e1 and e2 have aged out of the 500-event window. The store
    # now returns only [e3], which is NEWER than the cursor (e2's
    # event_time). Only e3 should be delivered; e1/e2 must NOT reappear.
    e3 = FakeEvent("e3", t0 + timedelta(seconds=10), "us-east-1")
    cycle2_store = FakeStore([e3])
    clients.s3.reset_mock()

    with patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
         patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=cycle2_store), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[
             ("000000000000", "us-east-1", backend),
         ]):
        ct_provider._run_delivery_cycle(threading.Event())

    assert clients.s3.put_object.call_count == 1
    second_body = clients.s3.put_object.call_args.kwargs["Body"]
    # The second body is distinct from the first (would be identical if e1/e2
    # were re-delivered).
    assert first_body != second_body

    # Cycle 3: no new events — store still returns [e3]. The cursor is now
    # at e3's time, so nothing should be delivered.
    clients.s3.reset_mock()
    with patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
         patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=cycle2_store), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[
             ("000000000000", "us-east-1", backend),
         ]):
        ct_provider._run_delivery_cycle(threading.Event())
    assert clients.s3.put_object.call_count == 0


# ---------------------------------------------------------------------------
# D3 — client cache returns the same instance across cycles
# ---------------------------------------------------------------------------
def test_d3_client_cache_reuses_instance_across_cycles():
    sentinel = SimpleNamespace(s3=MagicMock(), sns=MagicMock())
    calls = []

    def _fake_connect_to(**kwargs):
        calls.append(kwargs)
        return sentinel

    with patch("localemu.aws.connect.connect_to", side_effect=_fake_connect_to):
        c1 = ct_provider._get_delivery_clients("000000000000", "us-east-1")
        c2 = ct_provider._get_delivery_clients("000000000000", "us-east-1")

    assert c1 is c2
    assert len(calls) == 1, "connect_to should only be called once per (account, region)"

    # Different key -> new construction
    with patch("localemu.aws.connect.connect_to", side_effect=_fake_connect_to):
        c3 = ct_provider._get_delivery_clients("000000000000", "eu-west-1")
    assert c3 is sentinel  # our fake always returns the same sentinel
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# D4 — concurrent mutation of trails dict doesn't crash the cycle
# ---------------------------------------------------------------------------
def test_d4_concurrent_trails_mutation_does_not_crash():
    """A mutator thread keeps creating/deleting trails while the delivery
    cycle iterates. The cycle must complete without RuntimeError."""
    trails = {"t{}".format(i): _trail(name=f"t{i}") for i in range(20)}
    backend = SimpleNamespace(trails=trails)

    stop = threading.Event()

    def _mutator():
        n = 0
        while not stop.is_set():
            key = f"mut-{n}"
            trails[key] = _trail(name=key)
            trails.pop(key, None)
            n += 1

    mutator = threading.Thread(target=_mutator, daemon=True)
    mutator.start()
    try:
        clients = SimpleNamespace(s3=MagicMock(), sns=MagicMock())
        with patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
             patch(
                 "localemu.services.cloudtrail.event_store.get_event_store",
                 return_value=FakeStore([FakeEvent("e1", datetime.now(timezone.utc), "us-east-1")]),
             ), \
             patch("localemu.dashboard.api._iter_moto_backends", return_value=[
                 ("000000000000", "us-east-1", backend),
             ]):
            # Run multiple cycles to expose any race.
            for _ in range(20):
                ct_provider._run_delivery_cycle(threading.Event())
    finally:
        stop.set()
        mutator.join(timeout=2)


# ---------------------------------------------------------------------------
# D5 — exception in one iteration is logged WARNING but loop continues
# ---------------------------------------------------------------------------
def test_d5_per_trail_exception_is_logged_warning_and_loop_continues(caplog):
    """A trail that raises during processing must not abort the cycle:
    the failure is logged at WARNING and subsequent trails are still
    processed."""
    # Trail A raises on attribute access; trail B succeeds.
    class Bomb:
        @property
        def is_logging(self):
            raise RuntimeError("boom")

        # other attributes exist to avoid AttributeError before the bomb
        s3_bucket_name = "bkt-a"
        s3_key_prefix = ""

    trail_a = Bomb()
    trail_b = _trail(name="good", bucket="bkt-b")
    backend = SimpleNamespace(trails={"bad": trail_a, "good": trail_b})

    clients = SimpleNamespace(s3=MagicMock(), sns=MagicMock())
    store = FakeStore([FakeEvent("e1", datetime.now(timezone.utc), "us-east-1")])

    with caplog.at_level(logging.WARNING, logger=ct_provider.LOG.name), \
         patch.object(ct_provider, "_get_delivery_clients", return_value=clients), \
         patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=store), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[
             ("000000000000", "us-east-1", backend),
         ]):
        ct_provider._run_delivery_cycle(threading.Event())

    # The good trail still delivered.
    buckets = [c.kwargs["Bucket"] for c in clients.s3.put_object.call_args_list]
    assert "bkt-b" in buckets

    # The failure was logged at WARNING (not silently eaten).
    warning_records = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("bad" in r.getMessage() or "boom" in str(r.exc_info) for r in warning_records), \
        f"expected a WARNING mentioning the bad trail or the underlying error, got: {warning_records}"


# ---------------------------------------------------------------------------
# D6 — stop then start yields a fresh Event; new thread waits a full cycle
# ---------------------------------------------------------------------------
def test_d6_restart_uses_fresh_event_and_does_not_spin():
    """After stop, the module-global Event is set. Restart must install a
    fresh (un-set) Event so the new thread's first wait() blocks for the
    full timeout instead of returning immediately and spinning."""
    # 1) prime the state as if a previous lifecycle had completed.
    ct_provider._s3_delivery_stop.set()
    assert ct_provider._s3_delivery_stop.is_set()

    # 2) Start the delivery thread. We don't want a real 60s wait in the
    # test, so we just observe that the Event held by the new thread is
    # freshly un-set.
    with patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=FakeStore([])), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[]):
        ct_provider._start_s3_log_delivery()
        try:
            # The module-global Event has been replaced with a fresh one.
            assert not ct_provider._s3_delivery_stop.is_set(), \
                "restart must install a fresh, un-set Event to avoid a spin"
            # And the thread is alive and hasn't already exited (which is
            # what would happen if it observed a pre-set stop flag).
            assert ct_provider._s3_delivery_thread is not None
            assert ct_provider._s3_delivery_thread.is_alive()

            # Give the thread a brief moment; it should still be waiting,
            # not spinning through cycles. (If the Event were stale, the
            # loop would complete many iterations in this interval and
            # the thread would call _run_delivery_cycle repeatedly; with
            # our fresh Event it blocks in wait(60) instead.)
            time.sleep(0.1)
            assert ct_provider._s3_delivery_thread.is_alive()
        finally:
            ct_provider._stop_s3_log_delivery()


# ---------------------------------------------------------------------------
# D7 — shutdown handler registered exactly once across repeated starts
# ---------------------------------------------------------------------------
def test_d7_shutdown_handler_registered_once_across_many_starts():
    from localemu.runtime.shutdown import SHUTDOWN_HANDLERS

    ct_provider._s3_delivery_shutdown_registered = False

    # Count how many times our stop function is present in the global
    # handler list. (It may already be present from prior service boot.)
    baseline = SHUTDOWN_HANDLERS._callbacks.count(ct_provider._stop_s3_log_delivery)

    with patch("localemu.services.cloudtrail.event_store.get_event_store", return_value=FakeStore([])), \
         patch("localemu.dashboard.api._iter_moto_backends", return_value=[]):
        for _ in range(5):
            ct_provider._start_s3_log_delivery()

    try:
        after = SHUTDOWN_HANDLERS._callbacks.count(ct_provider._stop_s3_log_delivery)
        # Exactly one registration regardless of how many starts we did.
        assert after - baseline == 1, (
            f"shutdown handler registered {after - baseline} times across 5 starts; "
            "expected exactly 1"
        )
    finally:
        ct_provider._stop_s3_log_delivery()
        # Unregister so the accumulated handler doesn't leak into other tests.
        try:
            SHUTDOWN_HANDLERS.unregister(ct_provider._stop_s3_log_delivery)
        except Exception:
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
