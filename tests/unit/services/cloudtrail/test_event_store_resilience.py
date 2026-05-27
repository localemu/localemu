"""Regression tests for CloudTrail event store resilience fixes (E1..E5).

These tests map 1:1 to the five defects in the CloudTrail event store audit:

    E1 — ``save_to_disk`` must be atomic (tmp file + fsync + os.replace).
    E2 — ``load_from_disk`` must not corrupt descending-time order when the
         store is non-empty.
    E3 — Duplicate ``request_id`` must not leak stale events in the deque.
    E4 — ``MaxResults`` <= 0 must clamp server-side to 1.
    E5 — Overlapping ``save_to_disk`` calls must produce a valid final file.

The module under test is ``localemu.services.cloudtrail.event_store``.
Tests stub persistence paths via ``CloudTrailEventStore._persistence_path``
rather than engaging real config machinery — the store only cares that the
method returns a string path (or ``None`` to disable persistence).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from localemu.services.cloudtrail.event_store import (
    CloudTrailEvent,
    CloudTrailEventStore,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _mk_event(
    i: int = 0,
    *,
    request_id: str | None = None,
    t: datetime | None = None,
) -> CloudTrailEvent:
    """Build a minimal CloudTrailEvent with a stable-ish identity for assertions."""
    return CloudTrailEvent(
        event_id=f"evt-{i}",
        event_time=t or datetime.now(timezone.utc),
        event_source="s3.amazonaws.com",
        event_name="PutObject",
        aws_region="us-east-1",
        source_ip="127.0.0.1",
        user_agent="test/1.0",
        account_id="000000000000",
        read_only=False,
        username="localemu",
        access_key_id="AKIATEST",
        error_code=None,
        error_message=None,
        resources=[],
        request_id=request_id or f"req-{i}",
    )


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A fresh store whose persistence path points into tmp_path."""
    s = CloudTrailEventStore(max_events=1000)
    path = str(tmp_path / "cloudtrail_events.json")
    monkeypatch.setattr(s, "_persistence_path", lambda: path)
    return s


# ---------------------------------------------------------------------------
# E1: atomic save_to_disk
# ---------------------------------------------------------------------------
class TestE1AtomicSave:
    def test_successful_save_leaves_no_tmp_file(self, store, tmp_path):
        store.record(_mk_event(1))
        store.save_to_disk()

        final = tmp_path / "cloudtrail_events.json"
        tmp = tmp_path / "cloudtrail_events.json.tmp"
        assert final.exists(), "final persistence file must exist after save"
        assert not tmp.exists(), ".tmp file must be cleaned up on success"

        # Sanity: file contents are valid JSON and reflect the recorded event.
        data = json.loads(final.read_text())
        assert len(data) == 1
        assert data[0]["request_id"] == "req-1"

    def test_crash_mid_save_leaves_existing_file_untouched(self, store, tmp_path):
        """If os.replace raises, the previous on-disk state must survive."""
        # Seed the destination with a known-good previous save.
        store.record(_mk_event(0))
        store.save_to_disk()
        final = tmp_path / "cloudtrail_events.json"
        original_bytes = final.read_bytes()

        # Add a second event and simulate a crash right at the atomic rename.
        store.record(_mk_event(1))

        real_replace = os.replace

        def boom(src, dst):  # noqa: ANN001
            raise OSError("simulated crash during os.replace")

        with mock.patch(
            "localemu.services.cloudtrail.event_store.os.replace",
            side_effect=boom,
        ):
            # save_to_disk swallows errors (best-effort persistence); we
            # only need to verify the on-disk file is untouched.
            store.save_to_disk()

        # The original file must be byte-identical — no partial overwrite.
        assert final.read_bytes() == original_bytes
        # And no stray .tmp file should remain.
        tmp = tmp_path / "cloudtrail_events.json.tmp"
        assert not tmp.exists()

        # Sanity: real os.replace still works (we didn't leave a global
        # mock behind).
        assert real_replace is os.replace


# ---------------------------------------------------------------------------
# E2: load_from_disk ordering
# ---------------------------------------------------------------------------
class TestE2LoadOrdering:
    def test_load_into_empty_store_preserves_descending_time(self, store):
        base = datetime.now(timezone.utc)
        for i in range(5):
            store.record(_mk_event(i, t=base - timedelta(seconds=5 - i)))
        store.save_to_disk()

        # Wipe in-memory state, then load.
        store.reset()
        store.load_from_disk()

        recent = store.get_recent(limit=10)
        times = [e.event_time for e in recent]
        assert times == sorted(times, reverse=True), (
            "load_from_disk into an empty store must yield descending time order"
        )
        assert len(recent) == 5

    def test_load_into_non_empty_store_is_noop(self, store):
        # Persist an older batch.
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        for i in range(3):
            store.record(_mk_event(100 + i, t=old_time + timedelta(seconds=i)))
        store.save_to_disk()
        store.reset()

        # Live events arrive after "startup": these are newer than persisted.
        live_time = datetime.now(timezone.utc)
        for i in range(3):
            store.record(_mk_event(i, t=live_time + timedelta(seconds=i)))

        before = [e.event_id for e in store.get_recent(limit=100)]
        store.load_from_disk()
        after = [e.event_id for e in store.get_recent(limit=100)]

        # Documented behavior: no-op. The live events are untouched, the
        # persisted file is ignored to preserve descending-time ordering.
        assert after == before, "load_from_disk must not mutate a non-empty store"


# ---------------------------------------------------------------------------
# E3: duplicate request_id eviction
# ---------------------------------------------------------------------------
class TestE3DuplicateRequestId:
    def test_duplicate_request_id_evicts_stale_event(self, store):
        first = _mk_event(1, request_id="dup")
        second = _mk_event(2, request_id="dup")

        store.record(first)
        store.record(second)

        # Only the newest survives in the deque — no stale duplicate left behind.
        all_events = store.get_recent(limit=100)
        assert len(all_events) == 1
        assert all_events[0].event_id == second.event_id

        # And the index still resolves to the newest.
        resolved = store.get_by_request_id("dup")
        assert resolved is not None
        assert resolved.event_id == second.event_id

    def test_distinct_request_ids_are_preserved(self, store):
        a = _mk_event(1, request_id="rid-a")
        b = _mk_event(2, request_id="rid-b")
        store.record(a)
        store.record(b)

        assert len(store.get_recent(limit=100)) == 2
        assert store.get_by_request_id("rid-a").event_id == a.event_id
        assert store.get_by_request_id("rid-b").event_id == b.event_id


# ---------------------------------------------------------------------------
# E4: MaxResults clamping
# ---------------------------------------------------------------------------
class TestE4MaxResultsClamp:
    def test_zero_clamps_to_one(self, store):
        for i in range(5):
            store.record(_mk_event(i))
        page, _ = store.query(max_results=0)
        assert len(page) == 1

    def test_negative_clamps_to_one(self, store):
        for i in range(5):
            store.record(_mk_event(i))
        page, _ = store.query(max_results=-10)
        assert len(page) == 1

    def test_upper_bound_caps_at_fifty(self, store):
        for i in range(75):
            store.record(_mk_event(i))
        page, _ = store.query(max_results=1000)
        assert len(page) == 50

    def test_get_recent_lower_bound_clamp(self, store):
        for i in range(5):
            store.record(_mk_event(i))
        # Negative/zero must not return the entire store or raise.
        assert len(store.get_recent(limit=0)) == 1
        assert len(store.get_recent(limit=-5)) == 1


# ---------------------------------------------------------------------------
# E5: concurrent save_to_disk
# ---------------------------------------------------------------------------
class TestE5ConcurrentSaves:
    def test_two_concurrent_saves_produce_valid_file(self, store, tmp_path):
        for i in range(50):
            store.record(_mk_event(i))

        errors: list[BaseException] = []

        def saver():
            try:
                for _ in range(20):
                    store.save_to_disk()
            except BaseException as exc:  # pragma: no cover - surfaced via errors list
                errors.append(exc)

        t1 = threading.Thread(target=saver)
        t2 = threading.Thread(target=saver)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"saver threads raised: {errors!r}"

        final = tmp_path / "cloudtrail_events.json"
        tmp = tmp_path / "cloudtrail_events.json.tmp"
        assert final.exists()
        assert not tmp.exists(), ".tmp must not linger after concurrent saves"

        # The winning writer left a fully valid JSON document.
        data = json.loads(final.read_text())
        assert isinstance(data, list)
        assert len(data) == 50

    def test_save_does_not_block_record(self, store):
        """Saves run outside the store lock — record() must not wait on disk I/O.

        Verified by stalling save I/O via a patched ``json.dump`` and checking
        that record() returns while a save is still in flight.
        """
        for i in range(10):
            store.record(_mk_event(i))

        release = threading.Event()
        in_save = threading.Event()
        real_dump = json.dump

        def slow_dump(obj, fp, **kw):
            in_save.set()
            # Block until the main thread has recorded its event.
            assert release.wait(timeout=5), "release never signaled"
            return real_dump(obj, fp, **kw)

        saver_done = threading.Event()

        def saver():
            with mock.patch(
                "localemu.services.cloudtrail.event_store.json.dump",
                side_effect=slow_dump,
            ):
                store.save_to_disk()
            saver_done.set()

        t = threading.Thread(target=saver)
        t.start()

        assert in_save.wait(timeout=5), "saver never entered json.dump"
        # While the saver is stalled inside disk I/O, record() must still work.
        store.record(_mk_event(999, request_id="during-save"))
        assert store.get_by_request_id("during-save") is not None

        release.set()
        t.join(timeout=5)
        assert saver_done.is_set()
