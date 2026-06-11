"""Unit tests for the pure-Python Kinesis polling consumer.

Replaces the KCL-based consumer that needed Java + amazon_kclpy.
These tests mock the boto3 client so they run in milliseconds without
requiring a live LocalEmu instance.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from localemu.utils.kinesis.kinesis_poll_consumer import (
    KinesisPollConsumer,
    _normalize_record,
    listen_to_kinesis,
)


# ---------------------------------------------------------------------------
# Record normalization
# ---------------------------------------------------------------------------


def test_normalize_record_converts_datetime_to_millis():
    ts = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    record = {"Data": b"hello", "ApproximateArrivalTimestamp": ts}

    _normalize_record(record)

    assert record["ApproximateArrivalTimestamp"] == int(ts.timestamp() * 1000)
    assert record["Data"] == b"hello"  # bytes untouched


def test_normalize_record_leaves_int_timestamp_alone():
    record = {"Data": b"x", "ApproximateArrivalTimestamp": 1747490400000}
    _normalize_record(record)
    assert record["ApproximateArrivalTimestamp"] == 1747490400000


def test_normalize_record_handles_missing_timestamp():
    record = {"Data": b"x"}
    _normalize_record(record)
    assert "ApproximateArrivalTimestamp" not in record


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_kinesis_client():
    """A boto3-shaped kinesis client mock that returns one shard and a batch of records."""
    client = MagicMock()
    client.describe_stream.return_value = {
        "StreamDescription": {
            "Shards": [{"ShardId": "shardId-000000000000"}],
        }
    }
    client.get_shard_iterator.return_value = {"ShardIterator": "ITER-1"}

    arrival = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    client.get_records.side_effect = [
        {
            "Records": [
                {
                    "SequenceNumber": "49",
                    "ApproximateArrivalTimestamp": arrival,
                    "Data": b"payload-1",
                    "PartitionKey": "pk-1",
                },
                {
                    "SequenceNumber": "50",
                    "ApproximateArrivalTimestamp": arrival,
                    "Data": b"payload-2",
                    "PartitionKey": "pk-2",
                },
            ],
            "NextShardIterator": "ITER-2",
        },
        # Subsequent polls return no records; consumer keeps looping until stopped.
        *[{"Records": [], "NextShardIterator": f"ITER-{i}"} for i in range(3, 100)],
    ]
    return client


def test_consumer_invokes_listener_with_normalized_records(mock_kinesis_client):
    received: list[list[dict]] = []
    done = threading.Event()

    def listener(records):
        received.append(records)
        done.set()

    consumer = KinesisPollConsumer(
        stream_name="my-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=listener,
        poll_interval_secs=0.01,
    )
    with patch.object(consumer, "_build_client", return_value=mock_kinesis_client):
        consumer.start()
        try:
            assert done.wait(timeout=2.0), "listener was not called within 2s"
        finally:
            consumer.stop()

    assert len(received) >= 1
    first_batch = received[0]
    assert len(first_batch) == 2
    assert first_batch[0]["Data"] == b"payload-1"
    assert first_batch[1]["PartitionKey"] == "pk-2"
    # ApproximateArrivalTimestamp should have been normalized from datetime -> int millis.
    assert isinstance(first_batch[0]["ApproximateArrivalTimestamp"], int)


def test_consumer_stops_cleanly(mock_kinesis_client):
    def listener(_records):
        pass

    consumer = KinesisPollConsumer(
        stream_name="my-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=listener,
        poll_interval_secs=0.01,
    )
    with patch.object(consumer, "_build_client", return_value=mock_kinesis_client):
        consumer.start()
        time.sleep(0.05)
        consumer.stop()

    assert consumer.stopped is True
    for t in consumer._shard_threads:
        assert not t.is_alive(), f"thread {t.name} did not exit after stop()"


def test_consumer_strips_arn_to_stream_name():
    arn = "arn:aws:kinesis:us-east-1:000000000000:stream/orders"
    consumer = KinesisPollConsumer(
        stream_name=arn,
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda _r: None,
    )
    assert consumer.stream_name == "orders"


def test_consumer_one_thread_per_shard():
    client = MagicMock()
    client.describe_stream.return_value = {
        "StreamDescription": {
            "Shards": [
                {"ShardId": "shardId-000000000000"},
                {"ShardId": "shardId-000000000001"},
                {"ShardId": "shardId-000000000002"},
            ],
        }
    }
    client.get_shard_iterator.return_value = {"ShardIterator": "ITER"}
    client.get_records.return_value = {"Records": [], "NextShardIterator": "ITER"}

    consumer = KinesisPollConsumer(
        stream_name="my-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda _r: None,
        poll_interval_secs=0.01,
    )
    with patch.object(consumer, "_build_client", return_value=client):
        consumer.start()
        try:
            assert len(consumer._shard_threads) == 3
            assert all(t.is_alive() for t in consumer._shard_threads)
        finally:
            consumer.stop()


def test_listener_exception_does_not_kill_polling(mock_kinesis_client):
    call_count = {"n": 0}
    done = threading.Event()

    def bad_listener(_records):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ValueError("intentional test exception")
        done.set()

    # Make the mock return two non-empty batches in a row so the listener
    # gets called at least twice — and we can verify it survives the first raise.
    arrival = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    one_record = {
        "Records": [{"SequenceNumber": "1", "ApproximateArrivalTimestamp": arrival,
                     "Data": b"x", "PartitionKey": "pk"}],
        "NextShardIterator": "NEXT",
    }
    mock_kinesis_client.get_records.side_effect = [one_record, one_record] + [
        {"Records": [], "NextShardIterator": "ITER"} for _ in range(100)
    ]

    consumer = KinesisPollConsumer(
        stream_name="my-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=bad_listener,
        poll_interval_secs=0.01,
    )
    with patch.object(consumer, "_build_client", return_value=mock_kinesis_client):
        consumer.start()
        try:
            assert done.wait(timeout=2.0), "polling died after listener raised"
        finally:
            consumer.stop()

    assert call_count["n"] >= 2


def test_describe_stream_failure_propagates():
    client = MagicMock()
    client.describe_stream.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Stream not found"}},
        "DescribeStream",
    )
    consumer = KinesisPollConsumer(
        stream_name="missing-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda _r: None,
    )
    with patch.object(consumer, "_build_client", return_value=client):
        with pytest.raises(ClientError):
            consumer.start()


def test_get_records_error_does_not_kill_thread(mock_kinesis_client):
    """Transient GetRecords failures should be logged and retried, not crash the poller."""
    arrival = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    success_resp = {
        "Records": [{"SequenceNumber": "1", "ApproximateArrivalTimestamp": arrival,
                     "Data": b"x", "PartitionKey": "pk"}],
        "NextShardIterator": "ITER",
    }
    mock_kinesis_client.get_records.side_effect = [
        ClientError({"Error": {"Code": "InternalFailure", "Message": "boom"}}, "GetRecords"),
        ClientError({"Error": {"Code": "InternalFailure", "Message": "boom"}}, "GetRecords"),
        success_resp,
        *[{"Records": [], "NextShardIterator": "ITER"} for _ in range(100)],
    ]
    received = []
    done = threading.Event()

    def listener(records):
        received.append(records)
        done.set()

    consumer = KinesisPollConsumer(
        stream_name="my-stream",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=listener,
        poll_interval_secs=0.01,
    )
    with patch.object(consumer, "_build_client", return_value=mock_kinesis_client):
        consumer.start()
        try:
            assert done.wait(timeout=2.0), "consumer did not recover from transient errors"
        finally:
            consumer.stop()

    assert len(received) == 1


# ---------------------------------------------------------------------------
# Public listen_to_kinesis() entry point
# ---------------------------------------------------------------------------


def test_listen_to_kinesis_returns_started_consumer(mock_kinesis_client):
    with patch(
        "localemu.utils.kinesis.kinesis_poll_consumer.KinesisPollConsumer._build_client",
        return_value=mock_kinesis_client,
    ):
        consumer = listen_to_kinesis(
            stream_name="my-stream",
            account_id="000000000000",
            region_name="us-east-1",
            listener_func=lambda _r: None,
            wait_until_started=True,
            ddb_lease_table_suffix="-firehose-abc",  # accepted, ignored
        )
        try:
            assert consumer.wait_is_up(timeout=1.0)
            assert isinstance(consumer, KinesisPollConsumer)
        finally:
            consumer.stop()


def test_back_compat_alias_kinesis_processor_thread():
    from localemu.utils.kinesis.kinesis_connector import (
        KinesisPollConsumer as A,
        KinesisProcessorThread as B,
    )
    assert A is B, "KinesisProcessorThread must alias the new consumer class"


# ---------------------------------------------------------------------------
# Thread-protocol compatibility: is_alive()
#
# ``KinesisPollConsumer.start()`` registers ``self`` in
# :data:`localemu.utils.threads.TMP_THREADS`. That list is pruned on every
# :func:`localemu.utils.threads.start_thread` call via ``t.is_alive()``.
# Without an ``is_alive`` method the prune crashed with ``AttributeError``,
# which fired on every Lambda invocation (CloudWatch metric recorder uses
# ``start_thread``) and cascaded into thousands of downstream
# ``ResourceNotFoundException`` errors. These tests pin the contract.
# ---------------------------------------------------------------------------


def test_is_alive_returns_false_before_start():
    """Before ``start()`` the consumer has no threads -> dead."""
    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    assert consumer.is_alive() is False


def test_is_alive_returns_true_while_shard_threads_run():
    """Between ``start()`` and ``stop()`` with live shard threads -> alive."""
    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    # Simulate post-start state without spawning real threads.
    fake_thread = MagicMock()
    fake_thread.is_alive.return_value = True
    consumer._shard_threads = [fake_thread]
    consumer._started.set()
    assert consumer.is_alive() is True


def test_is_alive_returns_false_after_stop():
    """After ``stop()`` the consumer is dead even if a shard thread happens
    to outlive the join timeout."""
    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    fake_thread = MagicMock()
    fake_thread.is_alive.return_value = True
    consumer._shard_threads = [fake_thread]
    consumer._started.set()
    consumer.stopped = True
    assert consumer.is_alive() is False


def test_is_alive_returns_false_if_every_shard_thread_died():
    """If every shard polling thread has exited the consumer is dead."""
    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    dead_a, dead_b = MagicMock(), MagicMock()
    dead_a.is_alive.return_value = False
    dead_b.is_alive.return_value = False
    consumer._shard_threads = [dead_a, dead_b]
    consumer._started.set()
    assert consumer.is_alive() is False


def test_is_alive_returns_true_if_any_one_shard_thread_lives():
    """A single surviving shard thread keeps the consumer alive."""
    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    dead = MagicMock()
    dead.is_alive.return_value = False
    alive = MagicMock()
    alive.is_alive.return_value = True
    consumer._shard_threads = [dead, alive, dead]
    consumer._started.set()
    assert consumer.is_alive() is True


# ---------------------------------------------------------------------------
# Regression: start_thread can prune TMP_THREADS containing a
# KinesisPollConsumer without crashing.
# ---------------------------------------------------------------------------


def test_start_thread_can_prune_tmp_threads_with_poll_consumer():
    """If a KinesisPollConsumer sits in TMP_THREADS, the next
    ``start_thread`` call must prune the list without raising
    ``AttributeError: 'KinesisPollConsumer' object has no attribute 'is_alive'``.
    """
    from localemu.utils import threads as t_mod
    from localemu.utils.threads import start_thread

    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    # Mimic what KinesisPollConsumer.start() does at its tail.
    consumer._started.set()

    # Snapshot + drop TMP_THREADS to avoid leaking other tests' state, then
    # seed it with our consumer.
    saved = list(t_mod.TMP_THREADS)
    t_mod.TMP_THREADS[:] = [consumer]
    try:
        # The lambda is just any callable; the body returns immediately.
        t = start_thread(lambda *_args, **_kw: None, name="prune-regression")
        try:
            t.join(timeout=2.0)
        finally:
            # After prune, the dead consumer must be gone (it returned
            # is_alive=False because we never populated _shard_threads) and
            # the freshly-spawned FuncThread must be present.
            assert consumer not in t_mod.TMP_THREADS, (
                "prune should have dropped the consumer when its shards "
                "list was empty"
            )
            assert t in t_mod.TMP_THREADS
    finally:
        t_mod.TMP_THREADS[:] = saved


def test_start_thread_keeps_live_poll_consumer_in_tmp_threads():
    """A KinesisPollConsumer with a live shard thread must SURVIVE the prune."""
    from localemu.utils import threads as t_mod
    from localemu.utils.threads import start_thread

    consumer = KinesisPollConsumer(
        stream_name="s",
        account_id="000000000000",
        region_name="us-east-1",
        listener_function=lambda recs: None,
    )
    fake_thread = MagicMock()
    fake_thread.is_alive.return_value = True
    consumer._shard_threads = [fake_thread]
    consumer._started.set()

    saved = list(t_mod.TMP_THREADS)
    t_mod.TMP_THREADS[:] = [consumer]
    try:
        t = start_thread(lambda *_args, **_kw: None, name="keep-live-consumer")
        try:
            t.join(timeout=2.0)
        finally:
            assert consumer in t_mod.TMP_THREADS, (
                "prune must keep a consumer that reports is_alive() True"
            )
            assert t in t_mod.TMP_THREADS
    finally:
        t_mod.TMP_THREADS[:] = saved
