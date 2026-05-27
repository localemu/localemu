"""Pure-Python Kinesis stream consumer for use by LocalEmu services.

Replaces the previous AWS KCL (Kinesis Client Library) based consumer that
spawned a Java MultiLangDaemon subprocess and required the `kclpy-ext`
extra at runtime. That implementation was inherited from LocalStack and
contradicted LocalEmu's pure-Python stack goal — it has been removed.

Design:
  - One polling thread per shard, spawned at start().
  - Each thread: GetShardIterator(LATEST) -> loop GetRecords -> invoke listener.
  - stop() signals a shared shutdown event so all polling threads exit cleanly.

Trade-offs vs. KCL (acceptable for LocalEmu's use case):
  - No DynamoDB-backed lease coordination. We run a single in-process
    consumer per stream — there are no distributed workers to coordinate.
  - No automatic resharding pickup. The consumer's shard set is fixed at
    start(); if shards split/merge during runtime, callers should restart
    the consumer. In practice, local-dev streams rarely reshard.

Record normalization:
  boto3.kinesis.get_records() returns records with PascalCase keys, raw
  bytes for Data, and a tz-aware datetime for ApproximateArrivalTimestamp.
  Firehose's downstream pipeline expects ApproximateArrivalTimestamp as an
  integer millis-since-epoch, so we normalize that field here. Data stays
  as bytes (firehose._reencode_record base64-encodes downstream as needed).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from localemu import config
from localemu.utils.aws import arns
from localemu.utils.threads import TMP_THREADS, FuncThread

LOG = logging.getLogger(__name__)

ListenerFunction = Callable[[list], Any]

_POLL_INTERVAL_SECS = 1.0
_GET_RECORDS_LIMIT = 10_000
_DEFAULT_ITERATOR_TYPE = "LATEST"
_DESCRIBE_TIMEOUT_SECS = 30
_STOP_JOIN_TIMEOUT_SECS = 5


def _normalize_record(record: dict) -> dict:
    """Convert boto3 record fields to the shape downstream firehose code expects."""
    ts = record.get("ApproximateArrivalTimestamp")
    if isinstance(ts, datetime):
        record["ApproximateArrivalTimestamp"] = int(ts.timestamp() * 1000)
    return record


class KinesisPollConsumer:
    """Polls a Kinesis stream and invokes ``listener_function`` per batch of records.

    Lifecycle:
        consumer = KinesisPollConsumer(stream_name, account_id, region, listener_func)
        consumer.start()           # spawns one thread per shard
        ...
        consumer.stop()            # signals shutdown, joins threads

    The listener function receives a list of record dicts (PascalCase keys,
    bytes Data, integer-millis ApproximateArrivalTimestamp). Exceptions raised
    by the listener are logged and do not kill the polling loop.
    """

    def __init__(
        self,
        stream_name: str,
        account_id: str,
        region_name: str,
        listener_function: ListenerFunction,
        poll_interval_secs: float = _POLL_INTERVAL_SECS,
        iterator_type: str = _DEFAULT_ITERATOR_TYPE,
    ):
        self.stream_name = arns.kinesis_stream_name(stream_name)
        self.account_id = account_id
        self.region_name = region_name
        self.listener_function = listener_function
        self.poll_interval_secs = poll_interval_secs
        self.iterator_type = iterator_type
        self._shutdown = threading.Event()
        self._started = threading.Event()
        self._shard_threads: list[FuncThread] = []
        self._client = None
        self.stopped = False

    def _build_client(self):
        endpoint = config.internal_service_url(protocol="http")
        return boto3.client(
            "kinesis",
            endpoint_url=endpoint,
            region_name=self.region_name,
            aws_access_key_id=self.account_id,
            aws_secret_access_key=self.account_id,
            config=BotoConfig(retries={"max_attempts": 3, "mode": "standard"}),
        )

    def start(self):
        """Describe the stream and spawn one polling thread per shard."""
        self._client = self._build_client()
        try:
            desc = self._client.describe_stream(StreamName=self.stream_name)
            shards = desc["StreamDescription"]["Shards"]
        except ClientError as e:
            LOG.error("Failed to describe Kinesis stream %s: %s", self.stream_name, e)
            raise

        for shard in shards:
            shard_id = shard["ShardId"]
            t = FuncThread(
                self._poll_shard,
                shard_id,
                name=f"kinesis-poll-{self.stream_name}-{shard_id}",
            )
            self._shard_threads.append(t)
            t.start()

        self._started.set()
        TMP_THREADS.append(self)

    def _poll_shard(self, shard_id: str):
        try:
            iterator_resp = self._client.get_shard_iterator(
                StreamName=self.stream_name,
                ShardId=shard_id,
                ShardIteratorType=self.iterator_type,
            )
            shard_iterator = iterator_resp["ShardIterator"]
        except ClientError as e:
            LOG.error(
                "Failed to get shard iterator for %s shard %s: %s",
                self.stream_name,
                shard_id,
                e,
            )
            return

        while not self._shutdown.is_set() and shard_iterator:
            try:
                resp = self._client.get_records(
                    ShardIterator=shard_iterator,
                    Limit=_GET_RECORDS_LIMIT,
                )
            except ClientError as e:
                LOG.warning(
                    "GetRecords on %s shard %s failed: %s",
                    self.stream_name,
                    shard_id,
                    e,
                )
                self._shutdown.wait(self.poll_interval_secs)
                continue

            records = [_normalize_record(r) for r in resp.get("Records", [])]
            if records:
                try:
                    self.listener_function(records)
                except Exception as e:
                    LOG.error(
                        "Listener function raised on %s shard %s: %s",
                        self.stream_name,
                        shard_id,
                        e,
                        exc_info=LOG.isEnabledFor(logging.DEBUG),
                    )
            shard_iterator = resp.get("NextShardIterator")
            self._shutdown.wait(self.poll_interval_secs)

    def stop(self, quiet: bool = False):
        """Signal shutdown to all polling threads and wait briefly for them to join."""
        if self.stopped:
            if not quiet:
                LOG.debug(
                    "Kinesis poll consumer for stream %s already stopped.",
                    self.stream_name,
                )
            return
        self.stopped = True
        LOG.debug("Stopping Kinesis poll consumer for stream %s", self.stream_name)
        self._shutdown.set()
        for t in self._shard_threads:
            try:
                t.join(timeout=_STOP_JOIN_TIMEOUT_SECS)
            except Exception:
                pass

    def wait_is_up(self, timeout: float | None = None) -> bool:
        """Block until start() has spawned all shard threads, or until ``timeout``."""
        return self._started.wait(timeout=timeout)

    def wait_subprocesses_initialized(self, timeout: float | None = None) -> bool:
        """Back-compat shim: the KCL implementation spawned subprocesses; we do not.

        Returns True once start() has completed. Same semantics as wait_is_up().
        """
        return self._started.wait(timeout=timeout)


def listen_to_kinesis(
    stream_name: str,
    account_id: str,
    region_name: str,
    listener_func: ListenerFunction,
    ddb_lease_table_suffix: str | None = None,  # noqa: ARG001  back-compat, unused
    wait_until_started: bool = False,
) -> KinesisPollConsumer:
    """Subscribe to a Kinesis stream and invoke ``listener_func`` per batch of records.

    Returns a started :class:`KinesisPollConsumer`. Call ``.stop()`` to cancel.

    The ``ddb_lease_table_suffix`` argument is accepted for back-compat with the
    previous KCL-based implementation and ignored — the polling consumer is
    in-process and does not need a DynamoDB lease table.
    """
    consumer = KinesisPollConsumer(
        stream_name=stream_name,
        account_id=account_id,
        region_name=region_name,
        listener_function=listener_func,
    )
    consumer.start()

    if wait_until_started:
        if not consumer.wait_is_up(timeout=_DESCRIBE_TIMEOUT_SECS):
            raise RuntimeError(
                f"Timeout waiting for Kinesis poll consumer to start for {stream_name}"
            )

    return consumer
