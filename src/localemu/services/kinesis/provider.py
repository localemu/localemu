import json
import logging
import random as _random_module
import re
import threading

from localemu import config
from localemu.aws.api import RequestContext
from localemu.aws.api.kinesis import (
    ConsumerARN,
    Data,
    GetResourcePolicyOutput,
    HashKey,
    KinesisApi,
    PartitionKey,
    Policy,
    ProvisionedThroughputExceededException,
    PutRecordOutput,
    PutRecordsOutput,
    PutRecordsRequestEntryList,
    PutRecordsResultEntry,
    ResourceARN,
    ResourceNotFoundException,
    SequenceNumber,
    ShardId,
    StartingPosition,
    StreamARN,
    StreamId,
    StreamName,
    SubscribeToShardEvent,
    SubscribeToShardEventStream,
    SubscribeToShardOutput,
    ValidationException,
)
from localemu.aws.connect import connect_to
from localemu.services.kinesis.models import KinesisStore, kinesis_stores
from localemu.services.plugins import ServiceLifecycleHook
from localemu.state import StateVisitor
from localemu.utils.aws import arns
from localemu.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn
from localemu.utils.time import now_utc

LOG = logging.getLogger(__name__)
MAX_SUBSCRIPTION_SECONDS = 300

# Thread-safe random source. The stdlib ``random`` module uses a single shared ``Random``
# instance and while CPython's implementation of ``random.random`` happens to be atomic under
# the GIL, the shared state is NOT safe across threads for the full API surface. ``SystemRandom``
# is backed by ``os.urandom`` which is thread-safe by construction.
_SECURE_RANDOM = _random_module.SystemRandom()


def _thread_safe_random() -> float:
    return _SECURE_RANDOM.random()

DATA_STREAM_ARN_REGEX = re.compile(
    r"^arn:aws(?:-[a-z]+)*:kinesis:[a-z0-9-]+:\d{12}:stream\/[a-zA-Z0-9_.\-]+$"
)
CONSUMER_ARN_REGEX = re.compile(
    r"^arn:aws(?:-[a-z]+)*:kinesis:[a-z0-9-]+:\d{12}:stream\/[a-zA-Z0-9_.\-]+\/consumer\/[a-zA-Z0-9_.\-]+:\d+$"
)


# Consumer ARNs are immutable — once a consumer is created against a stream it cannot be moved
# to another stream. We therefore memoise the reverse lookup to avoid an O(streams x consumers)
# scan on every SubscribeToShard call. The cache is bounded to avoid unbounded memory
# growth in long-running processes with churn of consumers.
_CONSUMER_STREAM_CACHE: dict[str, str] = {}
_CONSUMER_STREAM_CACHE_LOCK = threading.Lock()
_CONSUMER_STREAM_CACHE_MAX = 4096


def find_stream_for_consumer(consumer_arn):
    with _CONSUMER_STREAM_CACHE_LOCK:
        cached = _CONSUMER_STREAM_CACHE.get(consumer_arn)
    if cached is not None:
        return cached

    account_id = extract_account_id_from_arn(consumer_arn)
    region_name = extract_region_from_arn(consumer_arn)
    kinesis = connect_to(aws_access_key_id=account_id, region_name=region_name).kinesis
    for stream_name in kinesis.list_streams()["StreamNames"]:
        stream_arn = arns.kinesis_stream_arn(stream_name, account_id, region_name)
        for cons in kinesis.list_stream_consumers(StreamARN=stream_arn)["Consumers"]:
            if cons["ConsumerARN"] == consumer_arn:
                with _CONSUMER_STREAM_CACHE_LOCK:
                    if len(_CONSUMER_STREAM_CACHE) >= _CONSUMER_STREAM_CACHE_MAX:
                        # Simple FIFO eviction: drop the oldest entry.
                        _CONSUMER_STREAM_CACHE.pop(
                            next(iter(_CONSUMER_STREAM_CACHE)), None
                        )
                    _CONSUMER_STREAM_CACHE[consumer_arn] = stream_name
                return stream_name
    raise Exception(f"Unable to find stream for stream consumer {consumer_arn}")


def is_valid_kinesis_arn(resource_arn: ResourceARN) -> bool:
    """Check if the provided ARN is a valid Kinesis ARN."""
    return bool(CONSUMER_ARN_REGEX.match(resource_arn) or DATA_STREAM_ARN_REGEX.match(resource_arn))


class KinesisProvider(KinesisApi, ServiceLifecycleHook):
    service = "kinesis"

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(kinesis_stores)

    @staticmethod
    def get_store(account_id: str, region_name: str) -> KinesisStore:
        return kinesis_stores[account_id][region_name]

    def put_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceARN,
        policy: Policy,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> None:
        if not is_valid_kinesis_arn(resource_arn):
            raise ValidationException(f"invalid kinesis arn {resource_arn}")

        kinesis = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region
        ).kinesis
        try:
            kinesis.describe_stream_summary(StreamARN=resource_arn)
        except kinesis.exceptions.ResourceNotFoundException:
            raise ResourceNotFoundException(f"Stream with ARN {resource_arn} not found")

        store = self.get_store(context.account_id, context.region)
        store.resource_policies[resource_arn] = policy

    def get_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceARN,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> GetResourcePolicyOutput:
        if not is_valid_kinesis_arn(resource_arn):
            raise ValidationException(f"invalid kinesis arn {resource_arn}")

        kinesis = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region
        ).kinesis
        try:
            kinesis.describe_stream_summary(StreamARN=resource_arn)
        except kinesis.exceptions.ResourceNotFoundException:
            raise ResourceNotFoundException(f"Stream with ARN {resource_arn} not found")

        store = self.get_store(context.account_id, context.region)
        policy = store.resource_policies.get(resource_arn, json.dumps({}))
        return GetResourcePolicyOutput(Policy=policy)

    def delete_resource_policy(
        self,
        context: RequestContext,
        resource_arn: ResourceARN,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> None:
        if not is_valid_kinesis_arn(resource_arn):
            raise ValidationException(f"invalid kinesis arn {resource_arn}")

        # Mirror put / get_resource_policy: verify the target stream still exists so that callers
        # receive a deterministic ResourceNotFoundException if the stream has been deleted out from
        # under a stale policy entry.
        kinesis = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region
        ).kinesis
        try:
            kinesis.describe_stream_summary(StreamARN=resource_arn)
        except kinesis.exceptions.ResourceNotFoundException:
            raise ResourceNotFoundException(f"Stream with ARN {resource_arn} not found")

        store = self.get_store(context.account_id, context.region)
        if resource_arn not in store.resource_policies:
            raise ResourceNotFoundException(
                f"No resource policy found for resource ARN {resource_arn}"
            )
        del store.resource_policies[resource_arn]

    def subscribe_to_shard(
        self,
        context: RequestContext,
        consumer_arn: ConsumerARN,
        shard_id: ShardId,
        starting_position: StartingPosition,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> SubscribeToShardOutput:
        kinesis = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region
        ).kinesis
        stream_name = find_stream_for_consumer(consumer_arn)
        iter_type = starting_position["Type"]
        iter_kwargs = {}
        starting_sequence_number = starting_position.get("SequenceNumber") or "0"
        if iter_type in ["AT_SEQUENCE_NUMBER", "AFTER_SEQUENCE_NUMBER"]:
            iter_kwargs["StartingSequenceNumber"] = starting_sequence_number
        elif iter_type in ["AT_TIMESTAMP"]:
            timestamp = starting_position.get("Timestamp") or 1459799926.480
            iter_kwargs["Timestamp"] = timestamp
        initial_shard_iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType=iter_type, **iter_kwargs
        )["ShardIterator"]

        def event_generator():
            shard_iterator = initial_shard_iterator
            last_sequence_number = starting_sequence_number

            maximum_duration_subscription_timestamp = now_utc() + MAX_SUBSCRIPTION_SECONDS
            # Use an ``Event`` wait instead of ``time.sleep`` so the subscriber can be unblocked
            # immediately on shutdown / generator close rather than holding a thread hostage for
            # up to 3 seconds at a time.
            idle_wait_event = threading.Event()

            while now_utc() < maximum_duration_subscription_timestamp:
                try:
                    result = kinesis.get_records(ShardIterator=shard_iterator)
                except Exception as e:
                    if "ResourceNotFoundException" in str(e):
                        LOG.debug(
                            'Kinesis stream "%s" has been deleted, closing shard subscriber',
                            stream_name,
                        )
                        return
                    raise
                shard_iterator = result.get("NextShardIterator")
                records = result.get("Records", [])
                if records:
                    # Update the last sequence number to the last record's sequence number
                    # TODO: This will suffice for now but does not properly capture checkpointing when
                    # no data is written to a shard. See AWS docs:
                    # https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShardEvent.html#API_SubscribeToShardEvent_Contents
                    last_sequence_number = records[-1].get("SequenceNumber", last_sequence_number)
                else:
                    # On AWS there is *at least* 1 event every 5 seconds but this is not possible
                    # in this structure. We instead ``wait`` on an Event for up to 3 seconds so
                    # that shutdown / generator close can interrupt the idle period immediately
                    # rather than blocking the worker thread.
                    idle_wait_event.wait(timeout=3)
                    if idle_wait_event.is_set():
                        return

                yield SubscribeToShardEventStream(
                    SubscribeToShardEvent=SubscribeToShardEvent(
                        Records=records,
                        ContinuationSequenceNumber=str(last_sequence_number),
                        MillisBehindLatest=0,
                        ChildShards=None,  # TODO: Include shard children info
                    )
                )

        return SubscribeToShardOutput(EventStream=event_generator())

    def put_record(
        self,
        context: RequestContext,
        data: Data,
        partition_key: PartitionKey,
        stream_name: StreamName = None,
        explicit_hash_key: HashKey = None,
        sequence_number_for_ordering: SequenceNumber = None,
        stream_arn: StreamARN = None,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> PutRecordOutput:
        if _thread_safe_random() < config.KINESIS_ERROR_PROBABILITY:
            raise ProvisionedThroughputExceededException(
                "Rate exceeded for shard X in stream Y under account Z."
            )
        # Fall through to Moto backend
        raise NotImplementedError

    def put_records(
        self,
        context: RequestContext,
        records: PutRecordsRequestEntryList,
        stream_name: StreamName = None,
        stream_arn: StreamARN = None,
        stream_id: StreamId | None = None,
        **kwargs,
    ) -> PutRecordsOutput:
        if _thread_safe_random() < config.KINESIS_ERROR_PROBABILITY:
            records_count = len(records) if records is not None else 0
            records = [
                PutRecordsResultEntry(
                    ErrorCode="ProvisionedThroughputExceededException",
                    ErrorMessage="Rate exceeded for shard X in stream Y under account Z.",
                )
            ] * records_count
            return PutRecordsOutput(FailedRecordCount=records_count, Records=records)
        # Fall through to Moto backend
        raise NotImplementedError
