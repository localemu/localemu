import base64
import dataclasses
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from math import ceil

from botocore.config import Config

from localemu import config
from localemu.aws.api.lambda_ import InvocationType, TooManyRequestsException
from localemu.services.lambda_.analytics import (
    FunctionInitializationType,
    FunctionOperation,
    FunctionStatus,
    function_counter,
)
from localemu.services.lambda_.invocation.internal_sqs_queue import get_fake_sqs_client
from localemu.services.lambda_.invocation.lambda_models import (
    EventInvokeConfig,
    FunctionVersion,
    Invocation,
    InvocationResult,
)
from localemu.services.lambda_.invocation.version_manager import LambdaVersionManager
from localemu.utils.aws import dead_letter_queue
from localemu.utils.aws.message_forwarding import send_event_to_target
from localemu.utils.strings import md5, to_str
from localemu.utils.threads import FuncThread
from localemu.utils.time import timestamp_millis
from localemu.utils.xray.trace_header import TraceHeader

LOG = logging.getLogger(__name__)

# Timeout in seconds when waiting for the poller thread to join during shutdown.
POLLER_THREAD_JOIN_TIMEOUT_SECONDS = 3

# Default maximum event age for async invocations (6 hours), as documented by AWS:
# https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
DEFAULT_MAXIMUM_EVENT_AGE_SECONDS = 6 * 60 * 60

# Maximum delay between exception retries (5 minutes), matching SQS message timer quota:
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
MAXIMUM_EXCEPTION_RETRY_DELAY_SECONDS = 5 * 60

# Default maximum retry attempts for async invocations
DEFAULT_MAX_RETRY_ATTEMPTS = 2


def get_sqs_client(function_version: FunctionVersion, client_config=None):
    return get_fake_sqs_client()


# TODO: remove once DLQ handling is refactored following the removal of the legacy lambda provider
class LegacyInvocationException(Exception):
    def __init__(self, message, log_output=None, result=None):
        super().__init__(message)
        self.log_output = log_output
        self.result = result


@dataclasses.dataclass
class SQSInvocation:
    invocation: Invocation
    retries: int = 0
    exception_retries: int = 0

    def encode(self) -> str:
        # Encode TraceHeader as string
        aws_trace_header = self.invocation.trace_context.get("aws_trace_header")
        aws_trace_header_str = aws_trace_header.to_header_str()
        self.invocation.trace_context["aws_trace_header"] = aws_trace_header_str
        return json.dumps(
            {
                "payload": to_str(base64.b64encode(self.invocation.payload)),
                "invoked_arn": self.invocation.invoked_arn,
                "client_context": self.invocation.client_context,
                "invocation_type": self.invocation.invocation_type,
                "invoke_time": self.invocation.invoke_time.isoformat(),
                # = invocation_id
                "request_id": self.invocation.request_id,
                "retries": self.retries,
                "exception_retries": self.exception_retries,
                "trace_context": self.invocation.trace_context,
            }
        )

    @classmethod
    def decode(cls, message: str) -> "SQSInvocation":
        invocation_dict = json.loads(message)
        invocation = Invocation(
            payload=base64.b64decode(invocation_dict["payload"]),
            invoked_arn=invocation_dict["invoked_arn"],
            client_context=invocation_dict["client_context"],
            invocation_type=invocation_dict["invocation_type"],
            invoke_time=datetime.fromisoformat(invocation_dict["invoke_time"]),
            request_id=invocation_dict["request_id"],
            trace_context=invocation_dict.get("trace_context"),
        )
        # Decode TraceHeader
        aws_trace_header_str = invocation_dict.get("trace_context", {}).get("aws_trace_header")
        invocation_dict["trace_context"]["aws_trace_header"] = TraceHeader.from_header_str(
            aws_trace_header_str
        )
        return cls(
            invocation=invocation,
            retries=invocation_dict["retries"],
            exception_retries=invocation_dict["exception_retries"],
        )


def has_enough_time_for_retry(
    sqs_invocation: SQSInvocation, event_invoke_config: EventInvokeConfig
) -> bool:
    time_passed = datetime.now() - sqs_invocation.invocation.invoke_time
    delay_queue_invoke_seconds = (
        sqs_invocation.retries + 1
    ) * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
    maximum_event_age_in_seconds = DEFAULT_MAXIMUM_EVENT_AGE_SECONDS
    if event_invoke_config and event_invoke_config.maximum_event_age_in_seconds is not None:
        maximum_event_age_in_seconds = event_invoke_config.maximum_event_age_in_seconds
    return (
        maximum_event_age_in_seconds
        and ceil(time_passed.total_seconds()) + delay_queue_invoke_seconds
        <= maximum_event_age_in_seconds
    )


# TODO: optimize this client configuration. Do we need to consider client caching here?
CLIENT_CONFIG = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 0},
)


class Poller:
    version_manager: LambdaVersionManager
    event_queue_url: str
    _shutdown_event: threading.Event
    invoker_pool: ThreadPoolExecutor

    def __init__(self, version_manager: LambdaVersionManager, event_queue_url: str):
        self.version_manager = version_manager
        self.event_queue_url = event_queue_url
        self._shutdown_event = threading.Event()
        function_id = self.version_manager.function_version.id
        # TODO: think about scaling, test it, make it configurable?!
        self.invoker_pool = ThreadPoolExecutor(
            thread_name_prefix=f"lambda-invoker-{function_id.function_name}:{function_id.qualifier}"
        )

    def run(self, *args, **kwargs):
        sqs_client = get_sqs_client(
            self.version_manager.function_version, client_config=CLIENT_CONFIG
        )
        function_timeout = self.version_manager.function_version.config.timeout
        while not self._shutdown_event.is_set():
            try:
                response = sqs_client.receive_message(
                    QueueUrl=self.event_queue_url,
                    # TODO: consider replacing with short polling instead of long polling to prevent keeping connections open
                    # however, we had some serious performance issues when tried out, so those have to be investigated first
                    WaitTimeSeconds=2,
                    # Related: SQS event source mapping batches up to 10 messages:
                    # https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
                    MaxNumberOfMessages=10,
                    VisibilityTimeout=function_timeout + 60,
                )
                if not response.get("Messages"):
                    continue
                LOG.debug("[%s] Got %d messages", self.event_queue_url, len(response["Messages"]))
                # Guard against shutdown event arriving while polling SQS for messages
                if not self._shutdown_event.is_set():
                    for message in response["Messages"]:
                        # NOTE: queueing within the thread pool executor could lead to double executions
                        #  due to the visibility timeout
                        self.invoker_pool.submit(self.handle_message, message)

            except Exception as e:
                # TODO: if the gateway shuts down before the shutdown event even is set,
                #  we might still get an error message
                # after shutdown of LS, we might expectedly get errors, if other components shut down.
                # In any case, after the event manager is shut down, we do not need to spam error logs in case
                # some resource is already missing
                if self._shutdown_event.is_set():
                    return
                LOG.error(
                    "Error while polling lambda events for function %s: %s",
                    self.version_manager.function_version.qualified_arn,
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                # some time between retries to avoid running into the problem right again
                time.sleep(1)

    def stop(self):
        LOG.debug(
            "Stopping event poller %s %s",
            self.version_manager.function_version.qualified_arn,
            id(self),
        )
        self._shutdown_event.set()
        self.invoker_pool.shutdown(cancel_futures=True, wait=False)

    def handle_message(self, message: dict) -> None:
        failure_cause = None
        qualifier = self.version_manager.function_version.id.qualifier
        function_config = self.version_manager.function_version.config
        event_invoke_config = self.version_manager.function.event_invoke_configs.get(qualifier)
        runtime = None
        status = None
        # TODO: handle initialization_type provisioned-concurrency, which requires enriching invocation_result
        initialization_type = (
            FunctionInitializationType.lambda_managed_instances
            if function_config.capacity_provider_config
            else FunctionInitializationType.on_demand
        )
        try:
            sqs_invocation = SQSInvocation.decode(message["Body"])
            invocation = sqs_invocation.invocation
            try:
                invocation_result = self.version_manager.invoke(invocation=invocation)
                status = FunctionStatus.success
            except Exception as e:
                # Reserved concurrency == 0
                if self.version_manager.function.reserved_concurrent_executions == 0:
                    failure_cause = "ZeroReservedConcurrency"
                    status = FunctionStatus.zero_reserved_concurrency_error
                # Maximum event age expired (lookahead for next retry)
                elif not has_enough_time_for_retry(sqs_invocation, event_invoke_config):
                    failure_cause = "EventAgeExceeded"
                    status = FunctionStatus.event_age_exceeded_error

                if failure_cause:
                    invocation_result = InvocationResult(
                        is_error=True, request_id=invocation.request_id, payload=None, logs=None
                    )
                    self.process_failure_destination(
                        sqs_invocation, invocation_result, event_invoke_config, failure_cause
                    )
                    self.process_dead_letter_queue(sqs_invocation, invocation_result)
                    return
                # 3) Otherwise, retry without increasing counter
                status = self.process_throttles_and_system_errors(sqs_invocation, e)
                return
            finally:
                sqs_client = get_sqs_client(self.version_manager.function_version)
                sqs_client.delete_message(
                    QueueUrl=self.event_queue_url, ReceiptHandle=message["ReceiptHandle"]
                )
                if not status:
                    LOG.error("Invocation status was not set for %s, defaulting to system_error", self.version_manager.function_arn)
                    status = FunctionStatus.system_error
                function_counter.labels(
                    operation=FunctionOperation.invoke,
                    runtime=runtime or "n/a",
                    status=status,
                    invocation_type=InvocationType.Event,
                    package_type=function_config.package_type,
                    initialization_type=initialization_type,
                ).increment()

            # Good summary blogpost: https://haithai91.medium.com/aws-lambdas-retry-behaviors-edff90e1cf1b
            # Asynchronous invocation handling: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
            # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
            max_retry_attempts = DEFAULT_MAX_RETRY_ATTEMPTS
            if event_invoke_config and event_invoke_config.maximum_retry_attempts is not None:
                max_retry_attempts = event_invoke_config.maximum_retry_attempts

            if not invocation_result:
                LOG.error("Invocation result missing after invoke for %s", self.version_manager.function_arn)
                return

            # An invocation error either leads to a terminal failure or to a scheduled retry
            if invocation_result.is_error:  # invocation error
                failure_cause = None
                # Reserved concurrency == 0
                if self.version_manager.function.reserved_concurrent_executions == 0:
                    failure_cause = "ZeroReservedConcurrency"
                # Maximum retries exhausted
                elif sqs_invocation.retries >= max_retry_attempts:
                    failure_cause = "RetriesExhausted"
                # TODO: test what happens if max event age expired before it gets scheduled the first time?!
                # Maximum event age expired (lookahead for next retry)
                elif not has_enough_time_for_retry(sqs_invocation, event_invoke_config):
                    failure_cause = "EventAgeExceeded"

                if failure_cause:  # handle failure destination and DLQ
                    self.process_failure_destination(
                        sqs_invocation, invocation_result, event_invoke_config, failure_cause
                    )
                    self.process_dead_letter_queue(sqs_invocation, invocation_result)
                    return
                else:  # schedule retry
                    sqs_invocation.retries += 1
                    # Assumption: We assume that the internal exception retries counter is reset after
                    #  an invocation that does not throw an exception
                    sqs_invocation.exception_retries = 0
                    # LAMBDA_RETRY_BASE_DELAY_SECONDS has a limit of 300s because the maximum SQS DelaySeconds
                    # is 15 minutes (900s) and the maximum retry count is 3. SQS quota for "Message timer":
                    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
                    delay_seconds = sqs_invocation.retries * config.LAMBDA_RETRY_BASE_DELAY_SECONDS
                    # TODO: max SQS message size limit could break parity with AWS because
                    #  our SQSInvocation contains additional fields! 256kb is max for both Lambda payload + SQS
                    # TODO: write test with max SQS message size
                    sqs_client.send_message(
                        QueueUrl=self.event_queue_url,
                        MessageBody=sqs_invocation.encode(),
                        DelaySeconds=delay_seconds,
                    )
                    return
            else:  # invocation success
                self.process_success_destination(
                    sqs_invocation, invocation_result, event_invoke_config
                )
        except Exception as e:
            LOG.error(
                "Error handling lambda invoke %s", e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )

    def process_throttles_and_system_errors(
        self, sqs_invocation: SQSInvocation, error: Exception
    ) -> str:
        # If the function doesn't have enough concurrency available to process all events, additional
        # requests are throttled. For throttling errors (429) and system errors (500-series), Lambda returns
        # the event to the queue and attempts to run the function again for up to 6 hours. The retry interval
        # increases exponentially from 1 second after the first attempt to a maximum of 5 minutes. If the
        # queue contains many entries, Lambda increases the retry interval and reduces the rate at which it
        # reads events from the queue. Source:
        # https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
        # Difference depending on error cause:
        # https://aws.amazon.com/blogs/compute/introducing-new-asynchronous-invocation-metrics-for-aws-lambda/
        # Troubleshooting 500 errors:
        # https://repost.aws/knowledge-center/lambda-troubleshoot-invoke-error-502-500
        if isinstance(error, TooManyRequestsException):  # Throttles 429
            LOG.debug("Throttled lambda %s: %s", self.version_manager.function_arn, error)
            status = FunctionStatus.throttle_error
        else:  # System errors 5xx
            LOG.debug(
                "Service exception in lambda %s: %s", self.version_manager.function_arn, error
            )
            status = FunctionStatus.system_error
        delay_seconds = min(
            2**sqs_invocation.exception_retries, MAXIMUM_EXCEPTION_RETRY_DELAY_SECONDS
        )
        # TODO: calculate delay seconds into max event age handling
        sqs_client = get_sqs_client(self.version_manager.function_version)
        sqs_client.send_message(
            QueueUrl=self.event_queue_url,
            MessageBody=sqs_invocation.encode(),
            DelaySeconds=delay_seconds,
        )
        return status

    def process_success_destination(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
        event_invoke_config: EventInvokeConfig | None,
    ) -> None:
        if event_invoke_config is None:
            return
        success_destination = event_invoke_config.destination_config.get("OnSuccess", {}).get(
            "Destination"
        )
        if success_destination is None:
            return
        LOG.debug("Handling success destination for %s", self.version_manager.function_arn)

        original_payload = sqs_invocation.invocation.payload
        try:
            request_payload = json.loads(to_str(original_payload))
        except (json.JSONDecodeError, TypeError, ValueError):
            request_payload = to_str(original_payload)
        try:
            response_payload = json.loads(to_str(invocation_result.payload or b"{}"))
        except (json.JSONDecodeError, TypeError, ValueError):
            response_payload = to_str(invocation_result.payload)
        destination_payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": invocation_result.request_id,
                "functionArn": self.version_manager.function_version.qualified_arn,
                "condition": "Success",
                "approximateInvokeCount": sqs_invocation.retries + 1,
            },
            "requestPayload": request_payload,
            "responseContext": {
                "statusCode": 200,
                "executedVersion": self.version_manager.function_version.id.qualifier,
            },
            "responsePayload": response_payload,
        }

        target_arn = event_invoke_config.destination_config["OnSuccess"]["Destination"]
        try:
            send_event_to_target(
                target_arn=target_arn,
                event=destination_payload,
                role=self.version_manager.function_version.config.role,
                source_arn=self.version_manager.function_version.id.unqualified_arn(),
                source_service="lambda",
                events_source="lambda",
                events_detail_type="Lambda Function Invocation Result - Success",
            )
        except Exception as e:
            LOG.warning("Error sending invocation result to %s: %s", target_arn, e)

    def process_failure_destination(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
        event_invoke_config: EventInvokeConfig | None,
        failure_cause: str,
    ):
        if event_invoke_config is None:
            return
        failure_destination = event_invoke_config.destination_config.get("OnFailure", {}).get(
            "Destination"
        )
        if failure_destination is None:
            return
        LOG.debug("Handling failure destination for %s", self.version_manager.function_arn)

        original_payload = sqs_invocation.invocation.payload
        try:
            request_payload = json.loads(to_str(original_payload))
        except (json.JSONDecodeError, TypeError, ValueError):
            request_payload = to_str(original_payload)
        if failure_cause == "ZeroReservedConcurrency":
            approximate_invoke_count = sqs_invocation.retries
        else:
            approximate_invoke_count = sqs_invocation.retries + 1
        destination_payload = {
            "version": "1.0",
            "timestamp": timestamp_millis(),
            "requestContext": {
                "requestId": invocation_result.request_id,
                "functionArn": self.version_manager.function_version.qualified_arn,
                "condition": failure_cause,
                "approximateInvokeCount": approximate_invoke_count,
            },
            "requestPayload": request_payload,
        }
        if failure_cause != "ZeroReservedConcurrency":
            destination_payload["responseContext"] = {
                "statusCode": 200,
                "executedVersion": self.version_manager.function_version.id.qualifier,
                "functionError": "Unhandled",
            }
            try:
                response_payload = json.loads(to_str(invocation_result.payload))
            except (json.JSONDecodeError, TypeError, ValueError):
                response_payload = to_str(invocation_result.payload)
            destination_payload["responsePayload"] = response_payload

        target_arn = event_invoke_config.destination_config["OnFailure"]["Destination"]
        try:
            send_event_to_target(
                target_arn=target_arn,
                event=destination_payload,
                role=self.version_manager.function_version.config.role,
                source_arn=self.version_manager.function_version.id.unqualified_arn(),
                source_service="lambda",
                events_source="lambda",
                events_detail_type="Lambda Function Invocation Result - Failure",
            )
        except Exception as e:
            LOG.warning("Error sending invocation result to %s: %s", target_arn, e)

    def process_dead_letter_queue(
        self,
        sqs_invocation: SQSInvocation,
        invocation_result: InvocationResult,
    ):
        dlq_arn = self.version_manager.function_version.config.dead_letter_arn
        if not dlq_arn:
            return
        LOG.debug("Handling dead letter queue for %s", self.version_manager.function_arn)
        try:
            try:
                event_payload = json.loads(to_str(sqs_invocation.invocation.payload))
            except (json.JSONDecodeError, TypeError, ValueError):
                event_payload = {"raw_payload": to_str(sqs_invocation.invocation.payload)}
            dead_letter_queue._send_to_dead_letter_queue(
                source_arn=self.version_manager.function_arn,
                dlq_arn=dlq_arn,
                event=event_payload,
                # TODO: Refactor DLQ handling by removing the invocation exception from the legacy lambda provider
                # TODO: Check message. Possibly remove because it is not used in the DLQ message?!
                error=LegacyInvocationException(
                    message="hi", result=to_str(invocation_result.payload)
                ),
                role=self.version_manager.function_version.config.role,
            )
        except Exception as e:
            LOG.warning(
                "Error sending invocation result to DLQ %s: %s",
                self.version_manager.function_version.config.dead_letter_arn,
                e,
            )


class LambdaEventManager:
    version_manager: LambdaVersionManager
    poller: Poller | None
    poller_thread: FuncThread | None
    event_queue_url: str | None
    lifecycle_lock: threading.RLock
    stopped: threading.Event

    def __init__(self, version_manager: LambdaVersionManager):
        self.version_manager = version_manager
        self.poller = None
        self.poller_thread = None
        self.event_queue_url = None
        self.lifecycle_lock = threading.RLock()
        self.stopped = threading.Event()

    def enqueue_event(self, invocation: Invocation) -> None:
        message_body = SQSInvocation(invocation).encode()
        sqs_client = get_sqs_client(self.version_manager.function_version)
        try:
            sqs_client.send_message(QueueUrl=self.event_queue_url, MessageBody=message_body)
        except Exception as e:
            LOG.error(
                "Failed to enqueue Lambda event into queue %s. Invocation: request_id=%s, invoked_arn=%s",
                self.event_queue_url,
                invocation.request_id,
                invocation.invoked_arn,
            )
            from localemu.aws.api.lambda_ import ServiceException

            raise ServiceException(
                f"Failed to enqueue event for function {invocation.invoked_arn}", Type="Server"
            ) from e

    def start(self) -> None:
        LOG.debug(
            "Starting event manager %s id %s",
            self.version_manager.function_version.id.qualified_arn(),
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped before started.")
                return
            sqs_client = get_sqs_client(self.version_manager.function_version)
            function_id = self.version_manager.function_version.id
            # Truncate function name to ensure queue name limit of max 80 characters
            function_name_short = function_id.function_name[:47]
            # The instance id MUST be unique to the function and a given LocalEmu instance
            queue_namespace = (
                f"{function_id.qualified_arn()}-{self.version_manager.function.instance_id}"
            )
            queue_name = f"{function_name_short}-{md5(queue_namespace)}"
            create_queue_response = sqs_client.create_queue(QueueName=queue_name)
            self.event_queue_url = create_queue_response["QueueUrl"]
            # We don't need to purge the queue for persistence or cloud pods because the instance id is MUST be unique

            self.poller = Poller(self.version_manager, self.event_queue_url)
            self.poller_thread = FuncThread(
                self.poller.run,
                name=f"lambda-poller-{function_id.function_name}:{function_id.qualifier}",
            )
            self.poller_thread.start()

    def stop_for_update(self) -> None:
        """Stop the event manager for a version update while preserving the event queue.

        Messages are intentionally NOT drained from the queue. The queue is kept alive
        (not deleted) so that the new event manager created during update_version_state
        can re-attach to the same queue via idempotent ``create_queue``. Any in-flight or
        pending messages will be picked up by the new poller once it starts, ensuring no
        events are lost during a version rollover.
        """
        LOG.debug(
            "Stopping event manager but keep queue %s id %s",
            self.version_manager.function_version.qualified_arn,
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped!")
                return
            self.stopped.set()
            if self.poller:
                self.poller.stop()
                self.poller_thread.join(timeout=POLLER_THREAD_JOIN_TIMEOUT_SECONDS)
                LOG.debug("Waited for poller thread %s", self.poller_thread)
                if self.poller_thread.is_alive():
                    LOG.error("Poller did not shutdown %s", self.poller_thread)
                self.poller = None

    def stop(self) -> None:
        LOG.debug(
            "Stopping event manager %s: %s id %s",
            self.version_manager.function_version.qualified_arn,
            self.poller,
            id(self),
        )
        with self.lifecycle_lock:
            if self.stopped.is_set():
                LOG.debug("Event manager already stopped!")
                return
            self.stopped.set()
            if self.poller:
                self.poller.stop()
                self.poller_thread.join(timeout=POLLER_THREAD_JOIN_TIMEOUT_SECONDS)
                LOG.debug("Waited for poller thread %s", self.poller_thread)
                if self.poller_thread.is_alive():
                    LOG.error("Poller did not shutdown %s", self.poller_thread)
                self.poller = None
            if self.event_queue_url:
                sqs_client = get_sqs_client(
                    self.version_manager.function_version, client_config=CLIENT_CONFIG
                )
                sqs_client.delete_queue(QueueUrl=self.event_queue_url)
                self.event_queue_url = None
