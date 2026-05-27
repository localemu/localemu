import base64
import copy
import io
import json
import logging
import re
from collections.abc import Callable
from gzip import GzipFile
from typing import Any

from moto.core.utils import unix_time_millis
from moto.logs.models import LogEvent, LogsBackend
from moto.logs.models import LogGroup as MotoLogGroup
from moto.logs.models import LogStream as MotoLogStream

from localemu.aws.api import CommonServiceException, RequestContext, handler
from localemu.aws.api.logs import (
    AmazonResourceName,
    DeletionProtectionEnabled,
    DescribeLogGroupsRequest,
    DescribeLogGroupsResponse,
    DescribeLogStreamsRequest,
    DescribeLogStreamsResponse,
    Entity,
    InputLogEvents,
    InvalidParameterException,
    KmsKeyId,
    ListLogGroupsRequest,
    ListLogGroupsResponse,
    ListTagsForResourceResponse,
    ListTagsLogGroupResponse,
    LogGroupClass,
    LogGroupName,
    LogGroupSummary,
    LogsApi,
    LogStreamName,
    PutLogEventsResponse,
    ResourceNotFoundException,
    SequenceToken,
    TagKeyList,
    TagList,
    Tags,
)
from localemu.aws.connect import connect_to
from localemu.services import moto
from localemu.services.logs.models import get_moto_logs_backend, logs_stores
from localemu.services.moto import call_moto
from localemu.services.plugins import ServiceLifecycleHook
from localemu.state import StateVisitor
from localemu.utils.aws import arns
from localemu.utils.aws.client_types import ServicePrincipal
from localemu.utils.bootstrap import is_api_enabled
from localemu.utils.numbers import is_number
from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)


class LogsProvider(LogsApi, ServiceLifecycleHook):
    def __init__(self):
        super().__init__()
        self.cw_client = connect_to().cloudwatch

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.logs.models import logs_backends

        visitor.visit(logs_backends)
        visitor.visit(logs_stores)

    def put_log_events(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        log_stream_name: LogStreamName,
        log_events: InputLogEvents,
        sequence_token: SequenceToken | None = None,
        entity: Entity | None = None,
        **kwargs,
    ) -> PutLogEventsResponse:
        logs_backend = get_moto_logs_backend(context.account_id, context.region)
        metric_filters = logs_backend.filters.metric_filters if is_api_enabled("cloudwatch") else []
        for metric_filter in metric_filters:
            pattern = metric_filter.get("filterPattern", "")
            transformations = metric_filter.get("metricTransformations", [])
            matches = get_pattern_matcher(pattern)
            for log_event in log_events:
                if matches(pattern, log_event):
                    for tf in transformations:
                        value = tf.get("metricValue") or "1"
                        if "$size" in value:
                            LOG.info(
                                "Expression not yet supported for log filter metricValue", value
                            )
                        value = float(value) if is_number(value) else 1
                        data = [{"MetricName": tf["metricName"], "Value": value}]
                        try:
                            client = connect_to(
                                aws_access_key_id=context.account_id, region_name=context.region
                            ).cloudwatch
                            client.put_metric_data(Namespace=tf["metricNamespace"], MetricData=data)
                        except Exception as e:
                            LOG.info(
                                "Unable to put metric data for matching CloudWatch log events", e
                            )
        return call_moto(context)

    @handler("DescribeLogGroups", expand=False)
    def describe_log_groups(
        self, context: RequestContext, request: DescribeLogGroupsRequest
    ) -> DescribeLogGroupsResponse:
        region_backend = get_moto_logs_backend(context.account_id, context.region)

        prefix: str | None = request.get("logGroupNamePrefix", "")
        pattern: str | None = request.get("logGroupNamePattern", "")

        if pattern and prefix:
            raise InvalidParameterException(
                "LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters."
            )

        # CWL-2: avoid deep-copying every LogGroup (including all streams + events) on every
        # describe call. A shallow list snapshot is enough to iterate safely; each group's
        # `to_describe_dict()` is already defensive against concurrent stream mutation.
        moto_groups = list(region_backend.groups.values())

        groups = [
            {"logGroupClass": LogGroupClass.STANDARD} | group.to_describe_dict()
            for group in sorted(moto_groups, key=lambda g: g.name)
            if not (prefix or pattern)
            or (prefix and group.name.startswith(prefix))
            or (pattern and pattern in group.name)
        ]

        return DescribeLogGroupsResponse(logGroups=groups)

    @handler("DescribeLogStreams", expand=False)
    def describe_log_streams(
        self, context: RequestContext, request: DescribeLogStreamsRequest
    ) -> DescribeLogStreamsResponse:
        log_group_name: str | None = request.get("logGroupName")
        log_group_identifier: str | None = request.get("logGroupIdentifier")

        if log_group_identifier and log_group_name:
            raise CommonServiceException(
                "ValidationException",
                "LogGroup name and LogGroup ARN are mutually exclusive parameters.",
            )
        request_copy = copy.deepcopy(request)
        if log_group_identifier:
            request_copy.pop("logGroupIdentifier")
            # identifier can be arn or name
            request_copy["logGroupName"] = log_group_identifier.split(":")[-1]

        return moto.call_moto_with_request(context, request_copy)

    @handler("ListLogGroups", expand=False)
    def list_log_groups(
        self, context: RequestContext, request: ListLogGroupsRequest
    ) -> ListLogGroupsResponse:
        pattern: str | None = request.get("logGroupNamePattern")
        next_token: str | None = request.get("nextToken")
        limit: int | None = request.get("limit")

        region_backend: LogsBackend = get_moto_logs_backend(context.account_id, context.region)
        # Shallow snapshot — the deep copy was unnecessary since we only read .name/.arn.
        moto_groups = list(region_backend.groups.values())
        filtered = [
            LogGroupSummary(
                logGroupName=group.name, logGroupArn=group.arn, logGroupClass=LogGroupClass.STANDARD
            )
            for group in sorted(moto_groups, key=lambda g: g.name)
            if not pattern or pattern in group.name
        ]

        # CWL-5: implement nextToken/limit pagination. nextToken encodes the start index
        # (as a plain integer string), matching the scheme used elsewhere in LocalEmu
        # where the API itself does not prescribe an opaque token format.
        start = 0
        if next_token:
            try:
                start = max(0, int(next_token))
            except ValueError:
                start = 0
        end = len(filtered) if limit is None else min(len(filtered), start + limit)
        page = filtered[start:end]
        response = ListLogGroupsResponse(logGroups=page)
        if end < len(filtered):
            response["nextToken"] = str(end)
        return response

    def create_log_group(
        self,
        context: RequestContext,
        log_group_name: LogGroupName,
        kms_key_id: KmsKeyId | None = None,
        tags: Tags | None = None,
        log_group_class: LogGroupClass | None = None,
        deletion_protection_enabled: DeletionProtectionEnabled | None = None,
        **kwargs,
    ) -> None:
        call_moto(context)
        if tags:
            resource_arn = arns.log_group_arn(
                group_name=log_group_name, account_id=context.account_id, region_name=context.region
            )
            store = logs_stores[context.account_id][context.region]
            store.TAGS.setdefault(resource_arn, {}).update(tags)

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        tags = store.TAGS.get(resource_arn, {})
        return ListTagsForResourceResponse(tags=tags)

    def list_tags_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, **kwargs
    ) -> ListTagsLogGroupResponse:
        # deprecated implementation, new one: list_tags_for_resource
        self._verify_log_group_exists(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        store = logs_stores[context.account_id][context.region]
        tags = store.TAGS.get(resource_arn, {})
        return ListTagsLogGroupResponse(tags=tags)

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        tags_stored = store.TAGS.get(resource_arn, {})
        for tag in tag_keys:
            tags_stored.pop(tag, None)

    def untag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: TagList, **kwargs
    ) -> None:
        # deprecated implementation -> new one: untag_resource
        self._verify_log_group_exists(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        store = logs_stores[context.account_id][context.region]
        tags_stored = store.TAGS.get(resource_arn, {})
        for tag in tags:
            tags_stored.pop(tag, None)

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: Tags, **kwargs
    ) -> None:
        self._check_resource_arn_tagging(resource_arn)
        store = logs_stores[context.account_id][context.region]
        # CWL-3: use setdefault so tags are stored even when this is the first tagging
        # operation for the resource. Previously `.get(arn, {})` returned a throwaway
        # dict that was never written back, silently losing the tags.
        store.TAGS.setdefault(resource_arn, {}).update(tags or {})

    def tag_log_group(
        self, context: RequestContext, log_group_name: LogGroupName, tags: Tags, **kwargs
    ) -> None:
        # deprecated implementation -> new one: tag_resource
        self._verify_log_group_exists(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        resource_arn = arns.log_group_arn(
            group_name=log_group_name, account_id=context.account_id, region_name=context.region
        )
        store = logs_stores[context.account_id][context.region]
        # CWL-3: same fix as tag_resource — persist tags for newly-tagged resources.
        store.TAGS.setdefault(resource_arn, {}).update(tags or {})

    def _verify_log_group_exists(self, group_name: LogGroupName, account_id: str, region_name: str):
        store = get_moto_logs_backend(account_id, region_name)
        if group_name not in store.groups:
            raise ResourceNotFoundException()

    def _check_resource_arn_tagging(self, resource_arn):
        service = arns.extract_service_from_arn(resource_arn)
        region = arns.extract_region_from_arn(resource_arn)
        account = arns.extract_account_id_from_arn(resource_arn)

        # AWS currently only supports tagging for Log Group and Destinations
        # LS: we only verify if log group exists, and create tags for other resources
        if service.lower().startswith("log-group:"):
            self._verify_log_group_exists(
                service.split(":")[-1], account_id=account, region_name=region
            )


def _match_aws_filter_pattern(pattern: str, log_event: dict) -> bool:
    """Evaluate an AWS CloudWatch Logs filter pattern against a single log event.

    Implements the commonly-used terms-based syntax described in
    https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
    (CWL-1). An empty pattern matches everything (same as AWS).

    Supported constructs:
      - Space-separated terms (implicit AND). All non-optional terms must appear.
      - Quoted phrases ("foo bar") matched as a substring.
      - Prefix `-` (exclude): event must NOT contain the term.
      - Prefix `?` (at least-one-of): at least one of the `?` terms must match.
      - JSON selectors `{ $.path = "value" }` for simple equality are evaluated
        when the event message parses as JSON. Unsupported JSON expressions
        conservatively fall back to a substring match on the raw pattern.

    Anything more exotic (metric filter column patterns, numeric ranges on JSON)
    is not universally required by callers and falls through to the substring path.
    """
    if not pattern:
        return True

    message = log_event.get("message", "") if isinstance(log_event, dict) else str(log_event)

    pattern = pattern.strip()

    # JSON-filter pattern: {$.foo = "bar"} / {$.foo = 42}
    if pattern.startswith("{") and pattern.endswith("}"):
        try:
            parsed_msg = json.loads(message)
        except (ValueError, TypeError):
            return False
        expr = pattern[1:-1].strip()
        match = re.match(
            r"\$\.(?P<path>[A-Za-z0-9_.\[\]]+)\s*(?P<op>=|!=)\s*(?P<value>\"[^\"]*\"|-?\d+(?:\.\d+)?|true|false|null)",
            expr,
        )
        if not match:
            # Unsupported JSON expression — fall back to substring on raw message.
            return pattern in message
        path = match.group("path")
        op = match.group("op")
        raw_value = match.group("value")
        if raw_value.startswith('"') and raw_value.endswith('"'):
            expected: Any = raw_value[1:-1]
        elif raw_value in ("true", "false"):
            expected = raw_value == "true"
        elif raw_value == "null":
            expected = None
        else:
            expected = float(raw_value) if "." in raw_value else int(raw_value)
        actual: Any = parsed_msg
        for segment in path.split("."):
            if isinstance(actual, dict) and segment in actual:
                actual = actual[segment]
            else:
                actual = None
                break
        return (actual == expected) if op == "=" else (actual != expected)

    # Tokenize the pattern, preserving quoted phrases.
    tokens: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in pattern:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch.isspace() and not in_quotes:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))

    required: list[str] = []
    excluded: list[str] = []
    optional: list[str] = []
    for token in tokens:
        if not token:
            continue
        if token.startswith("-"):
            excluded.append(_unquote(token[1:]))
        elif token.startswith("?"):
            optional.append(_unquote(token[1:]))
        else:
            required.append(_unquote(token))

    for term in required:
        if term and term not in message:
            return False
    for term in excluded:
        if term and term in message:
            return False
    if optional and not any(term and term in message for term in optional):
        return False
    return True


def _unquote(term: str) -> str:
    if len(term) >= 2 and term.startswith('"') and term.endswith('"'):
        return term[1:-1]
    return term


def get_pattern_matcher(pattern: str) -> Callable[[str, dict], bool]:
    """Returns a pattern matcher. Can be patched by plugins to return a more sophisticated pattern matcher."""
    return _match_aws_filter_pattern


@patch(LogsBackend.put_subscription_filter)
def moto_put_subscription_filter(fn, self, *args, **kwargs):
    log_group_name = args[0]
    filter_name = args[1]
    filter_pattern = args[2]
    destination_arn = args[3]
    role_arn = args[4]

    log_group = self.groups.get(log_group_name)
    log_group_arn = arns.log_group_arn(log_group_name, self.account_id, self.region_name)

    if not log_group:
        raise ResourceNotFoundException("The specified log group does not exist.")

    arn_data = arns.parse_arn(destination_arn)

    if role_arn:
        factory = connect_to.with_assumed_role(
            role_arn=role_arn,
            service_principal=ServicePrincipal.logs,
            region_name=arn_data["region"],
        )
    else:
        factory = connect_to(aws_access_key_id=arn_data["account"], region_name=arn_data["region"])

    if ":lambda:" in destination_arn:
        client = factory.lambda_.request_metadata(
            source_arn=log_group_arn, service_principal=ServicePrincipal.logs
        )
        try:
            client.get_function(FunctionName=destination_arn)
        except Exception:
            raise InvalidParameterException(
                "destinationArn for vendor lambda cannot be used with roleArn"
            )

    elif ":kinesis:" in destination_arn:
        client = factory.kinesis.request_metadata(
            source_arn=log_group_arn, service_principal=ServicePrincipal.logs
        )
        stream_name = arns.kinesis_stream_name(destination_arn)
        try:
            # Kinesis-Local DescribeStream does not support StreamArn param, so use StreamName instead
            client.describe_stream(StreamName=stream_name)
        except Exception:
            raise InvalidParameterException(
                "Could not deliver message to specified Kinesis stream. "
                "Ensure that the Kinesis stream exists and is ACTIVE."
            )

    elif ":firehose:" in destination_arn:
        client = factory.firehose.request_metadata(
            source_arn=log_group_arn, service_principal=ServicePrincipal.logs
        )
        firehose_name = arns.firehose_name(destination_arn)
        try:
            client.describe_delivery_stream(DeliveryStreamName=firehose_name)
        except Exception:
            raise InvalidParameterException(
                "Could not deliver message to specified Firehose stream. "
                "Ensure that the Firehose stream exists and is ACTIVE."
            )

    else:
        raise InvalidParameterException(
            f"PutSubscriptionFilter operation cannot work with destinationArn for vendor {arn_data['service']}"
        )

    if filter_pattern:
        for stream in log_group.streams.values():
            stream.filter_pattern = filter_pattern

    log_group.put_subscription_filter(filter_name, filter_pattern, destination_arn, role_arn)


@patch(MotoLogStream.put_log_events, pass_target=False)
def moto_put_log_events(self: "MotoLogStream", log_events):
    # TODO: call/patch upstream method here, instead of duplicating the code!
    self.last_ingestion_time = int(unix_time_millis())
    self.stored_bytes += sum([len(log_event["message"]) for log_event in log_events])
    events = [LogEvent(self.last_ingestion_time, log_event) for log_event in log_events]
    self.events += events
    self.upload_sequence_token += 1

    # apply filter_pattern -> only forward what matches the pattern.
    # CWL-4: use distinct variable names per iteration to avoid shadowing the outer
    # `events` / `log_events` (which are reused across all subscription filters) and
    # leaking filtered state from one filter into the next.
    for subscription_filter in self.log_group.subscription_filters.values():
        if subscription_filter.filter_pattern:
            # TODO only patched in pro
            matches = get_pattern_matcher(subscription_filter.filter_pattern)
            filtered_events = [
                LogEvent(self.last_ingestion_time, raw_event)
                for raw_event in log_events
                if matches(subscription_filter.filter_pattern, raw_event)
            ]
        else:
            filtered_events = events

        if filtered_events and subscription_filter.destination_arn:
            destination_arn = subscription_filter.destination_arn
            forwarded_events = [
                {
                    "id": str(fe.event_id),
                    "timestamp": fe.timestamp,
                    "message": fe.message,
                }
                for fe in filtered_events
            ]

            data = {
                "messageType": "DATA_MESSAGE",
                "owner": self.account_id,  # AWS Account ID of the originating log data
                "logGroup": self.log_group.name,
                "logStream": self.log_stream_name,
                "subscriptionFilters": [subscription_filter.name],
                "logEvents": forwarded_events,
            }

            output = io.BytesIO()
            with GzipFile(fileobj=output, mode="w") as f:
                f.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
            payload_gz_encoded = output.getvalue()
            event = {"awslogs": {"data": base64.b64encode(output.getvalue()).decode("utf-8")}}

            log_group_arn = arns.log_group_arn(self.log_group.name, self.account_id, self.region)
            arn_data = arns.parse_arn(destination_arn)

            if subscription_filter.role_arn:
                factory = connect_to.with_assumed_role(
                    role_arn=subscription_filter.role_arn,
                    service_principal=ServicePrincipal.logs,
                    region_name=arn_data["region"],
                )
            else:
                factory = connect_to(
                    aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
                )

            if ":lambda:" in destination_arn:
                client = factory.lambda_.request_metadata(
                    source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                )
                client.invoke(FunctionName=destination_arn, Payload=json.dumps(event))

            if ":kinesis:" in destination_arn:
                client = factory.kinesis.request_metadata(
                    source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                )
                stream_name = arns.kinesis_stream_name(destination_arn)
                client.put_record(
                    StreamName=stream_name,
                    Data=payload_gz_encoded,
                    PartitionKey=self.log_group.name,
                )

            if ":firehose:" in destination_arn:
                client = factory.firehose.request_metadata(
                    source_arn=log_group_arn, service_principal=ServicePrincipal.logs
                )
                firehose_name = arns.firehose_name(destination_arn)
                client.put_record(
                    DeliveryStreamName=firehose_name,
                    Record={"Data": payload_gz_encoded},
                )

    return f"{self.upload_sequence_token:056d}"


@patch(MotoLogStream.filter_log_events)
def moto_filter_log_events(
    filter_log_events, self, start_time, end_time, filter_pattern, *args, **kwargs
):
    # moto currently raises an exception if filter_patterns is None, so we skip it
    events = filter_log_events(
        self, *args, start_time=start_time, end_time=end_time, filter_pattern=None, **kwargs
    )

    if not filter_pattern:
        return events

    matches = get_pattern_matcher(filter_pattern)
    return [event for event in events if matches(filter_pattern, event)]


@patch(MotoLogGroup.create_log_stream)
def moto_create_log_stream(target, self, log_stream_name):
    target(self, log_stream_name)
    stream = self.streams[log_stream_name]
    filters = self.describe_subscription_filters()
    stream.filter_pattern = filters[0]["filterPattern"] if filters else None


@patch(MotoLogGroup.to_describe_dict)
def moto_to_describe_dict(target, self):
    # reported race condition in https://github.com/localstack/localstack/issues/8011
    # making copy of "streams" dict here to avoid issues while summing up storedBytes
    copy_streams = copy.deepcopy(self.streams)
    log_group = {
        "arn": f"{self.arn}:*",
        "logGroupArn": self.arn,
        "creationTime": self.creation_time,
        "logGroupName": self.name,
        "metricFilterCount": 0,
        "storedBytes": sum(s.stored_bytes for s in copy_streams.values()),
    }
    if self.retention_in_days:
        log_group["retentionInDays"] = self.retention_in_days
    if self.kms_key_id:
        log_group["kmsKeyId"] = self.kms_key_id
    return log_group


@patch(MotoLogGroup.get_log_events)
def moto_get_log_events(
    target, self, log_stream_name, start_time, end_time, limit, next_token, start_from_head
):
    if log_stream_name not in self.streams:
        raise ResourceNotFoundException("The specified log stream does not exist.")
    return target(self, log_stream_name, start_time, end_time, limit, next_token, start_from_head)
