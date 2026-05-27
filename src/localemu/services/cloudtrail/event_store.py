"""
Shared CloudTrail event store for LocalEmu.

Records every API request flowing through the gateway with enriched
CloudTrail-compatible fields.  Both the dashboard and the CloudTrail
``LookupEvents`` API read from the same store — single source of truth.

Thread-safe, time-indexed, supports attribute filtering and pagination.
"""

from __future__ import annotations

import collections
import itertools
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# B6/B7/B9: typed errors surfaced from store.query() so the provider layer
# can translate them into AWS-compliant CommonServiceException responses.
# ---------------------------------------------------------------------------
VALID_EVENT_CATEGORIES = ("Management", "Data", "Insight")


class InvalidNextTokenError(Exception):
    """Raised when a supplied ``NextToken`` cannot be resolved to a known
    event. Mapped to ``InvalidNextTokenException`` (400) by the provider."""


class InvalidLookupAttributesError(Exception):
    """Raised when the caller supplies more than one ``LookupAttribute``.
    AWS rejects this with ``InvalidLookupAttributesException``."""


class InvalidEventCategoryError(Exception):
    """Raised when the caller supplies an ``EventCategory`` outside of
    ``Management``/``Data``/``Insight``."""


# ---------------------------------------------------------------------------
# Read-only detection
# ---------------------------------------------------------------------------
_READ_PREFIXES = (
    "Get", "List", "Describe", "Head", "Lookup", "Check",
    "Query", "Scan", "Search", "BatchGet", "Validate",
    "Select", "Test", "Simulate", "Decode", "Preview",
)


def _is_read_only(operation_name: str) -> bool:
    """Return True if the operation is read-only (non-mutating)."""
    return any(operation_name.startswith(p) for p in _READ_PREFIXES)


# ---------------------------------------------------------------------------
# Resource extraction — service-aware
# ---------------------------------------------------------------------------
_SERVICE_RESOURCE_TYPE = {
    "s3": "AWS::S3::Bucket",
    "dynamodb": "AWS::DynamoDB::Table",
    "sqs": "AWS::SQS::Queue",
    "lambda": "AWS::Lambda::Function",
    "sns": "AWS::SNS::Topic",
    "secretsmanager": "AWS::SecretsManager::Secret",
    "kinesis": "AWS::Kinesis::Stream",
    "events": "AWS::Events::Rule",
    "stepfunctions": "AWS::StepFunctions::StateMachine",
    "ecs": "AWS::ECS::Cluster",
    "eks": "AWS::EKS::Cluster",
    "rds": "AWS::RDS::DBInstance",
    "iam": "AWS::IAM::Role",
    "logs": "AWS::Logs::LogGroup",
    "cloudwatch": "AWS::CloudWatch::Alarm",
    "ec2": "AWS::EC2::Instance",
    "cloudformation": "AWS::CloudFormation::Stack",
}

# Map specific request keys to their resource type — this allows the same
# service (e.g. IAM) to report the correct resource type based on which key
# was matched, instead of always falling back to the service-level default.
_KEY_TO_RESOURCE_TYPE = {
    "RoleName": "AWS::IAM::Role",
    "UserName": "AWS::IAM::User",
    "PolicyName": "AWS::IAM::Policy",
    "PolicyArn": "AWS::IAM::Policy",
    "GroupName": "AWS::IAM::Group",
    "InstanceProfileName": "AWS::IAM::InstanceProfile",
    "Cluster": "AWS::ECS::Cluster",
    "ClusterName": "AWS::EKS::Cluster",
    "TaskDefinitionArn": "AWS::ECS::TaskDefinition",
    "DBClusterIdentifier": "AWS::RDS::DBCluster",
    "DBInstanceIdentifier": "AWS::RDS::DBInstance",
    "InstanceId": "AWS::EC2::Instance",
    "VpcId": "AWS::EC2::VPC",
    "SubnetId": "AWS::EC2::Subnet",
    "SecurityGroupId": "AWS::EC2::SecurityGroup",
}

# Keys to look for in the parsed service_request to extract the resource name.
# Order matters — first match wins.
_RESOURCE_NAME_KEYS = (
    "Bucket", "BucketName",
    "TableName",
    "QueueUrl", "QueueName",
    "FunctionName",
    "TopicArn", "TopicName",
    "SecretId", "Name",
    "StreamName",
    "RuleName",
    "StateMachineArn",
    "Cluster", "ClusterName",
    "DBInstanceIdentifier", "DBClusterIdentifier",
    "RoleName", "UserName", "PolicyName", "PolicyArn", "GroupName",
    "InstanceProfileName",
    "LogGroupName",
    "AlarmName",
    "InstanceId", "VpcId", "SubnetId", "SecurityGroupId",
    "StackName",
    "TaskDefinitionArn",
)


def _extract_resources(service: str, service_request: dict | None) -> list[dict[str, str]]:
    """Extract affected resources from the parsed AWS request parameters.

    Extracts all matching resource keys (not just the first), so operations
    affecting multiple resources (e.g. CopyObject with source + destination)
    report all of them.
    """
    if not service_request:
        return []

    default_type = _SERVICE_RESOURCE_TYPE.get(service, f"AWS::{service.upper()}::Resource")
    resources = []

    for key in _RESOURCE_NAME_KEYS:
        val = service_request.get(key)
        if val and isinstance(val, str):
            # Extract short name from ARNs
            name = val.split("/")[-1] if "/" in val else val.split(":")[-1] if ":" in val else val
            resource_type = _KEY_TO_RESOURCE_TYPE.get(key, default_type)
            resources.append({"ResourceType": resource_type, "ResourceName": name})

    return resources


# ---------------------------------------------------------------------------
# CloudTrailEvent
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CloudTrailEvent:
    """A single CloudTrail event with all standard fields."""

    event_id: str
    event_time: datetime
    event_source: str       # "s3.amazonaws.com"
    event_name: str         # "CreateBucket"
    aws_region: str         # "us-east-1"
    source_ip: str          # "127.0.0.1"
    user_agent: str
    account_id: str         # "000000000000"
    read_only: bool
    username: str           # access key or IAM user
    access_key_id: str
    error_code: str | None
    error_message: str | None
    resources: list[dict[str, str]]
    request_id: str
    request_parameters: dict[str, Any] | None = None
    response_elements: dict[str, Any] | None = None
    http_status_code: int = 0
    # B6/B8: Every event carries its CloudTrail category. LocalEmu records
    # management-plane API calls, so the default is "Management". Data- and
    # Insight-category events are recorded explicitly by callers that know
    # they've observed data-plane activity or insight anomalies.
    event_category: str = "Management"

    def to_cloudtrail_event_json(self) -> str:
        """Build the full CloudTrailEvent JSON string (what AWS returns).

        B8 fixes:
          * ``eventTime`` is serialized in UTC with second precision
            (``YYYY-MM-DDTHH:MM:SSZ``). If the stored datetime is naive
            (e.g. loaded from an older on-disk format), it is assumed to be
            UTC and stamped accordingly.
          * ``eventCategory`` is emitted (AWS requires it for all events).
          * ``managementEvent`` is ``true`` only for Management-category
            events, matching AWS CloudTrail JSON schema 1.08.
        """
        et = self.event_time
        if et.tzinfo is None:
            et = et.replace(tzinfo=timezone.utc)
        else:
            et = et.astimezone(timezone.utc)
        event_time_str = et.strftime("%Y-%m-%dT%H:%M:%SZ")

        category = self.event_category or "Management"

        event_dict: dict[str, Any] = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.access_key_id or "AIDAEXAMPLE",
                "arn": f"arn:aws:iam::{self.account_id}:user/{self.username}",
                "accountId": self.account_id,
                "accessKeyId": self.access_key_id or "ANONYMOUS",
                "userName": self.username,
            },
            "eventTime": event_time_str,
            "eventSource": self.event_source,
            "eventName": self.event_name,
            "awsRegion": self.aws_region,
            "sourceIPAddress": self.source_ip,
            "userAgent": self.user_agent,
            "requestID": self.request_id,
            "eventID": self.event_id,
            "readOnly": self.read_only,
            "eventType": "AwsApiCall",
            "managementEvent": category == "Management",
            "eventCategory": category,
            "recipientAccountId": self.account_id,
        }

        if self.request_parameters:
            event_dict["requestParameters"] = self.request_parameters

        if self.response_elements and not self.read_only:
            event_dict["responseElements"] = self.response_elements

        if self.resources:
            event_dict["resources"] = self.resources

        if self.error_code:
            event_dict["errorCode"] = self.error_code
        if self.error_message:
            event_dict["errorMessage"] = self.error_message

        return json.dumps(event_dict, default=str)

    def to_lookup_event(self) -> dict[str, Any]:
        """Build the Event dict for LookupEvents response."""
        event: dict[str, Any] = {
            "EventId": self.event_id,
            "EventName": self.event_name,
            "ReadOnly": str(self.read_only).lower(),
            "AccessKeyId": self.access_key_id or "ANONYMOUS",
            "EventTime": self.event_time,
            "EventSource": self.event_source,
            "Username": self.username,
            "CloudTrailEvent": self.to_cloudtrail_event_json(),
        }

        if self.resources:
            event["Resources"] = [
                {"ResourceType": r["ResourceType"], "ResourceName": r["ResourceName"]}
                for r in self.resources
            ]

        return event

    def to_dashboard_event(self) -> dict[str, Any]:
        """Build the event dict for the dashboard API (backward compatible)."""
        return {
            "timestamp": self.event_time.isoformat(),
            "service": self.event_source.removesuffix(".amazonaws.com"),
            "operation": self.event_name,
            "status": self.http_status_code,
            "account_id": self.account_id,
            "region": self.aws_region,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_id": self.request_id,
            "read_only": self.read_only,
            "error_code": self.error_code,
            "resources": self.resources,
        }


# ---------------------------------------------------------------------------
# Attribute filters for LookupEvents
# ---------------------------------------------------------------------------
_ATTRIBUTE_FILTERS = {
    "EventName": lambda evt, val: evt.event_name == val,
    "EventSource": lambda evt, val: evt.event_source == val,
    "EventId": lambda evt, val: evt.event_id == val,
    "ReadOnly": lambda evt, val: str(evt.read_only).lower() == val.lower(),
    "Username": lambda evt, val: evt.username == val,
    "ResourceType": lambda evt, val: any(
        r.get("ResourceType") == val for r in evt.resources
    ),
    "ResourceName": lambda evt, val: any(
        r.get("ResourceName") == val for r in evt.resources
    ),
    "AccessKeyId": lambda evt, val: evt.access_key_id == val,
}


# ---------------------------------------------------------------------------
# CloudTrailEventStore
# ---------------------------------------------------------------------------
class CloudTrailEventStore:
    """Thread-safe, queryable store for CloudTrail events.

    Events are stored newest-first using a bounded deque (O(1) append).
    Supports time-range queries, attribute filtering, event-id-based
    pagination, and O(1) lookup by request_id.
    """

    def __init__(self, max_events: int = 10_000) -> None:
        self._lock = threading.Lock()
        # E5: separate lock for disk writes so a save in flight doesn't block record().
        # Serializes concurrent save_to_disk calls (overlapping counter roll-overs),
        # guaranteeing at most one writer is doing I/O at any time.
        self._disk_lock = threading.Lock()
        self._events: collections.deque[CloudTrailEvent] = collections.deque(maxlen=max_events)
        # Index for O(1) lookup by request_id (used by dashboard detail view)
        self._by_request_id: dict[str, CloudTrailEvent] = {}
        # QUALITY-03: Track event count for periodic persistence
        self._record_count_since_save = 0
        self._SAVE_INTERVAL = 100  # Save every 100 events

    def record(self, event: CloudTrailEvent) -> None:
        """Record a new event. Called from the response handler hook."""
        # ISSUE-02: threshold check + counter reset must happen atomically
        # inside the lock to prevent multiple threads from simultaneously
        # crossing the threshold and triggering concurrent save_to_disk calls.
        should_save = False
        with self._lock:
            # If deque is full, the oldest event will be evicted — clean its index entry
            if len(self._events) == self._events.maxlen:
                oldest = self._events[-1]
                self._by_request_id.pop(oldest.request_id, None)
            # E3: if an event with the same request_id already exists, evict the
            # stale one from the deque so queries don't return duplicates while
            # get_by_request_id resolves only to the newest. Linear in deque size,
            # but duplicate request_ids are expected to be rare.
            if event.request_id:
                stale = self._by_request_id.get(event.request_id)
                if stale is not None:
                    try:
                        self._events.remove(stale)
                    except ValueError:
                        pass
            self._events.appendleft(event)
            if event.request_id:
                self._by_request_id[event.request_id] = event
            self._record_count_since_save += 1
            if self._record_count_since_save >= self._SAVE_INTERVAL:
                self._record_count_since_save = 0
                should_save = True

        # QUALITY-03: Periodically persist events to disk (outside the lock
        # so disk I/O does not block record()).
        if should_save:
            try:
                self.save_to_disk()
            except Exception:
                pass

    def get_by_request_id(self, request_id: str) -> CloudTrailEvent | None:
        """O(1) lookup of a single event by request_id."""
        with self._lock:
            return self._by_request_id.get(request_id)

    def query(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        lookup_attributes: list[dict[str, str]] | None = None,
        max_results: int = 50,
        next_token: str | None = None,
        event_category: str | None = None,
    ) -> tuple[list[CloudTrailEvent], str | None]:
        """Query events with filtering and event-id-based pagination.

        Returns (events, next_token). next_token is None when there are
        no more results. The token is an event_id (opaque to the client),
        stable across concurrent inserts.

        Compliance (B6/B7/B9):
          * At most ONE ``LookupAttribute`` — raises
            ``InvalidLookupAttributesError`` on more.
          * ``event_category`` must be ``Management``/``Data``/``Insight``
            when supplied; raises ``InvalidEventCategoryError`` otherwise.
          * A ``next_token`` that resolves to no known event raises
            ``InvalidNextTokenError`` rather than silently restarting.
        """
        # B9: AWS LookupEvents rejects requests with more than one attribute.
        if lookup_attributes and len(lookup_attributes) > 1:
            raise InvalidLookupAttributesError(
                "You can only specify one LookupAttribute per request."
            )

        # B6: validate EventCategory up-front.
        if event_category is not None and event_category not in VALID_EVENT_CATEGORIES:
            raise InvalidEventCategoryError(
                "EventCategory must be one of "
                f"{VALID_EVENT_CATEGORIES}, got {event_category!r}"
            )

        with self._lock:
            snapshot = list(self._events)

        # B6: category filter. Events recorded before this field existed
        # default to "Management" via the dataclass default, so the
        # historical corpus still matches ``EventCategory=Management``.
        if event_category:
            snapshot = [
                e for e in snapshot
                if (e.event_category or "Management") == event_category
            ]

        # Apply time-range filter
        if start_time:
            snapshot = [e for e in snapshot if e.event_time >= start_time]
        if end_time:
            snapshot = [e for e in snapshot if e.event_time <= end_time]

        # B9 (defence in depth): the >1 guard above means at most one
        # attribute reaches this loop. Kept in loop form so any future AWS
        # relaxation becomes transparent.
        if lookup_attributes:
            for attr in lookup_attributes:
                key = attr.get("AttributeKey", "")
                val = attr.get("AttributeValue", "")
                filter_fn = _ATTRIBUTE_FILTERS.get(key)
                if filter_fn:
                    snapshot = [e for e in snapshot if filter_fn(e, val)]

        # B7: event-id-based pagination — raise on a token we can't resolve
        # so paginating clients get a clear error instead of duplicate pages
        # or an infinite restart loop.
        offset = 0
        if next_token:
            found = False
            for i, evt in enumerate(snapshot):
                if evt.event_id == next_token:
                    offset = i + 1
                    found = True
                    break
            if not found:
                raise InvalidNextTokenError(
                    "Invalid NextToken: cursor does not match any known event."
                )

        # E4: clamp MaxResults server-side. Raw HTTP clients can pass 0 or
        # negative values; boto3 clients default to 50. AWS documents the
        # valid range as 1..50 — enforce it here regardless of caller.
        try:
            mr_int = int(max_results) if max_results is not None else 50
        except (TypeError, ValueError):
            mr_int = 50
        max_results = max(1, min(50, mr_int))
        page = snapshot[offset: offset + max_results]

        new_token = None
        if offset + max_results < len(snapshot):
            # Use the last event's ID as the cursor
            new_token = page[-1].event_id if page else None

        return page, new_token

    def get_event_count(self) -> int:
        """Return the total number of stored events."""
        with self._lock:
            return len(self._events)

    def get_recent(self, limit: int = 100) -> list[CloudTrailEvent]:
        """Return the most recent events (for dashboard).

        E4: clamp ``limit`` to a sane lower bound. 0, negative, or non-int
        values are raised to 1 — islice treats negative slice sizes as an
        error and 0 as empty, neither of which is the documented intent.
        The upper bound is not capped: dashboard and S3 log-delivery callers
        legitimately request more than 50 events at a time.
        """
        try:
            lim_int = int(limit) if limit is not None else 100
        except (TypeError, ValueError):
            lim_int = 100
        lim_int = max(1, lim_int)
        with self._lock:
            return list(itertools.islice(self._events, lim_int))

    def reset(self) -> None:
        """Clear all events."""
        with self._lock:
            self._events.clear()
            self._by_request_id.clear()

    # ------------------------------------------------------------------
    # QUALITY-03: Persistence — save/load events from disk
    # ------------------------------------------------------------------
    def _persistence_path(self) -> str | None:
        """Return the file path for persisted events, or None if persistence is disabled."""
        try:
            from localemu import config
            if not getattr(config, "PERSISTENCE", False):
                return None
            data_dir = getattr(config, "dirs", None)
            if data_dir and hasattr(data_dir, "data"):
                path = os.path.join(data_dir.data, "cloudtrail_events.json")
                return path
        except Exception:
            pass
        return None

    def save_to_disk(self) -> None:
        """Persist events to disk if PERSISTENCE is enabled.

        E1: writes are atomic — the JSON payload is written to ``<path>.tmp``,
        ``fsync``'d, then ``os.replace``'d over the final path. A crash mid-
        write leaves either the old file or the new file fully intact, never
        a partial truncation that ``load_from_disk`` would silently drop.

        E5: disk I/O is serialized through ``_disk_lock`` — independent of
        the in-memory ``_lock`` — so overlapping saves (e.g. two record()
        calls both crossing the roll-over threshold) cannot race over the
        same ``.tmp`` file. The snapshot is taken under ``_lock`` and released
        before the I/O proceeds, so record() is never blocked by disk work.
        """
        path = self._persistence_path()
        if not path:
            return

        # Snapshot under the store lock; release before any I/O.
        with self._lock:
            events_data = [
                {
                    "event_id": evt.event_id,
                    "event_time": evt.event_time.isoformat(),
                    "event_source": evt.event_source,
                    "event_name": evt.event_name,
                    "aws_region": evt.aws_region,
                    "source_ip": evt.source_ip,
                    "user_agent": evt.user_agent,
                    "account_id": evt.account_id,
                    "read_only": evt.read_only,
                    "username": evt.username,
                    "access_key_id": evt.access_key_id,
                    "error_code": evt.error_code,
                    "error_message": evt.error_message,
                    "resources": evt.resources,
                    "request_id": evt.request_id,
                    "request_parameters": evt.request_parameters,
                    "response_elements": evt.response_elements,
                    "http_status_code": evt.http_status_code,
                    "event_category": evt.event_category,
                }
                for evt in self._events
            ]

        tmp_path = path + ".tmp"
        # Serialize all disk work: atomic rename prevents partial writes, and
        # _disk_lock prevents two concurrent saves from clobbering tmp_path.
        with self._disk_lock:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(tmp_path, "w") as f:
                    json.dump(events_data, f, default=str)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
                LOG.debug(
                    "Persisted %d CloudTrail events to %s", len(events_data), path
                )
            except Exception:
                # Best-effort cleanup of the temp file on failure. The previous
                # file at ``path`` is untouched because os.replace ran last (or
                # not at all).
                try:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                except Exception:
                    pass
                LOG.debug("Failed to persist CloudTrail events", exc_info=True)

    def load_from_disk(self) -> None:
        """Load persisted events from disk if PERSISTENCE is enabled.

        E2: persisted events are only loaded when the store is empty.
        ``appendleft``-ing persisted events in front of live ones would break
        the deque's descending-time invariant (persisted batch is older than
        whatever ran after the startup that created those live events), and
        silently return stale events first from ``query`` / ``get_recent``.
        Callers that want to merge post-startup should call ``reset()`` first
        or rely on the startup-time load path.
        """
        path = self._persistence_path()
        if not path:
            return
        try:
            if not os.path.exists(path):
                return
            with open(path) as f:
                events_data = json.load(f)
            count = 0
            with self._lock:
                if len(self._events) > 0:
                    LOG.debug(
                        "Skipping load_from_disk: store already contains %d live events",
                        len(self._events),
                    )
                    return
                for data in reversed(events_data):  # oldest first so newest end up at front
                    evt = CloudTrailEvent(
                        event_id=data["event_id"],
                        event_time=datetime.fromisoformat(data["event_time"]),
                        event_source=data["event_source"],
                        event_name=data["event_name"],
                        aws_region=data["aws_region"],
                        source_ip=data["source_ip"],
                        user_agent=data["user_agent"],
                        account_id=data["account_id"],
                        read_only=data["read_only"],
                        username=data["username"],
                        access_key_id=data["access_key_id"],
                        error_code=data.get("error_code"),
                        error_message=data.get("error_message"),
                        resources=data.get("resources", []),
                        request_id=data["request_id"],
                        request_parameters=data.get("request_parameters"),
                        response_elements=data.get("response_elements"),
                        http_status_code=data.get("http_status_code", 0),
                        event_category=data.get("event_category", "Management"),
                    )
                    self._events.appendleft(evt)
                    if evt.request_id:
                        self._by_request_id[evt.request_id] = evt
                    count += 1
            LOG.info("Loaded %d persisted CloudTrail events from %s", count, path)
        except Exception:
            LOG.debug("Failed to load persisted CloudTrail events", exc_info=True)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_store: CloudTrailEventStore | None = None
_store_lock = threading.Lock()


def get_event_store() -> CloudTrailEventStore:
    """Return the global CloudTrail event store singleton."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = CloudTrailEventStore()
    return _store


# ---------------------------------------------------------------------------
# Helper: build a CloudTrailEvent from request context
# ---------------------------------------------------------------------------
# Service-specific parameter renames that real AWS CloudTrail applies on top of
# the general lowerCamelCase normalisation. Key = service_name (lowercase);
# value = {old_camel_key: aws_canonical_key}.
_CLOUDTRAIL_PARAM_RENAMES: dict[str, dict[str, str]] = {
    "s3": {"bucket": "bucketName"},
}


def _lowercase_first_char(s: str) -> str:
    """Convert a PascalCase parameter name to lowerCamelCase per AWS
    CloudTrail convention, preserving acronyms and type-tag discriminators."""
    if not s:
        return s
    # Single-char uppercase: preserve (e.g. DynamoDB type tags "S", "N", "B").
    if len(s) == 1 and s.isupper():
        return s
    # Leading ALL-CAPS run of 2+ chars: preserve (e.g. "ACL", "KMSKeyId").
    if len(s) >= 2 and s[0].isupper() and s[1].isupper():
        return s
    return s[0].lower() + s[1:]


def _normalize_keys(obj, service_name: str | None = None, _depth: int = 0):
    """Recursively rewrite dict keys to the AWS CloudTrail JSON convention.

    AWS CloudTrail events use lowerCamelCase parameter names, derived from the
    service's API model PascalCase by lowercasing the first char (and applying
    a small set of per-service renames). boto3's ``service_request`` already
    carries the PascalCase model names, so we post-process here.
    """
    if _depth > 12:  # paranoia: bail out on any unexpectedly deep structure
        return obj
    if isinstance(obj, dict):
        out = {}
        renames = _CLOUDTRAIL_PARAM_RENAMES.get((service_name or "").lower(), {})
        for k, v in obj.items():
            nk = _lowercase_first_char(k) if isinstance(k, str) else k
            # Per-service rename (applied at every nesting level to match AWS).
            if isinstance(nk, str) and nk in renames:
                nk = renames[nk]
            out[nk] = _normalize_keys(v, service_name, _depth + 1)
        return out
    if isinstance(obj, list):
        return [_normalize_keys(x, service_name, _depth + 1) for x in obj]
    return obj


# Primitive types we know json.dumps can serialize. Anything else (e.g.
# a consumed Twisted input stream) gets stringified to a safe placeholder
# rather than leaking the object repr into the CloudTrail event.
_JSON_PRIMITIVES = (str, int, float, bool, type(None), dict, list, tuple,
                    bytes, bytearray)


def _try_decode_bytes(val: bytes | bytearray) -> str | None:
    """If *val* decodes as small UTF-8, return the decoded string; else None.

    Useful for Lambda Invoke payloads (request body and response body),
    which are almost always JSON in practice. Showing the actual JSON in
    the dashboard drill-down is far more valuable than a ``<binary>`` tag.
    """
    if len(val) > 8192:  # don't inline large bodies
        return None
    try:
        return bytes(val).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _sanitize_params(
    params: dict | None,
    max_size: int = 32_768,
    *,
    service_name: str | None = None,
) -> dict | None:
    """Truncate request/response parameters to avoid storing huge payloads.

    Large values (Lambda code, S3 body) are replaced with a placeholder. Also
    normalises key casing to AWS CloudTrail's lowerCamelCase convention so that
    EventBridge rules like ``detail.requestParameters.bucketName`` match.
    """
    if not params:
        return None
    sanitized = {}
    for key, val in params.items():
        if isinstance(val, (bytes, bytearray)):
            decoded = _try_decode_bytes(val)
            if decoded is not None:
                sanitized[key] = decoded
            else:
                sanitized[key] = f"<binary, {len(val)} bytes>"
        elif isinstance(val, str) and len(val) > 1024:
            sanitized[key] = val[:1024] + f"... <truncated, {len(val)} chars>"
        elif not isinstance(val, _JSON_PRIMITIVES):
            # Catch consumed streams and other opaque objects before they
            # leak through json.dumps(default=str) as a useless repr.
            sanitized[key] = f"<{type(val).__name__}>"
        else:
            sanitized[key] = val
    # Apply lowerCamelCase (+ per-service renames) BEFORE the size guard so the
    # stored shape matches what consumers expect.
    sanitized = _normalize_keys(sanitized, service_name)
    # Final size guard
    try:
        encoded = json.dumps(sanitized, default=str)
        if len(encoded) > max_size:
            return {"_truncated": True, "_size": len(encoded)}
    except (TypeError, ValueError):
        return {"_error": "unserializable"}
    return sanitized


def create_event_from_context(
    service_name: str,
    operation_name: str,
    account_id: str = "",
    region: str = "",
    source_ip: str = "127.0.0.1",
    user_agent: str = "",
    request_id: str = "",
    access_key_id: str = "",
    username: str = "",
    error_code: str | None = None,
    error_message: str | None = None,
    service_request: dict | None = None,
    response_elements: dict | None = None,
    http_status_code: int = 0,
    event_category: str = "Management",
) -> CloudTrailEvent:
    """Create a CloudTrailEvent from handler chain context fields.

    B11: the previous ``username or access_key_id or "localemu"`` fallback
    was dead code — ``access_key_id`` is populated on every recorded call
    via the ``Authorization`` header extraction in the dashboard hook, so
    the ``"localemu"`` branch never ran. Simplified to the two real values.
    The only way ``username`` is empty is when the recording hook passes
    empty strings for both the caller-supplied username AND access key —
    in that case we store the literal ``"anonymous"`` so that downstream
    JSON (``userIdentity.userName``, ``arn``) stays well-formed rather
    than embedding empty strings.
    """
    return CloudTrailEvent(
        event_id=str(uuid.uuid4()),
        event_time=datetime.now(timezone.utc),
        event_source=f"{service_name}.amazonaws.com",
        event_name=operation_name,
        aws_region=region or "us-east-1",
        source_ip=source_ip or "127.0.0.1",
        user_agent=user_agent,
        account_id=account_id or "000000000000",
        read_only=_is_read_only(operation_name),
        username=username or access_key_id or "anonymous",
        access_key_id=access_key_id or "ANONYMOUS",
        error_code=error_code,
        error_message=error_message,
        resources=_extract_resources(service_name, service_request),
        request_id=request_id or str(uuid.uuid4()),
        request_parameters=_sanitize_params(service_request, service_name=service_name),
        response_elements=_sanitize_params(response_elements, service_name=service_name),
        http_status_code=http_status_code,
        event_category=event_category,
    )
