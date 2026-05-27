"""
Native LocalEmu implementations for modern CloudTrail APIs that moto does
not implement: Channels, Dashboards, Imports, Resource Policy, Federation,
Organization delegated admin, Event configuration, and Insights list APIs.

Goals
-----
* Store state in process-memory module-level dicts — no disk persistence.
* Persist across API calls within the same process: ``Create`` then ``Get``
  on the same resource must succeed.
* Match AWS API response shapes exactly (botocore serializer will strip
  unknown members; missing members become defaults).
* Be *honest*: where we do not actually perform the documented side-effect
  (e.g. reading from S3 for imports, computing insight metrics), we still
  return well-formed state, but the docstring explicitly says what we do
  not do.

Thread-safety
-------------
AWS API calls arrive on worker threads. The stores below are guarded by
a single module-level ``RLock``. None of the operations do I/O under the
lock; they only mutate small dicts.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.api.core import CommonServiceException

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
# Every store is keyed appropriately per resource so Create → Get works.
# All stores are per-process (module-level), shared across accounts/regions
# because CloudTrail resources are typically regional but the tests and
# docs do not distinguish — we key by ARN which embeds both.
_LOCK = threading.RLock()

# Channel ARN -> channel state dict
_CHANNELS: dict[str, dict[str, Any]] = {}

# Dashboard ARN -> dashboard state dict
_DASHBOARDS: dict[str, dict[str, Any]] = {}
# Also a secondary index by name for uniqueness enforcement on Create.
_DASHBOARD_NAMES: dict[str, str] = {}  # name -> ARN

# Import ID -> import state dict
_IMPORTS: dict[str, dict[str, Any]] = {}
# Import ID -> list of failure dicts (always empty for our fake imports)
_IMPORT_FAILURES: dict[str, list[dict[str, Any]]] = {}

# Resource ARN -> {"ResourcePolicy": str, "DelegatedAdminResourcePolicy": str | None}
_RESOURCE_POLICIES: dict[str, dict[str, Any]] = {}

# EventDataStore ARN -> {"FederationRoleArn": str, "FederationStatus": "ENABLED"|"DISABLED"}
_FEDERATIONS: dict[str, dict[str, Any]] = {}

# Account ID of the organization delegated admin, or None.
_DELEGATED_ADMIN: dict[str, str | None] = {"account_id": None}

# Event configuration by resource ARN (Trail ARN or EventDataStore ARN).
_EVENT_CONFIGURATIONS: dict[str, dict[str, Any]] = {}


def _reset_all_state() -> None:
    """Test hook: wipe every in-memory CloudTrail native store.

    Unit tests that want a clean slate call this in a fixture. Not called
    by any production code path.
    """
    with _LOCK:
        _CHANNELS.clear()
        _DASHBOARDS.clear()
        _DASHBOARD_NAMES.clear()
        _IMPORTS.clear()
        _IMPORT_FAILURES.clear()
        _RESOURCE_POLICIES.clear()
        _FEDERATIONS.clear()
        _DELEGATED_ADMIN["account_id"] = None
        _EVENT_CONFIGURATIONS.clear()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _arn(context: RequestContext, resource_type: str, resource_id: str) -> str:
    partition = context.partition or "aws"
    region = context.region or "us-east-1"
    account = context.account_id or "000000000000"
    return f"arn:{partition}:cloudtrail:{region}:{account}:{resource_type}/{resource_id}"


def _require(request: ServiceRequest, field: str) -> Any:
    value = request.get(field)
    if value is None or value == "":
        raise CommonServiceException(
            "InvalidParameterCombination",
            f"Missing required field: {field}",
        )
    return value


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------
# Channel shape (per botocore spec):
#   CreateChannelRequest: Name (required), Source (required),
#                         Destinations (required, list), Tags (optional)
#   Destination: { Type: "EVENT_DATA_STORE"|..., Location: <arn> }
#
# We store the full channel record, generate an ARN, and return it as-is.
# "Source" on AWS must match "aws.<service>" for integration channels.

def _channel_arn(context: RequestContext, channel_id: str) -> str:
    return _arn(context, "channel", channel_id)


def create_channel(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    name = _require(request, "Name")
    source = _require(request, "Source")
    destinations = _require(request, "Destinations")
    tags = request.get("Tags") or []

    channel_id = str(uuid.uuid4())
    arn = _channel_arn(context, channel_id)

    with _LOCK:
        for existing in _CHANNELS.values():
            if existing["Name"] == name:
                raise CommonServiceException(
                    "ChannelAlreadyExistsException",
                    f"Channel with name {name} already exists.",
                    sender_fault=True,
                )
        record = {
            "ChannelArn": arn,
            "Name": name,
            "Source": source,
            "SourceConfig": {
                "ApplyToAllRegions": True,
                "AdvancedEventSelectors": [],
            },
            "Destinations": list(destinations),
            "Tags": list(tags),
            "IngestionStatus": {
                "LatestIngestionSuccessTime": _now(),
                "LatestIngestionSuccessEventID": "",
                "LatestIngestionErrorCode": "",
                "LatestIngestionAttemptTime": _now(),
                "LatestIngestionAttemptEventID": "",
            },
        }
        _CHANNELS[arn] = record

    return {
        "ChannelArn": arn,
        "Name": name,
        "Source": source,
        "Destinations": record["Destinations"],
        "Tags": record["Tags"],
    }


def _lookup_channel_arn(identifier: str) -> str:
    """Accept either a full ARN or a bare channel name/UUID."""
    with _LOCK:
        if identifier in _CHANNELS:
            return identifier
        for arn, record in _CHANNELS.items():
            if record["Name"] == identifier or arn.endswith(f"/{identifier}"):
                return arn
    raise CommonServiceException(
        "ChannelNotFoundException",
        f"Channel {identifier} not found.",
        sender_fault=True,
    )


def delete_channel(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "Channel")
    arn = _lookup_channel_arn(identifier)
    with _LOCK:
        _CHANNELS.pop(arn, None)
    return {}


def get_channel(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "Channel")
    arn = _lookup_channel_arn(identifier)
    with _LOCK:
        record = _CHANNELS[arn]
        return {
            "ChannelArn": record["ChannelArn"],
            "Name": record["Name"],
            "Source": record["Source"],
            "SourceConfig": record["SourceConfig"],
            "Destinations": record["Destinations"],
            "IngestionStatus": record["IngestionStatus"],
        }


def list_channels(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    with _LOCK:
        # ``Channels`` list item shape is {ChannelArn, Name}.
        channels = [
            {"ChannelArn": r["ChannelArn"], "Name": r["Name"]}
            for r in _CHANNELS.values()
        ]
    return {"Channels": channels}


def update_channel(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "Channel")
    arn = _lookup_channel_arn(identifier)
    with _LOCK:
        record = _CHANNELS[arn]
        new_name = request.get("Name")
        new_destinations = request.get("Destinations")
        if new_name:
            # Uniqueness check
            for other_arn, other in _CHANNELS.items():
                if other_arn != arn and other["Name"] == new_name:
                    raise CommonServiceException(
                        "ChannelAlreadyExistsException",
                        f"Channel with name {new_name} already exists.",
                        sender_fault=True,
                    )
            record["Name"] = new_name
        if new_destinations is not None:
            record["Destinations"] = list(new_destinations)
        return {
            "ChannelArn": record["ChannelArn"],
            "Name": record["Name"],
            "Source": record["Source"],
            "Destinations": record["Destinations"],
        }


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------
# NOTE: real CloudTrail dashboards render query-based widgets against an
# EventDataStore. We do NOT execute widget queries — we store metadata and
# echo it back. ``StartDashboardRefresh`` returns a synthetic RefreshId and
# we do not actually run the queries (no EventDataStore Lake in LocalEmu).
# This is documented in the dashboard skill gap.

def _dashboard_arn(context: RequestContext, name: str) -> str:
    return _arn(context, "dashboard", name)


def create_dashboard(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    name = _require(request, "Name")
    widgets = request.get("Widgets") or []
    refresh_schedule = request.get("RefreshSchedule")
    tags = request.get("TagsList") or []
    termination_protection = bool(request.get("TerminationProtectionEnabled") or False)

    with _LOCK:
        if name in _DASHBOARD_NAMES:
            raise CommonServiceException(
                "ResourceAlreadyExistsException",
                f"Dashboard {name} already exists.",
                sender_fault=True,
            )
        arn = _dashboard_arn(context, name)
        now = _now()
        # Dashboard ``Type`` is CUSTOM for user-created dashboards.
        record = {
            "DashboardArn": arn,
            "Name": name,
            "Type": "CUSTOM",
            "Status": "CREATED",
            "Widgets": list(widgets),
            "RefreshSchedule": refresh_schedule,
            "CreatedTimestamp": now,
            "UpdatedTimestamp": now,
            "LastRefreshId": None,
            "LastRefreshFailureReason": None,
            "TerminationProtectionEnabled": termination_protection,
            "TagsList": list(tags),
        }
        _DASHBOARDS[arn] = record
        _DASHBOARD_NAMES[name] = arn

    response = {
        "DashboardArn": arn,
        "Name": name,
        "Type": "CUSTOM",
        "Widgets": record["Widgets"],
        "TagsList": record["TagsList"],
        "TerminationProtectionEnabled": record["TerminationProtectionEnabled"],
    }
    if refresh_schedule is not None:
        response["RefreshSchedule"] = refresh_schedule
    return response


def _lookup_dashboard_arn(identifier: str) -> str:
    with _LOCK:
        if identifier in _DASHBOARDS:
            return identifier
        if identifier in _DASHBOARD_NAMES:
            return _DASHBOARD_NAMES[identifier]
        # Allow suffix match
        for arn in _DASHBOARDS:
            if arn.endswith(f"/{identifier}"):
                return arn
    raise CommonServiceException(
        "ResourceNotFoundException",
        f"Dashboard {identifier} not found.",
        sender_fault=True,
    )


def delete_dashboard(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "DashboardId")
    arn = _lookup_dashboard_arn(identifier)
    with _LOCK:
        record = _DASHBOARDS.get(arn)
        if record and record.get("TerminationProtectionEnabled"):
            raise CommonServiceException(
                "ConflictException",
                "Dashboard has termination protection enabled.",
                sender_fault=True,
            )
        if record:
            _DASHBOARD_NAMES.pop(record["Name"], None)
            _DASHBOARDS.pop(arn, None)
    return {}


def get_dashboard(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "DashboardId")
    arn = _lookup_dashboard_arn(identifier)
    with _LOCK:
        r = _DASHBOARDS[arn]
        response: dict[str, Any] = {
            "DashboardArn": r["DashboardArn"],
            "Type": r["Type"],
            "Status": r["Status"],
            "Widgets": r["Widgets"],
            "CreatedTimestamp": r["CreatedTimestamp"],
            "UpdatedTimestamp": r["UpdatedTimestamp"],
            "TerminationProtectionEnabled": r["TerminationProtectionEnabled"],
        }
        if r.get("RefreshSchedule") is not None:
            response["RefreshSchedule"] = r["RefreshSchedule"]
        if r.get("LastRefreshId"):
            response["LastRefreshId"] = r["LastRefreshId"]
        if r.get("LastRefreshFailureReason"):
            response["LastRefreshFailureReason"] = r["LastRefreshFailureReason"]
        return response


def list_dashboards(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    # ListDashboardsResponse.Dashboards is list<DashboardDetail>{DashboardArn, Type}.
    with _LOCK:
        dashboards = [
            {"DashboardArn": r["DashboardArn"], "Type": r["Type"]}
            for r in _DASHBOARDS.values()
        ]
    return {"Dashboards": dashboards}


def update_dashboard(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    identifier = _require(request, "DashboardId")
    arn = _lookup_dashboard_arn(identifier)
    with _LOCK:
        r = _DASHBOARDS[arn]
        if "Widgets" in request:
            r["Widgets"] = list(request.get("Widgets") or [])
        if "RefreshSchedule" in request:
            r["RefreshSchedule"] = request.get("RefreshSchedule")
        if "TerminationProtectionEnabled" in request:
            r["TerminationProtectionEnabled"] = bool(
                request.get("TerminationProtectionEnabled")
            )
        r["UpdatedTimestamp"] = _now()
        response = {
            "DashboardArn": r["DashboardArn"],
            "Name": r["Name"],
            "Type": r["Type"],
            "Widgets": r["Widgets"],
            "TerminationProtectionEnabled": r["TerminationProtectionEnabled"],
            "CreatedTimestamp": r["CreatedTimestamp"],
            "UpdatedTimestamp": r["UpdatedTimestamp"],
        }
        if r.get("RefreshSchedule") is not None:
            response["RefreshSchedule"] = r["RefreshSchedule"]
        return response


def start_dashboard_refresh(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """Return a synthetic RefreshId.

    We do NOT actually execute the widget queries against an EventDataStore
    — CloudTrail Lake is not implemented in LocalEmu. The RefreshId can be
    stored on the dashboard record so ``GetDashboard`` reports it, but no
    data will ever populate.
    """
    identifier = _require(request, "DashboardId")
    arn = _lookup_dashboard_arn(identifier)
    refresh_id = str(uuid.uuid4())
    with _LOCK:
        r = _DASHBOARDS[arn]
        r["LastRefreshId"] = refresh_id
        r["UpdatedTimestamp"] = _now()
    return {"RefreshId": refresh_id}


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
# We store metadata only. We do NOT open the S3 location, enumerate prefixes,
# or ingest CloudTrail log files. The state machine is:
#     INITIALIZING -> IN_PROGRESS -> COMPLETED
# Each call to GetImport advances the state one step, which matches the
# expected terminal behavior a polling client would observe.

_IMPORT_STATE_SEQUENCE = ["INITIALIZING", "IN_PROGRESS", "COMPLETED"]


def _advance_import_state(record: dict[str, Any]) -> None:
    current = record.get("ImportStatus", "INITIALIZING")
    try:
        idx = _IMPORT_STATE_SEQUENCE.index(current)
    except ValueError:
        return
    if idx + 1 < len(_IMPORT_STATE_SEQUENCE):
        record["ImportStatus"] = _IMPORT_STATE_SEQUENCE[idx + 1]
        record["UpdatedTimestamp"] = _now()
    if record["ImportStatus"] == "COMPLETED":
        record["ImportStatistics"] = {
            "PrefixesFound": 1,
            "PrefixesCompleted": 1,
            "FilesCompleted": 0,
            "EventsCompleted": 0,
            "FailedEntries": 0,
        }


def start_import(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    import_id = request.get("ImportId") or str(uuid.uuid4())
    destinations = request.get("Destinations") or []
    import_source = request.get("ImportSource")
    start_event_time = request.get("StartEventTime")
    end_event_time = request.get("EndEventTime")

    with _LOCK:
        if import_id in _IMPORTS:
            # Resume existing import (AWS accepts ImportId for resume).
            record = _IMPORTS[import_id]
            if record["ImportStatus"] == "STOPPED":
                record["ImportStatus"] = "IN_PROGRESS"
                record["UpdatedTimestamp"] = _now()
        else:
            now = _now()
            record = {
                "ImportId": import_id,
                "Destinations": list(destinations),
                "ImportSource": import_source,
                "StartEventTime": start_event_time,
                "EndEventTime": end_event_time,
                "ImportStatus": "INITIALIZING",
                "CreatedTimestamp": now,
                "UpdatedTimestamp": now,
                "ImportStatistics": {
                    "PrefixesFound": 0,
                    "PrefixesCompleted": 0,
                    "FilesCompleted": 0,
                    "EventsCompleted": 0,
                    "FailedEntries": 0,
                },
            }
            _IMPORTS[import_id] = record
            _IMPORT_FAILURES[import_id] = []

    response = {
        "ImportId": record["ImportId"],
        "Destinations": record["Destinations"],
        "ImportStatus": record["ImportStatus"],
        "CreatedTimestamp": record["CreatedTimestamp"],
        "UpdatedTimestamp": record["UpdatedTimestamp"],
    }
    if record.get("ImportSource") is not None:
        response["ImportSource"] = record["ImportSource"]
    if record.get("StartEventTime") is not None:
        response["StartEventTime"] = record["StartEventTime"]
    if record.get("EndEventTime") is not None:
        response["EndEventTime"] = record["EndEventTime"]
    return response


def stop_import(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    import_id = _require(request, "ImportId")
    with _LOCK:
        record = _IMPORTS.get(import_id)
        if not record:
            raise CommonServiceException(
                "ImportNotFoundException",
                f"Import {import_id} not found.",
                sender_fault=True,
            )
        if record["ImportStatus"] not in {"COMPLETED", "FAILED", "STOPPED"}:
            record["ImportStatus"] = "STOPPED"
            record["UpdatedTimestamp"] = _now()
        return {
            "ImportId": record["ImportId"],
            "ImportSource": record.get("ImportSource"),
            "Destinations": record["Destinations"],
            "ImportStatus": record["ImportStatus"],
            "CreatedTimestamp": record["CreatedTimestamp"],
            "UpdatedTimestamp": record["UpdatedTimestamp"],
            "StartEventTime": record.get("StartEventTime"),
            "EndEventTime": record.get("EndEventTime"),
            "ImportStatistics": record["ImportStatistics"],
        }


def get_import(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    import_id = _require(request, "ImportId")
    with _LOCK:
        record = _IMPORTS.get(import_id)
        if not record:
            raise CommonServiceException(
                "ImportNotFoundException",
                f"Import {import_id} not found.",
                sender_fault=True,
            )
        # Advance the status one step so a polling client eventually sees
        # a terminal COMPLETED state. We only advance from INITIALIZING /
        # IN_PROGRESS; terminal states are left alone.
        if record["ImportStatus"] in {"INITIALIZING", "IN_PROGRESS"}:
            _advance_import_state(record)
        response = {
            "ImportId": record["ImportId"],
            "Destinations": record["Destinations"],
            "ImportStatus": record["ImportStatus"],
            "CreatedTimestamp": record["CreatedTimestamp"],
            "UpdatedTimestamp": record["UpdatedTimestamp"],
            "ImportStatistics": record["ImportStatistics"],
        }
        if record.get("ImportSource") is not None:
            response["ImportSource"] = record["ImportSource"]
        if record.get("StartEventTime") is not None:
            response["StartEventTime"] = record["StartEventTime"]
        if record.get("EndEventTime") is not None:
            response["EndEventTime"] = record["EndEventTime"]
        return response


def list_imports(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    destination = request.get("Destination")
    status_filter = request.get("ImportStatus")
    with _LOCK:
        items: list[dict[str, Any]] = []
        for r in _IMPORTS.values():
            if destination and not any(
                d.get("Location") == destination or d == destination
                for d in r["Destinations"]
            ):
                continue
            if status_filter and r["ImportStatus"] != status_filter:
                continue
            items.append({
                "ImportId": r["ImportId"],
                "ImportStatus": r["ImportStatus"],
                "Destinations": r["Destinations"],
                "CreatedTimestamp": r["CreatedTimestamp"],
                "UpdatedTimestamp": r["UpdatedTimestamp"],
            })
    return {"Imports": items}


def list_import_failures(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    import_id = _require(request, "ImportId")
    with _LOCK:
        if import_id not in _IMPORTS:
            raise CommonServiceException(
                "ImportNotFoundException",
                f"Import {import_id} not found.",
                sender_fault=True,
            )
        failures = list(_IMPORT_FAILURES.get(import_id, []))
    return {"Failures": failures}


# ---------------------------------------------------------------------------
# Resource policy
# ---------------------------------------------------------------------------

def _validate_policy_json(policy: str) -> None:
    """Reject malformed resource policies.

    AWS requires a valid JSON document with a ``Statement`` array. We do
    NOT evaluate the policy; we only confirm it parses and has the
    minimum required shape. This matches the behavior of AWS's first-pass
    syntactic validation at PutResourcePolicy time.
    """
    try:
        parsed = json.loads(policy)
    except (TypeError, ValueError) as e:
        raise CommonServiceException(
            "ResourcePolicyNotValidException",
            f"Resource policy is not valid JSON: {e}",
            sender_fault=True,
        )
    if not isinstance(parsed, dict):
        raise CommonServiceException(
            "ResourcePolicyNotValidException",
            "Resource policy must be a JSON object.",
            sender_fault=True,
        )
    statement = parsed.get("Statement")
    if not isinstance(statement, list) or not statement:
        raise CommonServiceException(
            "ResourcePolicyNotValidException",
            "Resource policy must contain a non-empty Statement array.",
            sender_fault=True,
        )


def put_resource_policy(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    resource_arn = _require(request, "ResourceArn")
    policy = _require(request, "ResourcePolicy")
    _validate_policy_json(policy)
    with _LOCK:
        record = _RESOURCE_POLICIES.get(resource_arn, {})
        record["ResourcePolicy"] = policy
        _RESOURCE_POLICIES[resource_arn] = record
        response = {"ResourceArn": resource_arn, "ResourcePolicy": policy}
        if record.get("DelegatedAdminResourcePolicy"):
            response["DelegatedAdminResourcePolicy"] = record[
                "DelegatedAdminResourcePolicy"
            ]
        return response


def get_resource_policy(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    resource_arn = _require(request, "ResourceArn")
    with _LOCK:
        record = _RESOURCE_POLICIES.get(resource_arn)
        if not record:
            raise CommonServiceException(
                "ResourcePolicyNotFoundException",
                f"No resource policy found for {resource_arn}.",
                sender_fault=True,
            )
        response = {
            "ResourceArn": resource_arn,
            "ResourcePolicy": record["ResourcePolicy"],
        }
        if record.get("DelegatedAdminResourcePolicy"):
            response["DelegatedAdminResourcePolicy"] = record[
                "DelegatedAdminResourcePolicy"
            ]
        return response


def delete_resource_policy(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    resource_arn = _require(request, "ResourceArn")
    with _LOCK:
        if resource_arn not in _RESOURCE_POLICIES:
            raise CommonServiceException(
                "ResourcePolicyNotFoundException",
                f"No resource policy found for {resource_arn}.",
                sender_fault=True,
            )
        _RESOURCE_POLICIES.pop(resource_arn)
    return {}


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------
# EnableFederation/DisableFederation mutate a flag on a (conceptual) event
# data store. LocalEmu does not implement EventDataStore fully, so we treat
# the ``EventDataStore`` parameter as an opaque ARN/key.

def enable_federation(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    eds = _require(request, "EventDataStore")
    role = _require(request, "FederationRoleArn")
    with _LOCK:
        _FEDERATIONS[eds] = {
            "FederationRoleArn": role,
            "FederationStatus": "ENABLED",
        }
    return {
        "EventDataStoreArn": eds,
        "FederationStatus": "ENABLED",
        "FederationRoleArn": role,
    }


def disable_federation(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    eds = _require(request, "EventDataStore")
    with _LOCK:
        if eds in _FEDERATIONS:
            _FEDERATIONS[eds]["FederationStatus"] = "DISABLED"
        else:
            # Record a DISABLED state for later Describe consistency.
            _FEDERATIONS[eds] = {
                "FederationRoleArn": "",
                "FederationStatus": "DISABLED",
            }
    return {
        "EventDataStoreArn": eds,
        "FederationStatus": "DISABLED",
    }


# ---------------------------------------------------------------------------
# Organization delegated admin
# ---------------------------------------------------------------------------

def register_organization_delegated_admin(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    account_id = _require(request, "MemberAccountId")
    with _LOCK:
        _DELEGATED_ADMIN["account_id"] = account_id
    return {}


def deregister_organization_delegated_admin(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    account_id = _require(request, "DelegatedAdminAccountId")
    with _LOCK:
        if _DELEGATED_ADMIN.get("account_id") != account_id:
            raise CommonServiceException(
                "AccountNotRegisteredException",
                f"Account {account_id} is not a registered delegated admin.",
                sender_fault=True,
            )
        _DELEGATED_ADMIN["account_id"] = None
    return {}


# ---------------------------------------------------------------------------
# Event configuration
# ---------------------------------------------------------------------------
# PutEventConfiguration / GetEventConfiguration target either a trail or an
# event data store. We key by whichever identifier the caller provided.

def _event_config_key(request: ServiceRequest) -> str:
    trail = request.get("TrailName")
    eds = request.get("EventDataStore")
    if not trail and not eds:
        raise CommonServiceException(
            "InvalidParameterCombination",
            "Either TrailName or EventDataStore must be provided.",
            sender_fault=True,
        )
    return f"trail::{trail}" if trail else f"eds::{eds}"


def put_event_configuration(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    key = _event_config_key(request)
    trail = request.get("TrailName")
    eds = request.get("EventDataStore")
    max_event_size = request.get("MaxEventSize") or "Standard"
    context_key_selectors = request.get("ContextKeySelectors") or []
    aggregation = request.get("AggregationConfigurations") or []

    with _LOCK:
        _EVENT_CONFIGURATIONS[key] = {
            "TrailARN": trail,
            "EventDataStoreArn": eds,
            "MaxEventSize": max_event_size,
            "ContextKeySelectors": list(context_key_selectors),
            "AggregationConfigurations": list(aggregation),
        }
    response: dict[str, Any] = {
        "MaxEventSize": max_event_size,
        "ContextKeySelectors": list(context_key_selectors),
        "AggregationConfigurations": list(aggregation),
    }
    if trail:
        response["TrailARN"] = trail
    if eds:
        response["EventDataStoreArn"] = eds
    return response


def get_event_configuration(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    key = _event_config_key(request)
    with _LOCK:
        record = _EVENT_CONFIGURATIONS.get(key)
        if not record:
            # AWS returns default-ish values when no config has been put.
            # But callers that do not know this expect an error — we mimic
            # AWS by raising a ResourceNotFoundException.
            raise CommonServiceException(
                "EventConfigurationNotFoundException",
                f"No event configuration found for {key}.",
                sender_fault=True,
            )
        response: dict[str, Any] = {
            "MaxEventSize": record["MaxEventSize"],
            "ContextKeySelectors": record["ContextKeySelectors"],
            "AggregationConfigurations": record["AggregationConfigurations"],
        }
        if record.get("TrailARN"):
            response["TrailARN"] = record["TrailARN"]
        if record.get("EventDataStoreArn"):
            response["EventDataStoreArn"] = record["EventDataStoreArn"]
        return response


# ---------------------------------------------------------------------------
# Insights list APIs
# ---------------------------------------------------------------------------
# LocalEmu does NOT compute insight detection. CloudTrail insights require
# baseline learning over weeks of API call patterns and emit unusual-activity
# events. We do not implement this machinery. Returning empty-but-valid
# paginated results is the honest answer: no insights detected.

def list_insights_data(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """Return an empty list of insight events.

    Insight detection itself is NOT implemented. Clients using this API
    against LocalEmu should not expect unusual-activity detection to fire.
    """
    return {"Events": []}


def list_insights_metric_data(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """Return an empty metric series.

    Insight detection itself is NOT implemented — see ``list_insights_data``.
    The echo-back fields (``EventSource`` etc.) come from the request so the
    response still validates against the AWS spec.
    """
    return {
        "EventSource": request.get("EventSource", ""),
        "EventName": request.get("EventName", ""),
        "InsightType": request.get("InsightType", ""),
        "Timestamps": [],
        "Values": [],
    }


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

NATIVE_OPS: dict[str, Any] = {
    # Channels
    "CreateChannel": create_channel,
    "DeleteChannel": delete_channel,
    "GetChannel": get_channel,
    "ListChannels": list_channels,
    "UpdateChannel": update_channel,
    # Dashboards
    "CreateDashboard": create_dashboard,
    "DeleteDashboard": delete_dashboard,
    "GetDashboard": get_dashboard,
    "ListDashboards": list_dashboards,
    "UpdateDashboard": update_dashboard,
    "StartDashboardRefresh": start_dashboard_refresh,
    # Imports
    "StartImport": start_import,
    "StopImport": stop_import,
    "GetImport": get_import,
    "ListImports": list_imports,
    "ListImportFailures": list_import_failures,
    # Resource policy
    "PutResourcePolicy": put_resource_policy,
    "GetResourcePolicy": get_resource_policy,
    "DeleteResourcePolicy": delete_resource_policy,
    # Federation
    "EnableFederation": enable_federation,
    "DisableFederation": disable_federation,
    # Organization
    "RegisterOrganizationDelegatedAdmin": register_organization_delegated_admin,
    "DeregisterOrganizationDelegatedAdmin": deregister_organization_delegated_admin,
    # Event configuration
    "PutEventConfiguration": put_event_configuration,
    "GetEventConfiguration": get_event_configuration,
    # Insights
    "ListInsightsData": list_insights_data,
    "ListInsightsMetricData": list_insights_metric_data,
}
