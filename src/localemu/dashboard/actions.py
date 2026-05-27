"""
Dashboard write-actions: small HTTP handlers that let the LocalEmu
Control Center send real AWS API calls (Invoke, SendMessage, Publish,
PutEvents, RotateSecret, PutItem, Scan) into the running gateway.

The handlers run in-process inside the gateway. They obtain a boto3
client via :func:`localemu.aws.connect.connect_to`, which routes the
request through the local endpoint (loopback) and therefore exercises
the full gateway stack (CloudTrail recording, auth, persistence) just
like an external caller would. We never bypass the public AWS API
surface.

Each ``POST /_localemu/api/actions/<service>/<action>`` reads a small
JSON body, runs the corresponding AWS call, and returns the boto3
response (or a structured error). The frontend renders the result in
a modal.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

from localemu.constants import DEFAULT_AWS_ACCOUNT_ID
from localemu.http import Request, Response

LOG = logging.getLogger(__name__)

DEFAULT_REGION = "us-east-1"


def _json_response(data: dict, status: int = 200) -> Response:
    """Mirror the helper in ``api.py`` to keep imports lean."""
    from localemu.utils.common import CustomEncoder

    body = json.dumps(data, cls=CustomEncoder, default=str)
    return Response(body, status=status, content_type="application/json")


def _parse_body(request: Request) -> dict:
    """Parse a JSON request body; return ``{}`` on missing/empty body.

    Rejects bodies whose ``Content-Type`` is not JSON-compatible. This
    blocks CSRF "simple request" attacks that POST ``text/plain`` from
    a malicious browser page (a same-site fetch from the dashboard
    sends ``application/json`` and never trips this check).
    """
    # Empty body is allowed; some action verbs take no parameters.
    headers = getattr(request, "headers", {}) or {}
    content_type = (headers.get("Content-Type") or headers.get("content-type") or "").lower().split(";")[0].strip()
    has_body = False
    try:
        raw = request.get_data(as_text=True) if hasattr(request, "get_data") else (request.data or "")
    except Exception:
        raw = ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    raw = (raw or "").strip()
    if raw:
        has_body = True
    if has_body and content_type and content_type != "application/json":
        raise _ActionError(
            "Content-Type must be application/json for action endpoints "
            f"(got {content_type!r})"
        )
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _ActionError(f"Invalid JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise _ActionError("Request body must be a JSON object")
    return parsed


class _ActionError(Exception):
    """User-facing 4xx error raised by an action handler."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _connect(service: str, region: str | None = None, account_id: str | None = None):
    """Obtain a boto3 client wired to the local gateway."""
    from localemu.aws.connect import connect_to

    target = connect_to(
        aws_access_key_id=account_id or DEFAULT_AWS_ACCOUNT_ID,
        region_name=region or DEFAULT_REGION,
    )
    return getattr(target, service)


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------


def _action_lambda_invoke(body: dict) -> dict:
    function_name = body.get("function_name") or body.get("FunctionName")
    if not function_name:
        raise _ActionError("'function_name' is required")
    payload = body.get("payload")
    invocation_type = body.get("invocation_type") or body.get("InvocationType") or "RequestResponse"
    qualifier = body.get("qualifier") or body.get("Qualifier") or "$LATEST"

    kwargs: dict[str, Any] = {
        "FunctionName": function_name,
        "InvocationType": invocation_type,
        "Qualifier": qualifier,
        "LogType": "Tail",
    }
    if payload is not None:
        if isinstance(payload, (dict, list)):
            kwargs["Payload"] = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, bytes):
            kwargs["Payload"] = payload
        else:
            kwargs["Payload"] = str(payload).encode("utf-8")

    client = _connect("lambda", region=body.get("region"))
    resp = client.invoke(**kwargs)

    body_bytes = resp.get("Payload")
    if body_bytes is not None and hasattr(body_bytes, "read"):
        body_bytes = body_bytes.read()
    response_body: Any = None
    if body_bytes:
        try:
            response_body = json.loads(body_bytes)
        except Exception:
            response_body = body_bytes.decode("utf-8", errors="replace") if isinstance(body_bytes, bytes) else body_bytes

    log_b64 = resp.get("LogResult")
    log_tail = None
    if log_b64:
        try:
            log_tail = base64.b64decode(log_b64).decode("utf-8", errors="replace")
        except Exception:
            log_tail = None

    return {
        "status_code": resp.get("StatusCode"),
        "executed_version": resp.get("ExecutedVersion"),
        "function_error": resp.get("FunctionError"),
        "response": response_body,
        "log_tail": log_tail,
    }


# ---------------------------------------------------------------------------
# SQS
# ---------------------------------------------------------------------------


def _resolve_queue_url(body: dict, region: str | None) -> str:
    url = body.get("queue_url") or body.get("QueueUrl")
    if url:
        return url
    name = body.get("queue_name") or body.get("QueueName")
    if not name:
        raise _ActionError("Either 'queue_url' or 'queue_name' is required")
    client = _connect("sqs", region=region)
    return client.get_queue_url(QueueName=name)["QueueUrl"]


def _action_sqs_send_message(body: dict) -> dict:
    region = body.get("region")
    queue_url = _resolve_queue_url(body, region)
    message_body = body.get("body") or body.get("MessageBody") or ""
    if isinstance(message_body, (dict, list)):
        message_body = json.dumps(message_body)
    kwargs: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MessageBody": str(message_body),
    }
    if body.get("delay_seconds") is not None:
        kwargs["DelaySeconds"] = int(body["delay_seconds"])
    group_id = body.get("message_group_id") or body.get("MessageGroupId")
    if group_id:
        kwargs["MessageGroupId"] = group_id
    dedup = body.get("message_deduplication_id") or body.get("MessageDeduplicationId")
    if dedup:
        kwargs["MessageDeduplicationId"] = dedup
    attrs = body.get("message_attributes") or body.get("MessageAttributes")
    if isinstance(attrs, dict) and attrs:
        # Accept the simple {key: "value"} shape from the UI and lift it
        # to the AWS-required {key: {StringValue: ..., DataType: "String"}} form.
        normalised = {}
        for key, val in attrs.items():
            if isinstance(val, dict) and "DataType" in val:
                normalised[key] = val
            else:
                normalised[key] = {"DataType": "String", "StringValue": str(val)}
        kwargs["MessageAttributes"] = normalised

    client = _connect("sqs", region=region)
    resp = client.send_message(**kwargs)
    return {
        "message_id": resp.get("MessageId"),
        "md5_of_body": resp.get("MD5OfMessageBody"),
        "sequence_number": resp.get("SequenceNumber"),
    }


# ---------------------------------------------------------------------------
# SNS
# ---------------------------------------------------------------------------


def _resolve_topic_arn(body: dict, region: str | None) -> str:
    arn = body.get("topic_arn") or body.get("TopicArn")
    if arn:
        return arn
    name = body.get("topic_name") or body.get("TopicName") or body.get("name")
    if not name:
        raise _ActionError("Either 'topic_arn' or 'topic_name' is required")
    region_str = region or DEFAULT_REGION
    return f"arn:aws:sns:{region_str}:{DEFAULT_AWS_ACCOUNT_ID}:{name}"


def _action_sns_publish(body: dict) -> dict:
    region = body.get("region")
    topic_arn = _resolve_topic_arn(body, region)
    message = body.get("message") or body.get("Message")
    if message is None:
        raise _ActionError("'message' is required")
    if isinstance(message, (dict, list)):
        message = json.dumps(message)
    kwargs: dict[str, Any] = {
        "TopicArn": topic_arn,
        "Message": str(message),
    }
    subject = body.get("subject") or body.get("Subject")
    if subject:
        kwargs["Subject"] = subject
    group_id = body.get("message_group_id") or body.get("MessageGroupId")
    if group_id:
        kwargs["MessageGroupId"] = group_id
    dedup = body.get("message_deduplication_id") or body.get("MessageDeduplicationId")
    if dedup:
        kwargs["MessageDeduplicationId"] = dedup
    attrs = body.get("message_attributes") or body.get("MessageAttributes")
    if isinstance(attrs, dict) and attrs:
        normalised = {}
        for key, val in attrs.items():
            if isinstance(val, dict) and "DataType" in val:
                normalised[key] = val
            else:
                normalised[key] = {"DataType": "String", "StringValue": str(val)}
        kwargs["MessageAttributes"] = normalised

    client = _connect("sns", region=region)
    resp = client.publish(**kwargs)
    return {
        "message_id": resp.get("MessageId"),
        "sequence_number": resp.get("SequenceNumber"),
    }


# ---------------------------------------------------------------------------
# EventBridge
# ---------------------------------------------------------------------------


def _action_events_put_events(body: dict) -> dict:
    entries_in = body.get("entries") or body.get("Entries")
    if not entries_in or not isinstance(entries_in, list):
        raise _ActionError("'entries' must be a non-empty list")
    entries: list[dict[str, Any]] = []
    for raw in entries_in:
        if not isinstance(raw, dict):
            raise _ActionError("Each entry must be a JSON object")
        entry: dict[str, Any] = {}
        entry["Source"] = raw.get("source") or raw.get("Source") or "localemu.dashboard"
        entry["DetailType"] = raw.get("detail_type") or raw.get("DetailType") or "Dashboard Test"
        detail = raw.get("detail") or raw.get("Detail")
        if isinstance(detail, (dict, list)):
            entry["Detail"] = json.dumps(detail)
        elif detail is None:
            entry["Detail"] = "{}"
        else:
            entry["Detail"] = str(detail)
        bus = raw.get("event_bus_name") or raw.get("EventBusName")
        if bus:
            entry["EventBusName"] = bus
        resources = raw.get("resources") or raw.get("Resources")
        if isinstance(resources, list):
            entry["Resources"] = [str(r) for r in resources]
        entries.append(entry)

    client = _connect("events", region=body.get("region"))
    resp = client.put_events(Entries=entries)
    return {
        "failed_entry_count": resp.get("FailedEntryCount", 0),
        "entries": resp.get("Entries", []),
    }


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------


def _action_secretsmanager_rotate(body: dict) -> dict:
    secret_id = body.get("secret_id") or body.get("SecretId") or body.get("name")
    if not secret_id:
        raise _ActionError("'secret_id' is required")
    rotation_lambda_arn = (
        body.get("rotation_lambda_arn")
        or body.get("RotationLambdaARN")
    )
    rotate_immediately = bool(body.get("rotate_immediately", True))

    client = _connect("secretsmanager", region=body.get("region"))
    kwargs: dict[str, Any] = {
        "SecretId": secret_id,
        "RotateImmediately": rotate_immediately,
    }
    if rotation_lambda_arn:
        kwargs["RotationLambdaARN"] = rotation_lambda_arn
    rules = body.get("rotation_rules") or body.get("RotationRules")
    if isinstance(rules, dict):
        kwargs["RotationRules"] = rules
    resp = client.rotate_secret(**kwargs)
    return {
        "arn": resp.get("ARN"),
        "name": resp.get("Name"),
        "version_id": resp.get("VersionId"),
    }


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------


def _action_dynamodb_put_item(body: dict) -> dict:
    table = body.get("table_name") or body.get("TableName") or body.get("name")
    item = body.get("item") or body.get("Item")
    if not table or not item:
        raise _ActionError("'table_name' and 'item' are required")
    if not isinstance(item, dict):
        raise _ActionError("'item' must be a JSON object in DynamoDB attribute-value form")
    client = _connect("dynamodb", region=body.get("region"))
    client.put_item(TableName=table, Item=item)
    return {"ok": True, "table_name": table}


def _action_dynamodb_scan(body: dict) -> dict:
    table = body.get("table_name") or body.get("TableName") or body.get("name")
    if not table:
        raise _ActionError("'table_name' is required")
    try:
        limit = int(body.get("limit") or body.get("Limit") or 25)
    except (TypeError, ValueError) as exc:
        raise _ActionError(f"'limit' must be an integer: {exc}") from exc
    client = _connect("dynamodb", region=body.get("region"))
    resp = client.scan(TableName=table, Limit=limit)
    return {
        "items": resp.get("Items", []),
        "count": resp.get("Count", 0),
        "scanned_count": resp.get("ScannedCount", 0),
        "last_evaluated_key": resp.get("LastEvaluatedKey"),
    }


def _action_dynamodb_get_item(body: dict) -> dict:
    table = body.get("table_name") or body.get("TableName") or body.get("name")
    key = body.get("key") or body.get("Key")
    if not table or not key:
        raise _ActionError("'table_name' and 'key' are required")
    if not isinstance(key, dict):
        raise _ActionError("'key' must be a JSON object in DynamoDB attribute-value form")
    client = _connect("dynamodb", region=body.get("region"))
    resp = client.get_item(TableName=table, Key=key)
    item = resp.get("Item")
    return {"item": item, "found": item is not None}


def _action_dynamodb_query(body: dict) -> dict:
    table = body.get("table_name") or body.get("TableName") or body.get("name")
    kce = body.get("key_condition_expression") or body.get("KeyConditionExpression")
    if not table or not kce:
        raise _ActionError("'table_name' and 'key_condition_expression' are required")
    eav = body.get("expression_attribute_values") or body.get("ExpressionAttributeValues") or {}
    if not isinstance(eav, dict):
        raise _ActionError("'expression_attribute_values' must be a JSON object")
    try:
        limit = int(body.get("limit") or body.get("Limit") or 25)
    except (TypeError, ValueError) as exc:
        raise _ActionError(f"'limit' must be an integer: {exc}") from exc
    client = _connect("dynamodb", region=body.get("region"))
    kwargs = {
        "TableName": table,
        "KeyConditionExpression": kce,
        "Limit": limit,
    }
    if eav:
        kwargs["ExpressionAttributeValues"] = eav
    ean = body.get("expression_attribute_names") or body.get("ExpressionAttributeNames")
    if ean:
        kwargs["ExpressionAttributeNames"] = ean
    fce = body.get("filter_expression") or body.get("FilterExpression")
    if fce:
        kwargs["FilterExpression"] = fce
    index = body.get("index_name") or body.get("IndexName")
    if index:
        kwargs["IndexName"] = index
    resp = client.query(**kwargs)
    return {
        "items": resp.get("Items", []),
        "count": resp.get("Count", 0),
        "scanned_count": resp.get("ScannedCount", 0),
        "last_evaluated_key": resp.get("LastEvaluatedKey"),
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


_DISPATCH: dict[tuple[str, str], Any] = {
    ("lambda", "invoke"): _action_lambda_invoke,
    ("sqs", "send-message"): _action_sqs_send_message,
    ("sns", "publish"): _action_sns_publish,
    ("events", "put-events"): _action_events_put_events,
    ("secretsmanager", "rotate-secret"): _action_secretsmanager_rotate,
    ("dynamodb", "put-item"): _action_dynamodb_put_item,
    ("dynamodb", "get-item"): _action_dynamodb_get_item,
    ("dynamodb", "query"): _action_dynamodb_query,
    ("dynamodb", "scan"): _action_dynamodb_scan,
}


class ActionsResource:
    """``POST /_localemu/api/actions/<service>/<action>``: dashboard write paths."""

    def on_post(self, request: Request, service: str = "", action: str = ""):
        LOG.debug("Dashboard action: POST /actions/%s/%s", service, action)
        handler = _DISPATCH.get((service, action))
        if handler is None:
            return _json_response(
                {"error": f"Unknown action: {service}/{action}"}, status=404,
            )
        try:
            body = _parse_body(request)
            result = handler(body)
            return _json_response({"ok": True, "result": result})
        except _ActionError as exc:
            return _json_response({"error": str(exc)}, status=exc.status)
        except Exception as exc:
            LOG.debug("dashboard action error", exc_info=True)
            # Surface ClientError-style messages to the UI.
            code = type(exc).__name__
            try:
                from botocore.exceptions import ClientError

                if isinstance(exc, ClientError):
                    err = exc.response.get("Error", {})
                    code = err.get("Code") or code
            except Exception:
                pass
            return _json_response(
                {"error": str(exc), "error_code": code}, status=500,
            )
