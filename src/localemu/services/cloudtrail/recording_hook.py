"""CloudTrail recording-hook — owned by the CloudTrail service itself.

Historically this handler lived as a closure inside
``localemu.dashboard.plugins.register_dashboard``. That coupling meant:

* If the dashboard plugin was disabled, CloudTrail silently stopped
  recording events (F2 in the audit).
* The duplicate-registration guard compared function-object identity
  against a fresh closure, so repeated ``register_dashboard()`` calls
  registered the handler multiple times (F3).

The fix (F2+F3):

* The hook is a **named module-level function** living with the
  CloudTrail service.
* It carries a string attribute ``_le_handler_tag`` that the registrar
  checks against, so identity survives reloads / re-imports.
* The CloudTrail service registers it via its lifecycle hook.
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PARITY-C1: CloudTrail -> EventBridge forwarding helpers.
#
# Mirrors real AWS: every recorded management event is also published to
# the default event bus so EventBridge rules can match on it. Best-effort,
# never propagates failures.
# ---------------------------------------------------------------------------
_EVB_RESOURCE_ARN_BUILDERS = {
    "s3": lambda p, r, a: (
        [f"arn:aws:s3:::{p['Bucket']}"] if p.get("Bucket") else []
    ),
    "sqs": lambda p, r, a: (
        [f"arn:aws:sqs:{r}:{a}:{p['QueueName']}"] if p.get("QueueName") else []
    ),
    "sns": lambda p, r, a: (
        [f"arn:aws:sns:{r}:{a}:{p['Name']}"] if p.get("Name") else []
    ),
    "dynamodb": lambda p, r, a: (
        [f"arn:aws:dynamodb:{r}:{a}:table/{p['TableName']}"]
        if p.get("TableName") else []
    ),
    "lambda": lambda p, r, a: (
        [f"arn:aws:lambda:{r}:{a}:function:{p['FunctionName']}"]
        if p.get("FunctionName") else []
    ),
}


def _build_eventbridge_resources(
    service_name: str,
    service_request: dict,
    region: str,
    account_id: str,
) -> list[str]:
    try:
        builder = _EVB_RESOURCE_ARN_BUILDERS.get((service_name or "").lower())
        if not builder:
            return []
        return builder(service_request or {}, region or "us-east-1",
                       account_id or "000000000000")
    except Exception:
        return []


def _emit_cloudtrail_to_eventbridge(
    service_name: str,
    account_id: str,
    region: str,
    event,
    service_request: dict,
) -> None:
    if (service_name or "").lower() == "events":
        return
    try:
        from localemu.aws.connect import connect_to

        entry = {
            "Source": f"aws.{service_name.lower()}",
            "DetailType": "AWS API Call via CloudTrail",
            "Detail": event.to_cloudtrail_event_json(),
            "Time": event.event_time,
        }
        resources = _build_eventbridge_resources(
            service_name, service_request, region, account_id
        )
        if resources:
            entry["Resources"] = resources

        events_client = connect_to(
            aws_access_key_id=account_id or "000000000000",
            region_name=region or "us-east-1",
        ).events
        events_client.put_events(Entries=[entry])
    except Exception:
        LOG.debug(
            "CloudTrail->EventBridge forwarding failed for %s.%s",
            service_name,
            getattr(event, "event_name", "?"),
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# The recording handler — NAMED module-level function.
#
# F3 fix: we tag this function with a string attribute
# ``_le_handler_tag = "cloudtrail-activity-recorder"``. The registrar (see
# ``register_recording_hook`` below) checks for that tag rather than function
# identity, so that hot reloads importing a fresh module object still
# recognise an already-registered handler.
# ---------------------------------------------------------------------------
def cloudtrail_activity_handler(chain, context, response):
    """Record API activity to the CloudTrail event store (single source of truth)."""
    try:
        if not (context.service and context.operation):
            return
        service_name = context.service.service_name
        operation_name = context.operation.name
        account_id = str(getattr(context, "account_id", "") or "")
        region = str(getattr(context, "region", "") or "")

        user_agent = ""
        try:
            if hasattr(context, "request") and context.request:
                user_agent = (
                    context.request.headers.get("User-Agent", "")
                    if hasattr(context.request, "headers")
                    else ""
                )
        except Exception:
            pass

        # Skip dashboard self-recording. The dashboard makes reentrant
        # boto3 calls when listing SNS subscriptions, peeking SQS
        # messages and a few other read-only helpers. Without this
        # guard each dashboard tick would inflate CloudTrail with
        # ListSubscriptionsByTopic / ReceiveMessage / ListRules rows
        # the user never made.
        if user_agent.startswith(_DASHBOARD_USER_AGENT_PREFIX) or _is_internal_dashboard_call():
            return

        access_key_id = ""
        try:
            auth_header = context.request.headers.get("Authorization", "")
            if "Credential=" in auth_header:
                cred_part = auth_header.split("Credential=")[1].split(",")[0]
                access_key_id = cred_part.split("/")[0]
        except Exception:
            pass

        error_code = None
        error_message = None
        try:
            exc = getattr(context, "service_exception", None)
            if exc:
                error_code = getattr(exc, "code", None) or type(exc).__name__
                error_message = str(exc)
            elif response.status_code >= 400:
                error_code = str(response.status_code)
        except Exception:
            pass

        request_id = str(getattr(context, "request_id", "") or "")

        # PARITY-03/07/08: trail logging state and event-selector filtering.
        should_record = True
        try:
            import moto.backends as moto_backends

            from localemu.services.cloudtrail.event_store import _is_read_only

            ct_backend = moto_backends.get_backend("cloudtrail")[
                account_id or "000000000000"][region or "us-east-1"]
            trails = getattr(ct_backend, "trails", {})
            if trails:
                is_read = _is_read_only(operation_name)
                any_trail_accepts = False
                for t in trails.values():
                    if not getattr(t, "is_logging", True):
                        continue
                    selectors = getattr(t, "event_selectors", None) or []
                    if not selectors:
                        any_trail_accepts = True
                        break
                    for sel in selectors:
                        rw_type = sel.get("ReadWriteType", "All")
                        if rw_type == "All":
                            any_trail_accepts = True
                            break
                        elif rw_type == "ReadOnly" and is_read:
                            any_trail_accepts = True
                            break
                        elif rw_type == "WriteOnly" and not is_read:
                            any_trail_accepts = True
                            break
                    if any_trail_accepts:
                        break
                should_record = any_trail_accepts
        except Exception:
            pass

        if not should_record:
            return

        try:
            from localemu.services.cloudtrail.event_store import (
                create_event_from_context,
                get_event_store,
            )

            service_request = getattr(context, "service_request", None) or {}
            service_response = getattr(context, "service_response", None) or {}
            if not isinstance(service_response, dict):
                service_response = None

            source_ip = "127.0.0.1"
            if context.request:
                source_ip = getattr(context.request, "remote_addr", None) or "127.0.0.1"

            event = create_event_from_context(
                service_name=service_name,
                operation_name=operation_name,
                account_id=account_id,
                region=region,
                source_ip=source_ip,
                user_agent=user_agent,
                request_id=request_id,
                access_key_id=access_key_id,
                username=access_key_id or "localemu",
                error_code=error_code,
                error_message=error_message,
                service_request=service_request,
                response_elements=service_response,
                http_status_code=response.status_code,
            )
            get_event_store().record(event)

            # Publish to the dashboard event bus so live SSE subscribers see
            # the call within milliseconds, and so the count cache can
            # invalidate on Create/Delete/Put/Update operations. Failures
            # never break the request path.
            try:
                from localemu.dashboard.bus import (
                    is_mutating,
                    publish_activity,
                    publish_resource_changed,
                )
                from localemu.dashboard.api import _count_cache

                publish_activity(
                    service=service_name,
                    operation=operation_name,
                    status=response.status_code,
                    request_id=request_id,
                    account_id=account_id,
                    region=region,
                    source_ip=source_ip,
                )
                if (
                    is_mutating(operation_name)
                    and 200 <= response.status_code < 300
                ):
                    publish_resource_changed(
                        service=service_name,
                        operation=operation_name,
                        resource_id="",
                        region=region,
                        account_id=account_id,
                    )
                    _count_cache.pop(service_name, None)
            except Exception:
                LOG.debug("dashboard bus publish failed", exc_info=True)

            _emit_cloudtrail_to_eventbridge(
                service_name=service_name,
                account_id=account_id,
                region=region,
                event=event,
                service_request=service_request,
            )
        except Exception:
            LOG.debug("CloudTrail event recording failed", exc_info=True)
    except Exception:
        LOG.debug("Activity recording handler failed", exc_info=True)


# F3 fix: tag the handler with a stable string so duplicate-registration
# detection survives module reloads / fresh imports.
cloudtrail_activity_handler._le_handler_tag = "cloudtrail-activity-recorder"  # type: ignore[attr-defined]


_HANDLER_TAG = "cloudtrail-activity-recorder"


_DASHBOARD_USER_AGENT_PREFIX = "LocalEmu-Dashboard/"

# Threading-local flag used by the dashboard's reentrant boto3 helpers
# to suppress CloudTrail recording. A simple int counter so nested
# context managers compose. ContextVar would also work but a thread-
# local matches the rest of the project's idioms and avoids picking up
# accidental cross-thread leakage from asyncio-based callers.
import threading as _threading

_internal_dashboard_call = _threading.local()


def _is_internal_dashboard_call() -> bool:
    return getattr(_internal_dashboard_call, "depth", 0) > 0


class suppress_recording:
    """Context manager: skip CloudTrail recording for reentrant calls.

    Used by the dashboard when it calls boto3 to read state for its own
    list panels (e.g. peeking SQS messages, listing SNS subscriptions).
    Without this guard every dashboard refresh would inflate CloudTrail
    with rows the user never issued.
    """

    def __enter__(self):
        _internal_dashboard_call.depth = getattr(_internal_dashboard_call, "depth", 0) + 1
        return self

    def __exit__(self, exc_type, exc, tb):
        _internal_dashboard_call.depth = max(0, getattr(_internal_dashboard_call, "depth", 0) - 1)
        return False


def register_recording_hook() -> None:
    """Register the CloudTrail activity-recording response handler.

    F3: idempotent via the ``_le_handler_tag`` string attribute, NOT via
    function-object identity (which fails across reloads because a fresh
    closure is a new object each time).
    """
    from localemu.aws.handlers import run_custom_response_handlers

    for existing in run_custom_response_handlers.handlers:
        if getattr(existing, "_le_handler_tag", None) == _HANDLER_TAG:
            return
    run_custom_response_handlers.handlers.append(cloudtrail_activity_handler)
    LOG.debug("CloudTrail activity-recording hook registered")


def unregister_recording_hook() -> None:
    """Remove the CloudTrail activity-recording handler (service stop)."""
    try:
        from localemu.aws.handlers import run_custom_response_handlers
    except Exception:
        return
    run_custom_response_handlers.handlers[:] = [
        h for h in run_custom_response_handlers.handlers
        if getattr(h, "_le_handler_tag", None) != _HANDLER_TAG
    ]
