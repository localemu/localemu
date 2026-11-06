"""Adapter that dispatches a Scheduler Target via the EventBridge TargetSender.

EventBridge Scheduler reuses the same target shape as EventBridge Rules,
so we can delegate to ``services/events/target.py`` for the actual call.
The only thing this adapter does is:

  1. translate a scheduler ``Target`` dict into the ``Target`` shape the
     sender factory expects (they're already aligned but Scheduler uses
     ``RoleArn`` at the top level instead of inside ``RoleArn`` on each
     target — the field name is identical, just calling it out),
  2. synthesise the event envelope so the receiving target sees an
     EventBridge-style payload with ``source = "aws.scheduler"`` and a
     ``detail-type = "Scheduled Event"`` (matches real AWS), and
  3. invoke ``TargetSender.process_event``, which carries the existing
     retry + DLQ implementation. We do not re-implement either here.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from localemu.aws.connect import connect_to
from localemu.services.events.target import TargetSenderFactory
from localemu.utils.aws.client_types import ServicePrincipal

LOG = logging.getLogger(__name__)

_UNIVERSAL_TARGET_PREFIX = "arn:aws:scheduler:::aws-sdk:"


def _snake_case(name: str) -> str:
    """lowerCamelCase SDK action name -> boto3's snake_case method name
    (``getParameter`` -> ``get_parameter``)."""
    import re

    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _invoke_universal_target(
    *, schedule_arn: str, target: dict, account_id: str, region: str,
) -> None:
    """Universal targets (``arn:aws:scheduler:::aws-sdk:<service>:<action>``)
    call an arbitrary AWS SDK action directly - they don't go through the
    EventBridge Rule/Target-sender machinery at all (there's no "event" to
    deliver, no retry/DLQ semantics AWS documents for them), and the result
    goes nowhere on real AWS, same here.

    Previously unrecognised entirely: ``TargetSenderFactory`` tried to
    resolve a service from the ARN's own (``scheduler``) segment, found no
    matching sender, and the schedule silently never fired.
    """
    arn = target["Arn"]
    service_and_action = arn[len(_UNIVERSAL_TARGET_PREFIX):]
    service, _, action = service_and_action.partition(":")
    if not service or not action:
        LOG.warning("Scheduler %s has a malformed universal target ARN %s", schedule_arn, arn)
        return

    role_arn = target.get("RoleArn")
    if not role_arn:
        LOG.warning("Scheduler %s universal target %s has no RoleArn", schedule_arn, arn)
        return

    client_factory = connect_to.with_assumed_role(
        role_arn=role_arn,
        service_principal=ServicePrincipal("scheduler"),
        region_name=region,
    )
    client = client_factory.get_client(service)
    client = client.request_metadata(
        service_principal=ServicePrincipal("scheduler"),
        source_arn=schedule_arn,
        # Same opt-in as the v1 target path: the role's own permission
        # policy must gate this call, not just its trust policy.
        enforce_role_permissions=True,
    )

    raw_input = target.get("Input")
    kwargs = {}
    if raw_input:
        try:
            kwargs = json.loads(raw_input) if isinstance(raw_input, str) else dict(raw_input)
        except (TypeError, ValueError):
            LOG.warning("Scheduler %s universal target has non-JSON Input", schedule_arn)
            return

    method_name = _snake_case(action)
    method = getattr(client, method_name, None)
    if method is None:
        LOG.warning(
            "Scheduler %s universal target %s has no such %s operation",
            schedule_arn, arn, method_name,
        )
        return
    # The result is discarded - real AWS documents universal targets as
    # having nowhere for the response to go.
    method(**kwargs)


def _synthesise_event(
    *,
    schedule_arn: str,
    account_id: str,
    region: str,
    target_input: Any,
) -> dict:
    """Build the EventBridge-style envelope the sender expects.

    AWS-generated Scheduler invocations carry these fields on the event the
    target receives:

      * ``source = "aws.scheduler"``
      * ``detail-type = "Scheduled Event"``
      * ``resources = [<schedule arn>]``
      * ``detail`` = the user-provided ``Target.Input`` (parsed as JSON if
        it parses cleanly, else passed through as a string)
    """
    detail: Any = ""
    if target_input is not None:
        if isinstance(target_input, str):
            try:
                detail = json.loads(target_input)
            except (TypeError, ValueError):
                detail = target_input
        else:
            detail = target_input
    return {
        "version": "0",
        "id": _new_event_id(),
        "source": "aws.scheduler",
        "detail-type": "Scheduled Event",
        "account": account_id,
        "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "region": region,
        "resources": [schedule_arn],
        "detail": detail,
    }


def _new_event_id() -> str:
    import uuid

    return str(uuid.uuid4())


def invoke(
    *,
    schedule_arn: str,
    schedule_name: str,
    target: dict,
    account_id: str,
    region: str,
) -> None:
    """Dispatch a single scheduled invocation through the events TargetSender.

    Synchronous from the caller's point of view; the job scheduler is
    expected to call this from a worker thread so the polling loop never
    blocks on target I/O. ``TargetSender.process_event`` already implements
    retry-with-backoff and DLQ delivery, so we don't wrap it again.
    """
    if not target or not target.get("Arn"):
        LOG.warning(
            "Scheduler invocation skipped — schedule %s has no Target.Arn",
            schedule_arn,
        )
        return

    if target["Arn"].startswith(_UNIVERSAL_TARGET_PREFIX):
        _invoke_universal_target(
            schedule_arn=schedule_arn, target=target, account_id=account_id, region=region,
        )
        return

    factory = TargetSenderFactory(
        target=target,
        # The sender shapes its DLQ + log messages with rule_arn / rule_name;
        # we substitute the schedule ARN + name verbatim. Downstream code
        # only treats these as opaque identifiers so the substitution is
        # safe and gives DLQ consumers a useful breadcrumb.
        rule_arn=schedule_arn,
        rule_name=schedule_name,
        region=region,
        account_id=account_id,
        # Assume the target's RoleArn as ``scheduler.amazonaws.com`` —
        # the trust policy users write for Scheduler-managed roles names
        # that principal, not EventBridge's.
        caller_service_principal="scheduler",
        # The role's own permission policy gates invocation too, not
        # just its trust policy.
        enforce_role_permissions=True,
    )
    try:
        sender = factory.get_target_sender()
    except Exception:
        LOG.warning(
            "Scheduler %s has unsupported target service for ARN %s",
            schedule_arn, target.get("Arn"),
            exc_info=True,
        )
        return

    event = _synthesise_event(
        schedule_arn=schedule_arn,
        account_id=account_id,
        region=region,
        target_input=target.get("Input"),
    )
    # No X-Ray trace propagation from Scheduler in v1 — pass None.
    sender.process_event(event, trace_header=None)
