"""Dispatch a transformed batch to a Pipe's target.

The 6 v1 target services (Lambda, SQS, SNS, Step Functions, EventBridge
bus, Kinesis) all have existing senders in ``services/events/target.py``.
We re-use the factory + sender contract there rather than re-implement
batch dispatch; the only Pipes-specific behaviour is:

  * The factory wraps a synthesised ``Target`` dict (matching the
    EventBridge Rule shape) so the sender doesn't care that the upstream
    is a pipe.
  * RoleArn assumption uses ``ServicePrincipal.pipes`` so the target
    role's trust policy validates against ``pipes.amazonaws.com``, not
    EventBridge's ``events.amazonaws.com``.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.services.events.target import TargetSenderFactory

LOG = logging.getLogger(__name__)


class PipeTargetDispatcher:
    """One dispatcher per pipe — created at PipeWorker build time and
    reused for every batch the poller hands over."""

    def __init__(
        self,
        *,
        pipe_arn: str,
        pipe_name: str,
        target_arn: str,
        role_arn: str | None,
        target_parameters: dict | None,
        account_id: str,
        region: str,
    ) -> None:
        self.pipe_arn = pipe_arn
        self.pipe_name = pipe_name
        self.target_arn = target_arn
        self.role_arn = role_arn
        self.target_parameters = target_parameters or {}
        self.account_id = account_id
        self.region = region
        self._sender = None

    def _ensure_sender(self):
        if self._sender is not None:
            return self._sender
        target = self._build_events_style_target()
        factory = TargetSenderFactory(
            target=target,
            rule_arn=self.pipe_arn,
            rule_name=self.pipe_name,
            region=self.region,
            account_id=self.account_id,
            # Assume the target's RoleArn as ``pipes.amazonaws.com``;
            # the AWS-documented trust policy for Pipes-managed roles
            # names that principal.
            caller_service_principal="pipes",
        )
        self._sender = factory.get_target_sender()
        return self._sender

    def _build_events_style_target(self) -> dict:
        """Translate the Pipe target + parameters into the dict shape
        the EventBridge Rule sender family expects."""
        target: dict[str, Any] = {
            "Arn": self.target_arn,
            "Id": self.pipe_name,
        }
        if self.role_arn:
            target["RoleArn"] = self.role_arn

        # InputTemplate handling lives in transform.py; by the time the
        # dispatcher runs, the events list is already transformed.
        # InputPath / InputTransformer are intentionally NOT forwarded
        # to the sender — Pipes' transform happens upstream.

        return target

    def dispatch(self, events: list[Any]) -> dict | None:
        """Send each event in *events* to the target via the underlying
        TargetSender. Returns a partial-failure payload (dict with
        ``batchItemFailures``) when the sender produces one; otherwise
        ``None`` for full-batch success.
        """
        if not events:
            return None

        sender = self._ensure_sender()
        failures: list[dict] = []
        for index, event in enumerate(events):
            try:
                sender.send_event(event, trace_header=None)
            except Exception as exc:
                LOG.warning(
                    "Pipe %s target dispatch failed on event %d: %s",
                    self.pipe_arn, index, exc,
                )
                failures.append({"itemIdentifier": str(index)})
        if failures:
            return {"batchItemFailures": failures}
        return None
