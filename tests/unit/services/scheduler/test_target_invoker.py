"""Tests for ``scheduler.target_invoker.invoke``.

What we pin:

  * The TargetSender factory is asked for a sender based on the ARN's
    service prefix; whatever sender it returns has ``process_event``
    invoked exactly once.
  * The synthesised event carries ``source="aws.scheduler"``,
    ``detail-type="Scheduled Event"``, ``resources=[<schedule_arn>]``,
    and the schedule's ``Target.Input`` parsed as JSON when it parses,
    or the raw string when it doesn't.
  * Empty / missing Target.Arn short-circuits without raising.
  * Factory errors on unsupported services are swallowed with a warning
    rather than escaping (the polling thread relies on this).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.scheduler import target_invoker


def _target(arn: str = "arn:aws:lambda:us-east-1:000000000000:function:foo",
            input_: str | None = None) -> dict:
    return {
        "Arn": arn,
        "RoleArn": "arn:aws:iam::000000000000:role/r",
        **({"Input": input_} if input_ is not None else {}),
    }


class TestInvocation:
    def test_event_envelope_has_aws_scheduler_source(self):
        mock_sender = MagicMock()
        with patch(
            "localemu.services.scheduler.target_invoker.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = mock_sender
            target_invoker.invoke(
                schedule_arn="arn:aws:scheduler:us-east-1:000000000000:schedule/default/s",
                schedule_name="s",
                target=_target(input_='{"k":"v"}'),
                account_id="000000000000",
                region="us-east-1",
            )
        assert mock_sender.process_event.call_count == 1
        call = mock_sender.process_event.call_args
        event = call.args[0]
        assert call.kwargs.get("trace_header") is None
        assert event["source"] == "aws.scheduler"
        assert event["detail-type"] == "Scheduled Event"
        assert event["resources"] == [
            "arn:aws:scheduler:us-east-1:000000000000:schedule/default/s"
        ]
        assert event["account"] == "000000000000"
        assert event["region"] == "us-east-1"
        # Input was valid JSON — it must be parsed into the detail field,
        # not left as a string.
        assert event["detail"] == {"k": "v"}

    def test_input_passthrough_when_not_valid_json(self):
        mock_sender = MagicMock()
        with patch(
            "localemu.services.scheduler.target_invoker.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = mock_sender
            target_invoker.invoke(
                schedule_arn="arn:aws:scheduler:us-east-1:000000000000:schedule/default/s",
                schedule_name="s",
                target=_target(input_="not-json"),
                account_id="000000000000",
                region="us-east-1",
            )
        event = mock_sender.process_event.call_args.args[0]
        assert event["detail"] == "not-json"

    def test_missing_target_arn_is_a_silent_noop(self):
        """The polling loop calls us with whatever the moto backend
        currently has; a schedule that was created with a malformed
        target shouldn't escalate to an exception that kills the loop."""
        with patch(
            "localemu.services.scheduler.target_invoker.TargetSenderFactory"
        ) as MockFactory:
            target_invoker.invoke(
                schedule_arn="arn:aws:scheduler:us-east-1:000000000000:schedule/default/s",
                schedule_name="s",
                target={"RoleArn": "arn:aws:iam::000000000000:role/r"},
                account_id="000000000000",
                region="us-east-1",
            )
        MockFactory.assert_not_called()

    def test_unsupported_service_does_not_raise(self):
        with patch(
            "localemu.services.scheduler.target_invoker.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.side_effect = Exception(
                "Unsupported target for Service: madeup"
            )
            target_invoker.invoke(
                schedule_arn="arn:aws:scheduler:us-east-1:000000000000:schedule/default/s",
                schedule_name="s",
                target=_target(arn="arn:aws:madeup:us-east-1:000000000000:thing"),
                account_id="000000000000",
                region="us-east-1",
            )
        # No call to process_event — factory raised, we logged and returned.
        # No exception propagated to the test.

    def test_schedule_arn_is_passed_through_as_rule_arn(self):
        """DLQ messages and retry logs in the sender are keyed on
        ``rule_arn`` — we substitute the schedule ARN there so DLQ
        consumers see a breadcrumb that traces back to the scheduling
        decision, not a synthetic empty rule arn."""
        with patch(
            "localemu.services.scheduler.target_invoker.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = MagicMock()
            target_invoker.invoke(
                schedule_arn="arn:aws:scheduler:us-east-1:000000000000:schedule/default/s",
                schedule_name="s",
                target=_target(),
                account_id="000000000000",
                region="us-east-1",
            )
        kw = MockFactory.call_args.kwargs
        assert kw["rule_arn"] == (
            "arn:aws:scheduler:us-east-1:000000000000:schedule/default/s"
        )
        assert kw["rule_name"] == "s"
