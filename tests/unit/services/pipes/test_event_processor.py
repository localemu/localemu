"""PipeEventProcessor — orchestrates transform → dispatch → partial-failure
propagation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from localemu.services.lambda_.event_source_mapping.event_processor import (
    PartialBatchFailureError,
)
from localemu.services.pipes.event_processor import PipeEventProcessor


def _processor(
    enrichment_tpl: str | None = None,
    target_tpl: str | None = None,
    dispatcher_result=None,
):
    dispatcher = MagicMock()
    dispatcher.dispatch.return_value = dispatcher_result
    return (
        PipeEventProcessor(
            pipe_arn="arn:aws:pipes:us-east-1:000000000000:pipe/p",
            pipe_name="p",
            enrichment_input_template=enrichment_tpl,
            target_input_template=target_tpl,
            target_dispatcher=dispatcher,
        ),
        dispatcher,
    )


class TestProcessor:
    def test_no_templates_forwards_events_verbatim(self):
        proc, dispatcher = _processor()
        events = [{"x": 1}, {"x": 2}]
        proc.process_events_batch(events)
        dispatcher.dispatch.assert_called_once_with([{"x": 1}, {"x": 2}])

    def test_target_template_is_applied_per_event(self):
        proc, dispatcher = _processor(
            target_tpl='{"renamed": <$.body.value>}',
        )
        proc.process_events_batch([
            {"body": {"value": "a"}},
            {"body": {"value": "b"}},
        ])
        dispatcher.dispatch.assert_called_once_with([
            {"renamed": "a"},
            {"renamed": "b"},
        ])

    def test_partial_failure_propagates(self):
        proc, _ = _processor(
            dispatcher_result={"batchItemFailures": [{"itemIdentifier": "0"}]},
        )
        with pytest.raises(PartialBatchFailureError) as ei:
            proc.process_events_batch([{"x": 1}])
        assert ei.value.partial_failure_payload == {
            "batchItemFailures": [{"itemIdentifier": "0"}],
        }
