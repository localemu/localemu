"""Per-pipe :class:`EventProcessor` that orchestrates the pipeline.

Sequence per batch handed from the poller:

  1. (Filter is already applied by the poller via ``Poller.filter_events``.)
  2. Apply enrichment input template, if configured.
  3. Invoke enrichment, if configured. ``None`` / empty list drops the
     batch entirely (AWS behaviour).
  4. Apply target input template, if configured.
  5. Dispatch to target. Partial batch failures bubble up via
     :class:`PartialBatchFailureError` so the poller can decide what to
     do with the unprocessed events (delete from queue / re-iterate
     shard / send to DLQ).
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.services.lambda_.event_source_mapping.event_processor import (
    EventProcessor,
    PartialBatchFailureError,
)
from localemu.services.pipes.target import PipeTargetDispatcher
from localemu.services.pipes.transform import apply_input_template

LOG = logging.getLogger(__name__)


class PipeEventProcessor(EventProcessor):
    def __init__(
        self,
        *,
        pipe_arn: str,
        pipe_name: str,
        enrichment_input_template: str | None = None,
        target_input_template: str | None = None,
        target_dispatcher: PipeTargetDispatcher,
    ) -> None:
        self.pipe_arn = pipe_arn
        self.pipe_name = pipe_name
        self.enrichment_input_template = enrichment_input_template
        self.target_input_template = target_input_template
        self.target_dispatcher = target_dispatcher

    def process_events_batch(self, input_events: list[Any]) -> None:
        events = list(input_events)
        if self.enrichment_input_template:
            events = [
                apply_input_template(self.enrichment_input_template, e) for e in events
            ]
        # v1 ships without enrichment; reserved hook for a future
        # commit when EnrichmentDispatcher lands.
        if self.target_input_template:
            events = [
                apply_input_template(self.target_input_template, e) for e in events
            ]
        failure_payload = self.target_dispatcher.dispatch(events)
        if failure_payload:
            raise PartialBatchFailureError(partial_failure_payload=failure_payload)

    def generate_event_failure_context(self, abort_condition: str, **kwargs) -> dict:
        """DLQ context shape — mirrors the EventBridge Pipes documented
        message format so consumers can introspect why a batch failed."""
        return {
            "context": {
                "condition": abort_condition,
                "pipeArn": self.pipe_arn,
                "pipeName": self.pipe_name,
            },
            **kwargs,
        }
