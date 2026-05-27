"""Build a :class:`PipeWorker` from a moto ``Pipe`` model.

Today this only knows about SQS sources; the design has slots for
Kinesis and DynamoDB Streams (mirroring the ESM pollers) which land
in a follow-up commit. Anything else raises ``NotImplementedError``
with a clear message that pinpoints the limitation — the polling
thread should never fail silently.
"""

from __future__ import annotations

import logging

from localemu.aws.connect import connect_to
from localemu.services.lambda_.event_source_mapping.pipe_utils import (
    get_internal_client,
)
from localemu.services.lambda_.event_source_mapping.pollers.sqs_poller import (
    SqsPoller,
)
from localemu.services.pipes.event_processor import PipeEventProcessor
from localemu.services.pipes.pipe_worker import PipeWorker
from localemu.services.pipes.target import PipeTargetDispatcher
from localemu.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)


_SQS_SERVICE = "sqs"


def build_worker(pipe, account_id: str, region: str, desired_running: bool) -> PipeWorker:
    """Factory entry point — pipe is the moto ``Pipe`` model.

    Reads the pipe's source + source_parameters, builds a poller
    appropriate to the source service, wires up the target dispatcher
    and event processor, and returns a :class:`PipeWorker` ready to be
    handed to :class:`PipeManager`.
    """
    source_arn: str = pipe.source
    source_service = _extract_service(source_arn)

    source_parameters = dict(pipe.source_parameters or {})
    target_parameters = dict(pipe.target_parameters or {})

    enrichment_input_template = (pipe.enrichment_parameters or {}).get("InputTemplate")
    target_input_template = (target_parameters.get("InputTemplate") or None)

    target_dispatcher = PipeTargetDispatcher(
        pipe_arn=pipe.arn,
        pipe_name=pipe.name,
        target_arn=pipe.target,
        role_arn=getattr(pipe, "role_arn", None),
        target_parameters=target_parameters,
        account_id=account_id,
        region=region,
    )
    processor = PipeEventProcessor(
        pipe_arn=pipe.arn,
        pipe_name=pipe.name,
        enrichment_input_template=enrichment_input_template,
        target_input_template=target_input_template,
        target_dispatcher=target_dispatcher,
    )

    if source_service == _SQS_SERVICE:
        # SqsPoller expects source_parameters with the ``SqsQueueParameters``
        # subkey populated; AWS defaults the inner dict to {} if not provided.
        if "SqsQueueParameters" not in source_parameters:
            source_parameters["SqsQueueParameters"] = {}
        source_client = get_internal_client(
            arn=source_arn,
            role_arn=getattr(pipe, "role_arn", None),
            service_principal="pipes",
            source_arn=pipe.arn,
            service="sqs",
        )
        poller = SqsPoller(
            source_arn=source_arn,
            source_parameters=source_parameters,
            source_client=source_client,
            processor=processor,
        )
    else:
        raise NotImplementedError(
            f"Pipe source service {source_service!r} is not yet implemented. "
            "v1 supports sqs; Kinesis and DynamoDB Streams are coming next."
        )

    return PipeWorker(
        pipe_arn=pipe.arn,
        pipe_name=pipe.name,
        account_id=account_id,
        region=region,
        poller=poller,
        desired_running=desired_running,
    )


def _extract_service(arn: str) -> str:
    try:
        return parse_arn(arn)["service"]
    except Exception:
        return ""
