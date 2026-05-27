"""Back-compat re-export shim for the Kinesis stream consumer.

This module used to host a KCL (Kinesis Client Library) based consumer that
spawned a Java MultiLangDaemon subprocess. The KCL plumbing has been
removed (it was inherited from LocalStack and contradicted LocalEmu's
pure-Python stack goal). The consumer is now a boto3 polling implementation
in :mod:`localemu.utils.kinesis.kinesis_poll_consumer`.

This shim preserves the import paths used by ``localemu.services.firehose``
and a handful of integration tests:

    from localemu.utils.kinesis import kinesis_connector
    kinesis_connector.listen_to_kinesis(...)

    from localemu.utils.kinesis.kinesis_connector import KinesisProcessorThread
"""

from localemu.utils.kinesis.kinesis_poll_consumer import (
    KinesisPollConsumer,
    ListenerFunction,
    listen_to_kinesis,
)

# The KCL implementation exposed a class called KinesisProcessorThread; firehose
# uses that name as a type annotation. Alias it to the new consumer class so the
# annotation stays valid without forcing a firehose import change.
KinesisProcessorThread = KinesisPollConsumer

__all__ = [
    "KinesisPollConsumer",
    "KinesisProcessorThread",
    "ListenerFunction",
    "listen_to_kinesis",
]
