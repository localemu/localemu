from collections import defaultdict

from localemu.aws.api.kinesis import (
    ConsumerDescription,
    MetricsName,
    Policy,
    ResourceARN,
    StreamName,
)
from localemu.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    LocalAttribute,
)


class KinesisStore(BaseStore):
    # list of stream consumer details
    stream_consumers: list[ConsumerDescription] = LocalAttribute(default=list)

    # maps stream name to list of enhanced monitoring metrics
    enhanced_metrics: dict[StreamName, set[MetricsName]] = LocalAttribute(
        default=lambda: defaultdict(set)
    )

    resource_policies: dict[ResourceARN, Policy] = LocalAttribute(default=dict)


kinesis_stores = AccountRegionBundle("kinesis", KinesisStore)
