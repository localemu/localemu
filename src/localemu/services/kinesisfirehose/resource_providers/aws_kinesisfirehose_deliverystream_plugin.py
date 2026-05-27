from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KinesisFirehoseDeliveryStreamProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::KinesisFirehose::DeliveryStream"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.kinesisfirehose.resource_providers.aws_kinesisfirehose_deliverystream import (
            KinesisFirehoseDeliveryStreamProvider,
        )

        self.factory = KinesisFirehoseDeliveryStreamProvider
