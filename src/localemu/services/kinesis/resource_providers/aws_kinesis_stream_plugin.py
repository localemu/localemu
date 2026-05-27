from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KinesisStreamProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Kinesis::Stream"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.kinesis.resource_providers.aws_kinesis_stream import (
            KinesisStreamProvider,
        )

        self.factory = KinesisStreamProvider
