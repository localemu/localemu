from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2EIPProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::EIP"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.ec2.resource_providers.aws_ec2_eip import (
            EC2EIPProvider,
        )

        self.factory = EC2EIPProvider
