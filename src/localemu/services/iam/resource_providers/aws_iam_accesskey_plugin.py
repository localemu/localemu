from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMAccessKeyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::AccessKey"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.iam.resource_providers.aws_iam_accesskey import (
            IAMAccessKeyProvider,
        )

        self.factory = IAMAccessKeyProvider
