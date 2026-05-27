from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMManagedPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::ManagedPolicy"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.iam.resource_providers.aws_iam_managedpolicy import (
            IAMManagedPolicyProvider,
        )

        self.factory = IAMManagedPolicyProvider
