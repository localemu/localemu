from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::Policy"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.iam.resource_providers.aws_iam_policy import IAMPolicyProvider

        self.factory = IAMPolicyProvider
