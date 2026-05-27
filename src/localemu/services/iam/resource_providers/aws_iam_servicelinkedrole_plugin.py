from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMServiceLinkedRoleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::ServiceLinkedRole"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.iam.resource_providers.aws_iam_servicelinkedrole import (
            IAMServiceLinkedRoleProvider,
        )

        self.factory = IAMServiceLinkedRoleProvider
