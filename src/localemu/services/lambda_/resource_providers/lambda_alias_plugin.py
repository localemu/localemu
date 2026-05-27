from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaAliasProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Alias"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.lambda_.resource_providers.lambda_alias import LambdaAliasProvider

        self.factory = LambdaAliasProvider
