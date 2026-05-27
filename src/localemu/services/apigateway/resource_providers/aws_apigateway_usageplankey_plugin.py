from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayUsagePlanKeyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::UsagePlanKey"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.apigateway.resource_providers.aws_apigateway_usageplankey import (
            ApiGatewayUsagePlanKeyProvider,
        )

        self.factory = ApiGatewayUsagePlanKeyProvider
