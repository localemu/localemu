from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayResourceProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Resource"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.apigateway.resource_providers.aws_apigateway_resource import (
            ApiGatewayResourceProvider,
        )

        self.factory = ApiGatewayResourceProvider
