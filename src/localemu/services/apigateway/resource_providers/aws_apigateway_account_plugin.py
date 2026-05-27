from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayAccountProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Account"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.apigateway.resource_providers.aws_apigateway_account import (
            ApiGatewayAccountProvider,
        )

        self.factory = ApiGatewayAccountProvider
