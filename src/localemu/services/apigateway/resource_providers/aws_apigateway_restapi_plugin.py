from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayRestApiProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::RestApi"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.apigateway.resource_providers.aws_apigateway_restapi import (
            ApiGatewayRestApiProvider,
        )

        self.factory = ApiGatewayRestApiProvider
