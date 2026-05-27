from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class DynamoDBGlobalTableProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::DynamoDB::GlobalTable"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.dynamodb.resource_providers.aws_dynamodb_globaltable import (
            DynamoDBGlobalTableProvider,
        )

        self.factory = DynamoDBGlobalTableProvider
