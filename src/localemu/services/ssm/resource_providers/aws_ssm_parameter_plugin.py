from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SSMParameterProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::Parameter"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.ssm.resource_providers.aws_ssm_parameter import (
            SSMParameterProvider,
        )

        self.factory = SSMParameterProvider
