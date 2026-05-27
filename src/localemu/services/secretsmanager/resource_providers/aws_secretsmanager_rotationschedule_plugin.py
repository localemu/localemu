from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SecretsManagerRotationScheduleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SecretsManager::RotationSchedule"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.secretsmanager.resource_providers.aws_secretsmanager_rotationschedule import (
            SecretsManagerRotationScheduleProvider,
        )

        self.factory = SecretsManagerRotationScheduleProvider
