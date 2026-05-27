from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SSMMaintenanceWindowTaskProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::MaintenanceWindowTask"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.ssm.resource_providers.aws_ssm_maintenancewindowtask import (
            SSMMaintenanceWindowTaskProvider,
        )

        self.factory = SSMMaintenanceWindowTaskProvider
