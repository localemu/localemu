from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SSMMaintenanceWindowTargetProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::MaintenanceWindowTarget"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.ssm.resource_providers.aws_ssm_maintenancewindowtarget import (
            SSMMaintenanceWindowTargetProvider,
        )

        self.factory = SSMMaintenanceWindowTargetProvider
