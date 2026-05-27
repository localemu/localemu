from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CertificateManagerCertificateProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CertificateManager::Certificate"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.certificatemanager.resource_providers.aws_certificatemanager_certificate import (
            CertificateManagerCertificateProvider,
        )

        self.factory = CertificateManagerCertificateProvider
