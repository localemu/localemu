from functools import cached_property

from rolo.gateway import Gateway

from localemu.aws.app import LocalemuAwsGateway
from localemu.runtime.components import BaseComponents


class AwsComponents(BaseComponents):
    """
    Runtime components specific to the AWS emulator.
    """

    name = "aws"

    @cached_property
    def gateway(self) -> Gateway:
        # FIXME: the ServiceManager should be reworked to be more generic, and then become part of the
        #  components
        from localemu.services.plugins import SERVICE_PLUGINS

        return LocalemuAwsGateway(SERVICE_PLUGINS)
