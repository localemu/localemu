from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsConnectionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::Connection"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.events.resource_providers.aws_events_connection import (
            EventsConnectionProvider,
        )

        self.factory = EventsConnectionProvider
