from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsApiDestinationProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::ApiDestination"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.events.resource_providers.aws_events_apidestination import (
            EventsApiDestinationProvider,
        )

        self.factory = EventsApiDestinationProvider
