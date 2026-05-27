from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsEventBusPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::EventBusPolicy"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.events.resource_providers.aws_events_eventbuspolicy import (
            EventsEventBusPolicyProvider,
        )

        self.factory = EventsEventBusPolicyProvider
