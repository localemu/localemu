from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EventsRuleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Events::Rule"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localemu.services.events.resource_providers.aws_events_rule import EventsRuleProvider

        self.factory = EventsRuleProvider
