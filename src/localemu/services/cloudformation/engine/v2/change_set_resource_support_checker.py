"""Resource-support checker for CloudFormation v2 change sets.

What "supported" means for LocalEmu:
  * the type has a registered ``CloudFormationResourceProviderPlugin``
    in the ``localemu.cloudformation.resource_providers`` namespace, or
  * the type is one of the AWS pseudo-resources (``AWS::CloudFormation::
    *``) the engine handles natively.

The check previously consulted a generated dump of EVERY CFN resource
that exists in any AWS region, regardless of whether LocalEmu could
actually deploy it. The result: ``AWS::Glue::Crawler`` and dozens of
other unimplemented types passed the supported-check, the change-set
went through, and the deploy silently produced no real resource. The
honest authoritative set is the registered provider plugin list —
anything not in it returns a clear error message pointing at the
issue tracker.
"""

from functools import cache

from plux import PluginManager

from localemu.aws.api.cloudformation import ChangeSetType
from localemu.services.cloudformation.engine.v2.change_set_model import NodeResource
from localemu.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)
from localemu.services.cloudformation.engine.v2.unsupported_resource import (
    should_ignore_unsupported_resource_type,
)
from localemu.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
)

# Pseudo-types implemented inside the engine itself (not via a separate
# resource provider plugin). They MUST be treated as supported even though
# they have no registered plugin.
_ENGINE_BUILTIN_RESOURCE_TYPES = frozenset({
    "AWS::CloudFormation::Stack",
    "AWS::CloudFormation::WaitCondition",
    "AWS::CloudFormation::WaitConditionHandle",
    "AWS::CloudFormation::CustomResource",
})


@cache
def _implemented_resource_types() -> frozenset[str]:
    """Return the authoritative set of CloudFormation resource types
    LocalEmu can actually deploy — the registered provider plugins plus
    the engine-builtin pseudo-types.

    Cached because plugin discovery is a hot path for every change-set
    visit and the answer doesn't change across the lifetime of a
    LocalEmu process.
    """
    pm = PluginManager(CloudFormationResourceProviderPlugin.namespace)
    try:
        registered = frozenset(pm.list_names())
    except Exception:
        # plux discovery hiccups must not silently make every resource
        # "supported"; fall back to just the engine builtins so the
        # change-set surfaces the unsupported list honestly.
        registered = frozenset()
    return registered | _ENGINE_BUILTIN_RESOURCE_TYPES


class ChangeSetResourceSupportChecker(ChangeSetModelVisitor):
    """Flags CloudFormation resource types that LocalEmu does not currently emulate."""

    change_set_type: ChangeSetType

    TITLE_MESSAGE = "Unsupported resources detected:"

    def __init__(self, change_set_type: ChangeSetType):
        self._resource_failure_messages: dict[str, str] = {}
        self.change_set_type = change_set_type

    def visit_node_resource(self, node_resource: NodeResource):
        resource_type = node_resource.type_.value
        ignore_unsupported = should_ignore_unsupported_resource_type(
            resource_type=resource_type, change_set_type=self.change_set_type
        )

        # Custom:: resources are routed to AWS::CloudFormation::CustomResource
        # by ``get_resource_type``; mirror that here so a user template that
        # declares ``Custom::MyThing`` doesn't get incorrectly flagged.
        effective_type = (
            "AWS::CloudFormation::CustomResource"
            if resource_type.startswith("Custom::")
            else resource_type
        )

        if (
            resource_type not in self._resource_failure_messages
            and not ignore_unsupported
            and effective_type not in _implemented_resource_types()
        ):
            self._resource_failure_messages[resource_type] = (
                f"The {resource_type} resource is not currently emulated by LocalEmu. "
                f"Open an issue at https://github.com/localemu/localemu/issues if you need it."
            )
        super().visit_node_resource(node_resource)

    @property
    def failure_messages(self) -> list[str]:
        return list(self._resource_failure_messages.values())
