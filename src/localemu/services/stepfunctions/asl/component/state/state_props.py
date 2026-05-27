from typing import Any, Final

from localemu.services.stepfunctions.asl.component.common.flow.end import End
from localemu.services.stepfunctions.asl.component.common.flow.next import Next
from localemu.services.stepfunctions.asl.component.common.parargs import Parargs
from localemu.services.stepfunctions.asl.component.common.timeouts.heartbeat import Heartbeat
from localemu.services.stepfunctions.asl.component.common.timeouts.timeout import Timeout
from localemu.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_type import (
    Comparison,
)
from localemu.services.stepfunctions.asl.component.state.state_choice.comparison.variable import (
    Variable,
)
from localemu.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.max_items_decl import (
    MaxItemsDecl,
)
from localemu.services.stepfunctions.asl.component.state.state_execution.state_map.items.items import (
    Items,
)
from localemu.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrencyDecl,
)
from localemu.services.stepfunctions.asl.component.state.state_execution.state_map.tolerated_failure import (
    ToleratedFailureCountDecl,
    ToleratedFailurePercentageDecl,
)
from localemu.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localemu.services.stepfunctions.asl.component.state.state_fail.cause_decl import CauseDecl
from localemu.services.stepfunctions.asl.component.state.state_fail.error_decl import ErrorDecl
from localemu.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localemu.services.stepfunctions.asl.parse.typed_props import TypedProps

UNIQUE_SUBINSTANCES: Final[set[type]] = {
    Items,
    Resource,
    WaitFunction,
    Timeout,
    Heartbeat,
    MaxItemsDecl,
    MaxConcurrencyDecl,
    ToleratedFailureCountDecl,
    ToleratedFailurePercentageDecl,
    ErrorDecl,
    CauseDecl,
    Variable,
    Parargs,
    Comparison,
}


class StateProps(TypedProps):
    name: str

    def add(self, instance: Any) -> None:
        inst_type = type(instance)

        # End-Next conflicts:
        if inst_type == End and Next in self._instance_by_type:
            raise ValueError(f"End redefines Next, from '{self.get(Next)}' to '{instance}'.")
        if inst_type == Next and End in self._instance_by_type:
            raise ValueError(f"Next redefines End, from '{self.get(End)}' to '{instance}'.")

        # Subclasses
        for typ in UNIQUE_SUBINSTANCES:
            if issubclass(inst_type, typ):
                super()._add(typ, instance)
                return

        # Base and delegate to preprocessor.
        super().add(instance)
