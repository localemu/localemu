from localemu.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
)
from localemu.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localemu.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localemu.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localemu.services.stepfunctions.asl.eval.environment import Environment
from localemu.utils.strings import long_uid


class StatesFunctionUUID(StatesFunction):
    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.UUID),
            argument_list=argument_list,
        )
        if argument_list.size != 0:
            raise ValueError(
                f"Expected no arguments for function type '{type(self)}', but got: '{argument_list}'."
            )

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(long_uid())
