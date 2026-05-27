from typing import Final

from localemu.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localemu.services.stepfunctions.asl.eval.environment import Environment


class PayloadArr(PayloadValue):
    def __init__(self, payload_values: list[PayloadValue]):
        self.payload_values: Final[list[PayloadValue]] = payload_values

    def _eval_body(self, env: Environment) -> None:
        arr = []
        for payload_value in self.payload_values:
            payload_value.eval(env)
            arr.append(env.stack.pop())
        env.stack.append(arr)
