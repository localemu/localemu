import abc
from typing import Any

from localemu.services.stepfunctions.asl.eval.environment import Environment
from localemu.utils.objects import SubtypesInstanceManager


class Operator(abc.ABC, SubtypesInstanceManager):
    @staticmethod
    @abc.abstractmethod
    def eval(env: Environment, value: Any) -> None:
        pass
