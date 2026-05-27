import abc

from localemu.aws.api.lambda_ import Arn
from localemu.services.lambda_.invocation.execution_environment import ExecutionEnvironment

DEFAULT_LDM_TIMEOUT_SECONDS: int = 3_600
IS_LDM_ENABLED: bool = False


class LDMProvisioner(abc.ABC):
    @abc.abstractmethod
    def get_execution_environment(
        self, qualified_lambda_arn: Arn, user_agent: str | None
    ) -> ExecutionEnvironment | None: ...
