import copy

from localemu.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localemu.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localemu.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localemu.services.stepfunctions.asl.eval.environment import Environment
from localemu.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localemu.services.stepfunctions.local_mocking.mock_config import (
    LocalMockedResponse,
    LocalMockedResponseReturn,
    LocalMockedResponseThrow,
)


def _eval_mocked_response_throw(
    env: Environment, mocked_response: LocalMockedResponseThrow
) -> None:
    task_failed_event_details = TaskFailedEventDetails(
        error=mocked_response.error, cause=mocked_response.cause
    )
    error_name = CustomErrorName(mocked_response.error)
    failure_event = FailureEvent(
        env=env,
        error_name=error_name,
        event_type=HistoryEventType.TaskFailed,
        event_details=EventDetails(taskFailedEventDetails=task_failed_event_details),
    )
    raise FailureEventException(failure_event=failure_event)


def _eval_mocked_response_return(
    env: Environment, mocked_response: LocalMockedResponseReturn
) -> None:
    payload_copy = copy.deepcopy(mocked_response.payload)
    env.stack.append(payload_copy)


def eval_local_mocked_response(env: Environment, mocked_response: LocalMockedResponse) -> None:
    if isinstance(mocked_response, LocalMockedResponseReturn):
        _eval_mocked_response_return(env=env, mocked_response=mocked_response)
    elif isinstance(mocked_response, LocalMockedResponseThrow):
        _eval_mocked_response_throw(env=env, mocked_response=mocked_response)
    else:
        raise RuntimeError(f"Invalid MockedResponse type '{type(mocked_response)}'")
