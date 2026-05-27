import logging

from moto.scheduler.models import EventBridgeSchedulerBackend, scheduler_backends

from localemu.aws.api.scheduler import SchedulerApi, ValidationException
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.scheduler.expression import (
    InvalidScheduleExpression,
    validate_schedule_expression,
)
from localemu.services.scheduler.job_scheduler import SchedulerJobScheduler
from localemu.state import StateVisitor
from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)


class SchedulerProvider(SchedulerApi, ServiceLifecycleHook):
    """LocalEmu provider for AWS EventBridge Scheduler.

    Control-plane verbs (create/update/delete/list...) flow through moto
    via the default dispatcher; this provider adds:

      * schedule-expression validation that matches AWS's accepted set
        (including ``rate(N seconds)`` which the original LocalStack
        port did not validate),
      * lifecycle hooks that start the polling thread on infra-start,
        stop it on infra-stop, and rebuild the in-memory job registry
        from moto state on every snapshot-load / state-reset, and
      * @patch hooks on create / update / delete / delete_group that
        keep the polling registry in sync with what the API caller
        has just changed.
    """

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(scheduler_backends)

    # -- lifecycle ------------------------------------------------------
    def on_before_start(self):
        SchedulerJobScheduler.start()

    def on_before_stop(self):
        SchedulerJobScheduler.shutdown()

    def on_after_state_load(self):
        SchedulerJobScheduler.instance().rebuild_from_backends()

    def on_before_state_reset(self):
        SchedulerJobScheduler.instance().clear_all()

    def on_after_state_reset(self):
        SchedulerJobScheduler.instance().rebuild_from_backends()


def _validate_or_raise(expr: str) -> None:
    try:
        validate_schedule_expression(expr)
    except InvalidScheduleExpression as e:
        raise ValidationException(str(e))


def _account_and_region(backend) -> tuple[str, str]:
    """Pull account_id + region off a moto scheduler backend instance.

    moto exposes both on the BaseBackend; we read them in one place so
    the per-verb patches don't each hard-code the attribute path.
    """
    return backend.account_id, backend.region_name


@patch(EventBridgeSchedulerBackend.create_schedule)
def create_schedule(fn, self, **kwargs):
    if schedule_expression := kwargs.get("schedule_expression"):
        _validate_or_raise(schedule_expression)
    schedule = fn(self, **kwargs)
    try:
        account_id, region = _account_and_region(self)
        SchedulerJobScheduler.start().add_schedule(schedule, account_id, region)
    except Exception:
        LOG.warning(
            "Failed to register schedule %s with polling thread",
            getattr(schedule, "arn", "?"), exc_info=True,
        )
    return schedule


@patch(EventBridgeSchedulerBackend.update_schedule)
def update_schedule(fn, self, **kwargs):
    # Re-validate on update — otherwise a malformed expression that
    # was valid on create but mutated on update would bypass the check.
    if schedule_expression := kwargs.get("schedule_expression"):
        _validate_or_raise(schedule_expression)
    schedule = fn(self, **kwargs)
    try:
        account_id, region = _account_and_region(self)
        scheduler_inst = SchedulerJobScheduler.start()
        scheduler_inst.remove_schedule(schedule.arn)
        scheduler_inst.add_schedule(schedule, account_id, region)
    except Exception:
        LOG.warning(
            "Failed to update schedule %s in polling thread",
            getattr(schedule, "arn", "?"), exc_info=True,
        )
    return schedule


@patch(EventBridgeSchedulerBackend.delete_schedule)
def delete_schedule(fn, self, group_name=None, name=None):
    # moto calls this positionally as ``delete_schedule(group_name, name)``;
    # accept both positional and keyword shapes so the wrapper signature
    # doesn't desync with whatever call site reached it.
    grp = group_name or "default"
    arn = None
    try:
        group = self.schedule_groups.get(grp)
        if group is not None:
            sched = group.schedules.get(name)
            if sched is not None:
                arn = sched.arn
    except Exception:
        arn = None
    result = fn(self, group_name=group_name, name=name)
    if arn:
        try:
            SchedulerJobScheduler.instance().remove_schedule(arn)
        except Exception:
            LOG.debug(
                "Failed to unregister deleted schedule %s from polling thread",
                arn, exc_info=True,
            )
    return result


@patch(EventBridgeSchedulerBackend.delete_schedule_group)
def delete_schedule_group(fn, self, name=None):
    group_name = name or "default"
    result = fn(self, name=name)
    try:
        account_id, region = _account_and_region(self)
        SchedulerJobScheduler.instance().remove_group(account_id, region, group_name)
    except Exception:
        LOG.debug(
            "Failed to unregister deleted schedule group %s", group_name, exc_info=True,
        )
    return result
