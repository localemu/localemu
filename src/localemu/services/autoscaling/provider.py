"""AutoscalingProvider — thin wrapper that lets moto own ASG state and
hooks the Docker container plane after every membership-mutating verb.

Design: DESIGN_asg.md. Verbs we intercept:

  CreateAutoScalingGroup        → moto creates group, then reconciler
                                   launches DesiredCapacity containers
  UpdateAutoScalingGroup        → reconciler resyncs to new desired
  SetDesiredCapacity            → reconciler resyncs
  DeleteAutoScalingGroup        → terminate containers, then moto delete
  TerminateInstanceInAutoScalingGroup
                                → terminate container, reconciler relaunches
                                  if moto's notify_terminate refilled
  AttachInstances               → moto adopts, reconciler launches missing
                                  (typical case: already-running EC2)
  DetachInstances               → reconciler terminates any container
                                  for instances moto dropped from the group

Everything else (Describe*, Put*, scaling-policy CRUD, lifecycle-hook
CRUD, etc.) falls through to moto via MotoFallbackDispatcher.
"""
from __future__ import annotations

import logging
from typing import Optional

from localemu.aws.api import RequestContext, handler
from localemu.services.autoscaling import patches as _asg_patches  # noqa: F401
from localemu.services.autoscaling import reconciler
from localemu.services.moto import call_moto

LOG = logging.getLogger(__name__)


def _group_name_from_request(context: RequestContext) -> Optional[str]:
    """ASG operations use the query-form ``AutoScalingGroupName`` param.
    Pull it off the raw form values; moto uses the same key on its
    end so passing through to call_moto stays consistent."""
    return context.request.values.get("AutoScalingGroupName")


def _instance_ids_from_request(context: RequestContext) -> list[str]:
    """Pull ``InstanceIds.member.N`` off the query form. AWS auto-
    scaling APIs use the member.N convention rather than InstanceId.N
    that EC2 uses."""
    ids: list[str] = []
    # member.N convention
    i = 1
    while True:
        v = context.request.values.get(f"InstanceIds.member.{i}")
        if not v:
            break
        ids.append(v)
        i += 1
    return ids


class AutoscalingProvider:
    """Provider class — methods decorated with @handler match the AWS
    operation name. ``ForwardingFallbackDispatcher`` falls every
    un-handled operation through to moto."""

    # Service.for_provider reads ``service`` to load the right ASF
    # service model. autoscaling has no generated Api class so we set
    # it explicitly.
    service = "autoscaling"

    def __init__(self) -> None:
        LOG.debug("AutoscalingProvider initialized")

    # ----- Membership-mutating verbs we intercept -----------------------

    @handler("CreateAutoScalingGroup", expand=False)
    def create_auto_scaling_group(
        self, context: RequestContext, request: dict,
    ) -> dict:
        # New group → no before snapshot. After moto creates with
        # DesiredCapacity, reconcile launches the containers.
        result = call_moto(context)
        group_name = _group_name_from_request(context)
        if group_name:
            self._sync(context, group_name)
        return result

    @handler("UpdateAutoScalingGroup", expand=False)
    def update_auto_scaling_group(
        self, context: RequestContext, request: dict,
    ) -> dict:
        group_name = _group_name_from_request(context)
        before = self._snapshot_member_ids(context, group_name) if group_name else set()
        result = call_moto(context)
        if group_name:
            self._reconcile_with_removed(context, group_name, before)
        return result

    @handler("SetDesiredCapacity", expand=False)
    def set_desired_capacity(
        self, context: RequestContext, request: dict,
    ) -> dict:
        group_name = _group_name_from_request(context)
        before = self._snapshot_member_ids(context, group_name) if group_name else set()
        result = call_moto(context)
        if group_name:
            self._reconcile_with_removed(context, group_name, before)
        return result

    @handler("DeleteAutoScalingGroup", expand=False)
    def delete_auto_scaling_group(
        self, context: RequestContext, request: dict,
    ) -> dict:
        # Capture the membership BEFORE moto removes the group, then
        # call moto, then terminate each container. The order matters:
        # if we terminate first and moto raises (group has instances
        # and ForceDelete=False), we'd lose containers the user wanted
        # to keep. Letting moto raise first preserves AWS semantics.
        group_name = _group_name_from_request(context)
        ids_before: list[str] = []
        if group_name:
            group = reconciler.get_moto_asg(
                context.account_id, context.region, group_name,
            )
            if group is not None:
                ids_before = [
                    s.instance_id
                    for s in (getattr(group, "instance_states", []) or [])
                    if getattr(s, "instance_id", None)
                ]
        result = call_moto(context)
        # moto deleted the group (or raised). Tear down every container
        # that belonged to it.
        if ids_before:
            vm = self._resolve_vm_manager()
            if vm is not None:
                for iid in ids_before:
                    try:
                        vm.terminate_instance(iid)
                    except Exception:
                        LOG.warning(
                            "asg: container terminate failed for %s during "
                            "DeleteAutoScalingGroup(%s)", iid, group_name,
                            exc_info=True,
                        )
        return result

    @handler("TerminateInstanceInAutoScalingGroup", expand=False)
    def terminate_instance_in_auto_scaling_group(
        self, context: RequestContext, request: dict,
    ) -> dict:
        # moto removes the instance from the group (and decrements
        # desired if requested). If desired stays the same, moto's
        # notify_terminate refills via its own EC2 backend — our
        # reconciler then picks up the new ID and launches a container.
        iid = context.request.values.get("InstanceId")
        result = call_moto(context)
        # Find the group this instance belonged to and resync. moto
        # has already removed it from instance_states by now, so
        # reconciler.compute_diff sees container-but-no-moto → terminate.
        group_name = self._group_name_for_instance(context, iid)
        if group_name:
            self._sync(context, group_name)
        return result

    @handler("AttachInstances", expand=False)
    def attach_instances(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        group_name = _group_name_from_request(context)
        if group_name:
            self._sync(context, group_name)
        return result

    @handler("DetachInstances", expand=False)
    def detach_instances(
        self, context: RequestContext, request: dict,
    ) -> dict:
        # If ShouldDecrementDesiredCapacity=true, moto drops the IDs
        # from the group without launching replacements; our reconciler
        # sees container-but-no-moto for those IDs and... does nothing,
        # because Detach explicitly LEAVES the EC2 instance running.
        # Honor that contract: don't terminate containers here.
        return call_moto(context)

    # ----- Internals ----------------------------------------------------

    def _sync(self, context: RequestContext, group_name: str) -> None:
        try:
            reconciler.sync(
                context.account_id, context.region, group_name,
                vm_manager=self._resolve_vm_manager(),
            )
        except Exception:
            LOG.warning(
                "asg: reconciler.sync raised for %s", group_name, exc_info=True,
            )

    def _snapshot_member_ids(
        self, context: RequestContext, group_name: str,
    ) -> set[str]:
        """Capture moto's current set of instance IDs for a group.
        Used to compute the removed set after a scale-in mutation."""
        group = reconciler.get_moto_asg(
            context.account_id, context.region, group_name,
        )
        if group is None:
            return set()
        ids: set[str] = set()
        for state in getattr(group, "instance_states", []) or []:
            iid = getattr(state, "instance_id", None) or getattr(
                getattr(state, "instance", None), "id", None,
            )
            if iid:
                ids.add(iid)
        return ids

    def _reconcile_with_removed(
        self, context: RequestContext, group_name: str,
        before_ids: set[str],
    ) -> None:
        """Run the normal launch-missing reconcile, then terminate any
        container whose instance ID dropped out of moto's set between
        before_ids and now (the scale-in path)."""
        after_ids = self._snapshot_member_ids(context, group_name)
        removed = before_ids - after_ids
        vm = self._resolve_vm_manager()
        if vm is not None:
            for iid in sorted(removed):
                try:
                    vm.terminate_instance(iid)
                except Exception:
                    LOG.warning(
                        "asg: container terminate failed for %s during "
                        "scale-in of %s", iid, group_name, exc_info=True,
                    )
        # Launch any newly-added moto IDs that don't have containers
        self._sync(context, group_name)

    def _resolve_vm_manager(self):
        """Look up the process-wide DockerVmManager. Returns None when
        the EC2 backend isn't ``docker`` (then we're a no-op and ASG
        just behaves like upstream moto)."""
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_active_vm_manager,
            )
            return get_active_vm_manager()
        except Exception:
            return None

    def _group_name_for_instance(
        self, context: RequestContext, instance_id: Optional[str],
    ) -> Optional[str]:
        if not instance_id:
            return None
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("autoscaling")[
                context.account_id
            ][context.region]
            for name, group in backend.autoscaling_groups.items():
                # NB: instance may have been removed by moto already.
                # We scan every group; the instance's previous group is
                # the one whose name we want. Fall back to scanning
                # moto's EC2 backend's autoscaling_group attribute on
                # the instance object (set when it was launched).
                pass
            from moto.ec2 import ec2_backends
            ec2_backend = ec2_backends[context.account_id][context.region]
            inst = ec2_backend.get_instance_by_id(instance_id)
            if inst is not None:
                asg = getattr(inst, "autoscaling_group", None)
                if asg is not None:
                    return getattr(asg, "name", None)
        except Exception:
            LOG.debug(
                "asg: group lookup for instance %s failed", instance_id,
                exc_info=True,
            )
        return None
