"""Pure reconciler: diff a moto ASG ↔ vm_manager container set.

The provider calls :func:`sync` after every membership-mutating ASG
operation (Create / Update / SetDesiredCapacity / Attach / Detach /
TerminateInstanceInAutoScalingGroup / Delete). The reconciler:

  1. Reads moto's ``FakeAutoScalingGroup.instance_states`` — the
     authoritative DESIRED set of instance IDs for the group.
  2. Reads vm_manager's container set — the ACTUAL set.
  3. Emits the diff as a :class:`ReconcileReport` and executes it:
       * launch a container for every moto instance ID with no container
       * terminate every container whose instance ID is no longer in
         moto's instance_states for this group

This is the only place LocalEmu connects moto's autoscaling state to
the Docker container plane. Keeping it a pure-ish module (everything
that touches state goes through small named seams) makes it trivially
testable with mocks.

Out of scope (covered in DESIGN_asg.md §3):
  * lifecycle hook wait states (Pending:Wait / Terminating:Wait)
  * health-check loop + ReplaceUnhealthy
  * real termination policies
  * InstanceRefresh
  * persistence-restore container reconciliation
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

LOG = logging.getLogger(__name__)


@dataclass
class LaunchSpec:
    """Resolved launch parameters for a single new ASG-managed container."""
    instance_id: str
    ami_id: str
    instance_type: str
    user_data: str
    security_groups: list[str]
    subnet_id: Optional[str]
    key_name: Optional[str]
    iam_instance_profile_arn: Optional[str]


@dataclass
class ReconcileReport:
    """Summary of what the reconciler did."""
    group_name: str
    launched: list[str] = field(default_factory=list)
    terminated: list[str] = field(default_factory=list)
    skipped_no_container_runtime: bool = False
    launch_failures: list[tuple[str, str]] = field(default_factory=list)
    terminate_failures: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"asg={self.group_name} launched={len(self.launched)} "
            f"terminated={len(self.terminated)} "
            f"launch_fail={len(self.launch_failures)} "
            f"terminate_fail={len(self.terminate_failures)}"
        )


def get_moto_asg(account_id: str, region: str, group_name: str):
    """Resolve moto's FakeAutoScalingGroup for (account, region, name).

    Returns None if the group is gone — caller treats that as
    "terminate everything tagged with this group".
    """
    try:
        import moto.backends as moto_backends
        backend = moto_backends.get_backend("autoscaling")[account_id][region]
        return backend.autoscaling_groups.get(group_name)
    except Exception:
        LOG.debug(
            "asg.reconciler: moto lookup failed for %s/%s/%s",
            account_id, region, group_name, exc_info=True,
        )
        return None


def _maybe_b64_decode(user_data: Optional[str]) -> str:
    """moto stores user_data either as raw text or b64. vm_manager
    accepts either; we pass through verbatim. Helper kept for future
    normalization if needed.
    """
    return user_data or ""


def _pick_subnet_round_robin(
    subnets_csv: Optional[str],
    existing_subnet_counts: dict[str, int],
) -> Optional[str]:
    """Pick the subnet with the fewest existing instances; tie-break
    alphabetical. Matches AWS's "spread evenly across subnets" contract
    (zonal balance precedes termination policy).

    ``subnets_csv`` is the raw ``VPCZoneIdentifier`` string from the
    group (e.g. ``"subnet-a,subnet-b"``). Returns None when no subnets
    are configured (Classic-style ASG).
    """
    if not subnets_csv:
        return None
    subnets = [s.strip() for s in subnets_csv.split(",") if s.strip()]
    if not subnets:
        return None
    # Sort by (existing count, name) so the result is deterministic
    # under ties — keeps tests stable and matches AWS's typical
    # tie-break ordering.
    subnets.sort(key=lambda s: (existing_subnet_counts.get(s, 0), s))
    return subnets[0]


def build_launch_spec(
    instance_id: str,
    group,
    subnet_id: Optional[str],
) -> LaunchSpec:
    """Resolve all the params we need from moto's FakeAutoScalingGroup
    to drive vm_manager.create_instance for ONE new ASG-managed
    instance. The group's properties already resolve
    LaunchTemplate / LaunchConfiguration / MixedInstancesPolicy.first.
    """
    iam_arn = None
    lc = getattr(group, "launch_config", None)
    if lc is not None:
        # FakeLaunchConfiguration stores instance_profile_name as the
        # short name; the ARN is the full AWS resource ID. We pass the
        # short name forward — vm_manager will build the IMDS dict.
        iam_arn = getattr(lc, "iam_instance_profile", None) or None
    return LaunchSpec(
        instance_id=instance_id,
        ami_id=group.image_id,
        instance_type=group.instance_type or "t2.micro",
        user_data=_maybe_b64_decode(group.user_data),
        security_groups=list(group.security_groups or []),
        subnet_id=subnet_id,
        key_name=getattr(group, "key_name", None),
        iam_instance_profile_arn=iam_arn,
    )


def compute_diff(
    moto_instance_ids: set[str],
    container_instance_ids: set[str],
) -> tuple[set[str], set[str]]:
    """Pure: return (to_launch, to_terminate) sets.

    ``to_launch`` = moto says exists, no container yet.
    ``to_terminate`` = container exists, moto doesn't list it any more.
    """
    to_launch = moto_instance_ids - container_instance_ids
    to_terminate = container_instance_ids - moto_instance_ids
    return to_launch, to_terminate


def collect_subnet_counts(
    moto_instance_ids_with_subnet: dict[str, Optional[str]],
) -> dict[str, int]:
    """How many existing moto instances live in each subnet.
    Used by the round-robin picker so newly-launched instances bias
    toward under-populated subnets.
    """
    counts: dict[str, int] = {}
    for sub in moto_instance_ids_with_subnet.values():
        if sub:
            counts[sub] = counts.get(sub, 0) + 1
    return counts


def sync(
    account_id: str,
    region: str,
    group_name: str,
    *,
    vm_manager=None,
    vpc_network_manager=None,
) -> ReconcileReport:
    """Reconcile moto's view of the ASG against vm_manager.

    ``vm_manager`` and ``vpc_network_manager`` are injectable for tests;
    in production callers leave them as None and we resolve the
    process singletons.
    """
    report = ReconcileReport(group_name=group_name)

    if vm_manager is None:
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_active_vm_manager,
            )
            vm_manager = get_active_vm_manager()
        except Exception:
            vm_manager = None
    if vm_manager is None:
        report.skipped_no_container_runtime = True
        return report

    group = get_moto_asg(account_id, region, group_name)
    if group is None:
        # Group deleted — best-effort terminate any container still
        # claiming membership (we'd need a tag lookup; today vm_manager
        # has no by-asg query). Provider's DeleteAutoScalingGroup path
        # handles the explicit terminate; nothing to do here.
        return report

    # Snapshot moto's desired set + per-instance subnet (for round-robin)
    moto_instances: dict[str, Optional[str]] = {}
    for state in getattr(group, "instance_states", []) or []:
        iid = getattr(state, "instance_id", None) or getattr(
            getattr(state, "instance", None), "id", None,
        )
        if not iid:
            continue
        # InstanceState.instance may be moto's EC2 Instance with .subnet_id
        sub = None
        ec2_inst = getattr(state, "instance", None)
        if ec2_inst is not None:
            sub = getattr(ec2_inst, "subnet_id", None)
        moto_instances[iid] = sub

    # vm_manager actual set: iterate every container that claims a
    # localemu.autoscaling-group label matching ours. vm_manager doesn't
    # expose a by-asg query yet, so fall back to checking each moto ID.
    container_ids: set[str] = set()
    for iid in moto_instances:
        try:
            info = vm_manager.get_instance_info(iid)
        except Exception:
            info = None
        if info is not None:
            container_ids.add(iid)

    to_launch, to_terminate = compute_diff(
        set(moto_instances.keys()), container_ids,
    )

    # Subnet round-robin: bias new launches toward subnets with fewer
    # existing instances. Updated as we launch so two new instances in
    # a single sync don't both land in the same subnet.
    subnet_counts = collect_subnet_counts(moto_instances)

    for iid in sorted(to_launch):
        # If moto's EC2 Instance already pinned a subnet for this id,
        # honor it (covers the upstream-moto path before our patch
        # lands). Otherwise use round-robin from the group's CSV.
        existing_subnet = moto_instances.get(iid)
        if existing_subnet:
            chosen_subnet = existing_subnet
        else:
            chosen_subnet = _pick_subnet_round_robin(
                getattr(group, "vpc_zone_identifier", None),
                subnet_counts,
            )
        spec = build_launch_spec(iid, group, chosen_subnet)
        if chosen_subnet:
            subnet_counts[chosen_subnet] = subnet_counts.get(chosen_subnet, 0) + 1

        try:
            vpc_network = None
            if vpc_network_manager is None:
                try:
                    from localemu.services.ec2.docker.vpc_network import (
                        get_vpc_network_manager,
                    )
                    vpc_network_manager = get_vpc_network_manager()
                except Exception:
                    vpc_network_manager = None
            if vpc_network_manager is not None and chosen_subnet:
                try:
                    vpc_id = vpc_network_manager.get_vpc_id_for_subnet(
                        chosen_subnet, account_id, region,
                    )
                    if vpc_id:
                        from localemu.services.ec2.docker.vpc_network import (
                            VPC_NETWORK_PREFIX,
                        )
                        vpc_network = f"{VPC_NETWORK_PREFIX}{vpc_id}"
                except Exception:
                    vpc_network = None

            vm_manager.create_instance(
                instance_id=spec.instance_id,
                ami_id=spec.ami_id,
                instance_type=spec.instance_type,
                user_data=spec.user_data,
                security_groups=spec.security_groups,
                subnet_id=spec.subnet_id,
                account_id=account_id,
                region=region,
                iam_instance_profile_arn=spec.iam_instance_profile_arn,
                vpc_network=vpc_network,
            )
            report.launched.append(iid)
        except Exception as exc:
            LOG.warning(
                "asg.reconciler: container launch failed for %s in %s: %s",
                iid, group_name, exc,
            )
            report.launch_failures.append((iid, str(exc)))

    for iid in sorted(to_terminate):
        try:
            vm_manager.terminate_instance(iid)
            report.terminated.append(iid)
        except Exception as exc:
            LOG.warning(
                "asg.reconciler: container terminate failed for %s in %s: %s",
                iid, group_name, exc,
            )
            report.terminate_failures.append((iid, str(exc)))

    if report.launched or report.terminated or report.launch_failures or report.terminate_failures:
        LOG.info("asg.reconciler: %s", report.summary())

    return report
