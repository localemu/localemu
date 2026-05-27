"""moto autoscaling patches: round-robin subnet distribution.

Upstream moto's ``FakeAutoScalingGroup.replace_autoscaling_group_instances``
picks ``vpc_zone_identifier.split(",")[0]`` — the FIRST subnet — and
fires a single ``ec2_backend.run_instances(count_needed, subnet_id=...)``
call. The whole batch lands in one subnet, breaking the AWS contract
that says ASG spreads instances evenly across VPCZoneIdentifier
subnets (zonal balance is the highest-priority scale-in input).

The patch replaces the single batch call with one ``run_instances``
call per new instance, picking the subnet with the fewest existing
ASG members each time (round-robin with under-population bias). The
overall semantics — moto stores the InstanceStates, tags propagate,
ELBs get the registrations — are preserved unchanged.

The reconciler in :mod:`localemu.services.autoscaling.reconciler`
then reads moto's correctly-pinned ``Instance.subnet_id`` for each
new container.
"""
from __future__ import annotations

import logging
import random

from moto.autoscaling.models import FakeAutoScalingGroup, InstanceState

from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)


def _round_robin_subnet_choice(
    subnets: list[str], existing_per_subnet: dict[str, int],
) -> str:
    """Pick the subnet with the fewest existing instances; tie-break
    alphabetical for determinism. Mirrors
    ``reconciler._pick_subnet_round_robin``.
    """
    return sorted(
        subnets, key=lambda s: (existing_per_subnet.get(s, 0), s),
    )[0]


@patch(
    target=FakeAutoScalingGroup.replace_autoscaling_group_instances,
    pass_target=True,
)
def _replace_autoscaling_group_instances_round_robin(
    fn, self, count_needed, propagated_tags,
):
    """Replacement implementation that spreads new instances across
    every subnet in vpc_zone_identifier instead of jamming them all
    into the first one."""
    if not self.vpc_zone_identifier:
        # Classic / EC2-Classic — fall back to upstream behavior.
        return fn(self, count_needed, propagated_tags)

    subnets = [s.strip() for s in self.vpc_zone_identifier.split(",") if s.strip()]
    if len(subnets) <= 1:
        # Single subnet — upstream is already correct.
        return fn(self, count_needed, propagated_tags)

    propagated_tags["aws:autoscaling:groupName"] = self.name
    propagated_tags.update(self.instance_tags)
    associate_public_ip = (
        self.launch_config.associate_public_ip_address
        if self.launch_config
        else None
    )
    launch_template = None
    if self.ec2_launch_template:
        if self.ec2_launch_template.id:
            launch_template = {"LaunchTemplateId": self.ec2_launch_template.id}
        elif self.ec2_launch_template.name:
            launch_template = {"LaunchTemplateName": self.ec2_launch_template.name}

    # Seed the per-subnet counts from existing instances so a scale-out
    # biases toward the under-populated subnet rather than blindly
    # repeating the alphabetical order.
    existing: dict[str, int] = {s: 0 for s in subnets}
    for state in self.instance_states:
        sub = getattr(state.instance, "subnet_id", None)
        if sub in existing:
            existing[sub] += 1

    for _ in range(count_needed):
        chosen_subnet = _round_robin_subnet_choice(subnets, existing)
        existing[chosen_subnet] += 1
        reservation = self.autoscaling_backend.ec2_backend.run_instances(
            self.image_id,
            1,
            self.user_data,
            self.security_groups,
            instance_type=self.instance_type,
            tags={"instance": propagated_tags},
            placement=random.choice(self.availability_zones),
            launch_config=self.launch_config,
            launch_template=launch_template,
            is_instance_type_default=False,
            associate_public_ip=associate_public_ip,
            subnet_id=chosen_subnet,
        )
        for instance in reservation.instances:
            instance.autoscaling_group = self
            self.instance_states.append(
                InstanceState(
                    instance,
                    protected_from_scale_in=self.new_instances_protected_from_scale_in,
                )
            )


def apply_asg_patches() -> None:
    """No-op; importing this module triggers the @patch decorators."""
    LOG.debug("autoscaling: applied moto subnet round-robin patch")
