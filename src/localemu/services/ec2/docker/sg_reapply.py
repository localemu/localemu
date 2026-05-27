"""Event-driven Security Group re-apply .

Previously, AuthorizeSecurityGroupIngress / RevokeSecurityGroupIngress /
ModifyInstanceAttribute only updated moto state; the iptables chains
inside already-running EC2 containers were never refreshed. SG rule
changes were effectively invisible until the instance was re-created.

This module wires the EC2 control-plane events through to the data
plane:

  - ``record_instance_sgs`` is called at instance creation (and on
    ``ModifyInstanceAttribute``) so we always know which SGs are
    attached to which container.
  - ``rebuild_mapping_from_docker`` reconstructs the in-memory mapping
    after LocalEmu restart by walking container labels
    (``localemu.sg-ids``, ``localemu.account-id``, ``localemu.region``).
  - ``reapply_sg_for_sg_id`` is the hook for authorize/revoke — it
    walks every instance that has that SG attached and re-runs
    ``apply_sg_to_container``.
  - ``reapply_sg_for_instance`` is the hook for
    ``ModifyInstanceAttribute`` — it records the new SG set and
    re-applies immediately.

All failures are best-effort and logged; we never raise into the API
handler (AWS parity: the API says "rule authorized", the data-plane
eventually reflects it).
"""

from __future__ import annotations

import logging
import threading

from localemu.services.ec2.docker.sg_iptables import apply_sg_to_container
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# In-memory mapping: (account_id, region, instance_id) -> [sg_id, ...]
# Populated at instance create time, refreshed on ModifyInstanceAttribute,
# rebuilt from container labels on cold start.
_sg_mapping: dict[tuple[str, str, str], list[str]] = {}
_sg_mapping_lock = threading.Lock()


def record_instance_sgs(
    account_id: str, region: str, instance_id: str, sg_ids: list[str],
) -> None:
    """Record which SGs are attached to an instance.

    Called from ``DockerVmManager.create_instance`` and from
    ``reapply_sg_for_instance`` when ModifyInstanceAttribute updates
    the group set. Idempotent (last-writer wins).
    """
    with _sg_mapping_lock:
        _sg_mapping[(account_id, region, instance_id)] = list(sg_ids)


def forget_instance(account_id: str, region: str, instance_id: str) -> None:
    """Drop an instance from the mapping — call at terminate_instance."""
    with _sg_mapping_lock:
        _sg_mapping.pop((account_id, region, instance_id), None)


def rebuild_mapping_from_docker() -> None:
    """Reconstruct ``_sg_mapping`` from EC2 container labels.

    Called on cold start / persistence restore: the in-memory dict dies
    with the process but the labels are written at container create
    time and survive ``docker stop``/``docker start``.
    """
    try:
        containers = DOCKER_CLIENT.list_containers(
            filter=["label=localemu.service=ec2"], all=True,
        )
    except Exception as exc:
        LOG.debug("rebuild_mapping_from_docker: list_containers failed: %s", exc)
        return

    count = 0
    for c in containers:
        labels = c.get("labels") or {}
        instance_id = labels.get("localemu.instance-id")
        account_id = labels.get("localemu.account-id")
        region = labels.get("localemu.region")
        if not (instance_id and account_id and region):
            continue
        raw = labels.get("localemu.sg-ids") or ""
        sg_ids = [s for s in raw.split(",") if s]
        with _sg_mapping_lock:
            _sg_mapping[(account_id, region, instance_id)] = sg_ids
        count += 1
    if count:
        LOG.info("sg_reapply: rebuilt mapping for %d EC2 instances from labels", count)


def _container_name(instance_id: str) -> str:
    """Docker container name convention used by DockerVmManager."""
    return f"localemu-ec2-{instance_id}"


def reapply_sg_for_sg_id(sg_id: str, account_id: str, region: str) -> int:
    """Re-apply SG iptables to every instance that has this SG attached.

    Called after a successful AuthorizeSecurityGroupIngress /
    AuthorizeSecurityGroupEgress / RevokeSecurityGroupIngress /
    RevokeSecurityGroupEgress in that (account, region).

    Returns the number of instances that successfully re-applied. Logs
    a WARNING per failed instance but never raises.
    """
    with _sg_mapping_lock:
        targets = [
            (iid, list(sgs))
            for (acct, rgn, iid), sgs in _sg_mapping.items()
            if acct == account_id and rgn == region and sg_id in sgs
        ]

    if not targets:
        LOG.debug(
            "sg_reapply: no running instances with sg=%s in %s/%s",
            sg_id, account_id, region,
        )
        return 0

    applied = 0
    for instance_id, sg_ids in targets:
        try:
            if apply_sg_to_container(
                _container_name(instance_id), sg_ids, account_id, region,
            ):
                applied += 1
            else:
                LOG.warning(
                    "sg_reapply: instance %s SG re-apply returned False — "
                    "container may be in fail-closed DROP state",
                    instance_id,
                )
        except Exception:
            LOG.exception(
                "sg_reapply: unexpected error re-applying SG to %s", instance_id,
            )

    LOG.info(
        "sg_reapply: sg=%s %s/%s applied to %d/%d instances",
        sg_id, account_id, region, applied, len(targets),
    )
    return applied


def reapply_sg_for_instance(
    instance_id: str, account_id: str, region: str, new_sg_ids: list[str],
) -> bool:
    """Instance's attached SG set changed (``ModifyInstanceAttribute``).

    Records the new set, then re-applies iptables immediately.
    """
    record_instance_sgs(account_id, region, instance_id, new_sg_ids)
    try:
        return apply_sg_to_container(
            _container_name(instance_id), new_sg_ids, account_id, region,
        )
    except Exception:
        LOG.exception(
            "sg_reapply: unexpected error re-applying SG to %s after ModifyInstanceAttribute",
            instance_id,
        )
        return False


def _sg_rule_references(rule, sg_ids: set[str]) -> bool:
    """True if this moto SecurityGroupRule references any of sg_ids."""
    singular = getattr(rule, "source_group", None) or {}
    if isinstance(singular, dict) and singular.get("GroupId") in sg_ids:
        return True
    plural = getattr(rule, "source_groups", None) or []
    for ref in plural:
        gid = (
            ref.get("GroupId") if isinstance(ref, dict)
            else getattr(ref, "group_id", None)
        )
        if gid in sg_ids:
            return True
    return False


def reapply_sgs_referencing(
    changed_sg_ids: list[str], account_id: str, region: str,
) -> int:
    """Reapply every SG whose rules reference any of ``changed_sg_ids``.

    The membership of a referenced SG is dynamic: when a new ENI
    joins (or leaves) sg-X, every other SG with a rule of the form
    "allow ... from sg-X" must have its iptables rebuilt so the
    new member's IP appears (or disappears) in the ACCEPT list.

    Called from the EC2 vm_manager right after a fresh ENI is
    registered in the AddressIndex, so late-join members reach
    services that allow their SG.

    Returns the number of (referencing_sg) reapplies that ran.
    """
    if not changed_sg_ids:
        return 0
    sg_id_set = set(changed_sg_ids)
    try:
        import moto.backends as moto_backends
        backend = moto_backends.get_backend("ec2")[account_id][region]
    except Exception:
        LOG.debug("reapply_sgs_referencing: moto backend lookup failed",
                  exc_info=True)
        return 0

    referencing: set[str] = set()
    try:
        for sg in backend.describe_security_groups():
            for rule in list(getattr(sg, "ingress_rules", []) or []) + \
                        list(getattr(sg, "egress_rules", []) or []):
                if _sg_rule_references(rule, sg_id_set):
                    referencing.add(sg.id)
                    break
    except Exception:
        LOG.debug("reapply_sgs_referencing: iterate SGs failed",
                  exc_info=True)
        return 0

    if not referencing:
        return 0

    applied = 0
    for ref_sg in referencing:
        try:
            applied += reapply_sg_for_sg_id(ref_sg, account_id, region)
        except Exception:
            LOG.exception(
                "reapply_sgs_referencing: reapply %s failed", ref_sg,
            )
    LOG.info(
        "reapply_sgs_referencing: changed=%s referencers=%d applied=%d",
        sorted(sg_id_set), len(referencing), applied,
    )
    return applied
