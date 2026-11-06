"""Cross-account RAM resource-share visibility helpers.

RAM itself (moto passthrough) only ever records share state - no other
service consults it. This module is the one piece that makes a shared
resource actually show up for the account it was shared with, scoped
deliberately to EC2 subnets only (goat-bugs item 10, Phase 1 of
/tmp/le-ram-resource-shares-design.md).

Explicitly out of scope, per all three independent reviews of that design:
  - OU/Organization-level share principals (string match against the
    account ID only - an OU/Org principal naming that account indirectly
    is not resolved; doing so would need the same Organizations-ancestry
    walk ``_scp_denies`` does in ``iam_enforcement/evaluator.py``).
  - Every other RAM-shareable resource type (Glue, CodeBuild, License
    Manager, Network Manager, transit-gateway, prefix-list) - subnets are
    the only type with an existing native describe/enrich hook to extend.
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)

_SUBNET_RESOURCE_TYPE_MARKER = ":subnet/"


def get_shared_subnet_arns(account_id: str, region: str) -> list[tuple[str, str]]:
    """Return ``(subnet_arn, owning_account_id)`` pairs for every subnet
    actively shared with ``account_id`` in ``region`` via RAM.

    A share makes its resources visible to a principal the moment the
    share and the association are ACTIVE - moto has no pending/invitation
    state to model (confirmed: no ``ResourceShareInvitation`` type exists),
    so there is no accept/reject step to wait on here, unlike real AWS.
    """
    try:
        from moto.ram.models import ram_backends
    except Exception:
        LOG.debug("moto RAM backend unavailable", exc_info=True)
        return []

    shared: list[tuple[str, str]] = []
    try:
        # ram_backends is a BackendDict: {owning_account_id: {region: backend}}.
        # Every account's shares must be scanned - a share "for account_id"
        # is created and owned by some OTHER account, never account_id's own.
        for owning_account_id, region_map in dict(ram_backends).items():
            if owning_account_id == account_id:
                continue
            backend = region_map.get(region)
            if backend is None:
                continue
            for share in backend.resource_shares:
                if share.status != "ACTIVE":
                    continue
                if account_id not in share.principals:
                    continue
                for resource_arn in share.resource_arns:
                    if _SUBNET_RESOURCE_TYPE_MARKER in resource_arn:
                        shared.append((resource_arn, owning_account_id))
    except Exception:
        LOG.debug(
            "Failed to resolve RAM-shared subnets for account %s region %s",
            account_id, region, exc_info=True,
        )
        return []

    return shared


def _render_subnet(subnet) -> dict:
    """Render a moto ``Subnet`` model into the same PascalCase shape
    ``DescribeSubnets`` already returns for a caller's own subnets (see
    the field names ``ec2/provider.py::describe_subnets`` itself reads:
    ``SubnetId``, ``AvailabilityZone``, ...). Deliberately a bounded,
    explicit field set rather than full 1:1 parity with AWS's complete
    Subnet shape - everything a lab/test would realistically check
    (identity, CIDR, AZ, state, ownership, tags), not every obscure
    field (IPv6 associations, IPAM pool fields, etc.)."""
    return {
        "SubnetId": subnet.id,
        "VpcId": subnet.vpc_id,
        "CidrBlock": subnet.cidr_block,
        "AvailabilityZone": subnet.availability_zone,
        "AvailabilityZoneId": subnet.availability_zone_id,
        "State": subnet.state,
        "OwnerId": subnet.owner_id,
        "AvailableIpAddressCount": subnet._available_ip_addresses,
        "DefaultForAz": subnet.default_for_az,
        "MapPublicIpOnLaunch": subnet.map_public_ip_on_launch,
        "SubnetArn": subnet.arn,
        "Tags": subnet.get_tags(),
    }


def get_shared_subnets(account_id: str, region: str) -> list[dict]:
    """Return the full subnet dict (as ``DescribeSubnets`` would shape it)
    for every subnet shared with ``account_id`` in ``region``, read from
    the owning account's own EC2 backend.

    moto's subnet storage (``SubnetBackend.subnets``) is keyed by
    availability zone first, then subnet ID - NOT a flat dict keyed by
    subnet ID. ``backend.get_subnet(subnet_id)`` already handles that
    correctly (it scans every AZ), but raises ``InvalidSubnetIdError``
    instead of returning ``None`` for a miss, so that's caught here.
    """
    try:
        from moto.ec2.models import ec2_backends
    except Exception:
        LOG.debug("moto EC2 backend unavailable", exc_info=True)
        return []

    results: list[dict] = []
    for subnet_arn, owning_account_id in get_shared_subnet_arns(account_id, region):
        subnet_id = subnet_arn.rsplit("/", 1)[-1]
        try:
            owning_backend = ec2_backends[owning_account_id][region]
            subnet = owning_backend.get_subnet(subnet_id)
        except Exception:
            LOG.debug(
                "RAM-shared subnet %s (owner %s) could not be read",
                subnet_id, owning_account_id, exc_info=True,
            )
            continue
        try:
            results.append(_render_subnet(subnet))
        except Exception:
            LOG.debug("Failed to render RAM-shared subnet %s", subnet_id, exc_info=True)
    return results
