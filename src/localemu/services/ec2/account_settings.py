"""Account-region-scoped EC2 settings for features that AWS exposes as Get/Modify pairs.

Currently holds Snapshot Block Public Access and Serial Console Access. As more
EC2 account-level features come online (VPC Block Public Access options +
exclusions, EC2 Instance Connect Endpoints), they will join the same store so
account-region state lives in one place per service.

AWS exposes ``ManagedBy`` on these Get APIs to distinguish account-level state
from org-level declarative-policy state. LocalEmu emulates a single AWS account
in isolation, so ``ManagedBy`` is always ``account``.
"""

from __future__ import annotations

from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class Ec2AccountSettingsStore(BaseStore):
    """Per-account, per-region EC2 settings."""

    # Snapshot Block Public Access.
    # AWS docs: GetSnapshotBlockPublicAccessState returns
    #     { State, ManagedBy }
    # where State is one of "block-all-sharing", "block-new-sharing",
    # "unblocked". Default for a brand-new account is "unblocked".
    snapshot_bpa_state: str = LocalAttribute(default="unblocked")
    snapshot_bpa_managed_by: str = LocalAttribute(default="account")

    # EC2 Serial Console Access.
    # AWS docs: GetSerialConsoleAccessStatus returns
    #     { SerialConsoleAccessEnabled, ManagedBy }
    # Default disabled for a brand-new account.
    serial_console_enabled: bool = LocalAttribute(default=False)
    serial_console_managed_by: str = LocalAttribute(default="account")

    # VPC Block Public Access Options.
    # AWS docs: DescribeVpcBlockPublicAccessOptions returns
    #     { VpcBlockPublicAccessOptions: {
    #         AwsAccountId, AwsRegion, InternetGatewayBlockMode,
    #         State, ExclusionsAllowed, ManagedBy, LastUpdateTimestamp,
    #         Reason
    #     } }
    # Defaults for a brand-new account: ``InternetGatewayBlockMode`` is
    # ``off``, ``State`` is the literal string ``default-state`` (not
    # ``off`` - the State field is the management-transition state, not the
    # block mode), ``ExclusionsAllowed`` is ``allowed``.
    vpc_bpa_internet_gateway_block_mode: str = LocalAttribute(default="off")
    vpc_bpa_state: str = LocalAttribute(default="default-state")
    vpc_bpa_exclusions_allowed: str = LocalAttribute(default="allowed")
    vpc_bpa_managed_by: str = LocalAttribute(default="account")
    vpc_bpa_last_update_timestamp: float | None = LocalAttribute(default=None)

    # VPC BPA Exclusions keyed by ``vpcbpa-excl-<17-hex>``. Values are dicts
    # shaped like AWS's VpcBlockPublicAccessExclusion structure (mode,
    # resource ARN, state, timestamps, tags, etc.). See provider handlers
    # for the canonical write/read paths.
    vpc_bpa_exclusions: dict = LocalAttribute(default=dict)

    # EC2 Instance Connect Endpoints (EICE), keyed by ``eice-<17-hex>``.
    # Each value is the API-shaped Ec2InstanceConnectEndpoint dict
    # (subnet, VPC, security groups, IP-address-type, DNS, state,
    # timestamps, tags). The actual SSH tunnel is not emulated; the
    # endpoint serves as a metadata target so DescribeInstanceConnectEndpoints
    # returns realistic data for security scanners and IaC providers.
    instance_connect_endpoints: dict = LocalAttribute(default=dict)


# ``service_name="ec2"`` so RegionBundle accepts every real EC2 region; the
# persistence key in ``state.registry.NATIVE_STORES`` is the snapshot-file
# name ("ec2_account_settings") and is independent of this.
ec2_account_settings_stores = AccountRegionBundle("ec2", Ec2AccountSettingsStore)


# ---------- Data-plane query helpers (read-only) ----------


def get_vpc_bpa_mode(account_id: str, region: str) -> str:
    """The active InternetGatewayBlockMode for the given account-region.

    Returns one of ``off``, ``block-ingress``, ``block-bidirectional``. The
    EC2 docker layer reads this at instance start to decide whether to
    install link-local DROP rules on the IGW-facing interface.
    """
    return ec2_account_settings_stores[account_id][region].vpc_bpa_internet_gateway_block_mode


def is_instance_excluded_from_vpc_bpa(
    account_id: str, region: str, vpc_id: str | None, subnet_id: str | None
) -> bool:
    """Return True if there is an active (non-deleted) VPC BPA exclusion
    whose ResourceArn matches the instance's VPC ARN or subnet ARN.

    AWS treats a VPC-scoped exclusion as implicitly covering all of the
    VPC's subnets; a subnet-scoped exclusion covers only that subnet.
    """
    store = ec2_account_settings_stores[account_id][region]
    subnet_arn = (
        f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"
        if subnet_id
        else None
    )
    vpc_arn = (
        f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}" if vpc_id else None
    )
    for excl in store.vpc_bpa_exclusions.values():
        if excl.get("State") == "delete-complete":
            continue
        arn = excl.get("ResourceArn")
        if arn and arn in (subnet_arn, vpc_arn):
            return True
    return False
