import base64
import copy
import json
import logging
import os
import threading
import re
from abc import ABC
from datetime import UTC, datetime

from botocore.parsers import ResponseParserError
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from moto.core.utils import camelcase_to_underscores, underscores_to_camelcase
from moto.ec2.exceptions import InvalidVpcEndPointIdError
from moto.ec2.models import (
    EC2Backend,
    FlowLogsBackend,
    SubnetBackend,
    TransitGatewayAttachmentBackend,
    VPCBackend,
    ec2_backends,
)
from moto.ec2.models.launch_templates import LaunchTemplate as MotoLaunchTemplate
from moto.ec2.models.subnets import Subnet

from localemu.aws.api import CommonServiceException, RequestContext, handler
from localemu.aws.api.ec2 import (
    AvailabilityZone,
    Boolean,
    CreateFlowLogsRequest,
    CreateFlowLogsResult,
    CreateLaunchTemplateRequest,
    CreateLaunchTemplateResult,
    CreateSubnetRequest,
    CreateSubnetResult,
    CreateTransitGatewayRequest,
    CreateTransitGatewayResult,
    CurrencyCodeValues,
    DescribeAvailabilityZonesRequest,
    DescribeAvailabilityZonesResult,
    DescribeReservedInstancesOfferingsRequest,
    DescribeReservedInstancesOfferingsResult,
    DescribeReservedInstancesRequest,
    DescribeReservedInstancesResult,
    DescribeSubnetsRequest,
    DescribeSubnetsResult,
    DescribeTransitGatewaysRequest,
    DescribeTransitGatewaysResult,
    DescribeVpcEndpointServicesRequest,
    DescribeVpcEndpointServicesResult,
    DescribeVpcEndpointsRequest,
    DescribeVpcEndpointsResult,
    DnsOptions,
    DnsOptionsSpecification,
    DnsRecordIpType,
    Ec2Api,
    GetSecurityGroupsForVpcRequest,
    GetSecurityGroupsForVpcResult,
    InstanceType,
    IpAddressType,
    LaunchTemplate,
    ModifyLaunchTemplateRequest,
    ModifyLaunchTemplateResult,
    ModifySubnetAttributeRequest,
    ModifyVpcEndpointResult,
    OfferingClassType,
    OfferingTypeValues,
    PricingDetail,
    PurchaseReservedInstancesOfferingRequest,
    PurchaseReservedInstancesOfferingResult,
    RecurringCharge,
    RecurringChargeFrequency,
    ReservedInstances,
    ReservedInstancesOffering,
    ReservedInstanceState,
    RevokeSecurityGroupEgressRequest,
    RevokeSecurityGroupEgressResult,
    RIProductDescription,
    SecurityGroupForVpc,
    String,
    SubnetConfigurationsList,
    Tenancy,
    UnsuccessfulItem,
    UnsuccessfulItemError,
    VpcEndpointId,
    VpcEndpointRouteTableIdList,
    VpcEndpointSecurityGroupIdList,
    VpcEndpointSubnetIdList,
    scope,
)
from localemu.aws.connect import connect_to
from localemu.services.ec2.exceptions import (
    InvalidInstanceIdError,
    InvalidLaunchTemplateIdError,
    InvalidLaunchTemplateNameError,
    MissingParameterError,
)
from localemu.services.ec2 import eip_patches as _eip_patches  # noqa: F401
from localemu.services.ec2.models import get_ec2_backend
from localemu.services.ec2.patches import apply_patches
from localemu.services.moto import call_moto, call_moto_with_request
from localemu.services.plugins import ServiceLifecycleHook
from localemu.state import StateVisitor
from localemu.utils.patch import patch
from localemu.utils.strings import first_char_to_upper, long_uid, short_uid

LOG = logging.getLogger(__name__)

# Sidecar storage for public keys derived from CreateKeyPair / ImportKeyPair.
# Keyed by (account_id, region, key_name) -> public key string (OpenSSH format).
_key_pair_public_keys: dict[tuple[str, str, str], str] = {}
_key_pair_lock = threading.Lock()  # thread safety


def get_public_key_for_keypair(
    account_id: str, region: str, key_name: str
) -> str | None:
    """Return the stored public key for a key pair, or None if not found."""
    with _key_pair_lock:
        return _key_pair_public_keys.get((account_id, region, key_name))


# additional subnet attributes not yet supported upstream
ADDITIONAL_SUBNET_ATTRS = ("private_dns_name_options_on_launch", "enable_dns64")


def _extract_indexed_values(values: dict, key_prefix: str) -> list[str]:
    """Read AWS query-string indexed params like ``GroupId.1=sg-1, GroupId.2=sg-2``
    into a plain list. Empty if none found."""
    out: list[str] = []
    i = 1
    while True:
        v = values.get(f"{key_prefix}.{i}")
        if not v:
            break
        out.append(v)
        i += 1
    return out


def _reapply_sg_after_change(
    context: "RequestContext", request: dict, op: str,
) -> None:
    """Best-effort re-apply of SG iptables after a successful
    authorize/revoke. Never raises into the API handler."""
    try:
        group_id = request.get("GroupId") or context.request.values.get("GroupId")
        if not group_id:
            return
        from localemu.services.ec2.docker.sg_reapply import reapply_sg_for_sg_id

        count = reapply_sg_for_sg_id(group_id, context.account_id, context.region)
        LOG.debug(
            "%s sg=%s %s/%s re-applied to %d instance(s)",
            op, group_id, context.account_id, context.region, count,
        )
    except Exception:
        LOG.debug(
            "%s: SG re-apply hook failed",
            op, exc_info=True,
        )


def _refresh_eip_for_sg(context: "RequestContext", request: dict) -> None:
    """Notify the EIP data plane that a SG was mutated so it can open
    or close sidecar listeners for the newly-allowed/denied ports."""
    try:
        group_id = request.get("GroupId") or context.request.values.get("GroupId")
        if not group_id:
            return
        from localemu.services.ec2.eip import get_eip_data_plane
        get_eip_data_plane().refresh_sg(
            context.account_id, context.region or "us-east-1", group_id,
        )
    except Exception:
        LOG.debug("EIP refresh-on-SG-change failed", exc_info=True)


def _reapply_nacl_for_nacl_id(context: "RequestContext") -> None:
    """Best-effort NACL re-apply on every subnet that's associated with
    the given NACL. NEVER raises — the moto state change already
    succeeded, we just want the data plane to catch up."""
    try:
        nacl_id = context.request.values.get("NetworkAclId")
        if not nacl_id:
            return

        backend = ec2_backends[context.account_id][context.region]
        nacl = backend.network_acls.get(nacl_id)
        if not nacl:
            return

        subnet_ids: list[str] = []
        for assoc in getattr(nacl, "associations", {}).values() or []:
            sid = (
                assoc.get("SubnetId")
                if isinstance(assoc, dict)
                else getattr(assoc, "subnet_id", None)
            )
            if sid:
                subnet_ids.append(sid)

        if not subnet_ids:
            LOG.debug("NACL %s has no subnet associations — nothing to re-apply", nacl_id)
            return

        from localemu.services.ec2.docker.nacl_enforcer import (
            apply_nacl_to_subnet_containers,
        )
        for subnet_id in subnet_ids:
            try:
                apply_nacl_to_subnet_containers(
                    nacl_id, subnet_id, context.account_id, context.region,
                )
            except Exception:
                LOG.debug(
                    "NACL re-apply for %s/%s failed",
                    nacl_id, subnet_id, exc_info=True,
                )
    except Exception:
        LOG.debug("NACL re-apply hook failed", exc_info=True)


def _register_subnet_with_allocator(subnet_payload: dict) -> None:
    """Best-effort: register a freshly-created subnet with the IPv4
    allocator so containers launching into it get pinned addresses
    inside the AWS CIDR.

    Gated on ``LOCALEMU_VPC_IP_PINNING``. Failures are logged and
    swallowed; the allocator can also be populated lazily by the
    reconciler if this path drops the subnet on the floor.

    The Docker bridge for the VPC may not exist yet (bridges are
    created lazily on first container launch). In that case we use
    ``docker_cidr = aws_cidr`` as the optimistic assumption — if the
    bridge later lands on a fallback tier, ``vm_manager`` will detect
    the divergence and re-register with the corrected ``docker_cidr``.
    """
    from localemu import config

    if not config.LOCALEMU_VPC_IP_PINNING:
        return
    if not isinstance(subnet_payload, dict):
        return
    subnet_id = subnet_payload.get("SubnetId")
    vpc_id = subnet_payload.get("VpcId")
    aws_cidr = subnet_payload.get("CidrBlock")
    az = subnet_payload.get("AvailabilityZone", "")
    if not (subnet_id and vpc_id and aws_cidr):
        return

    try:
        from localemu.services.ec2.docker.subnet_allocator import (
            SubnetCidrConflict,
            get_subnet_allocator,
        )
        from localemu.services.ec2.docker.vpc_network import (
            get_vpc_network_manager,
        )
    except Exception:
        LOG.debug(
            "subnet allocator: import failed, skipping registration",
            exc_info=True,
        )
        return

    # The subnet allocator pool is carved within the SUBNET's CIDR, not
    # the VPC bridge's CIDR. AWS guarantees that an ENI's primary IP
    # lies inside its subnet's CidrBlock. If we used the VPC bridge's
    # CIDR here, the allocator would hand out IPs anywhere in the VPC
    # (e.g. 10.99.0.2 for an ENI in subnet 10.99.1.0/24) — which would
    # violate the AWS contract and confuse every tool that reads
    # NetworkInterface.PrivateIpAddress and assumes it's in SubnetId's
    # CIDR.
    #
    # Future work: when the VPC bridge falls back to a non-AWS CIDR
    # tier (e.g. user asked for 10.99.0.0/16 but Docker gave 172.20.0.0/16),
    # we'd need to translate the subnet's AWS-offset into the fallback
    # bridge's address space. For v1 the happy path is bridge_cidr ==
    # vpc_cidr and the subnet's aws_cidr is a valid sub-range — so
    # passing aws_cidr as docker_cidr is correct.
    docker_cidr = aws_cidr

    try:
        get_subnet_allocator().register_subnet(
            vpc_id=vpc_id,
            subnet_id=subnet_id,
            aws_cidr=aws_cidr,
            docker_cidr=docker_cidr,
            az=az,
        )
    except SubnetCidrConflict:
        # Re-registration with different CIDRs is a programming bug
        # (the user can't change subnet CIDR via the AWS API). Log and
        # move on — the existing pool is still usable.
        LOG.warning(
            "subnet allocator: cidr conflict on re-register of %s",
            subnet_id, exc_info=True,
        )
    except Exception:
        LOG.warning(
            "subnet allocator: failed to register %s",
            subnet_id, exc_info=True,
        )


def _unregister_subnet_from_allocator(
    account_id: str, region: str, subnet_id: str | None,
) -> None:
    """Best-effort: tear down the subnet's allocator pool when the
    user calls DeleteSubnet. Live allocations would normally signal
    a bug (you can't delete a subnet with running instances on AWS),
    but we use ``force_unregister_subnet`` for robustness."""
    from localemu import config

    if not (config.LOCALEMU_VPC_IP_PINNING and subnet_id):
        return
    try:
        # Look up the VPC for the subnet — moto's record is gone by now,
        # so we walk the allocator's pools directly.
        from localemu.services.ec2.docker.subnet_allocator import (
            get_subnet_allocator,
        )
        alloc = get_subnet_allocator()
        for pool in alloc.all_pools():
            if pool.subnet_id == subnet_id:
                alloc.force_unregister_subnet(pool.vpc_id, subnet_id)
                return
    except Exception:
        LOG.warning(
            "subnet allocator: failed to unregister %s",
            subnet_id, exc_info=True,
        )


def _reconcile_addressing_state() -> None:
    """Run the addressing redesign reconciliation on startup.

    Gated on ``LOCALEMU_VPC_IP_PINNING``. Sequence:
      1. Load persisted SubnetAllocator + AddressIndex from disk.
      2. Walk moto's subnets in every (account, region) and register
         each with the allocator (idempotent: subnets already loaded
         from disk are no-ops; new subnets get a fresh pool).
      3. Run the reconciler to converge in-memory state against Docker
         reality (claim IPs Docker reports, drop orphans, log drift).

    All failures are logged and never raise into the caller — the
    reconciler is best-effort and the upper layers must not depend on
    it for correctness (they get correctness from the per-call hooks).
    """
    from localemu import config

    if not config.LOCALEMU_VPC_IP_PINNING:
        return

    # Step 1: load state files
    try:
        from localemu.services.ec2.docker.addressing_persistence import (
            load_addressing_state,
        )
        load_addressing_state()
    except Exception:
        LOG.warning(
            "addressing reconcile: state load failed (continuing)",
            exc_info=True,
        )

    # Step 2: walk moto subnets, register in allocator
    try:
        from moto.ec2 import ec2_backends
        from localemu.services.ec2.docker.subnet_allocator import (
            SubnetCidrConflict,
            get_subnet_allocator,
        )
        from localemu.services.ec2.docker.vpc_network import (
            get_vpc_network_manager,
        )

        alloc = get_subnet_allocator()
        vpc_mgr = get_vpc_network_manager()
        for _account_id, region_map in list(ec2_backends.items()):
            if not isinstance(region_map, dict):
                continue
            for _region, backend in list(region_map.items()):
                subnets = getattr(backend, "subnets", None) or {}
                for az_map in subnets.values() if isinstance(subnets, dict) else []:
                    if not isinstance(az_map, dict):
                        continue
                    for subnet in az_map.values():
                        subnet_id = getattr(subnet, "id", None)
                        vpc_id = getattr(subnet, "vpc_id", None)
                        aws_cidr = getattr(subnet, "cidr_block", None)
                        az = getattr(subnet, "availability_zone", "") or ""
                        if not (subnet_id and vpc_id and aws_cidr):
                            continue
                        # Subnet pool is carved within the SUBNET's CIDR,
                        # not the VPC bridge's CIDR (AWS contract: ENI
                        # IP must lie inside SubnetId's CidrBlock).
                        docker_cidr = aws_cidr
                        try:
                            alloc.register_subnet(
                                vpc_id=vpc_id, subnet_id=subnet_id,
                                aws_cidr=aws_cidr, docker_cidr=docker_cidr,
                                az=az,
                            )
                        except SubnetCidrConflict:
                            # CIDR drift since the snapshot was written —
                            # use the current docker_cidr as authoritative
                            alloc.force_unregister_subnet(vpc_id, subnet_id)
                            alloc.register_subnet(
                                vpc_id=vpc_id, subnet_id=subnet_id,
                                aws_cidr=aws_cidr, docker_cidr=docker_cidr,
                                az=az,
                            )
                        except Exception:
                            LOG.debug(
                                "addressing reconcile: skip register %s",
                                subnet_id, exc_info=True,
                            )
    except Exception:
        LOG.warning(
            "addressing reconcile: moto subnet walk failed",
            exc_info=True,
        )

    # Step 3: reconcile against Docker
    try:
        from localemu.services.ec2.docker.address_reconciler import (
            reconcile_on_startup,
        )
        report = reconcile_on_startup()
        LOG.info("addressing reconcile: %s", report.summary())
    except Exception:
        LOG.warning(
            "addressing reconcile: walk failed", exc_info=True,
        )


def _eni_real_enabled() -> bool:
    """The ENI orchestration is gated on both addressing pinning AND the
    ENI flag. Requiring both keeps rollback simple: turning off either
    flag falls back to today's pure-moto behavior.
    """
    from localemu import config as _config
    if not _config.LOCALEMU_ENI_REAL:
        return False
    if not _config.LOCALEMU_VPC_IP_PINNING:
        # Defensive: warn once that the flag is set without its prereq
        global _ENI_FLAG_WARNED
        if not _ENI_FLAG_WARNED:
            LOG.warning(
                "LOCALEMU_ENI_REAL=1 ignored: requires LOCALEMU_VPC_IP_PINNING=1",
            )
            _ENI_FLAG_WARNED = True
        return False
    return True


_ENI_FLAG_WARNED = False


def _patch_moto_eni(eni_id: str, primary_ip: str, mac: str) -> None:
    """Overwrite the moto NetworkInterface's primary IP and MAC so that
    DescribeNetworkInterfaces reports the values LocalEmu actually
    pinned. Pattern mirrors _patch_moto_instance_ip — tries the
    attribute names that have shifted across moto versions, swallows
    individual failures.
    """
    try:
        import moto.backends as moto_backends
    except Exception:
        return
    for _acct, region_map in moto_backends.get_backend("ec2").items():
        if not isinstance(region_map, dict):
            continue
        for _region, backend in region_map.items():
            enis = getattr(backend, "enis", None)
            if not enis:
                continue
            eni = enis.get(eni_id)
            if eni is None:
                continue
            try:
                eni.private_ip_address = primary_ip
            except Exception:
                pass
            try:
                eni.mac_address = mac
            except Exception:
                pass
            # private_ip_addresses is a list of {Primary, PrivateIpAddress};
            # update the primary entry in place.
            pias = getattr(eni, "private_ip_addresses", None)
            if isinstance(pias, list) and pias:
                for entry in pias:
                    if isinstance(entry, dict) and entry.get("Primary"):
                        entry["PrivateIpAddress"] = primary_ip
                        break


def _translate_eni_error(exc: Exception):
    """Translate EniManager errors to AWS-shape CommonServiceException."""
    from localemu.services.ec2.docker.eni_manager import (
        CannotDetachPrimary,
        EniAlreadyAttached,
        EniInUse,
        EniNotAttached,
        EniNotFound,
        InvalidEniState,
    )
    if isinstance(exc, EniNotFound):
        return CommonServiceException(
            "InvalidNetworkInterfaceID.NotFound", str(exc), status_code=400,
        )
    if isinstance(exc, EniAlreadyAttached):
        return CommonServiceException(
            "InvalidParameterValue", str(exc), status_code=400,
        )
    if isinstance(exc, EniNotAttached):
        return CommonServiceException(
            "InvalidParameterValue", str(exc), status_code=400,
        )
    if isinstance(exc, EniInUse):
        return CommonServiceException(
            "InvalidParameterValue",
            f"Network interface is currently in use: {exc}",
            status_code=400,
        )
    if isinstance(exc, CannotDetachPrimary):
        return CommonServiceException(
            "OperationNotPermitted",
            f"You cannot detach the primary network interface: {exc}",
            status_code=400,
        )
    if isinstance(exc, InvalidEniState):
        return CommonServiceException(
            "InvalidParameterValue", str(exc), status_code=400,
        )
    return CommonServiceException(
        "InternalError", f"ENI op failed: {exc}", status_code=500,
    )


def _moto_instance_state(moto_instance) -> str:
    """Best-effort read of the instance's EC2 state (``"running"``,
    ``"stopped"``, etc.) across moto minor-version variance in the
    ``_state`` attribute shape."""
    state_obj = getattr(moto_instance, "_state", None)
    if state_obj is None:
        state_obj = getattr(moto_instance, "state", None)
    name = getattr(state_obj, "name", None) if state_obj is not None else None
    if not name:
        return "unknown"
    return str(name).lower()


class Ec2Provider(Ec2Api, ABC, ServiceLifecycleHook):
    _vm_manager = None

    def on_after_init(self):
        apply_patches()
        # Register the addressing persistence save hook. Gated internally
        # on PERSISTENCE; idempotent. Safe to call even when
        # LOCALEMU_VPC_IP_PINNING=0 — the save handler will write empty
        # state files in that case, which load cleanly on next start.
        try:
            from localemu.services.ec2.docker.addressing_persistence import (
                register_save_handler,
            )
            register_save_handler()
        except Exception:
            LOG.debug(
                "addressing_persistence: save-handler registration deferred",
                exc_info=True,
            )
        # Reap any v1 EIP sidecar containers left from the
        # discarded sidecar-based proxy design. The v2 host-side
        # proxy doesn't use sidecars; leftovers would fight for
        # host ports and confuse DescribeAddresses.
        try:
            from localemu.services.ec2.eip import cleanup_v1_sidecars
            cleanup_v1_sidecars()
        except Exception:
            LOG.debug(
                "EIP v1 sidecar cleanup deferred", exc_info=True,
            )
        # Initialize Docker VM manager if configured.
        #
        # EC2_VM_MANAGER defaults to "docker" so RunInstances produces
        # something users can actually SSH into / curl against out of
        # the box. Explicit opt-out via EC2_VM_MANAGER=none keeps the
        # historical state-only path for CI environments that don't
        # have access to the Docker daemon. If the default is in effect
        # but Docker isn't available, fall back to state-only silently —
        # the user didn't ask for Docker, so we shouldn't warn about it.
        vm_mode = os.environ.get("EC2_VM_MANAGER", "docker").lower()
        explicit_docker = os.environ.get("EC2_VM_MANAGER", "").lower() == "docker"
        if vm_mode == "docker":
            try:
                from localemu.services.ec2.docker.vm_manager import DockerVmManager
                from localemu.utils.docker_utils import DOCKER_CLIENT
                if DOCKER_CLIENT.has_docker():
                    self._vm_manager = DockerVmManager()
                    LOG.info("EC2 Docker backend enabled. RunInstances will create real containers.")
                elif explicit_docker:
                    LOG.warning(
                        "EC2_VM_MANAGER=docker but Docker is not available. "
                        "Using state-only mode."
                    )
                else:
                    LOG.debug(
                        "EC2 Docker backend unavailable (Docker daemon not reachable); "
                        "falling back to state-only mode."
                    )
            except Exception as e:
                LOG.warning("Failed to initialize EC2 Docker backend: %s", e)

        # Clean up orphaned Docker resources from previous crashes — but
        # NOT under persistence. When ``PERSISTENCE=1`` the leftover
        # ``localemu-ec2-*`` containers and ``localemu-vpc-*`` networks
        # are exactly what ``on_after_state_load`` is about to resume.
        # Blanket-removing them before the load hook fires silently
        # defeats the entire persistence path.
        from localemu import config as _config
        if not _config.PERSISTENCE:
            self._cleanup_orphaned_docker_resources()

        # Adopt any pre-existing ``localemu-vpc-*`` bridges and GC orphans.
        # Under PERSISTENCE=0 the cleanup above already removed them so
        # this is a no-op. Under PERSISTENCE=1 ``on_after_state_load``
        # will also call this, but doing it here first means any other
        # service that touches ``get_vpc_network_manager()`` before the
        # state-load hook fires gets a fully-populated tracking dict.
        try:
            from localemu.services.ec2.docker.vpc_network import (
                get_vpc_network_manager,
            )
            get_vpc_network_manager().adopt_vpc_networks_from_docker()
        except Exception:
            LOG.debug(
                "VPC bridge adoption on init failed", exc_info=True,
            )

        # Load persisted public keys from disk
        self._load_key_pair_public_keys()

    def _cleanup_orphaned_docker_resources(self):
        """Remove Docker containers and networks from previous LocalEmu runs.

        If LocalEmu crashed (SIGKILL, OOM), Docker resources are orphaned.
        We scan for anything with the localemu naming convention and remove it.

        Uses DOCKER_CLIENT API instead of subprocess calls.
        """
        try:
            from localemu.utils.docker_utils import DOCKER_CLIENT
            if not DOCKER_CLIENT.has_docker():
                return

            # Remove orphaned containers (EC2, NAT, VPC endpoints, IMDS
            # sidecars). The IMDS prefix matters: each VPC's sidecar is
            # the endpoint that pins the VPC bridge against ``docker
            # network rm`` below — leaving sidecars behind silently
            # defeats the entire orphan-network cleanup loop.
            for prefix in [
                "localemu-ec2-", "localemu-nat-", "localemu-vpce-",
                "localemu-imds-",
            ]:
                try:
                    containers = DOCKER_CLIENT.list_containers(filter=f"name={prefix}", all=True)
                    for container in containers:
                        name = container.get("name", "")
                        if name:
                            try:
                                DOCKER_CLIENT.remove_container(name, force=True)
                            except Exception:
                                pass
                except Exception:
                    pass

            # Remove orphaned networks (VPC, peering, TGW data-plane,
            # NAT bridge). TGW data-plane bridges (``localemu-tgw-*``)
            # likewise survive a crashed prior session and need to go.
            for prefix in [
                "localemu-vpc-", "localemu-pcx-", "localemu-tgw-",
                "localemu-nat-bridge-",
            ]:
                try:
                    # inspect_network raises if not found; list via Docker SDK
                    client = DOCKER_CLIENT.client()
                    networks = client.networks.list(names=[f"{prefix}*"])
                    for net in networks:
                        name = net.name if hasattr(net, "name") else net.get("Name", "")
                        if name and name.startswith(prefix):
                            try:
                                DOCKER_CLIENT.delete_network(name)
                            except Exception:
                                pass
                except Exception:
                    pass

            # Remove orphaned volumes (OpenSearch data)
            try:
                client = DOCKER_CLIENT.client()
                volumes = client.volumes.list(filters={"name": "localemu-"})
                for vol in volumes:
                    name = vol.name if hasattr(vol, "name") else ""
                    if name:
                        try:
                            vol.remove(force=True)
                        except Exception:
                            pass
            except Exception:
                pass

            LOG.info("Cleaned up orphaned Docker resources from previous runs")
        except Exception as e:
            LOG.debug("Orphaned Docker cleanup skipped: %s", e)

    @staticmethod
    def _key_pair_state_file() -> str | None:
        """Return the path to the key pair persistence file, or None if persistence is off."""
        from localemu import config
        if config.is_persistence_enabled() and config.dirs.data:
            return os.path.join(config.dirs.data, "ec2_key_pairs.json")
        return None

    def _load_key_pair_public_keys(self):
        """Load persisted public keys from disk on startup."""
        path = self._key_pair_state_file()
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            with _key_pair_lock:
                for entry in data:
                    key = (entry["account_id"], entry["region"], entry["key_name"])
                    _key_pair_public_keys[key] = entry["public_key"]
            LOG.info("Loaded %d persisted EC2 key pairs", len(data))
        except Exception as e:
            LOG.warning("Failed to load persisted key pairs: %s", e)

    def _save_key_pair_public_keys(self):
        """Save public keys to disk on shutdown."""
        path = self._key_pair_state_file()
        if not path:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with _key_pair_lock:
                data = [
                    {
                        "account_id": k[0],
                        "region": k[1],
                        "key_name": k[2],
                        "public_key": v,
                    }
                    for k, v in _key_pair_public_keys.items()
                ]
            with open(path, "w") as f:
                json.dump(data, f)
            LOG.info("Persisted %d EC2 key pairs", len(data))
        except Exception as e:
            LOG.warning("Failed to persist key pairs: %s", e)

    def on_before_stop(self):
        # Persist key pairs before shutdown
        self._save_key_pair_public_keys()
        from localemu import config as _config
        persistence_on = _config.PERSISTENCE
        if self._vm_manager:
            if persistence_on:
                # Stop containers (don't remove). Writable layer, VPC
                # network membership, and host-port bindings all survive
                # to be resumed in on_after_state_load.
                self._vm_manager.stop_all()
            else:
                self._vm_manager.cleanup_all()
        # VPC bridge networks, NAT gateways, and VPC endpoints stay alive
        # under persistence because the EC2 containers depend on them.
        # Under no-persistence, legacy behaviour: destroy them here.
        if not persistence_on:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                get_vpc_network_manager().cleanup_all()
            except Exception:
                pass
            try:
                from localemu.services.ec2.docker.nat_gateway import get_nat_gateway_manager
                get_nat_gateway_manager().cleanup_all()
            except Exception:
                pass
            try:
                from localemu.services.ec2.docker.vpc_endpoint import get_vpc_endpoint_manager
                get_vpc_endpoint_manager().cleanup_all()
            except Exception:
                pass

    def on_after_state_load(self):
        """Reconcile persisted EC2 instances with the live Docker daemon.

        Walks the moto EC2 backend for every ``(account, region)``, finds
        each instance's labeled container on the host, and resumes it via
        ``DockerVmManager.restore_instance``. Instances whose container
        no longer exists are logged as data-loss and left in whatever
        state moto holds — we do NOT pretend a missing container is fine.

        When ``EC2_VM_MANAGER`` is not ``docker`` there's nothing to
        reconcile; moto state alone answers every DescribeInstances call.
        """
        vm_mode = os.environ.get("EC2_VM_MANAGER", "docker").lower()
        if vm_mode != "docker":
            return
        if not self._vm_manager:
            try:
                from localemu.services.ec2.docker.vm_manager import DockerVmManager
                from localemu.utils.docker_utils import DOCKER_CLIENT
                if DOCKER_CLIENT.has_docker():
                    self._vm_manager = DockerVmManager()
            except Exception:
                LOG.warning("EC2 reconcile: cannot init vm manager", exc_info=True)
                return
        if not self._vm_manager:
            return

        # Rebuild VpcNetworkManager container tracking and
        # the sg_reapply mapping from Docker labels + network attachments
        # BEFORE we start touching individual instances, so subsequent
        # restore_instance calls see consistent state.
        try:
            from localemu.services.ec2.docker.vpc_network import (
                get_vpc_network_manager,
            )
            mgr = get_vpc_network_manager()
            # Adopt persisted ``localemu-vpc-*`` bridges before container
            # tracking runs. Without this, VPCs whose containers have all
            # been terminated (or VPCs that never had containers, e.g. the
            # persisted default VPC) would have no entry in ``_vpcs`` after
            # rebuild_from_docker, and any caller of get_network_for_vpc
            # would then re-enter the create path on every poll.
            mgr.adopt_vpc_networks_from_docker()
            mgr.rebuild_from_docker()
            try:
                mgr.reconcile_peerings_from_docker()
            except Exception:
                LOG.warning(
                    "VPC peering reconcile failed", exc_info=True,
                )
        except Exception:
            LOG.warning("VPC container tracking rebuild failed", exc_info=True)
        try:
            from localemu.services.ec2.docker.sg_reapply import (
                rebuild_mapping_from_docker,
            )
            rebuild_mapping_from_docker()
        except Exception:
            LOG.warning("SG reapply mapping rebuild failed", exc_info=True)

        # Addressing redesign reconciliation. Gated on
        # LOCALEMU_VPC_IP_PINNING; off-path is a no-op so the discover
        # loop below runs unchanged.
        _reconcile_addressing_state()

        discovered = self._vm_manager.discover_containers()
        resumed = lost = orphaned = 0
        for account_id, region_map in list(ec2_backends.items()):
            if not isinstance(region_map, dict):
                continue
            for _region, backend in list(region_map.items()):
                # moto 5.x exposes ``all_instances()`` on the backend itself,
                # not on ``backend.reservations`` (which is an OrderedDict).
                try:
                    instances = list(backend.all_instances())
                except Exception:
                    LOG.warning(
                        "EC2 reconcile: backend.all_instances() failed",
                        exc_info=True,
                    )
                    continue
                for moto_instance in instances:
                    state = _moto_instance_state(moto_instance)
                    if state == "terminated":
                        continue
                    summary = discovered.pop(moto_instance.id, None)
                    if summary is None:
                        LOG.warning(
                            "EC2 %s: persisted record but no container on host "
                            "(data loss for this instance)",
                            moto_instance.id,
                        )
                        lost += 1
                        continue
                    info = self._vm_manager.restore_instance(
                        moto_instance.id, state,
                        summary["name"], summary["inspect"],
                    )
                    if info:
                        resumed += 1
                    else:
                        lost += 1

        orphaned = len(discovered)
        for stale_id in discovered:
            LOG.warning(
                "Orphan EC2 container %s has no moto record — leaving alone",
                stale_id,
            )
        LOG.info(
            "EC2 reconcile: resumed=%d, lost=%d, orphaned=%d",
            resumed, lost, orphaned,
        )

    # ------------------------------------------------------------------
    # VPC ops — create/delete Docker networks for real isolation
    # ------------------------------------------------------------------

    @handler("CreateVpc", expand=False)
    def create_vpc(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        vpc = result.get("Vpc", {})
        vpc_id = vpc.get("VpcId")
        cidr = vpc.get("CidrBlock")

        if vpc_id and cidr:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                from localemu.utils.docker_utils import DOCKER_CLIENT
                if DOCKER_CLIENT.has_docker():
                    get_vpc_network_manager().create_vpc_network(vpc_id, cidr)
            except Exception as e:
                LOG.debug("VPC Docker network creation skipped for %s: %s", vpc_id, e)

        return result

    @handler("DeleteVpc", expand=False)
    def delete_vpc(self, context: RequestContext, request: dict) -> dict:
        vpc_id = context.request.values.get("VpcId", "")
        result = call_moto(context)

        if vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                get_vpc_network_manager().delete_vpc_network(vpc_id)
            except Exception as e:
                LOG.debug("VPC Docker network deletion skipped for %s: %s", vpc_id, e)

        return result

    # ------------------------------------------------------------------
    # Internet Gateway — toggle VPC network between internal and public
    # ------------------------------------------------------------------

    @handler("AttachInternetGateway", expand=False)
    def attach_internet_gateway(self, context: RequestContext, request: dict) -> dict:
        vpc_id = context.request.values.get("VpcId", "")

        # AWS enforces max 1 IGW per VPC — Moto doesn't check this
        if vpc_id:
            try:
                backend = ec2_backends[context.account_id][context.region]
                for igw in backend.internet_gateways.values():
                    attached_vpc = getattr(igw, "vpc", None)
                    if attached_vpc:
                        attached_vpc_id = getattr(attached_vpc, "id", str(attached_vpc))
                        if attached_vpc_id == vpc_id:
                            raise CommonServiceException(
                                "Resource.AlreadyAssociated",
                                f"resource {vpc_id} already has an internet gateway attached",
                            )
            except CommonServiceException:
                raise
            except Exception:
                pass

        result = call_moto(context)

        if vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                ok = get_vpc_network_manager().attach_internet_gateway(vpc_id)
                if not ok:
                    LOG.error(
                        "IGW attach: Docker network recreate FAILED for VPC %s; "
                        "moto state shows IGW attached but the Docker network "
                        "is still --internal. EC2s in this VPC will NOT have "
                        "outbound connectivity until this is fixed.",
                        vpc_id,
                    )
            except Exception as e:
                LOG.warning("IGW attach Docker network update skipped for %s: %s", vpc_id, e)

        return result

    @handler("DetachInternetGateway", expand=False)
    def detach_internet_gateway(self, context: RequestContext, request: dict) -> dict:
        vpc_id = context.request.values.get("VpcId", "")
        result = call_moto(context)

        if vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                ok = get_vpc_network_manager().detach_internet_gateway(vpc_id)
                if not ok:
                    LOG.error(
                        "IGW detach: Docker network recreate FAILED for VPC %s; "
                        "moto state shows IGW detached but the Docker network "
                        "still permits outbound connectivity. EC2s in this VPC "
                        "remain effectively reachable from the host.",
                        vpc_id,
                    )
            except Exception as e:
                LOG.warning("IGW detach Docker network update skipped for %s: %s", vpc_id, e)

        return result

    # ------------------------------------------------------------------
    # VPC Peering — connect/disconnect containers across VPCs
    # ------------------------------------------------------------------

    @staticmethod
    def _vpcs_overlap(vpc_a, vpc_b) -> bool:
        """Return True iff any IPv4 CIDR on ``vpc_a`` overlaps any IPv4
        CIDR on ``vpc_b`` (primary + secondaries).

        Real AWS rejects peering requests whose VPCs have overlapping
        CIDRs because traffic cannot be routed unambiguously.
        """
        import ipaddress as _ipa

        def _collect(vpc) -> list:
            nets: list = []
            primary = getattr(vpc, "cidr_block", None)
            if primary:
                try:
                    nets.append(_ipa.ip_network(primary, strict=False))
                except ValueError:
                    pass
            # moto stores secondaries under different attribute names
            # across versions; try each. Walk list OR dict shape.
            for attr in ("cidr_block_association_set",
                         "cidr_block_associations",
                         "_cidr_block_association_set"):
                raw = getattr(vpc, attr, None)
                if not raw:
                    continue
                items = raw.values() if isinstance(raw, dict) else raw
                for assoc in items or []:
                    cidr = None
                    if isinstance(assoc, dict):
                        cidr = (
                            assoc.get("cidr_block")
                            or assoc.get("CidrBlock")
                            or assoc.get("cidrBlock")
                        )
                    else:
                        cidr = (
                            getattr(assoc, "cidr_block", None)
                            or getattr(assoc, "CidrBlock", None)
                        )
                    if cidr:
                        try:
                            nets.append(_ipa.ip_network(cidr, strict=False))
                        except ValueError:
                            pass
            # Dedupe
            unique: list = []
            seen: set = set()
            for n in nets:
                if str(n) not in seen:
                    unique.append(n)
                    seen.add(str(n))
            return unique

        a_nets = _collect(vpc_a)
        b_nets = _collect(vpc_b)
        for na in a_nets:
            for nb in b_nets:
                if na.version == nb.version and na.overlaps(nb):
                    return True
        return False

    @staticmethod
    def _serialize_existing_pcx(backend, pcx) -> dict:
        """Render a moto VPC peering object in the wire shape that
        ``CreateVpcPeeringConnection`` would normally emit."""
        def _info(vpc) -> dict:
            if not vpc:
                return {}
            return {
                "CidrBlock": getattr(vpc, "cidr_block", ""),
                "OwnerId": getattr(vpc, "owner_id", None)
                    or getattr(vpc, "owner", "")
                    or getattr(backend, "account_id", ""),
                "VpcId": getattr(vpc, "id", ""),
                "Region": getattr(vpc, "region", None)
                    or getattr(backend, "region_name", ""),
            }
        status = getattr(pcx, "_status", None) or getattr(pcx, "status", None)
        code = getattr(status, "code", None)
        if code is None and isinstance(status, dict):
            code = status.get("Code") or status.get("code")
        message = getattr(status, "message", None)
        if message is None and isinstance(status, dict):
            message = status.get("Message") or status.get("message")
        return {
            "AccepterVpcInfo": _info(getattr(pcx, "peer_vpc", None)),
            "RequesterVpcInfo": _info(getattr(pcx, "vpc", None)),
            "Status": {"Code": code or "", "Message": message or ""},
            "Tags": [
                {"Key": k, "Value": v}
                for k, v in (getattr(pcx, "get_tags", lambda: {})() or {}).items()
            ],
            "VpcPeeringConnectionId": getattr(pcx, "id", ""),
        }

    @handler("CreateVpcPeeringConnection", expand=False)
    def create_vpc_peering_connection(self, context: RequestContext, request: dict) -> dict:
        """Validate then delegate to moto.

        AWS-parity checks we add here (moto does none):
          * self-peering → InvalidVpcPeeringConnectionId.Malformed
          * overlapping CIDR (same acct+region) →
            InvalidVpcPeeringConnectionRequest.OverlappingCidr
          * duplicate active/pending for same pair → return existing

        Cross-region peerings that name a non-existent accepter VPC
        are left to moto (it already raises InvalidVpcID.NotFound).
        """
        from moto.ec2.models import ec2_backends

        vpc_id = context.request.values.get("VpcId")
        peer_vpc = context.request.values.get("PeerVpcId")
        peer_owner = (
            context.request.values.get("PeerOwnerId") or context.account_id
        )
        peer_region = (
            context.request.values.get("PeerRegion") or context.region
        )

        if vpc_id and peer_vpc and vpc_id == peer_vpc and \
                peer_owner == context.account_id and peer_region == context.region:
            raise CommonServiceException(
                code="InvalidVpcPeeringConnectionId.Malformed",
                message=(
                    f"The vpcPeeringConnection ID '{vpc_id}' is malformed: "
                    f"a VPC cannot peer with itself"
                ),
                status_code=400,
            )

        try:
            req_backend = ec2_backends[context.account_id][context.region]
            acc_backend = ec2_backends.get(peer_owner, {}).get(peer_region)
        except Exception:
            req_backend = None
            acc_backend = None

        # Duplicate active/pending for same pair → return existing.
        if req_backend is not None:
            for pcx in getattr(req_backend, "vpc_pcxs", {}).values():
                status = getattr(pcx, "_status", None)
                if status is None:
                    status = getattr(pcx, "status", None)
                state_code = None
                if status is not None:
                    state_code = getattr(status, "code", None)
                    if state_code is None and isinstance(status, dict):
                        state_code = status.get("Code") or status.get("code")
                if state_code not in ("active", "pending-acceptance",
                                      "initiating-request", "provisioning"):
                    continue
                a = getattr(getattr(pcx, "vpc", None), "id", None)
                b = getattr(getattr(pcx, "peer_vpc", None), "id", None)
                if {a, b} == {vpc_id, peer_vpc}:
                    LOG.info(
                        "CreateVpcPeeringConnection: returning existing "
                        "active/pending pcx %s for pair (%s, %s)",
                        pcx.id, vpc_id, peer_vpc,
                    )
                    # Build a response that contains the existing pcx —
                    # call_moto would create a NEW one, which is exactly
                    # what we're preventing.
                    return {
                        "VpcPeeringConnection": self._serialize_existing_pcx(
                            req_backend, pcx,
                        ),
                    }

        # Overlap check — same account + same region only (real AWS
        # permits overlap across account/region with operator warning).
        if req_backend is not None and acc_backend is not None \
                and peer_owner == context.account_id \
                and peer_region == context.region:
            try:
                vpc_a = req_backend.get_vpc(vpc_id)
                vpc_b = req_backend.get_vpc(peer_vpc)
                if self._vpcs_overlap(vpc_a, vpc_b):
                    raise CommonServiceException(
                        code="InvalidVpcPeeringConnectionRequest.OverlappingCidr",
                        message=(
                            f"The requester and accepter VPCs have overlapping CIDRs: "
                            f"cannot create the VPC peering connection"
                        ),
                        status_code=400,
                    )
            except CommonServiceException:
                raise
            except Exception:
                # VPC lookup failures fall through to moto's own handling.
                LOG.debug(
                    "overlap check skipped for (%s, %s): lookup error",
                    vpc_id, peer_vpc, exc_info=True,
                )

        return call_moto(context)

    @handler("AcceptVpcPeeringConnection", expand=False)
    def accept_vpc_peering_connection(self, context: RequestContext, request: dict) -> dict:
        # Cross-region reject (LocalEmu single-Docker-daemon limitation).
        allow_cross_region = os.environ.get(
            "LOCALEMU_ALLOW_CROSS_REGION_PEERING", "0"
        ).strip().lower() in ("1", "true", "yes")
        if not allow_cross_region:
            from moto.ec2.models import ec2_backends
            pcx_id = context.request.values.get("VpcPeeringConnectionId") or ""
            be = ec2_backends.get(context.account_id, {}).get(context.region)
            pcx = getattr(be, "vpc_pcxs", {}).get(pcx_id) if be else None
            if pcx is not None:
                req_vpc = getattr(pcx, "vpc", None)
                acc_vpc = getattr(pcx, "peer_vpc", None)
                req_region = getattr(req_vpc, "region", None) \
                    or getattr(req_vpc, "_region", None) \
                    or context.region
                acc_region = getattr(acc_vpc, "region", None) \
                    or getattr(acc_vpc, "_region", None) \
                    or context.region
                if req_region != acc_region:
                    raise CommonServiceException(
                        code="OperationNotPermitted",
                        message=(
                            "Cross-region VPC peering is not supported by "
                            "LocalEmu. Set LOCALEMU_ALLOW_CROSS_REGION_PEERING=1 "
                            "to allow metadata-only cross-region peerings."
                        ),
                        status_code=400,
                    )

        result = call_moto(context)

        peering = result.get("VpcPeeringConnection", {})
        peering_id = peering.get("VpcPeeringConnectionId")
        vpc1_id = peering.get("RequesterVpcInfo", {}).get("VpcId")
        vpc2_id = peering.get("AccepterVpcInfo", {}).get("VpcId")

        if peering_id and vpc1_id and vpc2_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                get_vpc_network_manager().create_peering(peering_id, vpc1_id, vpc2_id)
            except Exception as e:
                LOG.debug("VPC peering Docker setup skipped for %s: %s", peering_id, e)

        return result

    @handler("ModifyVpcPeeringConnectionOptions", expand=False)
    def modify_vpc_peering_connection_options(
        self, context: RequestContext, request: dict,
    ) -> dict:
        """Reject modify on non-active peerings (real AWS returns
        InvalidStateTransition). moto accepts the mutation blindly,
        which is misleading."""
        from moto.ec2.models import ec2_backends
        pcx_id = context.request.values.get("VpcPeeringConnectionId") or ""
        be = ec2_backends.get(context.account_id, {}).get(context.region)
        pcx = getattr(be, "vpc_pcxs", {}).get(pcx_id) if be else None
        if pcx is None:
            raise CommonServiceException(
                code="InvalidVpcPeeringConnectionID.NotFound",
                message=(
                    f"The vpcPeeringConnection ID '{pcx_id}' does not exist"
                ),
                status_code=400,
            )
        state_code = getattr(getattr(pcx, "_status", None), "code", None)
        if state_code != "active":
            raise CommonServiceException(
                code="InvalidStateTransition",
                message=(
                    f"The VPC peering connection {pcx_id} is in state "
                    f"'{state_code}'; options can only be modified when active"
                ),
                status_code=400,
            )
        return call_moto(context)

    @handler("DeleteVpcPeeringConnection", expand=False)
    def delete_vpc_peering_connection(self, context: RequestContext, request: dict) -> dict:
        # Pre-check: reject a second delete with NotFound (real AWS does).
        # Moto accepts repeated deletes silently, which breaks idempotency
        # expectations the other way round (client thinks nothing changed).
        from moto.ec2.models import ec2_backends
        peering_id = context.request.values.get("VpcPeeringConnectionId", "") or ""
        be = ec2_backends.get(context.account_id, {}).get(context.region)
        pcx = getattr(be, "vpc_pcxs", {}).get(peering_id) if be else None
        state_code = getattr(getattr(pcx, "_status", None), "code", None) if pcx else None
        if pcx is None or state_code in ("deleted", "rejected", "failed"):
            raise CommonServiceException(
                code="InvalidVpcPeeringConnectionID.NotFound",
                message=(
                    f"The vpcPeeringConnection ID '{peering_id}' does not exist"
                ),
                status_code=400,
            )

        result = call_moto(context)

        if peering_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                get_vpc_network_manager().delete_peering(peering_id)
            except Exception as e:
                LOG.debug("VPC peering Docker teardown skipped for %s: %s", peering_id, e)

        return result

    # ------------------------------------------------------------------
    # NAT Gateway — Docker container bridging private to internet
    # ------------------------------------------------------------------

    @handler("CreateNatGateway", expand=False)
    def create_nat_gateway(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)

        nat_gw = result.get("NatGateway", {})
        nat_id = nat_gw.get("NatGatewayId")
        subnet_id = nat_gw.get("SubnetId")

        if nat_id and subnet_id:
            try:
                from localemu.services.ec2.docker.nat_gateway import get_nat_gateway_manager
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager

                vpc_id = get_vpc_network_manager().get_vpc_id_for_subnet(
                    subnet_id, context.account_id, context.region
                )
                if vpc_id:
                    get_nat_gateway_manager().create_nat_gateway(nat_id, vpc_id, subnet_id)
            except Exception as e:
                LOG.debug("NAT Gateway Docker setup skipped for %s: %s", nat_id, e)

        return result

    @handler("DeleteNatGateway", expand=False)
    def delete_nat_gateway(self, context: RequestContext, request: dict) -> dict:
        nat_id = context.request.values.get("NatGatewayId", "")
        result = call_moto(context)

        if nat_id:
            try:
                from localemu.services.ec2.docker.nat_gateway import get_nat_gateway_manager
                get_nat_gateway_manager().delete_nat_gateway(nat_id)
            except Exception as e:
                LOG.debug("NAT Gateway Docker teardown skipped for %s: %s", nat_id, e)

        return result

    # ------------------------------------------------------------------
    # VPC Endpoints — proxy container for private network access
    # ------------------------------------------------------------------

    @handler("CreateVpcEndpoint", expand=False)
    def create_vpc_endpoint(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)

        endpoint = result.get("VpcEndpoint", {})
        endpoint_id = endpoint.get("VpcEndpointId")
        vpc_id = endpoint.get("VpcId")
        service_name = endpoint.get("ServiceName", "")

        if endpoint_id and vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_endpoint import get_vpc_endpoint_manager
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager

                # Only create proxy if VPC has a Docker network
                if get_vpc_network_manager().get_network_for_vpc(vpc_id):
                    proxy_ip = get_vpc_endpoint_manager().create_endpoint(
                        endpoint_id, vpc_id, service_name,
                    )
                    if proxy_ip:
                        # Add proxy IP to the response for the user
                        endpoint.setdefault("DnsEntries", []).append({
                            "DnsName": proxy_ip,
                            "HostedZoneId": "Z1LOCALEMU",
                        })
            except Exception as e:
                LOG.debug("VPC Endpoint Docker setup skipped for %s: %s", endpoint_id, e)

        return result

    @handler("DeleteVpcEndpoints", expand=False)
    def delete_vpc_endpoints(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)

        # Extract endpoint IDs from request
        i = 1
        while f"VpcEndpointId.{i}" in context.request.values:
            endpoint_id = context.request.values[f"VpcEndpointId.{i}"]
            try:
                from localemu.services.ec2.docker.vpc_endpoint import get_vpc_endpoint_manager
                get_vpc_endpoint_manager().delete_endpoint(endpoint_id)
            except Exception:
                pass
            i += 1

        return result

    @handler("CreateKeyPair", expand=False)
    def create_key_pair(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        key_material = result.get("KeyMaterial", "")
        key_name = result.get("KeyName", "")
        if key_material and key_name:
            try:
                private_key = load_pem_private_key(key_material.encode(), password=None)
                public_key_bytes = private_key.public_key().public_bytes(
                    encoding=Encoding.OpenSSH,
                    format=PublicFormat.OpenSSH,
                )
                with _key_pair_lock:
                    _key_pair_public_keys[
                        (context.account_id, context.region, key_name)
                    ] = public_key_bytes.decode()
                LOG.debug("Stored public key for key pair %s", key_name)
            except Exception as e:
                LOG.warning("Failed to derive public key from CreateKeyPair %s: %s", key_name, e)
        return result

    @handler("ImportKeyPair", expand=False)
    def import_key_pair(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        key_name = result.get("KeyName", "") or context.request.values.get("KeyName", "")
        # The public key material is sent base64-encoded in the request
        pub_key_b64 = context.request.values.get("PublicKeyMaterial", "")
        if key_name and pub_key_b64:
            try:
                public_key_str = base64.b64decode(pub_key_b64).decode("utf-8").strip()
                with _key_pair_lock:
                    _key_pair_public_keys[
                        (context.account_id, context.region, key_name)
                    ] = public_key_str
                LOG.debug("Stored imported public key for key pair %s", key_name)
            except Exception as e:
                LOG.warning("Failed to store imported public key for %s: %s", key_name, e)
        return result

    @handler("DeleteKeyPair", expand=False)
    def delete_key_pair(self, context: RequestContext, request: dict) -> dict:
        key_name = context.request.values.get("KeyName", "")
        result = call_moto(context)
        if key_name:
            with _key_pair_lock:
                _key_pair_public_keys.pop(
                    (context.account_id, context.region, key_name), None
                )
            LOG.debug("Removed stored public key for key pair %s", key_name)
        return result

    # ------------------------------------------------------------------
    # EIP data plane handlers — make EIPs actually route to containers.
    # Closes the "a user can run nginx in EC2 but can't reach it from
    # their host machine" foundation gap.
    # ------------------------------------------------------------------

    @handler("AllocateAddress", expand=False)
    def allocate_address(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        public_ip = result.get("PublicIp")
        allocation_id = result.get("AllocationId")
        if public_ip and allocation_id:
            from localemu.services.ec2.eip import get_eip_store
            get_eip_store(
                context.account_id, context.region or "us-east-1",
            ).register_allocation(allocation_id, public_ip)
        return result

    @handler("AssociateAddress", expand=False)
    def associate_address(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        allocation_id = request.get("AllocationId")
        instance_id = request.get("InstanceId")
        public_ip = request.get("PublicIp")
        association_id = result.get("AssociationId")
        region = context.region or "us-east-1"
        account_id = context.account_id

        from localemu.services.ec2.eip import (
            EipAssociation, get_eip_data_plane, get_eip_store,
        )
        store = get_eip_store(account_id, region)
        if not public_ip and allocation_id:
            public_ip = store.allocations.get(allocation_id)
        if not (public_ip and instance_id):
            return result

        # Resolve container_name + SGs from the live vm manager.
        # v2 data plane uses ``docker exec`` into the container, so we
        # don't need a bridge IP — just the container name.
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_active_vm_manager,
            )
            mgr = get_active_vm_manager()
            info = mgr.get_instance_info(instance_id) if mgr else None
        except Exception:
            info = None

        container_name = info.container_name if info is not None else None

        sg_ids: list[str] = []
        try:
            backend = get_moto_backend(context)
            inst = backend.get_instance(instance_id)
            sg_ids = [sg.id for sg in (inst.security_groups or [])]
        except Exception:
            LOG.debug(
                "AssociateAddress: SG lookup failed for %s",
                instance_id, exc_info=True,
            )

        assoc = EipAssociation(
            allocation_id=allocation_id or public_ip,
            public_ip=public_ip,
            instance_id=instance_id,
            association_id=association_id or public_ip,
            container_name=container_name,
        )
        store.register_association(assoc)

        if container_name:
            try:
                get_eip_data_plane().attach(
                    public_ip=public_ip, instance_id=instance_id,
                    container_name=container_name,
                    sg_ids=sg_ids, account_id=account_id, region=region,
                )
                LOG.info(
                    "EIP %s associated to %s (container=%s sgs=%s)",
                    public_ip, instance_id, container_name, sg_ids,
                )
            except Exception:
                LOG.warning(
                    "EIP %s associate: data plane attach failed",
                    public_ip, exc_info=True,
                )
        else:
            LOG.warning(
                "EIP %s associate: instance %s has no Docker container; "
                "metadata-only association",
                public_ip, instance_id,
            )
        return result

    @handler("DisassociateAddress", expand=False)
    def disassociate_address(
        self, context: RequestContext, request: dict,
    ) -> dict:
        association_id = request.get("AssociationId")
        public_ip = request.get("PublicIp")
        region = context.region or "us-east-1"

        from localemu.services.ec2.eip import (
            get_eip_data_plane, get_eip_store,
        )
        store = get_eip_store(context.account_id, region)
        target_ip = public_ip
        if association_id and target_ip is None:
            assoc = store.associations.get(association_id)
            if assoc:
                target_ip = assoc.public_ip
        if target_ip:
            get_eip_data_plane().detach(target_ip)
            store.drop_association(association_id or target_ip)

        return call_moto(context)

    @handler("ReleaseAddress", expand=False)
    def release_address(self, context: RequestContext, request: dict) -> dict:
        allocation_id = request.get("AllocationId")
        public_ip = request.get("PublicIp")
        region = context.region or "us-east-1"

        from localemu.services.ec2.eip import (
            get_eip_data_plane, get_eip_store,
        )
        store = get_eip_store(context.account_id, region)
        target_ip = public_ip
        if allocation_id and target_ip is None:
            target_ip = store.allocations.get(allocation_id)
        if target_ip:
            assoc = store.by_ip(target_ip)
            if assoc:
                get_eip_data_plane().detach(target_ip)
                store.drop_association(assoc.association_id or assoc.allocation_id)
            if allocation_id:
                store.drop_allocation(allocation_id)
        return call_moto(context)

    @handler("DescribeAddresses", expand=False)
    def describe_addresses(self, context: RequestContext, request: dict) -> dict:
        """Enrich moto's response with LocalEmu host-port mapping tags
        so ``aws ec2 describe-addresses`` shows the user where to
        ``curl`` on the proxy path. On the DNAT path the EIP itself
        is reachable directly, so the map stays empty."""
        result = call_moto(context)
        from localemu.services.ec2.eip import (
            get_eip_data_plane, get_eip_store,
        )
        store = get_eip_store(
            context.account_id, context.region or "us-east-1",
        )
        for addr in result.get("Addresses", []) or []:
            ip = addr.get("PublicIp")
            if not ip:
                continue
            assoc = store.by_ip(ip)
            if assoc is None:
                continue
            tags = list(addr.get("Tags") or [])
            for cport, hport in (assoc.proxies or {}).items():
                tags.append({
                    "Key": f"localemu:HostPort:{cport}",
                    "Value": f"127.0.0.1:{hport}",
                })
            addr["Tags"] = tags
        return result

    @handler("DescribeInstances", expand=False)
    def describe_instances(self, context: RequestContext, request: dict) -> dict:
        result = call_moto(context)
        if self._vm_manager:
            for reservation in result.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    info = self._vm_manager.get_instance_info(inst.get("InstanceId"))
                    if info and info.ssh_port:
                        inst.setdefault("Tags", []).append(
                            {"Key": "localemu:ssh-port", "Value": str(info.ssh_port)}
                        )
                        # Only fall back to the 127.0.0.1 + host-port story
                        # when no Elastic IP has been associated. With an
                        # EIP attached, moto's response already carries the
                        # real public IP on the primary ENI; clobbering it
                        # would hide the user's association from
                        # DescribeInstances and break the
                        # public-ip-in-IMDS contract.
                        if not inst.get("PublicIpAddress"):
                            inst["PublicDnsName"] = "localhost"
                            inst["PublicIpAddress"] = "127.0.0.1"
        return result

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.ec2.models import ec2_backends

        visitor.visit(ec2_backends)

    @handler("RunInstances", expand=False)
    def run_instances(self, context: RequestContext, request: dict) -> dict:
        # Let moto create the state record first
        result = call_moto(context)

        # If Docker backend is enabled, create containers for each instance
        if self._vm_manager and result.get("Instances"):
            for instance in result["Instances"]:
                instance_id = instance.get("InstanceId")
                ami_id = instance.get("ImageId", "ami-ubuntu-22.04")
                instance_type = instance.get("InstanceType", "t2.micro")
                key_name = instance.get("KeyName")

                # Extract user data from the original request
                user_data = context.request.values.get("UserData")

                # Look up the public key for SSH injection
                public_key = None
                if key_name:
                    public_key = get_public_key_for_keypair(
                        context.account_id, context.region, key_name
                    )
                    if not public_key:
                        LOG.warning(
                            "No public key found for key pair %s - SSH will not be available",
                            key_name,
                        )

                # Extract security group IDs from moto response
                sg_ids = [
                    sg.get("GroupId", "") for sg in instance.get("SecurityGroups", [])
                    if sg.get("GroupId")
                ]

                # Extract IAM instance profile from Moto response
                iam_profile = instance.get("IamInstanceProfile", {})
                iam_profile_arn = iam_profile.get("Arn", "")
                iam_role_name = None
                if iam_profile_arn:
                    # Resolve the role attached to this instance profile via Moto
                    try:
                        from moto.iam.models import iam_backends
                        iam_backend = iam_backends[context.account_id]["global"]
                        profile_name = iam_profile_arn.split("/")[-1]
                        profile = iam_backend.instance_profiles.get(profile_name)
                        if profile and profile.roles:
                            iam_role_name = profile.roles[0].name
                    except Exception as e:
                        LOG.debug("Could not resolve IAM role from instance profile: %s", e)

                # Resolve VPC → Docker network for real network isolation.
                #
                # ``get_network_for_instance`` returns a network name only
                # when a real Docker bridge backs the VPC. If the instance
                # is destined for a VPC (has VpcId, SubnetId, or an ENI
                # tied to one) but no bridge could be created — e.g. all
                # fallback CIDR pools exhausted by leftover networks from
                # prior sessions — we must fail this RunInstances call
                # loudly rather than let ``vm_manager`` silently land the
                # container on Docker's default bridge. That silent path
                # produced "instance running but on 172.17/16, TGW can't
                # reach it" symptoms that surfaced far downstream as a
                # connectivity failure with no traceable cause.
                vpc_network = None
                intended_vpc_id = (
                    instance.get("VpcId")
                    or next(
                        (
                            n.get("VpcId")
                            for n in instance.get("NetworkInterfaces", [])
                            if n.get("VpcId")
                        ),
                        None,
                    )
                )
                from localemu.aws.api import CommonServiceException

                try:
                    from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                    vpc_mgr = get_vpc_network_manager()
                    vpc_network = vpc_mgr.get_network_for_instance(
                        instance, context.account_id, context.region,
                    )
                    if intended_vpc_id and not vpc_network:
                        # Distinguish "VPC genuinely unknown to moto" (no-op)
                        # from "we wanted to create the bridge and could not".
                        # Only the latter is a runnable-loud failure.
                        if not vpc_mgr.is_network_ready(intended_vpc_id):
                            raise CommonServiceException(
                                "InternalError",
                                (
                                    f"LocalEmu could not allocate a Docker "
                                    f"network for VPC {intended_vpc_id}. "
                                    "All fallback CIDR pools are exhausted "
                                    "on this host. Stop LocalEmu, run "
                                    "`docker network prune`, then restart."
                                ),
                                status_code=500,
                            )
                except CommonServiceException:
                    raise
                except Exception:
                    pass

                instance_subnet_id = instance.get("SubnetId") or next(
                    (
                        n.get("SubnetId")
                        for n in instance.get("NetworkInterfaces", [])
                        if n.get("SubnetId")
                    ),
                    None,
                )

                try:
                    info = self._vm_manager.create_instance(
                        instance_id=instance_id,
                        ami_id=ami_id,
                        instance_type=instance_type,
                        key_name=key_name,
                        user_data=user_data,
                        public_key=public_key,
                        security_groups=sg_ids,
                        subnet_id=instance_subnet_id,
                        account_id=context.account_id,
                        region=context.region,
                        iam_instance_profile_arn=iam_profile_arn,
                        iam_role_name=iam_role_name,
                        vpc_network=vpc_network,
                    )
                    # Add SSH port info to the instance metadata
                    if info.ssh_port:
                        instance.setdefault("Tags", []).append(
                            {"Key": "localemu:ssh-port", "Value": str(info.ssh_port)}
                        )
                except Exception as e:
                    LOG.warning("Failed to create Docker container for %s: %s", instance_id, e)
                    # Clean up any partially created container
                    try:
                        from localemu.utils.docker_utils import DOCKER_CLIENT as _dc
                        _dc.remove_container(f"localemu-ec2-{instance_id}", force=True)
                    except Exception:
                        pass

        return result

    @handler("TerminateInstances", expand=False)
    def terminate_instances(self, context: RequestContext, request: dict) -> dict:
        # Extract instance IDs before moto processes them
        instance_ids = []
        i = 1
        while f"InstanceId.{i}" in context.request.values:
            instance_ids.append(context.request.values[f"InstanceId.{i}"])
            i += 1

        # Capture which ASGs (if any) each instance currently belongs
        # to. moto's autoscaling backend hooks ec2_backend.terminate_
        # instances to refill the group; we need to drive our reconciler
        # AFTER moto refills so the new replacement instance IDs get
        # real Docker containers.
        affected_groups: set[str] = set()
        try:
            backend = get_ec2_backend(context.account_id, context.region)
            for iid in instance_ids:
                inst = backend.get_instance_by_id(iid)
                if inst is None:
                    continue
                asg = getattr(inst, "autoscaling_group", None)
                if asg is not None:
                    name = getattr(asg, "name", None)
                    if name:
                        affected_groups.add(name)
        except Exception:
            LOG.debug(
                "TerminateInstances: ASG affinity lookup failed",
                exc_info=True,
            )

        # Let moto update the state (this is what fires moto's
        # notify_terminate_instances → ASG.replace_autoscaling_group
        # _instances if the desired-capacity invariant requires it).
        result = call_moto(context)

        # Terminate Docker containers for the explicitly-named IDs
        if self._vm_manager:
            for instance_id in instance_ids:
                try:
                    self._vm_manager.terminate_instance(instance_id)
                except Exception as e:
                    LOG.debug("Failed to terminate Docker container for %s: %s", instance_id, e)

        # For every ASG that had one of its members terminated, walk
        # the new moto state and launch real containers for any
        # replacement instance IDs moto allocated.
        if affected_groups:
            try:
                from localemu.services.autoscaling import reconciler as _asg_reconciler
                for group_name in affected_groups:
                    _asg_reconciler.sync(
                        context.account_id, context.region, group_name,
                        vm_manager=self._vm_manager,
                    )
            except Exception:
                LOG.debug(
                    "TerminateInstances: ASG reconciler bridge failed",
                    exc_info=True,
                )

        return result

    @handler("StopInstances", expand=False)
    def stop_instances(self, context: RequestContext, request: dict) -> dict:
        instance_ids = []
        i = 1
        while f"InstanceId.{i}" in context.request.values:
            instance_ids.append(context.request.values[f"InstanceId.{i}"])
            i += 1

        result = call_moto(context)

        if self._vm_manager:
            for instance_id in instance_ids:
                try:
                    self._vm_manager.stop_instance(instance_id)
                except Exception as e:
                    LOG.debug("Failed to stop Docker container for %s: %s", instance_id, e)

        return result

    @handler("StartInstances", expand=False)
    def start_instances(self, context: RequestContext, request: dict) -> dict:
        instance_ids = []
        i = 1
        while f"InstanceId.{i}" in context.request.values:
            instance_ids.append(context.request.values[f"InstanceId.{i}"])
            i += 1

        result = call_moto(context)

        if self._vm_manager:
            for instance_id in instance_ids:
                try:
                    self._vm_manager.start_instance(instance_id)
                except Exception as e:
                    LOG.debug("Failed to start Docker container for %s: %s", instance_id, e)

        return result

    @handler("RebootInstances", expand=False)
    def reboot_instances(self, context: RequestContext, request: dict) -> dict:
        """Reboot one or more EC2 instances via Docker restart.

        Previously raised NotImplementedError from the base-class stub
        because no handler existed. Now wires to
        ``DockerVmManager.reboot_instance`` which calls Docker
        restart_container — the host port mapping, the container's
        IPAM assignment, the SG/NACL iptables, and the writable layer
        all survive across the restart because the netns is preserved.

        moto's RebootInstances does NOT change state machine (the
        instance stays 'running' across reboot), so the moto pass-through
        is just for parity with describe-instances response shape.
        """
        instance_ids = []
        i = 1
        while f"InstanceId.{i}" in context.request.values:
            instance_ids.append(context.request.values[f"InstanceId.{i}"])
            i += 1

        backend = get_ec2_backend(context.account_id, context.region)
        for instance_id in instance_ids:
            if backend.get_instance_by_id(instance_id) is None:
                raise InvalidInstanceIdError(instance_id)

        try:
            result = call_moto(context)
        except Exception:
            result = {}

        if self._vm_manager:
            for instance_id in instance_ids:
                try:
                    self._vm_manager.reboot_instance(instance_id)
                except Exception as e:
                    LOG.debug(
                        "Failed to reboot Docker container for %s: %s",
                        instance_id, e,
                    )

        return result

    @handler("GetConsoleOutput", expand=False)
    def get_console_output(self, context: RequestContext, request: dict) -> dict:
        instance_id = context.request.values.get("InstanceId")

        if self._vm_manager and instance_id:
            output = self._vm_manager.get_console_output(instance_id)
            if output:
                import base64
                return {
                    "InstanceId": instance_id,
                    "Output": base64.b64encode(output.encode()).decode(),
                    "Timestamp": datetime.now(UTC).isoformat(),
                }

        return call_moto(context)

    @handler("DescribeAvailabilityZones", expand=False)
    def describe_availability_zones(
        self,
        context: RequestContext,
        describe_availability_zones_request: DescribeAvailabilityZonesRequest,
    ) -> DescribeAvailabilityZonesResult:
        backend = get_ec2_backend(context.account_id, context.region)
        zone_names = describe_availability_zones_request.get("ZoneNames")
        zone_ids = describe_availability_zones_request.get("ZoneIds")
        if zone_names or zone_ids:
            filtered_zones = backend.describe_availability_zones(
                zone_names=zone_names, zone_ids=zone_ids
            )
            availability_zones = [
                AvailabilityZone(
                    State="available",
                    Messages=[],
                    RegionName=zone.region_name,
                    ZoneName=zone.name,
                    ZoneId=zone.zone_id,
                    ZoneType=zone.zone_type,
                )
                for zone in filtered_zones
            ]
            return DescribeAvailabilityZonesResult(AvailabilityZones=availability_zones)
        return call_moto(context)

    @handler("DescribeReservedInstancesOfferings", expand=False)
    def describe_reserved_instances_offerings(
        self,
        context: RequestContext,
        describe_reserved_instances_offerings_request: DescribeReservedInstancesOfferingsRequest,
    ) -> DescribeReservedInstancesOfferingsResult:
        return DescribeReservedInstancesOfferingsResult(
            ReservedInstancesOfferings=[
                ReservedInstancesOffering(
                    AvailabilityZone="eu-central-1a",
                    Duration=2628000,
                    FixedPrice=0.0,
                    InstanceType=InstanceType.t2_small,
                    ProductDescription=RIProductDescription.Linux_UNIX,
                    ReservedInstancesOfferingId=long_uid(),
                    UsagePrice=0.0,
                    CurrencyCode=CurrencyCodeValues.USD,
                    InstanceTenancy=Tenancy.default,
                    Marketplace=True,
                    PricingDetails=[PricingDetail(Price=0.0, Count=3)],
                    RecurringCharges=[
                        RecurringCharge(Amount=0.25, Frequency=RecurringChargeFrequency.Hourly)
                    ],
                    Scope=scope.Availability_Zone,
                )
            ]
        )

    @handler("DescribeReservedInstances", expand=False)
    def describe_reserved_instances(
        self,
        context: RequestContext,
        describe_reserved_instances_request: DescribeReservedInstancesRequest,
    ) -> DescribeReservedInstancesResult:
        return DescribeReservedInstancesResult(
            ReservedInstances=[
                ReservedInstances(
                    AvailabilityZone="eu-central-1a",
                    Duration=2628000,
                    End=datetime(2016, 6, 30, tzinfo=UTC),
                    FixedPrice=0.0,
                    InstanceCount=2,
                    InstanceType=InstanceType.t2_small,
                    ProductDescription=RIProductDescription.Linux_UNIX,
                    ReservedInstancesId=long_uid(),
                    Start=datetime(2016, 1, 1, tzinfo=UTC),
                    State=ReservedInstanceState.active,
                    UsagePrice=0.05,
                    CurrencyCode=CurrencyCodeValues.USD,
                    InstanceTenancy=Tenancy.default,
                    OfferingClass=OfferingClassType.standard,
                    OfferingType=OfferingTypeValues.Partial_Upfront,
                    RecurringCharges=[
                        RecurringCharge(Amount=0.05, Frequency=RecurringChargeFrequency.Hourly)
                    ],
                    Scope=scope.Availability_Zone,
                )
            ]
        )

    @handler("PurchaseReservedInstancesOffering", expand=False)
    def purchase_reserved_instances_offering(
        self,
        context: RequestContext,
        purchase_reserved_instances_offerings_request: PurchaseReservedInstancesOfferingRequest,
    ) -> PurchaseReservedInstancesOfferingResult:
        return PurchaseReservedInstancesOfferingResult(
            ReservedInstancesId=long_uid(),
        )

    @handler("ModifyVpcEndpoint")
    def modify_vpc_endpoint(
        self,
        context: RequestContext,
        vpc_endpoint_id: VpcEndpointId,
        dry_run: Boolean = None,
        reset_policy: Boolean = None,
        policy_document: String = None,
        add_route_table_ids: VpcEndpointRouteTableIdList = None,
        remove_route_table_ids: VpcEndpointRouteTableIdList = None,
        add_subnet_ids: VpcEndpointSubnetIdList = None,
        remove_subnet_ids: VpcEndpointSubnetIdList = None,
        add_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        remove_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        ip_address_type: IpAddressType = None,
        dns_options: DnsOptionsSpecification = None,
        private_dns_enabled: Boolean = None,
        subnet_configurations: SubnetConfigurationsList = None,
        **kwargs,
    ) -> ModifyVpcEndpointResult:
        backend = get_ec2_backend(context.account_id, context.region)

        vpc_endpoint = backend.vpc_end_points.get(vpc_endpoint_id)
        if not vpc_endpoint:
            raise InvalidVpcEndPointIdError(vpc_endpoint_id)

        if policy_document is not None:
            vpc_endpoint.policy_document = policy_document

        if add_route_table_ids is not None:
            vpc_endpoint.route_table_ids.extend(add_route_table_ids)

        if remove_route_table_ids is not None:
            vpc_endpoint.route_table_ids = [
                id_ for id_ in vpc_endpoint.route_table_ids if id_ not in remove_route_table_ids
            ]

        if add_subnet_ids is not None:
            vpc_endpoint.subnet_ids.extend(add_subnet_ids)

        if remove_subnet_ids is not None:
            vpc_endpoint.subnet_ids = [
                id_ for id_ in vpc_endpoint.subnet_ids if id_ not in remove_subnet_ids
            ]

        if private_dns_enabled is not None:
            vpc_endpoint.private_dns_enabled = private_dns_enabled

        return ModifyVpcEndpointResult(Return=True)

    @handler("ModifySubnetAttribute", expand=False)
    def modify_subnet_attribute(
        self, context: RequestContext, request: ModifySubnetAttributeRequest
    ) -> None:
        try:
            return call_moto(context)
        except Exception as e:
            if not isinstance(e, ResponseParserError) and "InvalidParameterValue" not in str(e):
                raise

            backend = get_ec2_backend(context.account_id, context.region)

            # fix setting subnet attributes currently not supported upstream
            subnet_id = request["SubnetId"]
            host_type = request.get("PrivateDnsHostnameTypeOnLaunch")
            a_record_on_launch = request.get("EnableResourceNameDnsARecordOnLaunch")
            aaaa_record_on_launch = request.get("EnableResourceNameDnsAAAARecordOnLaunch")
            enable_dns64 = request.get("EnableDns64")

            if host_type:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"HostnameType": host_type}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            ## explicitly checking None value as this could contain a False value
            if aaaa_record_on_launch is not None:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"EnableResourceNameDnsAAAARecord": aaaa_record_on_launch["Value"]}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            if a_record_on_launch is not None:
                attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
                value = {"EnableResourceNameDnsARecord": a_record_on_launch["Value"]}
                backend.modify_subnet_attribute(subnet_id, attr_name, value)
            if enable_dns64 is not None:
                attr_name = camelcase_to_underscores("EnableDns64")
                backend.modify_subnet_attribute(subnet_id, attr_name, enable_dns64["Value"])

    @handler("CreateSubnet", expand=False)
    def create_subnet(
        self, context: RequestContext, request: CreateSubnetRequest
    ) -> CreateSubnetResult:
        response = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        subnet_id = response["Subnet"]["SubnetId"]
        host_type = request.get("PrivateDnsHostnameTypeOnLaunch", "ip-name")
        attr_name = camelcase_to_underscores("PrivateDnsNameOptionsOnLaunch")
        value = {"HostnameType": host_type}
        backend.modify_subnet_attribute(subnet_id, attr_name, value)
        # Register the subnet with the IPv4 allocator when the addressing
        # redesign is enabled. Best-effort: failures are logged and never
        # block the API response (the reconciler will recover on next
        # restart, or vm_manager will register lazily on first launch).
        _register_subnet_with_allocator(response.get("Subnet", {}))
        return response

    @handler("DeleteSubnet", expand=False)
    def delete_subnet(
        self, context: RequestContext, request: dict,
    ) -> dict:
        subnet_id = request.get("SubnetId")
        response = call_moto(context)
        _unregister_subnet_from_allocator(
            context.account_id, context.region, subnet_id,
        )
        return response

    # ------------------------------------------------------------------
    # ENI (Elastic Network Interface) lifecycle handlers
    # ------------------------------------------------------------------
    # Each handler:
    #   1. Calls call_moto so moto remains the authoritative metadata store
    #   2. If LOCALEMU_ENI_REAL (+ LOCALEMU_VPC_IP_PINNING prereq) is on,
    #      delegates the Docker-side work to EniManager
    #   3. Translates EniManager errors to AWS-shape CommonServiceException
    # Off-path (flag off): identical to today's pure-moto behavior.

    @handler("CreateNetworkInterface", expand=False)
    def create_network_interface(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        if not _eni_real_enabled():
            return result
        eni = result.get("NetworkInterface") or {}
        eni_id = eni.get("NetworkInterfaceId")
        subnet_id = eni.get("SubnetId")
        vpc_id = eni.get("VpcId")
        sg_ids = [
            g.get("GroupId") for g in (eni.get("Groups") or [])
            if isinstance(g, dict) and g.get("GroupId")
        ]
        requested_ip = request.get("PrivateIpAddress")
        if not (eni_id and subnet_id and vpc_id):
            return result
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            ip, mac = get_eni_manager().create(
                eni_id=eni_id, vpc_id=vpc_id, subnet_id=subnet_id,
                sg_ids=sg_ids, requested_ip=requested_ip,
                delete_on_termination=False,  # AWS default for standalone
            )
        except Exception as exc:
            # Roll back moto's creation so the user doesn't see a half-baked ENI
            try:
                from localemu.services.ec2.docker.eni_manager import (
                    EniManagerError,
                )
                if isinstance(exc, EniManagerError):
                    self._call_moto_op(
                        context, "DeleteNetworkInterface",
                        {"NetworkInterfaceId": eni_id},
                    )
            except Exception:
                LOG.warning(
                    "CreateNetworkInterface: moto rollback failed for %s",
                    eni_id, exc_info=True,
                )
            raise _translate_eni_error(exc)
        # Patch moto's record with our allocator-issued IP + derived MAC
        _patch_moto_eni(eni_id, primary_ip=str(ip), mac=mac)
        # Update the response shape too
        eni["PrivateIpAddress"] = str(ip)
        eni["MacAddress"] = mac
        # Preserve moto-allocated secondary IPs (from SecondaryPrivateIpAddressCount
        # or explicit PrivateIpAddresses). Replace the primary entry's IP
        # with our allocator-issued value but keep secondaries intact, and
        # register them with the EniManager so they're real in the data plane.
        existing_addrs = eni.get("PrivateIpAddresses") or []
        secondary_addrs = [
            a for a in existing_addrs
            if isinstance(a, dict) and not a.get("Primary")
            and a.get("PrivateIpAddress")
        ]
        eni["PrivateIpAddresses"] = [
            {"Primary": True, "PrivateIpAddress": str(ip)},
            *secondary_addrs,
        ]
        secondary_ips = [a["PrivateIpAddress"] for a in secondary_addrs]
        if secondary_ips:
            try:
                from localemu.services.ec2.docker.eni_manager import (
                    get_eni_manager,
                )
                get_eni_manager().assign_private_ips(
                    eni_id=eni_id, explicit_ips=secondary_ips,
                )
            except Exception as exc:
                LOG.warning(
                    "CreateNetworkInterface: failed to register secondaries "
                    "for %s in EniManager: %s", eni_id, exc, exc_info=True,
                )
        return result

    @handler("AttachNetworkInterface", expand=False)
    def attach_network_interface(
        self, context: RequestContext, request: dict,
    ) -> dict:
        eni_id = request.get("NetworkInterfaceId")
        instance_id = request.get("InstanceId")
        try:
            device_index = int(request.get("DeviceIndex") or 1)
        except (TypeError, ValueError):
            device_index = 1
        result = call_moto(context)
        if not (_eni_real_enabled() and self._vm_manager and eni_id and instance_id):
            return result
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            get_eni_manager().attach(
                eni_id=eni_id, instance_id=instance_id,
                device_index=device_index,
            )
        except Exception as exc:
            # Roll back moto's attachment
            attachment_id = result.get("AttachmentId")
            if attachment_id:
                try:
                    self._call_moto_op(
                        context, "DetachNetworkInterface",
                        {"AttachmentId": attachment_id, "Force": True},
                    )
                except Exception:
                    LOG.warning(
                        "AttachNetworkInterface: moto rollback failed for %s",
                        eni_id, exc_info=True,
                    )
            raise _translate_eni_error(exc)
        return result

    @handler("DetachNetworkInterface", expand=False)
    def detach_network_interface(
        self, context: RequestContext, request: dict,
    ) -> dict:
        # Look up the eni_id from the attachment_id BEFORE moto removes it
        attachment_id = request.get("AttachmentId")
        eni_id_for_detach = None
        if _eni_real_enabled() and attachment_id:
            try:
                import moto.backends as moto_backends
                for _acct, region_map in moto_backends.get_backend("ec2").items():
                    if not isinstance(region_map, dict):
                        continue
                    for _region, backend in region_map.items():
                        for cand_id, eni in (getattr(backend, "enis", {}) or {}).items():
                            if getattr(eni, "attachment_id", None) == attachment_id:
                                eni_id_for_detach = cand_id
                                break
                        if eni_id_for_detach:
                            break
                    if eni_id_for_detach:
                        break
            except Exception:
                LOG.debug("DetachNetworkInterface: eni lookup failed",
                          exc_info=True)
        result = call_moto(context)
        if not (_eni_real_enabled() and eni_id_for_detach):
            return result
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            get_eni_manager().detach(eni_id_for_detach)
        except Exception as exc:
            raise _translate_eni_error(exc)
        return result

    @handler("DeleteNetworkInterface", expand=False)
    def delete_network_interface(
        self, context: RequestContext, request: dict,
    ) -> dict:
        eni_id = request.get("NetworkInterfaceId")
        # ENI must be detached on AWS — let moto enforce the check (it
        # already does). If moto refuses, we never reach the EniManager call.
        if _eni_real_enabled() and eni_id:
            try:
                from localemu.services.ec2.docker.eni_manager import (
                    EniInUse, get_eni_manager,
                )
                get_eni_manager().delete(eni_id)
            except EniInUse as exc:
                raise _translate_eni_error(exc)
            except Exception:
                # Allocator/index drift gets caught by reconciler; do not
                # block the moto delete
                LOG.debug(
                    "DeleteNetworkInterface: EniManager.delete soft-failed",
                    exc_info=True,
                )
        return call_moto(context)

    @handler("DescribeNetworkInterfaces", expand=False)
    def describe_network_interfaces(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        if not _eni_real_enabled():
            return result
        # Enrichment: overwrite mac_address and primary IP from AddressIndex
        # for ENIs we manage. This makes the response honest about the IPs
        # LocalEmu actually pinned (rather than moto's random_private_ip).
        try:
            from localemu.services.ec2.docker.address_index import (
                get_address_index,
            )
            idx = get_address_index()
            for eni in (result.get("NetworkInterfaces") or []):
                eni_id = eni.get("NetworkInterfaceId")
                entry = idx.get_eni(eni_id) if eni_id else None
                if entry is None:
                    continue
                eni["PrivateIpAddress"] = str(entry.primary_ip)
                eni["MacAddress"] = entry.mac
                # PrivateIpAddresses[] — primary + all secondaries
                pias = [{
                    "Primary": True,
                    "PrivateIpAddress": str(entry.primary_ip),
                }]
                for sec in entry.secondary_ips:
                    pias.append({
                        "Primary": False,
                        "PrivateIpAddress": str(sec),
                    })
                eni["PrivateIpAddresses"] = pias
                eni["SourceDestCheck"] = entry.source_dest_check
        except Exception:
            LOG.debug(
                "DescribeNetworkInterfaces: enrichment failed",
                exc_info=True,
            )
        return result

    @staticmethod
    def _call_moto_op(context, op_name, params):
        """Helper for rollback paths: call moto with a different op than
        the current request. Best-effort; logs but never raises."""
        try:
            from localemu.services.moto import call_moto_with_request
            call_moto_with_request(context, op_name, params)
        except Exception:
            LOG.debug(
                "_call_moto_op(%s) failed", op_name, exc_info=True,
            )

    @handler("AssignPrivateIpAddresses", expand=False)
    def assign_private_ip_addresses(
        self, context: RequestContext, request: dict,
    ) -> dict:
        eni_id = request.get("NetworkInterfaceId")
        result = call_moto(context)
        if not (_eni_real_enabled() and eni_id):
            return result
        # AWS request supports either explicit PrivateIpAddresses or a
        # SecondaryPrivateIpAddressCount (auto-pick)
        explicit_ips = (
            request.get("PrivateIpAddresses") or []
        ) if isinstance(request.get("PrivateIpAddresses"), list) else []
        try:
            count = int(request.get("SecondaryPrivateIpAddressCount") or 0)
        except (TypeError, ValueError):
            count = 0
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            assigned = get_eni_manager().assign_private_ips(
                eni_id=eni_id,
                explicit_ips=explicit_ips,
                count=count,
            )
        except Exception as exc:
            # moto already recorded the assignment; ENI-manager failure
            # means kernel-side or allocator-side rejection. Surface as
            # AWS fault and try to roll back moto.
            if explicit_ips:
                try:
                    self._call_moto_op(
                        context, "UnassignPrivateIpAddresses",
                        {"NetworkInterfaceId": eni_id,
                         "PrivateIpAddresses": explicit_ips},
                    )
                except Exception:
                    LOG.debug(
                        "AssignPrivateIpAddresses: moto rollback failed",
                        exc_info=True,
                    )
            raise _translate_eni_error(exc)
        # Patch the response to surface the allocator-issued IPs in the
        # auto-pick case (moto would have invented different ones)
        if count and not explicit_ips and assigned:
            result.setdefault("AssignedPrivateIpAddresses", [])
            result["AssignedPrivateIpAddresses"] = [
                {"PrivateIpAddress": str(ip)} for ip in assigned
            ]
        return result

    @handler("UnassignPrivateIpAddresses", expand=False)
    def unassign_private_ip_addresses(
        self, context: RequestContext, request: dict,
    ) -> dict:
        eni_id = request.get("NetworkInterfaceId")
        result = call_moto(context)
        if not (_eni_real_enabled() and eni_id):
            return result
        ips = request.get("PrivateIpAddresses") or []
        if not isinstance(ips, list) or not ips:
            return result
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            get_eni_manager().unassign_private_ips(
                eni_id=eni_id, ips=ips,
            )
        except Exception as exc:
            raise _translate_eni_error(exc)
        return result

    @handler("ModifyNetworkInterfaceAttribute", expand=False)
    def modify_network_interface_attribute(
        self, context: RequestContext, request: dict,
    ) -> dict:
        eni_id = request.get("NetworkInterfaceId")
        result = call_moto(context)
        if not (_eni_real_enabled() and eni_id):
            return result
        # AWS exposes attributes in three shapes in the request — the
        # API maps each ModifyNetworkInterfaceAttribute call to ONE
        # attribute change. Extract whichever is present.
        groups = None
        source_dest_check = None
        delete_on_termination = None
        # Groups: list field (Groups.N=sg-...)
        if request.get("Groups"):
            groups = list(request["Groups"])
        # SourceDestCheck: {"Value": True|False}
        sdc = request.get("SourceDestCheck")
        if isinstance(sdc, dict) and "Value" in sdc:
            source_dest_check = bool(sdc["Value"])
        elif isinstance(sdc, bool):
            source_dest_check = sdc
        # Attachment: {"AttachmentId": ..., "DeleteOnTermination": bool}
        attachment = request.get("Attachment")
        if isinstance(attachment, dict) and "DeleteOnTermination" in attachment:
            delete_on_termination = bool(attachment["DeleteOnTermination"])
        try:
            from localemu.services.ec2.docker.eni_manager import (
                get_eni_manager,
            )
            get_eni_manager().modify_attribute(
                eni_id=eni_id,
                groups=groups,
                source_dest_check=source_dest_check,
                delete_on_termination=delete_on_termination,
            )
        except Exception as exc:
            raise _translate_eni_error(exc)
        return result

    # ------------------------------------------------------------------
    # Security Group event hooks : re-apply iptables on running
    # EC2 containers whenever moto's rule set changes so the data plane
    # doesn't drift from the control plane.
    # ------------------------------------------------------------------

    @handler("AuthorizeSecurityGroupIngress", expand=False)
    def authorize_security_group_ingress(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_sg_after_change(context, request, op="AuthorizeIngress")
        _refresh_eip_for_sg(context, request)
        return result

    @handler("AuthorizeSecurityGroupEgress", expand=False)
    def authorize_security_group_egress(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_sg_after_change(context, request, op="AuthorizeEgress")
        return result

    @handler("RevokeSecurityGroupIngress", expand=False)
    def revoke_security_group_ingress(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_sg_after_change(context, request, op="RevokeIngress")
        _refresh_eip_for_sg(context, request)
        return result

    @handler("RevokeSecurityGroupEgress", expand=False)
    def revoke_security_group_egress(
        self,
        context: RequestContext,
        revoke_security_group_egress_request: RevokeSecurityGroupEgressRequest,
    ) -> RevokeSecurityGroupEgressResult:
        try:
            result = call_moto(context)
        except Exception as e:
            if "specified rule does not exist" in str(e):
                backend = get_ec2_backend(context.account_id, context.region)
                group_id = revoke_security_group_egress_request["GroupId"]
                group = backend.get_security_group_by_name_or_id(group_id)
                if group and not group.egress_rules:
                    result = RevokeSecurityGroupEgressResult(Return=True)
                else:
                    raise
            else:
                raise
        _reapply_sg_after_change(
            context, revoke_security_group_egress_request, op="RevokeEgress",
        )
        return result

    @handler("ModifyInstanceAttribute", expand=False)
    def modify_instance_attribute(
        self, context: RequestContext, request: dict,
    ) -> dict:
        """Forward to moto. When the attribute being modified is the
        instance's security-group set (``Groups``), refresh iptables on
        the container so the change reflects in the data plane."""
        result = call_moto(context)
        try:
            instance_id = context.request.values.get("InstanceId")
            sg_ids = _extract_indexed_values(context.request.values, "GroupId")
            if instance_id and sg_ids:
                from localemu.services.ec2.docker.sg_reapply import (
                    reapply_sg_for_instance,
                )
                reapply_sg_for_instance(
                    instance_id, context.account_id, context.region, sg_ids,
                )
        except Exception:
            LOG.debug(
                "SG re-apply after ModifyInstanceAttribute failed",
                exc_info=True,
            )
        return result

    # ------------------------------------------------------------------
    # Network ACL event hooks : push iptables refresh to every
    # container in the NACL's subnet whenever an entry is added,
    # replaced, or removed.
    # ------------------------------------------------------------------

    @handler("CreateNetworkAclEntry", expand=False)
    def create_network_acl_entry(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_nacl_for_nacl_id(context)
        return result

    @handler("DeleteNetworkAclEntry", expand=False)
    def delete_network_acl_entry(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_nacl_for_nacl_id(context)
        return result

    @handler("ReplaceNetworkAclEntry", expand=False)
    def replace_network_acl_entry(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        _reapply_nacl_for_nacl_id(context)
        return result

    @handler("ReplaceNetworkAclAssociation", expand=False)
    def replace_network_acl_association(
        self, context: RequestContext, request: dict,
    ) -> dict:
        """Swap a subnet's NACL binding.

        Before this hook existed, moto would record the new association
        but the iptables chain inside the affected containers still
        reflected whichever NACL the subnet started with (typically the
        VPC default's allow-all). With this hook the new NACL's entries
        are rebuilt onto every container in the now-rebound subnet.
        """
        result = call_moto(context)
        _reapply_nacl_for_nacl_id(context)
        return result

    @handler("DescribeSubnets", expand=False)
    def describe_subnets(
        self,
        context: RequestContext,
        request: DescribeSubnetsRequest,
    ) -> DescribeSubnetsResult:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        # add additional/missing attributes in subnet responses
        for subnet in result.get("Subnets", []):
            subnet_obj = backend.subnets[subnet["AvailabilityZone"]].get(subnet["SubnetId"])
            for attr in ADDITIONAL_SUBNET_ATTRS:
                if hasattr(subnet_obj, attr):
                    attr_name = first_char_to_upper(underscores_to_camelcase(attr))
                    if attr_name not in subnet:
                        subnet[attr_name] = getattr(subnet_obj, attr)
        return result

    @handler("CreateTransitGateway", expand=False)
    def create_transit_gateway(
        self,
        context: RequestContext,
        request: CreateTransitGatewayRequest,
    ) -> CreateTransitGatewayResult:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        transit_gateway_id = result["TransitGateway"]["TransitGatewayId"]
        transit_gateway = backend.transit_gateways.get(transit_gateway_id)
        result.get("TransitGateway").get("Options").update(transit_gateway.options)
        # T1: launch the router container for this TGW.
        try:
            from localemu.services.ec2.docker.tgw_network import (
                get_tgw_network_manager,
            )
            get_tgw_network_manager().create_tgw(transit_gateway_id)
        except Exception:
            LOG.debug(
                "TGW router setup skipped for %s", transit_gateway_id,
                exc_info=True,
            )
        return result

    @handler("DescribeTransitGateways", expand=False)
    def describe_transit_gateways(
        self,
        context: RequestContext,
        request: DescribeTransitGatewaysRequest,
    ) -> DescribeTransitGatewaysResult:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        for transit_gateway in result.get("TransitGateways", []):
            transit_gateway_id = transit_gateway["TransitGatewayId"]
            tgw = backend.transit_gateways.get(transit_gateway_id)
            transit_gateway["Options"].update(tgw.options)
        return result

    @handler("DeleteTransitGateway", expand=False)
    def delete_transit_gateway(
        self, context: RequestContext, request: dict,
    ) -> dict:
        tgw_id = context.request.values.get("TransitGatewayId") or ""
        result = call_moto(context)
        try:
            from localemu.services.ec2.docker.tgw_network import (
                get_tgw_network_manager,
            )
            get_tgw_network_manager().delete_tgw(tgw_id)
        except Exception:
            LOG.debug("TGW router teardown skipped for %s", tgw_id, exc_info=True)
        return result

    @handler("CreateTransitGatewayVpcAttachment", expand=False)
    def create_transit_gateway_vpc_attachment(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        att = result.get("TransitGatewayVpcAttachment", {}) or {}
        attachment_id = att.get("TransitGatewayAttachmentId")
        tgw_id = att.get("TransitGatewayId")
        vpc_id = att.get("VpcId")
        state_code = att.get("State")
        if (attachment_id and tgw_id and vpc_id
                and state_code in ("available", "pending-acceptance", "pending")):
            try:
                from localemu.services.ec2.docker.tgw_network import (
                    get_tgw_network_manager,
                )
                # Only same-account same-region attachments become
                # ``available`` automatically; pending-acceptance
                # attachments wait for AcceptTransitGatewayVpcAttachment
                # (T3) which will drive the data-plane attach.
                if state_code == "available":
                    get_tgw_network_manager().create_vpc_attachment(
                        attachment_id, tgw_id, vpc_id,
                    )
            except Exception:
                LOG.debug(
                    "TGW attachment data-plane skipped for %s",
                    attachment_id, exc_info=True,
                )
        return result

    @handler("DeleteTransitGatewayVpcAttachment", expand=False)
    def delete_transit_gateway_vpc_attachment(
        self, context: RequestContext, request: dict,
    ) -> dict:
        attachment_id = context.request.values.get(
            "TransitGatewayAttachmentId",
        ) or ""
        result = call_moto(context)
        try:
            from localemu.services.ec2.docker.tgw_network import (
                get_tgw_network_manager,
            )
            get_tgw_network_manager().delete_vpc_attachment(attachment_id)
        except Exception:
            LOG.debug(
                "TGW attachment teardown skipped for %s",
                attachment_id, exc_info=True,
            )
        return result

    # ------------------------------------------------------------------
    # T3: cross-account Accept / Reject. Moto auto-accepts all VPC
    # attachments; AWS leaves them in ``pendingAcceptance`` when the TGW
    # owner is a different account (or when AutoAcceptSharedAttachments
    # is disabled). We still implement Accept/Reject so a test or a
    # Terraform module that exercises the cross-account path works end
    # to end against LocalEmu.
    # ------------------------------------------------------------------

    @handler("AcceptTransitGatewayVpcAttachment", expand=False)
    def accept_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        request: dict = None,
    ) -> dict:
        attachment_id = (
            context.request.values.get("TransitGatewayAttachmentId") or ""
        )
        backend = get_ec2_backend(context.account_id, context.region)
        att = getattr(backend, "transit_gateway_attachments", {}).get(attachment_id)
        if att is None:
            raise CommonServiceException(
                code="InvalidTransitGatewayAttachmentID.NotFound",
                message=f"TGW attachment {attachment_id} not found",
                status_code=400,
            )
        current = getattr(att, "state", "") or ""
        if current not in ("pendingAcceptance", "pending-acceptance"):
            raise CommonServiceException(
                code="IncorrectState",
                message=(
                    f"{attachment_id} cannot be accepted from state "
                    f"{current!r}; must be pendingAcceptance"
                ),
                status_code=400,
            )
        att.state = "available"
        # Trigger the data-plane attach that was deferred at create time.
        tgw_id = getattr(att, "transit_gateway_id", None)
        vpc_id = (getattr(att, "vpc_id", None)
                  or getattr(att, "resource_id", None))
        if tgw_id and vpc_id:
            try:
                from localemu.services.ec2.docker.tgw_network import (
                    get_tgw_network_manager,
                )
                get_tgw_network_manager().create_vpc_attachment(
                    attachment_id, tgw_id, vpc_id,
                )
            except Exception:
                LOG.debug(
                    "TGW attachment data-plane attach skipped for %s",
                    attachment_id, exc_info=True,
                )
        return {"TransitGatewayVpcAttachment": self._serialize_tgw_vpc_attachment(att)}

    @handler("RejectTransitGatewayVpcAttachment", expand=False)
    def reject_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        request: dict = None,
    ) -> dict:
        attachment_id = (
            context.request.values.get("TransitGatewayAttachmentId") or ""
        )
        backend = get_ec2_backend(context.account_id, context.region)
        att = getattr(backend, "transit_gateway_attachments", {}).get(attachment_id)
        if att is None:
            raise CommonServiceException(
                code="InvalidTransitGatewayAttachmentID.NotFound",
                message=f"TGW attachment {attachment_id} not found",
                status_code=400,
            )
        current = getattr(att, "state", "") or ""
        if current not in ("pendingAcceptance", "pending-acceptance"):
            raise CommonServiceException(
                code="IncorrectState",
                message=(
                    f"{attachment_id} cannot be rejected from state "
                    f"{current!r}; must be pendingAcceptance"
                ),
                status_code=400,
            )
        att.state = "rejected"
        return {"TransitGatewayVpcAttachment": self._serialize_tgw_vpc_attachment(att)}

    @staticmethod
    def _serialize_tgw_vpc_attachment(att) -> dict:
        """Shape-match AWS's TransitGatewayVpcAttachment response."""
        return {
            "TransitGatewayAttachmentId": getattr(att, "id", ""),
            "TransitGatewayId": getattr(att, "transit_gateway_id", ""),
            "VpcId": (getattr(att, "vpc_id", None)
                      or getattr(att, "resource_id", "")),
            "VpcOwnerId": getattr(att, "resource_owner_id", ""),
            "State": getattr(att, "state", "available"),
            "SubnetIds": list(getattr(att, "subnet_ids", []) or []),
            "CreationTime": getattr(att, "create_time", None),
            "Options": dict(getattr(att, "options", {}) or {}),
            "Tags": [
                {"Key": k, "Value": v}
                for k, v in (getattr(att, "get_tags", lambda: {})() or {}).items()
            ],
        }

    # ------------------------------------------------------------------
    # TGW route-table semantics (T2): response shape + propagation +
    # association validation
    # ------------------------------------------------------------------

    @staticmethod
    def _refill_tgw_route_attachments(route: dict, backend) -> None:
        """Moto stores the TGW route's target attachment as a nested
        object under the camelCase key ``transitGatewayAttachments``,
        not a list. The ASF serializer drops that shape silently, so
        callers see ``TransitGatewayAttachments=[]``. Re-fill from the
        moto backend."""
        cidr = route.get("DestinationCidrBlock")
        rt_id = route.get("TransitGatewayRouteTableId")
        # Not all AWS route responses carry rt_id; if absent, skip.
        if not cidr:
            return
        target_att_id = None
        rt = None
        if rt_id:
            rt = getattr(backend, "transit_gateways_route_tables", {}).get(rt_id)
        else:
            for candidate in getattr(
                backend, "transit_gateways_route_tables", {}
            ).values():
                r = (getattr(candidate, "routes", None) or {}).get(cidr)
                if r:
                    rt = candidate
                    break
        if rt is not None:
            raw = (getattr(rt, "routes", None) or {}).get(cidr, {}) or {}
            nested = raw.get("transitGatewayAttachments") \
                or raw.get("TransitGatewayAttachments")
            if isinstance(nested, dict):
                target_att_id = (
                    nested.get("transitGatewayAttachmentId")
                    or nested.get("TransitGatewayAttachmentId")
                )
            elif isinstance(nested, list) and nested:
                first = nested[0]
                if isinstance(first, dict):
                    target_att_id = (
                        first.get("TransitGatewayAttachmentId")
                        or first.get("transitGatewayAttachmentId")
                    )
        if not target_att_id:
            route["TransitGatewayAttachments"] = []
            return
        att = getattr(backend, "transit_gateway_attachments", {}).get(target_att_id)
        if not att:
            route["TransitGatewayAttachments"] = []
            return
        route["TransitGatewayAttachments"] = [{
            "ResourceId": getattr(att, "resource_id", ""),
            "ResourceType": getattr(att, "resource_type", ""),
            "TransitGatewayAttachmentId": target_att_id,
        }]

    @staticmethod
    def _vpc_cidrs(backend, vpc_id: str) -> list[str]:
        """Return every IPv4 CIDR associated with ``vpc_id`` (primary +
        secondaries). Used to materialize propagated routes."""
        vpc = getattr(backend, "vpcs", {}).get(vpc_id)
        if not vpc:
            return []
        out = []
        primary = getattr(vpc, "cidr_block", None)
        if primary:
            out.append(primary)
        for attr in ("cidr_block_association_set", "cidr_block_associations"):
            raw = getattr(vpc, attr, None) or {}
            items = raw.values() if isinstance(raw, dict) else raw
            for assoc in items or []:
                if isinstance(assoc, dict):
                    c = assoc.get("cidr_block") or assoc.get("CidrBlock")
                    if c:
                        out.append(c)
        # Dedupe preserving order
        seen = set()
        dedup = []
        for c in out:
            if c and c not in seen:
                dedup.append(c)
                seen.add(c)
        return dedup

    @staticmethod
    def _materialize_propagation(backend, attachment_id: str, rt_id: str) -> None:
        """Insert ``type=propagated`` routes in ``rt`` for every CIDR
        learned from ``attachment_id``. Static routes take precedence
        on tie."""
        att = getattr(backend, "transit_gateway_attachments", {}).get(attachment_id)
        rt = getattr(backend, "transit_gateways_route_tables", {}).get(rt_id)
        if not att or not rt:
            return
        rtype = getattr(att, "resource_type", "") or ""
        if rtype and rtype != "vpc":
            return  # only VPC attachments auto-propagate here
        vpc_id = (getattr(att, "vpc_id", None)
                  or getattr(att, "resource_id", None))
        if not vpc_id:
            return
        for cidr in Ec2Provider._vpc_cidrs(backend, vpc_id):
            existing = (getattr(rt, "routes", None) or {}).get(cidr)
            if existing and existing.get("type") == "static":
                continue
            if getattr(rt, "routes", None) is None:
                rt.routes = {}
            rt.routes[cidr] = {
                "destinationCidrBlock": cidr,
                "prefixListId": None,
                "state": "active",
                "type": "propagated",
                "transitGatewayAttachments": {
                    "resourceId": getattr(att, "resource_id", ""),
                    "resourceType": getattr(att, "resource_type", ""),
                    "transitGatewayAttachmentId": attachment_id,
                },
            }

    @staticmethod
    def _dematerialize_propagation(
        backend, attachment_id: str, rt_id: str,
    ) -> None:
        """Drop propagated routes that pointed at ``attachment_id``."""
        rt = getattr(backend, "transit_gateways_route_tables", {}).get(rt_id)
        if not rt or not getattr(rt, "routes", None):
            return
        stale = [
            cidr for cidr, r in rt.routes.items()
            if r.get("type") == "propagated"
            and (r.get("transitGatewayAttachments") or {}).get(
                "transitGatewayAttachmentId") == attachment_id
        ]
        for cidr in stale:
            rt.routes.pop(cidr, None)

    @handler("CreateTransitGatewayRoute", expand=False)
    def create_transit_gateway_route(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        route = result.get("Route", {}) or {}
        # T2: re-fill the response's ``TransitGatewayAttachments`` that
        # moto drops because of a shape mismatch.
        route.setdefault(
            "TransitGatewayRouteTableId",
            context.request.values.get("TransitGatewayRouteTableId", ""),
        )
        self._refill_tgw_route_attachments(route, backend)
        result["Route"] = route
        return result

    @handler("SearchTransitGatewayRoutes", expand=False)
    def search_transit_gateway_routes(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        rt_id = context.request.values.get(
            "TransitGatewayRouteTableId",
        ) or ""
        for route in result.get("Routes", []) or []:
            route.setdefault("TransitGatewayRouteTableId", rt_id)
            self._refill_tgw_route_attachments(route, backend)
        return result

    @handler("EnableTransitGatewayRouteTablePropagation", expand=False)
    def enable_transit_gateway_route_table_propagation(
        self, context: RequestContext, request: dict,
    ) -> dict:
        result = call_moto(context)
        backend = get_ec2_backend(context.account_id, context.region)
        att_id = context.request.values.get("TransitGatewayAttachmentId") or ""
        rt_id = context.request.values.get("TransitGatewayRouteTableId") or ""
        if att_id and rt_id:
            self._materialize_propagation(backend, att_id, rt_id)
        return result

    @handler("DisableTransitGatewayRouteTablePropagation", expand=False)
    def disable_transit_gateway_route_table_propagation(
        self, context: RequestContext, request: dict,
    ) -> dict:
        backend = get_ec2_backend(context.account_id, context.region)
        att_id = context.request.values.get("TransitGatewayAttachmentId") or ""
        rt_id = context.request.values.get("TransitGatewayRouteTableId") or ""
        if att_id and rt_id:
            self._dematerialize_propagation(backend, att_id, rt_id)
        return call_moto(context)

    @handler("AssociateTransitGatewayRouteTable", expand=False)
    def associate_transit_gateway_route_table(
        self, context: RequestContext, request: dict,
    ) -> dict:
        backend = get_ec2_backend(context.account_id, context.region)
        att_id = context.request.values.get("TransitGatewayAttachmentId") or ""
        new_rt = context.request.values.get("TransitGatewayRouteTableId") or ""
        att = getattr(backend, "transit_gateway_attachments", {}).get(att_id)
        if att is None:
            raise CommonServiceException(
                code="InvalidTransitGatewayAttachmentID.NotFound",
                message=f"TGW attachment {att_id} not found",
                status_code=400,
            )
        current = (getattr(att, "association", None) or {}).get(
            "transitGatewayRouteTableId",
        )
        if current and current != new_rt:
            raise CommonServiceException(
                code="Resource.AlreadyAssociated",
                message=(
                    f"{att_id} is already associated with {current}; "
                    f"an attachment can only be associated with one RT"
                ),
                status_code=400,
            )
        return call_moto(context)

    @handler("CreateLaunchTemplate", expand=False)
    def create_launch_template(
        self,
        context: RequestContext,
        request: CreateLaunchTemplateRequest,
    ) -> CreateLaunchTemplateResult:
        # parameter validation
        if not request["LaunchTemplateData"]:
            raise MissingParameterError(parameter="LaunchTemplateData")

        name = request["LaunchTemplateName"]
        if len(name) < 3 or len(name) > 128 or not re.fullmatch(r"[a-zA-Z0-9.\-_()/]*", name):
            raise InvalidLaunchTemplateNameError()

        return call_moto(context)

    @handler("ModifyLaunchTemplate", expand=False)
    def modify_launch_template(
        self,
        context: RequestContext,
        request: ModifyLaunchTemplateRequest,
    ) -> ModifyLaunchTemplateResult:
        backend = get_ec2_backend(context.account_id, context.region)
        # Use .get() to prevent KeyError
        template_id = request.get("LaunchTemplateId")
        if not template_id:
            template_name = request.get("LaunchTemplateName")
            template_id = backend.launch_template_name_to_ids.get(template_name) if template_name else None
        if not template_id:
            raise InvalidLaunchTemplateIdError()
        template: MotoLaunchTemplate = backend.launch_templates[template_id]

        # check if defaultVersion exists
        if request["DefaultVersion"]:
            try:
                template.versions[int(request["DefaultVersion"]) - 1]
            except IndexError:
                raise InvalidLaunchTemplateIdError()

        template.default_version_number = int(request["DefaultVersion"])

        return ModifyLaunchTemplateResult(
            LaunchTemplate=LaunchTemplate(
                LaunchTemplateId=template.id,
                LaunchTemplateName=template.name,
                CreateTime=template.create_time,
                DefaultVersionNumber=template.default_version_number,
                LatestVersionNumber=template.latest_version_number,
                Tags=template.tags,
            )
        )

    @handler("DescribeVpcEndpointServices", expand=False)
    def describe_vpc_endpoint_services(
        self,
        context: RequestContext,
        request: DescribeVpcEndpointServicesRequest,
    ) -> DescribeVpcEndpointServicesResult:
        ep_services = VPCBackend._collect_default_endpoint_services(
            account_id=context.account_id, region=context.region
        )

        moto_backend = get_moto_backend(context)
        service_names = [s["ServiceName"] for s in ep_services]
        execute_api_name = f"com.amazonaws.{context.region}.execute-api"

        if execute_api_name not in service_names:
            # ensure that the service entry for execute-api exists
            zones = moto_backend.describe_availability_zones()
            zones = [zone.name for zone in zones]
            private_dns_name = f"*.execute-api.{context.region}.amazonaws.com"
            service = {
                "ServiceName": execute_api_name,
                "ServiceId": f"vpce-svc-{short_uid()}",
                "ServiceType": [{"ServiceType": "Interface"}],
                "AvailabilityZones": zones,
                "Owner": "amazon",
                "BaseEndpointDnsNames": [f"execute-api.{context.region}.vpce.amazonaws.com"],
                "PrivateDnsName": private_dns_name,
                "PrivateDnsNames": [{"PrivateDnsName": private_dns_name}],
                "VpcEndpointPolicySupported": True,
                "AcceptanceRequired": False,
                "ManagesVpcEndpoints": False,
                "PrivateDnsNameVerificationState": "verified",
                "SupportedIpAddressTypes": ["ipv4"],
            }
            ep_services.append(service)

        return call_moto(context)

    @handler("DescribeVpcEndpoints", expand=False)
    def describe_vpc_endpoints(
        self,
        context: RequestContext,
        request: DescribeVpcEndpointsRequest,
    ) -> DescribeVpcEndpointsResult:
        result: DescribeVpcEndpointsResult = call_moto(context)

        for endpoint in (result.get("VpcEndpoints") or []):
            endpoint.setdefault("DnsOptions", DnsOptions(DnsRecordIpType=DnsRecordIpType.ipv4))
            endpoint.setdefault("IpAddressType", IpAddressType.ipv4)
            endpoint.setdefault("RequesterManaged", False)
            endpoint.setdefault("RouteTableIds", [])
            # AWS parity: Version should not be contained in the policy response
            policy = endpoint.get("PolicyDocument")
            if policy and '"Version":' in policy:
                policy = json.loads(policy)
                policy.pop("Version", None)
                endpoint["PolicyDocument"] = json.dumps(policy)

        return result

    @handler("CreateFlowLogs", expand=False)
    def create_flow_logs(
        self,
        context: RequestContext,
        request: CreateFlowLogsRequest,
        **kwargs,
    ) -> CreateFlowLogsResult:
        if request.get("LogDestination") and request.get("LogGroupName"):
            raise CommonServiceException(
                code="InvalidParameter",
                message="Please only provide LogGroupName or only provide LogDestination.",
            )
        if request.get("LogDestinationType") == "s3":
            if request.get("LogGroupName"):
                raise CommonServiceException(
                    code="InvalidParameter",
                    message="LogDestination type must be cloud-watch-logs if LogGroupName is provided.",
                )
            elif not (bucket_arn := request.get("LogDestination")):
                raise CommonServiceException(
                    code="InvalidParameter",
                    message="LogDestination can't be empty if LogGroupName is not provided.",
                )

            # Moto will check in memory whether the bucket exists in Moto itself
            # we modify the request to not send a destination, so that the validation does not happen
            # we can add the validation ourselves
            service_request = copy.deepcopy(request)
            service_request["LogDestinationType"] = "__placeholder__"
            bucket_name = bucket_arn.split(":", 5)[5].split("/")[0]
            # TODO: validate how IAM is enforced? probably with DeliverLogsPermissionArn
            s3_client = connect_to().s3
            try:
                s3_client.head_bucket(Bucket=bucket_name)
            except Exception as e:
                LOG.debug(
                    "An exception occurred when trying to create FlowLogs with S3 destination: %s",
                    e,
                )
                return CreateFlowLogsResult(
                    FlowLogIds=[],
                    Unsuccessful=[
                        UnsuccessfulItem(
                            Error=UnsuccessfulItemError(
                                Code="400",
                                Message=f"LogDestination: {bucket_name} does not exist",
                            ),
                            ResourceId=resource_id,
                        )
                        for resource_id in request.get("ResourceIds", [])
                    ],
                )

            response: CreateFlowLogsResult = call_moto_with_request(context, service_request)
            moto_backend = get_moto_backend(context)
            for flow_log_id in response["FlowLogIds"]:
                if flow_log := moto_backend.flow_logs.get(flow_log_id):
                    # just to be sure to not override another value, we only replace if it's the placeholder
                    flow_log.log_destination_type = flow_log.log_destination_type.replace(
                        "__placeholder__", "s3"
                    )
        else:
            response = call_moto(context)

        # Register a subscription per FlowLog id so the recorder routes
        # captured packets to the user's destination instead of the
        # legacy hard-coded ``/localemu/vpc-flow-logs`` group.
        try:
            _register_flow_log_subscriptions(context, request, response)
        except Exception:
            LOG.warning(
                "CreateFlowLogs: failed to register subscriptions; "
                "records will fall through to legacy group",
                exc_info=True,
            )

        return response

    @handler("DeleteFlowLogs", expand=False)
    def delete_flow_logs(
        self,
        context: RequestContext,
        request: dict,
        **kwargs,
    ) -> dict:
        """Drop subscriptions before moto deletes the FlowLog records
        so the recorder stops routing to a destination the user just
        removed."""
        response = call_moto(context)
        try:
            from localemu.services.ec2.flow_logs import (
                get_flow_log_subscriptions,
            )
            registry = get_flow_log_subscriptions()
            for fl_id in request.get("FlowLogIds", []) or []:
                registry.deregister(fl_id)
        except Exception:
            LOG.debug(
                "DeleteFlowLogs: registry deregister failed; "
                "deletion itself succeeded",
                exc_info=True,
            )
        return response

    @handler("GetSecurityGroupsForVpc", expand=False)
    def get_security_groups_for_vpc(
        self,
        context: RequestContext,
        get_security_groups_for_vpc_request: GetSecurityGroupsForVpcRequest,
    ) -> GetSecurityGroupsForVpcResult:
        vpc_id = get_security_groups_for_vpc_request.get("VpcId")
        backend = get_ec2_backend(context.account_id, context.region)
        filters = {"vpc-id": [vpc_id]}
        filtered_sgs = backend.describe_security_groups(filters=filters)

        sgs = [
            SecurityGroupForVpc(
                Description=sg.description,
                GroupId=sg.id,
                GroupName=sg.name,
                OwnerId=context.account_id,
                PrimaryVpcId=sg.vpc_id,
                Tags=[{"Key": tag.get("key"), "Value": tag.get("value")} for tag in sg.get_tags()],
            )
            for sg in filtered_sgs
        ]
        return GetSecurityGroupsForVpcResult(SecurityGroupForVpcs=sgs, NextToken=None)


@patch(SubnetBackend.modify_subnet_attribute)
def modify_subnet_attribute(fn, self, subnet_id, attr_name, attr_value):
    subnet = self.get_subnet(subnet_id)
    if attr_name in ADDITIONAL_SUBNET_ATTRS:
        # private dns name options on launch contains dict with keys EnableResourceNameDnsARecord and EnableResourceNameDnsAAAARecord, HostnameType
        if attr_name == "private_dns_name_options_on_launch":
            if hasattr(subnet, attr_name):
                getattr(subnet, attr_name).update(attr_value)
                return
            else:
                setattr(subnet, attr_name, attr_value)
                return
        setattr(subnet, attr_name, attr_value)
        return
    return fn(self, subnet_id, attr_name, attr_value)


def get_moto_backend(context: RequestContext) -> EC2Backend:
    """Get the moto EC2 backend for the given request context"""
    return ec2_backends[context.account_id][context.region]


@patch(Subnet.get_filter_value)
def get_filter_value(fn, self, filter_name):
    if filter_name in (
        "ipv6CidrBlockAssociationSet.associationId",
        "ipv6-cidr-block-association.association-id",
    ):
        return self.ipv6_cidr_block_associations
    return fn(self, filter_name)


@patch(TransitGatewayAttachmentBackend.delete_transit_gateway_vpc_attachment)
def delete_transit_gateway_vpc_attachment(fn, self, transit_gateway_attachment_id, **kwargs):
    transit_gateway_attachment = self.transit_gateway_attachments.get(transit_gateway_attachment_id)
    transit_gateway_attachment.state = "deleted"
    return transit_gateway_attachment


def _register_flow_log_subscriptions(
    context: RequestContext,
    request: dict,
    response: dict,
) -> None:
    """For every FlowLog id moto just minted, build the matching
    ``FlowLogSubscription`` so the recorder can route captured records
    to the user's destination. One subscription per (FlowLog, ResourceId)
    pair — moto already fans the request out to one FlowLog id per
    ResourceId, so we ride that mapping."""
    from localemu.services.ec2.flow_logs import (
        FlowLogSubscription,
        get_flow_log_subscriptions,
    )

    flow_log_ids = response.get("FlowLogIds") or []
    if not flow_log_ids:
        return

    moto_backend = get_moto_backend(context)
    registry = get_flow_log_subscriptions()
    resource_type = request.get("ResourceType") or "NetworkInterface"
    for fl_id in flow_log_ids:
        flow_log = moto_backend.flow_logs.get(fl_id)
        if flow_log is None:
            continue
        traffic_type = (flow_log.traffic_type or "ALL").upper()
        destination_type = flow_log.log_destination_type or "cloud-watch-logs"
        log_group = flow_log.log_group_name or ""
        s3_destination = None
        if destination_type == "s3":
            s3_destination = flow_log.log_destination
            # No real S3 dispatcher yet — route to a CWL fallback group
            # named after the FlowLog so the records are still visible
            # and the user can find them.
            log_group = f"/aws/vendedlogs/flow-logs/{fl_id}"
        elif destination_type == "kinesis-data-firehose":
            log_group = f"/aws/vendedlogs/flow-logs/{fl_id}"
        elif not log_group:
            log_group = f"/aws/vendedlogs/flow-logs/{fl_id}"
        sub = FlowLogSubscription(
            flow_log_id=fl_id,
            account_id=context.account_id,
            region=context.region or "us-east-1",
            resource_type=resource_type,
            resource_id=flow_log.resource_id,
            traffic_type=traffic_type,  # type: ignore[arg-type]
            destination_type=destination_type,  # type: ignore[arg-type]
            log_group=log_group,
            s3_destination=s3_destination,
            log_format=flow_log.log_format or None,
        )
        registry.register(sub)


@patch(FlowLogsBackend._validate_request)
def _validate_request(
    fn,
    self,
    log_group_name: str,
    log_destination: str,
    log_destination_type: str,
    max_aggregation_interval: str,
    deliver_logs_permission_arn: str,
) -> None:
    if not log_destination_type and log_destination:
        # this is to fix the S3 destination issue, the validation will occur in the provider
        return

    fn(
        self,
        log_group_name,
        log_destination,
        log_destination_type,
        max_aggregation_interval,
        deliver_logs_permission_arn,
    )
