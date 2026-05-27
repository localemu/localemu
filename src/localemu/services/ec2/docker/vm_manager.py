"""Docker VM Manager for EC2 instances.

Manages the lifecycle of Docker containers that represent EC2 instances.
Follows the same patterns as the Lambda Docker executor.
"""

import base64
import logging
import threading
from dataclasses import dataclass, field

from localemu import config
from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

from .ami_mapping import DEFAULT_IMAGE, get_instance_resources, resolve_ami_to_image
from .imds import ImdsServer


def get_container_for_instance(
    account_id: str, region: str, instance_id: str,
) -> str | None:
    """Resolve an EC2 instance id to a running Docker container name.

    Returns ``None`` when:
      - no Docker-backed EC2 instance with that id exists (e.g. moto-only
        passthrough, or the instance has been terminated), or
      - the container exists but is not currently running.

    Module-level helper callable from other services (SSM, etc.) without
    them needing a reference to the ``DockerVmManager`` singleton. The
    ``(account_id, region)`` tuple is accepted so multi-account/region
    lookups don't collide on colliding ``i-*`` ids.
    """
    container_name = f"localemu-ec2-{instance_id}"
    try:
        inspect = DOCKER_CLIENT.inspect_container(container_name)
    except Exception:
        return None
    labels = (inspect.get("Config") or {}).get("Labels") or {}
    # Honour account/region labels when present so cross-account calls
    # can't accidentally target the wrong container.
    lbl_account = labels.get("localemu.account-id")
    lbl_region = labels.get("localemu.region")
    if lbl_account and lbl_account != account_id:
        return None
    if lbl_region and region and lbl_region != region:
        return None
    state = inspect.get("State") or {}
    if not state.get("Running"):
        return None
    return container_name


def _patch_moto_instance_ip(
    account_id: str, region: str, instance_id: str, real_ip: str,
) -> None:
    """Overwrite moto's recorded private IP for an instance to match
    the IP Docker actually assigned on the VPC bridge.

    Moto allocates IPs from its in-memory subnet pool (e.g. 10.50.1.4)
    while the Docker bridge for the VPC may assign from the wider VPC
    CIDR (e.g. 10.50.0.2). Without this reconciliation,
    ``DescribeInstances`` reports an address that does not route — every
    intra-VPC ping by the AWS-reported IP fails. We push the real Docker
    address into moto so callers see one consistent, routable address.

    Tries the various moto attribute shapes that have shifted across
    versions; failures are logged and swallowed (the instance is still
    usable by container name / DNS alias even if this misses).
    """
    import moto.backends as moto_backends

    backend = moto_backends.get_backend("ec2")[account_id][region]
    inst = None
    for candidate in backend.all_instances():
        if getattr(candidate, "id", None) == instance_id:
            inst = candidate
            break
    if inst is None:
        return

    for attr in ("private_ip", "private_ip_address", "_private_ip"):
        if hasattr(inst, attr):
            try:
                setattr(inst, attr, real_ip)
            except Exception:
                pass
    # ENI / NIC structure varies across moto versions
    nics = getattr(inst, "nics", None)
    if nics:
        for nic in (nics.values() if hasattr(nics, "values") else nics):
            for attr in ("private_ip_address", "_private_ip_address"):
                if hasattr(nic, attr):
                    try:
                        setattr(nic, attr, real_ip)
                    except Exception:
                        pass
            # Some moto versions keep a list of {PrivateIpAddress, Primary}
            pia = getattr(nic, "private_ip_addresses", None)
            if isinstance(pia, list) and pia:
                first = pia[0]
                if isinstance(first, dict):
                    first["PrivateIpAddress"] = real_ip
                else:
                    try:
                        setattr(first, "private_ip_address", real_ip)
                    except Exception:
                        pass


def _extract_imds_port_from_inspect(inspect: dict) -> int | None:
    """Parse the ``AWS_EC2_METADATA_SERVICE_ENDPOINT`` env var out of a
    container inspect result so the restore path can re-bind the
    per-instance IMDS proxy to the same port the container already
    expects.

    The env var has the shape ``http://host.docker.internal:<port>``.
    Returns ``None`` when the env var is missing or unparseable.
    """
    env_list = (inspect.get("Config") or {}).get("Env") or []
    for entry in env_list:
        if isinstance(entry, str) and entry.startswith(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT=",
        ):
            _, _, url = entry.partition("=")
            # ``http://host.docker.internal:12345``
            if ":" in url:
                try:
                    return int(url.rsplit(":", 1)[-1].rstrip("/"))
                except (TypeError, ValueError):
                    return None
    return None


def _reissue_sts_for_restore(
    iam_role_name: str, account_id: str, region: str, instance_id: str,
) -> dict | None:
    """Re-issue STS credentials for an instance profile during restore.

    Returns the IMDS-shaped credential dict (``Code``, ``AccessKeyId``,
    ``SecretAccessKey``, ``Token``, ``Expiration``) or ``None`` on
    failure. All exceptions are caught and logged — restore never
    blocks on STS.
    """
    try:
        from datetime import datetime, timedelta, timezone

        from moto.sts.models import sts_backends

        role_arn = f"arn:aws:iam::{account_id}:role/{iam_role_name}"
        sts_backend = sts_backends[account_id]["global"]
        assumed = sts_backend.assume_role(
            region_name=region or "us-east-1",
            role_session_name=f"ec2-{instance_id}",
            role_arn=role_arn,
            policy=None,
            duration=21600,  # 6h, matches AWS EC2 default
            external_id=None,
        )
        return {
            "Code": "Success",
            "LastUpdated": datetime.now(timezone.utc).isoformat(),
            "Type": "AWS-HMAC",
            "AccessKeyId": assumed.access_key_id,
            "SecretAccessKey": assumed.secret_access_key,
            "Token": assumed.session_token,
            "Expiration": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
        }
    except Exception:
        LOG.warning(
            "Restore STS re-issue failed for instance %s (role=%s)",
            instance_id, iam_role_name, exc_info=True,
        )
        return None


def _resolve_nacl_for_subnet(
    subnet_id: str, account_id: str, region: str,
) -> str | None:
    """Look up the Network ACL associated with a subnet via moto.
    Returns the NACL id, or None if none is associated or moto cannot
    be reached."""
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("ec2")[account_id][region]
        for nacl in getattr(backend, "network_acls", {}).values():
            associations = getattr(nacl, "associations", {}) or {}
            for assoc in associations.values():
                sid = (
                    assoc.get("SubnetId")
                    if isinstance(assoc, dict)
                    else getattr(assoc, "subnet_id", None)
                )
                if sid == subnet_id:
                    return getattr(nacl, "id", None) or nacl.get("NetworkAclId")
    except Exception:
        LOG.debug(
            "Could not resolve NACL for subnet %s in %s/%s",
            subnet_id, account_id, region, exc_info=True,
        )
    return None


def _resolve_container_private_ip(
    container_name: str, vpc_network_hint: str | None,
) -> str | None:
    """Probe a running container's private IPv4 address.

    Resolution order:
      1. ``vpc_network_hint`` (the VPC network we attached at create time).
      2. Any other ``localemu-vpc-*`` network on the container.
      3. Default ``bridge`` network.
      4. ``None`` — NO synthetic SHA256 fallback. A fake IP that looks
         real but doesn't route is worse than a clearly-absent one
         (callers can then surface the real state instead of lying).

    Empty-string IPs are treated as "not yet allocated" and we continue
    to the next network; this covers the race where Docker has a
    network attached but hasn't finished assigning an address.
    """
    probe_order: list[str] = []
    if vpc_network_hint:
        probe_order.append(vpc_network_hint)
    try:
        networks = DOCKER_CLIENT.get_networks(container_name)
        for net in networks:
            if net.startswith("localemu-vpc-") and net != vpc_network_hint:
                probe_order.append(net)
    except Exception as exc:
        LOG.debug("get_networks(%s) failed: %s", container_name, exc)
    if "bridge" not in probe_order:
        probe_order.append("bridge")

    for net in probe_order:
        try:
            ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container_name_or_id=container_name,
                container_network=net,
            )
            if ip:
                return ip
        except Exception:
            continue

    LOG.warning(
        "Container %s: could not resolve private IP on any known network "
        "(probed %s)",
        container_name, probe_order,
    )
    return None

LOG = logging.getLogger(__name__)

# Label applied to all EC2 Docker containers for identification
EC2_CONTAINER_LABEL = "localemu.service=ec2"

# Lock for image pull deduplication (same pattern as Lambda)
# Use an OrderedDict with maxsize to prevent unbounded growth
_IMAGE_PULL_LOCKS_MAXSIZE = 64
_image_pull_locks: dict[str, threading.Lock] = {}
_image_pull_locks_lock = threading.Lock()

# Entrypoint script for an EC2 container started from
# ``localemu/ec2-base:latest``. The base image already ships with
# openssh-server, iptables, host keys, /run/sshd and /root/.ssh — so
# this script is configure-and-launch only. NO runtime ``apt-get
# install`` (which would fail on internal VPC networks because there's
# no internet — the container would exit and the whole instance would
# be unreachable).
#
# The fallback ``apk/yum/dnf/apt-get`` install branches are kept as a
# best-effort path for non-LocalEmu base images (when a user maps an
# AMI to ``alpine:3.20`` or ``amazonlinux:2023``); on internal networks
# those paths still fail, but at least the user opted in by picking a
# bare image.
SSHD_ENTRYPOINT_SCRIPT = r"""#!/bin/sh
# Don't ``set -e`` at the top: we want to tolerate a missing ssh-keygen
# or sed inside extremely minimal user-supplied images and still try to
# bring sshd up.

# ----- IMDS DNAT (link-local 169.254.169.254 -> sidecar IP) -----
#
# Real AWS SDKs, curl, cloud-init, ec2-metadata and most third-party
# tools hardcode http://169.254.169.254/ — they ignore the
# AWS_EC2_METADATA_SERVICE_ENDPOINT env var, or only honor it for boto3.
# Without a DNAT rule the connection is refused because nothing inside
# the container listens on that IP. Install an iptables OUTPUT-chain
# DNAT rule so every locally-originating packet to 169.254.169.254:80
# is rewritten to the per-VPC sidecar (LOCALEMU_IMDS_SIDECAR_IP) or
# the host gateway (LOCALEMU_IMDS_HOST_FALLBACK=1, resolved via
# host.docker.internal). Idempotent: ``-C`` check first, then ``-A``.
#
# Alpine ships without iptables by default; install it on-demand so
# the DNAT path works the same as on Ubuntu/Amazon-Linux. apk add
# is silent + cached, adding ~1s on first boot only.
if ! command -v iptables >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache iptables >/dev/null 2>&1 || true
    fi
fi
if command -v iptables >/dev/null 2>&1; then
    _imds_target=""
    _imds_port="80"
    if [ -n "${LOCALEMU_IMDS_SIDECAR_IP:-}" ]; then
        _imds_target="$LOCALEMU_IMDS_SIDECAR_IP"
    elif [ -n "${LOCALEMU_IMDS_HOST_FALLBACK:-}" ]; then
        # Non-VPC path: route to host.docker.internal on the chosen port.
        _gw=$(getent hosts host.docker.internal 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$_gw" ]; then
            _imds_target="$_gw"
            _imds_port="${LOCALEMU_IMDS_HOST_FALLBACK_PORT:-80}"
        fi
    fi
    if [ -n "$_imds_target" ]; then
        iptables -t nat -C OUTPUT -d 169.254.169.254/32 -p tcp --dport 80 \
            -j DNAT --to-destination "$_imds_target:$_imds_port" 2>/dev/null || \
        iptables -t nat -A OUTPUT -d 169.254.169.254/32 -p tcp --dport 80 \
            -j DNAT --to-destination "$_imds_target:$_imds_port" 2>/dev/null || true
        # POSTROUTING MASQUERADE matches the just-rewritten dst so the
        # kernel picks a valid src IP from the egress interface. Without
        # this the OUT-chain DNAT'd SYN goes out with the link-local
        # 169.254.x source and the reply never finds its way back.
        iptables -t nat -C POSTROUTING -d "$_imds_target/32" -p tcp --dport "$_imds_port" \
            -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -d "$_imds_target/32" -p tcp --dport "$_imds_port" \
            -j MASQUERADE 2>/dev/null || true
    fi
fi

# Best-effort install only when sshd isn't already there. The LocalEmu
# base image has it pre-baked, so this entire block is a no-op for the
# common case.
if ! command -v sshd >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1 && \
            apt-get install -y -qq openssh-server >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y openssh-server >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssh-server >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache openssh-server >/dev/null 2>&1 || true
    fi
fi

# Idempotent set-up — no-op when the base image already did this.
ssh-keygen -A >/dev/null 2>&1 || true
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
fi

if [ -f /var/lib/localemu/user-data.sh ]; then
    chmod +x /var/lib/localemu/user-data.sh
    /var/lib/localemu/user-data.sh > /var/log/user-data.log 2>&1 || true
fi

# If sshd still isn't installed (bare image + internal network), keep
# the container alive instead of exiting — IMDS, SG enforcement and
# intra-VPC ping still work even without SSH.
if command -v sshd >/dev/null 2>&1 && [ -x /usr/sbin/sshd ]; then
    exec /usr/sbin/sshd -D -e
else
    echo "[localemu] sshd not available in this image — staying alive without SSH"
    exec sh -c 'while true; do sleep 3600; done'
fi
"""


@dataclass
class Ec2ContainerInfo:
    """Tracks a running EC2 Docker container."""
    instance_id: str
    container_name: str
    image: str
    ssh_port: int | None = None
    imds_port: int | None = None
    private_ip: str | None = None
    user_data: str | None = None
    key_name: str | None = None
    instance_type: str = "t2.micro"
    console_output: str = ""
    vpc_id: str | None = None


class _ImageFallback(Exception):
    """Raised when an image pull fails and falls back to default."""
    def __init__(self, fallback_image: str):
        self.fallback_image = fallback_image


# Process-wide reference to the most recently constructed
# DockerVmManager. Services outside the EC2 provider (autoscaling,
# future ECS/EKS/SSM integrations) read this via
# :func:`get_active_vm_manager` rather than importing the provider
# class directly — keeps the dependency direction one-way.
_ACTIVE_VM_MANAGER: "DockerVmManager | None" = None


def get_active_vm_manager() -> "DockerVmManager | None":
    """Return the process-wide DockerVmManager, or None if no EC2
    provider has initialized it yet (e.g. EC2_VM_MANAGER != docker)."""
    return _ACTIVE_VM_MANAGER


class DockerVmManager:
    """Manages Docker containers as EC2 instances.

    Each EC2 instance maps to one Docker container. The container runs
    a base OS image (Ubuntu, Amazon Linux, etc.) with optional user data
    execution and SSH access.
    """

    def __init__(self):
        self._instances: dict[str, Ec2ContainerInfo] = {}
        self._lock = threading.Lock()
        self._imds_server = ImdsServer()
        self._imds_server.start()
        # Opt-in per-instance flow-log pollers when FLOW_LOGS_FULL=1.
        # Key: instance_id → FlowLogPoller.
        self._flow_log_pollers: dict = {}
        # Register as the active vm_manager so cross-service callers
        # (autoscaling reconciler etc.) can find us.
        global _ACTIVE_VM_MANAGER
        _ACTIVE_VM_MANAGER = self

    def _container_name(self, instance_id: str) -> str:
        """Generate container name from instance ID."""
        return f"localemu-ec2-{instance_id}"

    # Public re-export so services outside the EC2 package (SSM, etc.)
    # can resolve an instance_id to the container name without importing
    # the private method.
    def container_name_for(self, instance_id: str) -> str:
        return self._container_name(instance_id)

    def _ensure_image(self, image: str) -> None:
        """Make a Docker image available locally before launching a container.

        Thread-safe via per-image locking.

        Special case: the LocalEmu-managed base image
        (``localemu/ec2-base:latest``) is BUILT (not pulled) by
        ``base_image.ensure_base_image``. The build runs on the
        LocalEmu host (where internet works) and the resulting image
        is reused by every EC2 container — including ones on internal
        VPC networks where ``apt-get install`` cannot reach the
        package mirrors at runtime.
        """
        with _image_pull_locks_lock:
            if image not in _image_pull_locks:
                # Evict oldest entries when maxsize is reached
                if len(_image_pull_locks) >= _IMAGE_PULL_LOCKS_MAXSIZE:
                    oldest_key = next(iter(_image_pull_locks))
                    del _image_pull_locks[oldest_key]
                _image_pull_locks[image] = threading.Lock()
            lock = _image_pull_locks[image]

        with lock:
            # LocalEmu-managed base image: build it from source if missing.
            from .base_image import BASE_IMAGE_TAG, ensure_base_image
            if image == BASE_IMAGE_TAG:
                ensure_base_image()
                return

            try:
                DOCKER_CLIENT.inspect_image(image)
                LOG.debug("Image %s already available", image)
            except Exception:
                LOG.info("Pulling Docker image %s for EC2 instance...", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                    LOG.info("Image %s pulled successfully", image)
                except Exception as e:
                    if image != DEFAULT_IMAGE:
                        LOG.warning("Failed to pull image %s: %s. Falling back to %s.", image, e, DEFAULT_IMAGE)
                        self._ensure_image(DEFAULT_IMAGE)
                        raise _ImageFallback(DEFAULT_IMAGE)
                    else:
                        # Default image is the LocalEmu base — try to build it.
                        try:
                            ensure_base_image()
                            return
                        except Exception as build_exc:
                            raise RuntimeError(
                                f"Failed to pull or build default image {image}: pull={e}, build={build_exc}"
                            ) from build_exc

    def _build_user_data_script(self, user_data_b64: str | None) -> str | None:
        """Decode and wrap user data as an executable script."""
        if not user_data_b64:
            return None
        try:
            decoded = base64.b64decode(user_data_b64).decode("utf-8")
            return decoded
        except Exception as e:
            LOG.warning("Failed to decode user data: %s", e)
            return None

    def create_instance(
        self,
        instance_id: str,
        ami_id: str,
        instance_type: str = "t2.micro",
        key_name: str | None = None,
        user_data: str | None = None,
        security_groups: list[str] | None = None,
        subnet_id: str | None = None,
        public_key: str | None = None,
        account_id: str = "000000000000",
        region: str | None = None,
        iam_instance_profile_arn: str | None = None,
        iam_role_name: str | None = None,
        vpc_network: str | None = None,
    ) -> Ec2ContainerInfo:
        """Create and start a Docker container for an EC2 instance.

        Args:
            instance_id: The EC2 instance ID (i-xxx)
            ami_id: AMI ID to resolve to a Docker image
            instance_type: EC2 instance type for resource limits
            key_name: SSH key pair name
            user_data: Base64-encoded user data script
            security_groups: Security group IDs (metadata only)
            subnet_id: Subnet ID (metadata only)
            iam_instance_profile_arn: Instance profile ARN (for IMDS credentials)
            iam_role_name: IAM role name associated with the instance profile

        Returns:
            Ec2ContainerInfo with container details
        """
        container_name = self._container_name(instance_id)
        image = resolve_ami_to_image(ami_id)
        resources = get_instance_resources(instance_type)

        LOG.info("Creating EC2 instance %s (image=%s, type=%s)", instance_id, image, instance_type)

        # Ensure the Docker image is available (may fall back to default)
        try:
            self._ensure_image(image)
        except _ImageFallback as fb:
            image = fb.fallback_image
            LOG.info("Using fallback image %s for instance %s", image, instance_id)

        # Allocate Docker-internal SSH port (bound to 127.0.0.1 when SG proxy is active)
        docker_ssh_port = get_free_tcp_port()

        # Build environment variables for the container.
        #
        # IMDS routing: VPC networks are --internal=true so EC2
        # containers cannot reach host.docker.internal directly. For
        # VPC-attached instances we point the env var at the per-VPC
        # IMDS sidecar (a dual-homed container that relays to the
        # host's ImdsServer with X-Localemu-Source-Ip stamped). For
        # non-VPC (legacy) instances we keep the per-instance proxy
        # port + host.docker.internal route.
        if not region:
            region = config.DEFAULT_REGION if hasattr(config, "DEFAULT_REGION") else "us-east-1"
        az = f"{region}a"

        imds_url = None
        imds_sidecar_ip: str | None = None
        imds_host_fallback_port: int | None = None
        if vpc_network:
            try:
                from localemu.services.ec2.docker.imds_sidecar import (
                    ensure_imds_sidecar,
                )
                vpc_id = vpc_network.removeprefix("localemu-vpc-")
                sidecar_ip = ensure_imds_sidecar(vpc_id, self._imds_server.port)
                if sidecar_ip:
                    imds_sidecar_ip = sidecar_ip
                    # Trailing slash is REQUIRED: older botocore (awscli
                    # v1 shipped with ubuntu:22.04) string-concatenates
                    # the path onto the base without re-inserting one,
                    # producing bad URLs like ``:80latest/api/token``.
                    imds_url = f"http://{sidecar_ip}:80/"
            except Exception:
                LOG.warning(
                    "IMDS sidecar setup failed for %s, falling back to host.docker.internal",
                    instance_id, exc_info=True,
                )
        if imds_url is None:
            try:
                per_instance_port = self._imds_server.allocate_port_for_instance(
                    instance_id,
                )
            except Exception:
                LOG.warning(
                    "Could not allocate per-instance IMDS port for %s, falling back to shared port",
                    instance_id, exc_info=True,
                )
                per_instance_port = self._imds_server.port
            imds_host_fallback_port = per_instance_port
            imds_url = f"http://host.docker.internal:{per_instance_port}/"

        from localemu import config as _le_config
        _gw_port = _le_config.GATEWAY_LISTEN[0].port
        env_vars = {
            "LOCALEMU_INSTANCE_ID": instance_id,
            "LOCALEMU_INSTANCE_TYPE": instance_type,
            "LOCALEMU_REGION": region,
            "LOCALEMU_AZ": az,
            "AWS_EC2_METADATA_SERVICE_ENDPOINT": imds_url,
            "AWS_ENDPOINT_URL": f"http://host.docker.internal:{_gw_port}",
            "AWS_REGION": region,
            "AWS_DEFAULT_REGION": region,
        }
        # IMDS DNAT target — picked up by SSHD_ENTRYPOINT_SCRIPT to install
        # an iptables OUTPUT rule rewriting 169.254.169.254:80 to the right
        # reachable address for this instance. Without this, tools that
        # hardcode the link-local IMDS IP (curl, cloud-init, ec2-metadata,
        # Java/Go SDKs) get connection-refused.
        if imds_sidecar_ip:
            env_vars["LOCALEMU_IMDS_SIDECAR_IP"] = imds_sidecar_ip
        elif imds_host_fallback_port is not None:
            env_vars["LOCALEMU_IMDS_HOST_FALLBACK"] = "1"
            env_vars["LOCALEMU_IMDS_HOST_FALLBACK_PORT"] = str(imds_host_fallback_port)

        # Build container configuration
        ports = PortMappings()
        ports.add(docker_ssh_port, 22)

        # When a public key is available, run sshd; otherwise fall back to sleep loop
        if public_key:
            container_command = ["sh", "-c", SSHD_ENTRYPOINT_SCRIPT]
        else:
            container_command = ["sh", "-c", "while true; do sleep 3600; done"]

        # Primary network is the shared port-publishing bridge so Docker
        # actually publishes ``-p`` bindings (VPC networks are
        # ``--internal=True`` and Docker silently ignores ``-p`` on
        # those — see moby/moby#27441). We attach the VPC network as a
        # secondary interface right after start so intra-VPC traffic
        # works. SG / NACL iptables still enforce on both interfaces.
        from .vpc_network import ensure_pubport_bridge
        primary_network = ensure_pubport_bridge() if vpc_network else None
        secondary_networks: list[str] = []
        if vpc_network:
            secondary_networks.append(vpc_network)
        container_config = ContainerConfiguration(
            image_name=image,
            name=container_name,
            env_vars=env_vars,
            ports=ports,
            entrypoint="",
            command=container_command,
            network=primary_network,
            # NET_ADMIN: SG/NACL iptables enforcement
            # SYSLOG: dmesg inside the container for VPC Flow Logs 
            cap_add=["NET_ADMIN", "SYSLOG"],
            # VPC networks are --internal=True so host.docker.internal
            # cannot be reached via the default route. Map it to the host
            # gateway explicitly so IMDS (and any other host-side service the
            # container needs) stays reachable from within the VPC.
            #
            # ``accept_local=1`` is critical for VPC-peering routing: it lets
            # the kernel accept packets arriving on the pcx interface whose
            # destination matches an IP that's local on ANOTHER interface
            # (the peered EC2's real VPC IP). Docker mounts /proc/sys as
            # read-only so ``sysctl -w`` after-the-fact is blocked; setting
            # it at container create is the only path.
            additional_flags=(
                "--add-host host.docker.internal:host-gateway "
                "--sysctl net.ipv4.conf.all.accept_local=1"
            ),
            detach=True,
            labels={
                "localemu.service": "ec2",
                "localemu.instance-id": instance_id,
                "localemu.instance-type": instance_type,
                "localemu.ami-id": ami_id,
                # Persist the SG set + location so sg_reapply can
                # rebuild its mapping after a LocalEmu restart.
                "localemu.account-id": account_id,
                "localemu.region": region or "us-east-1",
                "localemu.sg-ids": ",".join(security_groups or []),
                # Enough context for restore_instance to re-apply
                # every data-plane artefact (SG iptables, NACL iptables,
                # VPC registration, STS credentials) without needing to
                # call back into moto with incomplete state.
                "localemu.subnet-id": subnet_id or "",
                "localemu.iam-role-name": iam_role_name or "",
                "localemu.iam-profile-arn": iam_instance_profile_arn or "",
            },
            mem_limit=resources.get("mem_limit", "1g"),
            cpu_shares=resources.get("cpu_shares", 256),
        )

        # Create and start the container
        DOCKER_CLIENT.create_container_from_config(container_config)
        DOCKER_CLIENT.start_container(container_name)

        # Attach the VPC network as a secondary interface now that the
        # port bindings have been established on the primary pubport
        # bridge. SG/NACL iptables will be applied to every interface.
        #
        # When LOCALEMU_VPC_IP_PINNING is on AND we have subnet_id, the
        # VPC bridge attach pins to an allocator-reserved IP via
        # ipv4_address. Other secondary networks (peering, NAT) keep
        # Docker auto-IPAM today; their pinning lands in subsequent
        # commits.
        reserved_vpc_ip = None  # tracked for release on failure
        synth_eni_id = None
        for net in secondary_networks:
            ipv4_kwarg = None
            if (
                vpc_network
                and net == vpc_network
                and subnet_id
            ):
                from localemu import config as _config
                if _config.LOCALEMU_VPC_IP_PINNING:
                    try:
                        from localemu.services.ec2.docker.subnet_allocator import (
                            InsufficientFreeAddressesInSubnet,
                            UnknownSubnet,
                            get_subnet_allocator,
                        )
                        _vpc_id = vpc_network.removeprefix("localemu-vpc-")
                        synth_eni_id = f"eni-{instance_id.removeprefix('i-')}"
                        reserved_vpc_ip = get_subnet_allocator().reserve(
                            vpc_id=_vpc_id, subnet_id=subnet_id,
                            owner_key=synth_eni_id,
                        )
                        ipv4_kwarg = str(reserved_vpc_ip)
                    except (UnknownSubnet, InsufficientFreeAddressesInSubnet) as e:
                        LOG.warning(
                            "EC2 %s: cannot pin IP in subnet %s (%s) — "
                            "falling back to Docker auto-IPAM",
                            instance_id, subnet_id, e,
                        )
                    except Exception:
                        LOG.warning(
                            "EC2 %s: allocator reserve raised — falling back",
                            instance_id, exc_info=True,
                        )
            try:
                DOCKER_CLIENT.connect_container_to_network(
                    net, container_name, ipv4_address=ipv4_kwarg,
                )
            except Exception:
                LOG.warning(
                    "EC2 %s: secondary network %s attach failed",
                    instance_id, net, exc_info=True,
                )
                # Roll back IP reservation if this was the pinned VPC attach
                if reserved_vpc_ip is not None and net == vpc_network:
                    try:
                        from localemu.services.ec2.docker.subnet_allocator import (
                            get_subnet_allocator,
                        )
                        get_subnet_allocator().release(reserved_vpc_ip)
                    except Exception:
                        LOG.debug(
                            "EC2 %s: rollback release failed",
                            instance_id, exc_info=True,
                        )
                    reserved_vpc_ip = None
                    synth_eni_id = None

        # Handle user data.
        #
        # We write the decoded script to ``/var/lib/localemu/user-data.sh``
        # AND execute it right away. The file is also persisted for
        # audit / diagnostics; executing inline fixes a race: the
        # SSHD entrypoint only runs user-data if the file already
        # exists at container-startup time, but we create the file
        # AFTER ``start_container`` returns — so the entrypoint
        # always misses the first boot. Inline exec here closes that
        # gap for both sshd-enabled and sleep-loop instances.
        user_data_script = self._build_user_data_script(user_data)
        console_output = ""
        if user_data_script:
            try:
                DOCKER_CLIENT.exec_in_container(
                    container_name,
                    ["sh", "-c", "mkdir -p /var/lib/localemu"],
                )
                # base64 via env var and `printf` to avoid shell-arg
                # length limits and to handle any script content cleanly.
                import base64 as _b64
                ud_b64 = _b64.b64encode(user_data_script.encode()).decode()
                DOCKER_CLIENT.exec_in_container(
                    container_name,
                    ["sh", "-c",
                     f"printf '%s' '{ud_b64}' | base64 -d > /var/lib/localemu/user-data.sh "
                     f"&& chmod +x /var/lib/localemu/user-data.sh"],
                )
                out, _ = DOCKER_CLIENT.exec_in_container(
                    container_name,
                    ["sh", "-c",
                     "/var/lib/localemu/user-data.sh "
                     "> /var/log/user-data.log 2>&1; "
                     "cat /var/log/user-data.log 2>/dev/null"],
                )
                console_output = (
                    out.decode("utf-8") if isinstance(out, bytes) else str(out)
                )
                LOG.debug(
                    "User data executed for %s (%d bytes output)",
                    instance_id, len(console_output),
                )
            except Exception as e:
                console_output = f"Error executing user data: {e}"
                LOG.warning(
                    "User data execution failed for %s: %s", instance_id, e,
                )

        # Inject SSH key if a public key is available
        if key_name and public_key:
            self._inject_ssh_key(container_name, key_name, public_key)

        # Get container IP from Docker — VPC network first, then bridge.
        # When the container is only attached to a localemu-vpc-* network
        # (the common case for VPC instances), probing "bridge" first
        # would fail; we now walk the attached networks in priority order
        # and only return an address that actually routes. No SHA256
        # synthetic fallback — see ``_resolve_container_private_ip``.
        private_ip = _resolve_container_private_ip(container_name, vpc_network)

        # Patch moto so DescribeInstances reports the same IP the container
        # actually has on the VPC bridge. Otherwise moto invents an address
        # from its in-memory subnet pool that doesn't route — every
        # cross-instance ping by AWS-reported IP fails.
        if private_ip:
            try:
                _patch_moto_instance_ip(account_id, region or "us-east-1",
                                        instance_id, private_ip)
            except Exception:
                LOG.debug(
                    "moto IP patch failed for %s", instance_id, exc_info=True,
                )

        # Register the EC2 ENI in the AddressIndex when the addressing
        # redesign has pinned an IP. This makes the IP discoverable via
        # get_eni_for_ip and feeds the SG ipset programmer (kills the
        # silent allow-all at sg_iptables.py:93-94 once that landing
        # commit ships).
        if reserved_vpc_ip is not None and synth_eni_id and subnet_id:
            try:
                from localemu.services.ec2.docker.address_index import (
                    get_address_index,
                )
                _vpc_id_for_index = vpc_network.removeprefix("localemu-vpc-")
                get_address_index().register_eni(
                    eni_id=synth_eni_id,
                    vpc_id=_vpc_id_for_index,
                    subnet_id=subnet_id,
                    primary_ip=reserved_vpc_ip,
                    sg_ids=list(security_groups or []),
                    instance_id=instance_id,
                    iface_name="eth1",  # VPC bridge is the secondary iface today
                )
            except Exception:
                LOG.debug(
                    "EC2 %s: index.register_eni failed (non-fatal)",
                    instance_id, exc_info=True,
                )

            # The new ENI's IP is now in the AddressIndex. Any SG with a
            # rule of the form "allow ... from sg-X" where sg-X is in
            # this instance's SGs must have its iptables rebuilt so
            # this instance's /32 lands in the ACCEPT list (closing
            # the late-join enforcement gap for SG cross-references).
            if security_groups:
                try:
                    from localemu.services.ec2.docker.sg_reapply import (
                        reapply_sgs_referencing,
                    )
                    reapply_sgs_referencing(
                        list(security_groups), account_id,
                        region or "us-east-1",
                    )
                except Exception:
                    LOG.debug(
                        "EC2 %s: reapply_sgs_referencing failed (non-fatal)",
                        instance_id, exc_info=True,
                    )

        # SSH is reachable directly via the Docker-mapped host port now
        # that the container's primary network is the pubport bridge.
        # Security Group enforcement lives in iptables inside the
        # container (``sg_iptables.py`` + event-driven reapply via
        # ``sg_reapply.py``) — a single source of truth with correct
        # source-IP fidelity. The previous asyncio SG proxy has been
        # removed; it duplicated enforcement and broke source-IP
        # visibility for CIDR-based SG rules.
        ssh_port = docker_ssh_port

        # Register instance with the IMDS server
        user_data_decoded = self._build_user_data_script(user_data) or ""
        hostname = f"ip-{private_ip.replace('.', '-')}.ec2.internal" if private_ip else "localhost"
        metadata = {
            "instance_id": instance_id,
            "instance_type": instance_type,
            "ami_id": ami_id,
            "private_ip": private_ip or "",
            "region": region,
            "az": az,
            "hostname": hostname,
            "account_id": account_id,
            "user_data": user_data_decoded,
            "key_name": key_name,
        }

        # Generate real STS temporary credentials for the instance profile role.
        # This makes IMDS return credentials that IAM enforcement can resolve
        # back to the role's policies — exactly like real AWS.
        if iam_role_name:
            metadata["iam_role_name"] = iam_role_name
            metadata["instance_profile_arn"] = iam_instance_profile_arn or ""
            try:
                from datetime import timedelta

                from moto.sts.models import sts_backends

                role_arn = f"arn:aws:iam::{account_id}:role/{iam_role_name}"
                sts_backend = sts_backends[account_id]["global"]
                assumed_role = sts_backend.assume_role(
                    region_name=region or "us-east-1",
                    role_session_name=f"ec2-{instance_id}",
                    role_arn=role_arn,
                    policy=None,
                    duration=21600,  # 6 hours, matching AWS default for EC2
                    external_id=None,
                )
                from datetime import datetime, timezone
                metadata["iam_credentials"] = {
                    "Code": "Success",
                    "LastUpdated": datetime.now(timezone.utc).isoformat(),
                    "Type": "AWS-HMAC",
                    "AccessKeyId": assumed_role.access_key_id,
                    "SecretAccessKey": assumed_role.secret_access_key,
                    "Token": assumed_role.session_token,
                    "Expiration": (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat(),
                }
                LOG.info(
                    "Generated IMDS credentials for instance %s (role=%s, key=%s***)",
                    instance_id, iam_role_name, assumed_role.access_key_id[:4],
                )
            except Exception as e:
                metadata["iam_credentials_error"] = str(e)
                LOG.error(
                    "Failed to generate IMDS credentials for instance %s (role=%s): %s "
                    "(SDKs inside the container will see NoCredentialsError)",
                    instance_id, iam_role_name, e, exc_info=True,
                )

        self._imds_server.register_instance(instance_id, private_ip or "", metadata)

        # Extract VPC ID from network name for tracking
        _vpc_id = vpc_network.removeprefix("localemu-vpc-") if vpc_network else None

        info = Ec2ContainerInfo(
            instance_id=instance_id,
            container_name=container_name,
            image=image,
            ssh_port=ssh_port,
            imds_port=self._imds_server.port,
            private_ip=private_ip,
            user_data=user_data,
            key_name=key_name,
            instance_type=instance_type,
            console_output=console_output,
            vpc_id=_vpc_id,
        )

        with self._lock:
            self._instances[instance_id] = info

        # Register container with VPC network manager for peering/IGW tracking
        if vpc_network:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                # Extract VPC ID from network name (localemu-vpc-{vpc_id})
                vpc_id = vpc_network.removeprefix("localemu-vpc-")
                get_vpc_network_manager().register_container(
                    vpc_id, container_name, subnet_id=subnet_id,
                )
            except Exception:
                pass

            # T1: if any TGW has an attachment for this VPC, program
            # the newcomer's routing table to reach every peer VPC's
            # CIDR via the TGW router's IP in the local VPC.
            try:
                from localemu.services.ec2.docker.tgw_network import (
                    get_tgw_network_manager,
                )
                get_tgw_network_manager().on_container_registered(
                    vpc_id, container_name,
                )
            except Exception:
                LOG.debug(
                    "TGW on_container_registered hook failed for %s",
                    container_name, exc_info=True,
                )

            # If the VPC has a NAT Gateway, attach this instance to the
            # NAT bridge so Docker's built-in bridge-NAT carries its
            # egress traffic out to the internet. (Real AWS uses route
            # tables; we approximate by auto-connecting all instances
            # in NATted VPCs.)
            try:
                from localemu.services.ec2.docker.nat_gateway import (
                    get_nat_gateway_manager,
                )
                nat_mgr = get_nat_gateway_manager()
                bridge = nat_mgr.get_bridge_network_for_vpc(vpc_id)
                if bridge:
                    DOCKER_CLIENT.connect_container_to_network(bridge, container_name)
                    LOG.info(
                        "EC2 %s connected to NAT bridge %s for internet egress",
                        instance_id, bridge,
                    )
            except Exception:
                LOG.debug(
                    "NAT bridge attach skipped for %s", instance_id, exc_info=True,
                )

        # Apply Security Group iptables rules to the container. The
        # applier guarantees iptables is installed first and raises on
        # any failure. If we can't enforce the SG, we MUST NOT return
        # a "running" instance -- silently accepting all traffic while
        # claiming the SG is applied would be a security lie. Tear
        # the container down and fail the RunInstances call.
        if security_groups:
            from localemu.services.ec2.docker.sg_iptables import apply_sg_to_container
            try:
                apply_sg_to_container(
                    container_name, security_groups,
                    account_id, region or "us-east-1",
                )
            except Exception as e:
                LOG.error(
                    "EC2 %s: SG enforcement failed (%s). Tearing down "
                    "the container -- RunInstances will not return a "
                    "lying instance.",
                    instance_id, e,
                )
                try:
                    DOCKER_CLIENT.remove_container(container_name, force=True)
                except Exception:
                    LOG.warning(
                        "EC2 %s: post-failure container removal failed; "
                        "manual cleanup may be needed: docker rm -f %s",
                        instance_id, container_name,
                    )
                raise
        # Register in the sg-reapply mapping so future
        # AuthorizeSG / RevokeSG / ModifyInstanceAttribute events can
        # find and re-apply to this container.
        try:
            from localemu.services.ec2.docker.sg_reapply import record_instance_sgs
            record_instance_sgs(
                account_id, region or "us-east-1", instance_id, security_groups or [],
            )
        except Exception:
            LOG.debug("sg_reapply.record failed for %s", instance_id, exc_info=True)

        # Start the flow-log sidecar + poller when the operator
        # opted in. The sidecar (ulogd2 on alpine, NFLOG reader in the
        # EC2 container's netns) replaces the dmesg-scraping path the
        # old ``FlowLogPoller`` used — dmesg returns empty on macOS
        # Docker Desktop even with CAP_SYSLOG because the LinuxKit VM
        # shares one ring buffer across all containers. NFLOG is
        # netlink-based and per-netns, so it works on macOS AND Linux.
        #
        # Off by default because the sidecar adds ~5MB RAM and one
        # extra container per EC2 instance. The iptables NFLOG/LOG
        # directives that produce the raw data are always emitted once
        # ``apply_sg_to_container`` runs, so turning this back on later
        # (by restarting LocalEmu with FLOW_LOGS_FULL=1) observes the
        # already-instrumented rules.
        import os as _os
        if _os.environ.get("FLOW_LOGS_FULL", "").lower() in ("1", "true", "yes"):
            try:
                from localemu.services.ec2.docker.flow_log_recorder import (
                    SidecarFlowLogPoller, get_flow_log_recorder,
                )
                from localemu.services.ec2.docker.flow_log_sidecar import (
                    ensure_sidecar,
                )
                sidecar_name = ensure_sidecar(
                    instance_id=instance_id,
                    ec2_container_name=container_name,
                )
                if sidecar_name:
                    poller = SidecarFlowLogPoller(
                        sidecar_name=sidecar_name,
                        instance_id=instance_id,
                        account_id=account_id,
                        recorder=get_flow_log_recorder(),
                    )
                    poller.start()
                    self._flow_log_pollers[instance_id] = poller
                else:
                    LOG.warning(
                        "Flow log sidecar could not be started for %s; "
                        "capture disabled for this instance",
                        instance_id,
                    )
            except Exception:
                LOG.debug(
                    "Flow log sidecar/poller start failed for %s",
                    instance_id, exc_info=True,
                )

        LOG.info("EC2 instance %s running (container=%s, ssh_port=%s, network=%s)",
                 instance_id, container_name, ssh_port, vpc_network or "bridge")
        return info

    def _inject_ssh_key(self, container_name: str, key_name: str, public_key: str) -> None:
        """Inject SSH public key into the container for key-based authentication."""
        try:
            # avoid shell interpolation of public key
            # to prevent command injection via crafted key content
            DOCKER_CLIENT.exec_in_container(
                container_name,
                ["sh", "-c", "mkdir -p /root/.ssh && chmod 700 /root/.ssh"],
            )
            import base64
            key_b64 = base64.b64encode(public_key.encode()).decode()
            DOCKER_CLIENT.exec_in_container(
                container_name,
                [
                    "sh",
                    "-c",
                    f"echo {key_b64} | base64 -d >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys",
                ],
            )
            LOG.info("Injected SSH public key for key pair %s into container %s", key_name, container_name)
        except Exception as e:
            LOG.warning("Failed to inject SSH key %s: %s", key_name, e)

    def stop_instance(self, instance_id: str) -> None:
        """Stop an EC2 instance (Docker stop)."""
        container_name = self._container_name(instance_id)
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=10)
            LOG.info("EC2 instance %s stopped", instance_id)
        except Exception as e:
            LOG.warning("Failed to stop EC2 instance %s: %s", instance_id, e)

    def start_instance(self, instance_id: str) -> None:
        """Start a stopped EC2 instance (Docker start)."""
        container_name = self._container_name(instance_id)
        try:
            DOCKER_CLIENT.start_container(container_name)
            LOG.info("EC2 instance %s started", instance_id)
        except Exception as e:
            LOG.warning("Failed to start EC2 instance %s: %s", instance_id, e)

    def reboot_instance(self, instance_id: str) -> None:
        """Reboot an EC2 instance (Docker restart — atomic, preserves
        the host port mapping and the container's IPAM assignment).

        AWS RebootInstances is graceful (SIGTERM then SIGKILL after
        timeout); Docker's restart_container does the same with the
        configured stop_timeout (default 10s). The container's
        writable layer, network attachments, and SG/NACL iptables all
        survive because the netns is preserved across restart.
        """
        container_name = self._container_name(instance_id)
        try:
            DOCKER_CLIENT.restart_container(container_name, timeout=10)
            LOG.info("EC2 instance %s rebooted", instance_id)
        except Exception as e:
            LOG.warning("Failed to reboot EC2 instance %s: %s", instance_id, e)

    def terminate_instance(self, instance_id: str) -> None:
        """Terminate an EC2 instance (Docker stop + remove + VPC deregister)."""
        container_name = self._container_name(instance_id)

        # Get info before removing (deregister from VPC)
        with self._lock:
            info = self._instances.get(instance_id)

        self._imds_server.deregister_instance(instance_id)
        # Release the per-instance IMDS proxy port.
        try:
            self._imds_server.release_port_for_instance(instance_id)
        except Exception:
            LOG.debug(
                "release_port_for_instance(%s) failed", instance_id, exc_info=True,
            )

        # Stop the flow-log poller + tear down the sidecar
        # container if we started one. Both operations are best-effort
        # — a failing sidecar cleanup must not block instance
        # termination.
        poller = self._flow_log_pollers.pop(instance_id, None)
        if poller is not None:
            try:
                poller.stop()
            except Exception:
                LOG.debug(
                    "flow log poller.stop(%s) failed", instance_id, exc_info=True,
                )
        try:
            from localemu.services.ec2.docker.flow_log_sidecar import (
                cleanup_sidecar,
            )
            cleanup_sidecar(instance_id)
        except Exception:
            LOG.debug(
                "flow log sidecar cleanup(%s) failed",
                instance_id, exc_info=True,
            )

        # Drop from sg_reapply mapping so a future SG rule change
        # doesn't try to exec into a destroyed container.
        try:
            from localemu.services.ec2.docker.sg_reapply import forget_instance
            # Best-effort account/region lookup from the last known info;
            # if we don't have it, the entry will just get cleaned up by
            # rebuild_mapping_from_docker on next restart.
            if info:
                # vm_manager doesn't currently store account/region on
                # Ec2ContainerInfo — iterate the mapping and clear any
                # entry with this instance_id. Fast enough for the dict
                # sizes we deal with (bounded by live instances).
                from localemu.services.ec2.docker.sg_reapply import _sg_mapping, _sg_mapping_lock
                with _sg_mapping_lock:
                    keys = [
                        k for k in _sg_mapping if k[2] == instance_id
                    ]
                    for k in keys:
                        _sg_mapping.pop(k, None)
        except Exception:
            LOG.debug("sg_reapply.forget failed for %s", instance_id, exc_info=True)

        # Deregister from VPC network manager
        if info and info.vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
                get_vpc_network_manager().deregister_container(info.vpc_id, container_name)
            except Exception:
                pass

        # Release addressing-redesign state for this instance. The ENI
        # ID is the deterministic ``eni-<instance_id without 'i-' prefix>``
        # synthesized at create time. If pinning was off when this
        # container was created, both ops are no-ops.
        try:
            from localemu.services.ec2.docker.address_index import (
                get_address_index,
            )
            from localemu.services.ec2.docker.subnet_allocator import (
                get_subnet_allocator,
            )
            eni_id = f"eni-{instance_id.removeprefix('i-')}"
            removed = get_address_index().delete_eni(eni_id)
            if removed is not None:
                get_subnet_allocator().release(removed.primary_ip)
        except Exception:
            LOG.debug(
                "EC2 %s: address-index/allocator cleanup failed",
                instance_id, exc_info=True,
            )

        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=5)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(container_name)
        except Exception:
            pass
        with self._lock:
            self._instances.pop(instance_id, None)
        LOG.info("EC2 instance %s terminated", instance_id)

    def get_console_output(self, instance_id: str) -> str:
        """Get the console output for an instance."""
        container_name = self._container_name(instance_id)
        info = self._instances.get(instance_id)

        # Return user data output + container logs
        output = ""
        if info and info.console_output:
            output = info.console_output + "\n"

        try:
            logs = DOCKER_CLIENT.get_container_logs(container_name)
            if isinstance(logs, bytes):
                logs = logs.decode("utf-8")
            output += logs
        except Exception:
            pass

        return output

    def get_instance_info(self, instance_id: str) -> Ec2ContainerInfo | None:
        """Get container info for an instance."""
        return self._instances.get(instance_id)

    def cleanup_all(self) -> None:
        """Stop and remove all EC2 containers. Called on LocalEmu shutdown
        when persistence is OFF. Destructive — containers and their
        writable layers are wiped. See ``stop_all`` for the persistence path.
        """
        LOG.info("Cleaning up EC2 Docker containers...")
        with self._lock:
            instance_ids = list(self._instances.keys())

        for instance_id in instance_ids:
            try:
                self.terminate_instance(instance_id)
            except Exception as e:
                LOG.debug("Failed to clean up EC2 instance %s: %s", instance_id, e)

        self._imds_server.stop()

    def stop_all(self, timeout: int = 10) -> None:
        """Stop (but do NOT remove) every EC2 container and shut down the
        IMDS singleton.

        Called on LocalEmu shutdown when ``PERSISTENCE=1``. Containers
        remain registered with Docker, carry their writable layer intact,
        and will be resumed by ``Ec2Provider.on_after_state_load`` on the
        next boot. We intentionally keep ``self._instances`` populated —
        if shutdown is interrupted the in-memory state stays consistent,
        and on cold-start the new ``DockerVmManager.__init__`` rebuilds
        the dict from Docker labels anyway.
        """
        LOG.info("Stopping EC2 Docker containers (containers preserved)...")
        with self._lock:
            instance_ids = list(self._instances.keys())
        for instance_id in instance_ids:
            name = self._container_name(instance_id)
            try:
                DOCKER_CLIENT.stop_container(name, timeout=timeout)
            except Exception as exc:
                LOG.debug("stop %s failed: %s", name, exc)
        # IMDS holds per-container state; restart fresh on load.
        try:
            self._imds_server.stop()
        except Exception:
            LOG.debug("imds stop failed", exc_info=True)

    def discover_containers(self) -> dict[str, dict]:
        """Return ``{instance_id: {name, labels, inspect}}`` for every
        ``localemu.service=ec2`` container on the host (running or stopped).

        Used by ``Ec2Provider.on_after_state_load`` to map persisted moto
        instance IDs to live Docker containers.
        """
        result: dict[str, dict] = {}
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=["label=localemu.service=ec2"], all=True,
            )
        except Exception:
            LOG.warning("discover_containers: list_containers failed", exc_info=True)
            return result
        for c in containers:
            labels = c.get("labels") or {}
            iid = labels.get("localemu.instance-id")
            if not iid:
                continue
            name = c.get("name") or c.get("id") or ""
            try:
                inspect = DOCKER_CLIENT.inspect_container(name)
            except Exception:
                continue
            result[iid] = {"name": name, "labels": labels, "inspect": inspect}
        return result

    def restore_instance(
        self,
        instance_id: str,
        moto_state: str,
        container_name: str,
        inspect: dict,
    ) -> Ec2ContainerInfo | None:
        """Re-hydrate ``self._instances[instance_id]`` from a live Docker
        container and (when moto says the instance was running) ``docker start``
        it.

        The restore is now a full data-plane reconciliation —
        the iptables chains from ``apply_sg_to_container`` do NOT survive
        a Docker daemon restart, so leaving them off means containers
        boot with whatever default policy Docker has (typically ACCEPT)
        while moto keeps reporting the SGs as enforced. We re-apply:

          - Security Group iptables (via the labels ``localemu.sg-ids``).
          - Network ACL iptables on the container's subnet.
          - ``VpcNetworkManager`` container tracking (so IGW toggle
            and peering operations see the container after restart).
          - STS credentials (the old ones expired after 6h and
            ``restore_instance`` previously left IMDS without any).

        Older containers (created before the account-id / region / sg-ids
        labels were added) won't carry those keys; for them we skip the
        steps that depend on the missing labels.
        """
        # Port — SSH is the one port LocalEmu publishes for EC2.
        port_bindings = (inspect.get("HostConfig") or {}).get("PortBindings") or {}
        ssh_binding = port_bindings.get("22/tcp") or []
        ssh_port = None
        if ssh_binding:
            try:
                ssh_port = int(ssh_binding[0].get("HostPort") or 0) or None
            except (TypeError, ValueError):
                ssh_port = None

        # Private IP — first VPC network wins; fall back to default bridge.
        # Explicitly ignore ``localemu-pubport-br``: its 172.31.255.x
        # address is an internal LocalEmu port-publishing artefact, not
        # a valid AWS PrivateIpAddress.
        from .vpc_network import PUBPORT_BRIDGE_NAME
        networks = (inspect.get("NetworkSettings") or {}).get("Networks") or {}
        private_ip = None
        vpc_id = None
        for net_name, net_info in networks.items():
            if net_name.startswith("localemu-vpc-"):
                private_ip = (net_info or {}).get("IPAddress") or None
                vpc_id = net_name.removeprefix("localemu-vpc-")
                break
        if not private_ip:
            fallback = (inspect.get("NetworkSettings") or {}).get("IPAddress") or None
            # Only use the top-level IPAddress if it's not the pubport
            # bridge IP — otherwise we'd return a 172.31.255.x address
            # that isn't routable from anywhere meaningful.
            pubport_info = networks.get(PUBPORT_BRIDGE_NAME) or {}
            pubport_ip = pubport_info.get("IPAddress") or ""
            if fallback and fallback != pubport_ip:
                private_ip = fallback

        labels = (inspect.get("Config") or {}).get("Labels") or {}
        image = (inspect.get("Config") or {}).get("Image", "")
        instance_type = labels.get("localemu.instance-type", "t2.micro")
        account_id = labels.get("localemu.account-id") or ""
        region = labels.get("localemu.region") or ""
        subnet_id = labels.get("localemu.subnet-id") or ""
        raw_sgs = labels.get("localemu.sg-ids") or ""
        sg_ids = [s for s in raw_sgs.split(",") if s]
        iam_role_name = labels.get("localemu.iam-role-name") or ""
        iam_profile_arn = labels.get("localemu.iam-profile-arn") or ""

        # Re-allocate the per-instance IMDS proxy port. The
        # container's env var AWS_EC2_METADATA_SERVICE_ENDPOINT was
        # baked at create time; we extract the port from the inspect
        # result and ask the IMDS server to bind the new proxy there
        # so the container's calls continue to land on a listener.
        imds_port_requested = _extract_imds_port_from_inspect(inspect)
        try:
            if imds_port_requested:
                imds_port = self._imds_server.allocate_port_for_instance(
                    instance_id, requested_port=imds_port_requested,
                )
            else:
                imds_port = self._imds_server.port
        except Exception:
            LOG.debug(
                "restore: could not allocate per-instance IMDS port for %s",
                instance_id, exc_info=True,
            )
            imds_port = self._imds_server.port

        info = Ec2ContainerInfo(
            instance_id=instance_id,
            container_name=container_name,
            image=image,
            ssh_port=ssh_port,
            imds_port=imds_port,
            private_ip=private_ip,
            instance_type=instance_type,
            vpc_id=vpc_id,
        )
        with self._lock:
            self._instances[instance_id] = info

        if moto_state == "running":
            try:
                DOCKER_CLIENT.start_container(container_name)
            except Exception as exc:
                LOG.warning(
                    "docker start %s failed during restore: %s", container_name, exc,
                )
                return info

        # --- Data-plane reconciliation -----------------------------------
        if account_id and region and sg_ids:
            try:
                from localemu.services.ec2.docker.sg_iptables import (
                    apply_sg_to_container,
                )
                if not apply_sg_to_container(container_name, sg_ids, account_id, region):
                    LOG.warning(
                        "Restore %s: SG iptables re-apply failed — "
                        "container is in fail-closed DROP state",
                        instance_id,
                    )
                # Also re-register with the sg_reapply mapping so future
                # AuthorizeSG events reach this restored instance.
                from localemu.services.ec2.docker.sg_reapply import (
                    record_instance_sgs,
                )
                record_instance_sgs(account_id, region, instance_id, sg_ids)
            except Exception:
                LOG.warning(
                    "Restore %s: SG re-apply raised", instance_id, exc_info=True,
                )

        if vpc_id:
            try:
                from localemu.services.ec2.docker.vpc_network import (
                    get_vpc_network_manager,
                )
                get_vpc_network_manager().register_container(
                    vpc_id, container_name, subnet_id=subnet_id or None,
                )
            except Exception:
                LOG.debug(
                    "Restore %s: VPC container re-register failed",
                    instance_id, exc_info=True,
                )

        if account_id and region and subnet_id:
            try:
                nacl_id = _resolve_nacl_for_subnet(subnet_id, account_id, region)
                if nacl_id:
                    from localemu.services.ec2.docker.nacl_enforcer import (
                        apply_nacl_to_subnet_containers,
                    )
                    apply_nacl_to_subnet_containers(
                        nacl_id, subnet_id, account_id, region,
                    )
            except Exception:
                LOG.debug(
                    "Restore %s: NACL re-apply failed",
                    instance_id, exc_info=True,
                )

        iam_credentials = None
        if iam_role_name and account_id:
            iam_credentials = _reissue_sts_for_restore(
                iam_role_name, account_id, region or "us-east-1", instance_id,
            )

        # IMDS re-register carries the re-issued credentials so the
        # instance's SDK calls keep working after LocalEmu restart.
        try:
            az_region = region or "us-east-1"
            az = f"{az_region}a"
            metadata = {
                "instance_id": instance_id,
                "instance-id": instance_id,
                "instance_type": instance_type,
                "instance-type": instance_type,
                "local-ipv4": private_ip or "",
                "public-ipv4": private_ip or "",
                "private_ip": private_ip or "",
                "ami-id": labels.get("localemu.ami-id", "ami-ubuntu-22.04"),
                "ami_id": labels.get("localemu.ami-id", "ami-ubuntu-22.04"),
                "placement/availability-zone": az,
                "az": az,
                "region": az_region,
                "account_id": account_id or "000000000000",
                "hostname": f"ip-{(private_ip or '').replace('.', '-')}.ec2.internal"
                if private_ip
                else "localhost",
            }
            if iam_role_name:
                metadata["iam_role_name"] = iam_role_name
                metadata["instance_profile_arn"] = iam_profile_arn or ""
            if iam_credentials:
                metadata["iam_credentials"] = iam_credentials
            if private_ip:
                self._imds_server.register_instance(
                    instance_id, private_ip, metadata,
                )
        except Exception:
            LOG.debug("IMDS re-register failed for %s", instance_id, exc_info=True)

        return info

