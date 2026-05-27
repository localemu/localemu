"""Docker Task Manager for ECS tasks.

Manages the lifecycle of Docker containers running real container images
for ECS tasks. Each RunTask call starts one or more Docker containers
matching the task definition's containerDefinitions.

Port mapping TOCTOU is a known limitation. Docker's port allocation
is inherently non-atomic — between get_free_tcp_port() and the actual bind
in container start, another process could claim the port. This is an accepted
trade-off for local emulation; production ECS does not have this issue.
"""

import logging
import shlex
import threading
import time
import uuid
from dataclasses import dataclass, field

from localemu.utils.container_utils.container_client import (
    BindMount,
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

# Label for identifying ECS containers
ECS_CONTAINER_LABEL = "localemu.service=ecs"

# Image pull locks (same pattern as Lambda, EC2, and RDS)
# PERF-R2-01: bounded with LRU eviction to prevent unbounded growth
_IMAGE_PULL_LOCKS_MAXSIZE = 64
_image_pull_locks: dict[str, threading.Lock] = {}
_image_pull_locks_lock = threading.Lock()


@dataclass
class EcsContainerInfo:
    """Tracks a single running container within an ECS task."""

    container_name: str
    docker_name: str
    image: str
    host_ports: dict[int, int] = field(default_factory=dict)
    status: str = "PENDING"
    exit_code: int | None = None


@dataclass
class EcsTaskInfo:
    """Tracks a running ECS task (which may have multiple containers)."""

    task_arn: str
    task_id: str
    cluster_name: str
    task_definition_arn: str
    containers: list[EcsContainerInfo] = field(default_factory=list)
    status: str = "RUNNING"
    # PARITY-04: Timing fields
    created_at: float | None = None
    started_at: float | None = None
    stopped_at: float | None = None


class DockerTaskManager:
    """Manages Docker containers as ECS task instances.

    Each ECS task maps to one or more Docker containers, one per
    containerDefinition in the task definition.
    """

    def __init__(self):
        self._tasks: dict[str, EcsTaskInfo] = {}
        self._lock = threading.Lock()
        self._recover_orphaned_containers()

    def _recover_orphaned_containers(self) -> None:
        """Scan for labeled ECS containers left from a previous run (BUG-11 equivalent)."""
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=["label=localemu.service=ecs"],
                all=False,
            )
            recovered = 0
            for container in containers:
                labels = container.get("labels", {})
                task_arn = labels.get("localemu.task-arn")
                if not task_arn or task_arn in self._tasks:
                    continue
                c_name = labels.get("localemu.container-name", "unknown")
                docker_name = container.get("name", "")
                cluster = labels.get("localemu.cluster", "default")
                task_id = task_arn.split("/")[-1] if "/" in task_arn else task_arn[:12]
                ci = EcsContainerInfo(
                    container_name=c_name,
                    docker_name=docker_name,
                    image=container.get("image", ""),
                    status="RUNNING",
                )
                if task_arn not in self._tasks:
                    self._tasks[task_arn] = EcsTaskInfo(
                        task_arn=task_arn,
                        task_id=task_id,
                        cluster_name=cluster,
                        task_definition_arn="",
                    )
                self._tasks[task_arn].containers.append(ci)
                recovered += 1
            if recovered:
                LOG.info("Recovered %d orphaned ECS containers", recovered)
        except Exception as e:
            LOG.debug("Failed to scan for orphaned ECS containers: %s", e)

    def _container_name(
        self, cluster: str, task_id: str, container_name: str
    ) -> str:
        """Generate a Docker container name for an ECS task container.

        Format: localemu-ecs-{cluster_short}-{task_id_prefix}-{container_name}

        BUG-11: Use 12-char prefix instead of 8 to reduce collision probability.
        """
        cluster_short = cluster.split("/")[-1] if "/" in cluster else cluster
        # Truncate cluster name to keep Docker name reasonable
        cluster_short = cluster_short[:20]
        return f"localemu-ecs-{cluster_short}-{task_id[:12]}-{container_name}"

    def _ensure_image(self, image: str) -> None:
        """Pull Docker image if not available. Thread-safe."""
        with _image_pull_locks_lock:
            if image not in _image_pull_locks:
                # PERF-R2-01: evict oldest entry when maxsize reached
                if len(_image_pull_locks) >= _IMAGE_PULL_LOCKS_MAXSIZE:
                    oldest_key = next(iter(_image_pull_locks))
                    del _image_pull_locks[oldest_key]
                _image_pull_locks[image] = threading.Lock()
            lock = _image_pull_locks[image]

        with lock:
            try:
                DOCKER_CLIENT.inspect_image(image)
            except Exception:
                LOG.info("Pulling ECS task image %s...", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                    LOG.info("Image %s pulled successfully", image)
                except Exception as e:
                    raise RuntimeError(
                        f"Failed to pull ECS task image {image}: {e}"
                    ) from e

    def run_task(
        self,
        cluster_name: str,
        task_definition: dict,
        task_arn: str,
        count: int = 1,
        overrides: dict | None = None,
        launch_type: str = "EC2",
        region: str = "us-east-1",
        network_configuration: dict | None = None,
        account_id: str = "",
    ) -> list[EcsTaskInfo]:
        """Start Docker containers for an ECS RunTask call.

        Args:
            cluster_name: ECS cluster name or ARN.
            task_definition: The resolved task definition dict containing
                containerDefinitions and other metadata.
            task_arn: The task ARN assigned by Moto.
            count: Number of task copies to launch.
            overrides: Optional container overrides from the RunTask request.
            launch_type: EC2 or FARGATE (PARITY-02).
            Region: AWS region for env vars .

        Returns:
            List of EcsTaskInfo with container details.
        """
        container_defs = task_definition.get("containerDefinitions") or task_definition.get("container_definitions") or []
        if not container_defs:
            LOG.warning("Task definition has no containerDefinitions, skipping Docker launch")
            return []

        container_overrides = {}
        if overrides and overrides.get("containerOverrides"):
            for co in overrides["containerOverrides"]:
                name = co.get("name")
                if name:
                    container_overrides[name] = co

        # PARITY-03: Extract network mode from task definition
        network_mode = task_definition.get("networkMode", "bridge")

        # Task role for IAM — RunTask's ``overrides.taskRoleArn`` wins over
        # the task definition's ``taskRoleArn`` (AWS API semantics).
        task_role_arn = (overrides or {}).get("taskRoleArn") or task_definition.get(
            "taskRoleArn"
        )

        # PARITY-07: Extract volume definitions for mounting
        td_volumes = task_definition.get("volumes", [])
        # Build a map of volume name -> host path or Docker volume name
        volume_map: dict[str, str] = {}
        for vol in td_volumes:
            vol_name = vol.get("name", "") if isinstance(vol, dict) else ""
            if not vol_name:
                continue
            host = vol.get("host", {}) if isinstance(vol, dict) else {}
            if isinstance(host, dict) and host.get("sourcePath"):
                volume_map[vol_name] = host["sourcePath"]
            else:
                # Use a Docker named volume
                volume_map[vol_name] = vol_name

        results: list[EcsTaskInfo] = []

        for i in range(count):
            # BUG-05: Generate unique task ID for each count iteration
            # When count > 1, Moto creates one task ARN but we need unique IDs
            if i == 0:
                task_id = task_arn.split("/")[-1] if "/" in task_arn else str(uuid.uuid4())
                effective_arn = task_arn
            else:
                task_id = str(uuid.uuid4())
                # Build a unique ARN for each additional copy
                arn_prefix = "/".join(task_arn.split("/")[:-1]) if "/" in task_arn else task_arn
                effective_arn = f"{arn_prefix}/{task_id}"

            task_info = EcsTaskInfo(
                task_arn=effective_arn,
                task_id=task_id,
                cluster_name=cluster_name,
                task_definition_arn=task_definition.get("taskDefinitionArn", ""),
                # PARITY-04: Track creation time
                created_at=time.time(),
            )

            for cdef in container_defs:
                c_name = cdef.get("name", "container")
                image = cdef.get("image", "")

                if not image:
                    LOG.warning(
                        "ECS container %s has no image, skipping", c_name
                    )
                    continue

                # Apply overrides
                co = container_overrides.get(c_name, {})
                if co.get("command"):
                    command = co["command"]
                elif cdef.get("command"):
                    command = cdef["command"]
                else:
                    command = None

                # Use shlex.split() for string commands
                if command and isinstance(command, str):
                    command = shlex.split(command)
                elif command and isinstance(command, list):
                    pass  # already a list, keep as-is
                else:
                    command = None

                # Build environment variables
                env_vars: dict[str, str] = {}
                for env in cdef.get("environment", []):
                    env_vars[env.get("name", "")] = env.get("value", "")
                # Apply environment overrides
                for env in co.get("environment", []):
                    env_vars[env.get("name", "")] = env.get("value", "")
                # Add LocalEmu metadata
                env_vars["LOCALEMU_ECS_TASK_ARN"] = effective_arn
                env_vars["LOCALEMU_ECS_CLUSTER"] = cluster_name
                env_vars["LOCALEMU_ECS_CONTAINER_NAME"] = c_name

                # / #79: Standard ECS env vars. The credentials
                # endpoint runs on the LocalEmu host; inside the task
                # container we DNAT 169.254.170.2:80 → host:creds_port
                # after start_container (AWS SDK only trusts the approved
                # link-local hosts for the credentials endpoint, so we
                # MUST present 169.254.170.2). The DNAT install happens
                # below after docker start, inside the container's
                # netns (requires NET_ADMIN capability).
                from localemu import config as _le_config
                from localemu.services.ecs.docker.task_credentials import (
                    get_task_credentials_server,
                )
                _creds_server = get_task_credentials_server()
                _creds_port = _creds_server.port
                _gw_port = _le_config.GATEWAY_LISTEN[0].port

                env_vars["ECS_CONTAINER_METADATA_URI"] = (
                    f"http://169.254.170.2/v3/{task_id}"
                )
                env_vars["ECS_CONTAINER_METADATA_URI_V4"] = (
                    f"http://169.254.170.2/v4/{task_id}"
                )
                env_vars["AWS_DEFAULT_REGION"] = region
                env_vars["AWS_REGION"] = region
                env_vars["AWS_ENDPOINT_URL"] = f"http://host.docker.internal:{_gw_port}"
                if task_role_arn:
                    # RELATIVE_URI resolves against 169.254.170.2 (one of
                    # the SDK's four approved hosts). DNAT does the rest.
                    env_vars["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"] = (
                        f"/v2/credentials/{task_id}"
                    )
                    # Mint STS creds via moto's backend; the assumed_role
                    # entry it creates lets our IAM enforcer resolve the
                    # signed request back to the correct role.
                    try:
                        from datetime import datetime, timedelta, timezone
                        from moto.sts.models import sts_backends
                        sts_backend = sts_backends[account_id or "000000000000"]["global"]
                        assumed = sts_backend.assume_role(
                            region_name=region,
                            role_session_name=f"ecs-task-{task_id[:32]}",
                            role_arn=task_role_arn,
                            policy=None,
                            duration=3600,
                            external_id=None,
                        )
                        _creds_server.store.put(task_id, {
                            "RoleArn": task_role_arn,
                            "AccessKeyId": assumed.access_key_id,
                            "SecretAccessKey": assumed.secret_access_key,
                            "Token": assumed.session_token,
                            "Expiration": (
                                datetime.now(timezone.utc) + timedelta(hours=1)
                            ).isoformat().replace("+00:00", "Z"),
                        })
                        LOG.info(
                            "Generated task-role credentials for ECS task %s "
                            "(role=%s, key=%s***)",
                            task_id, task_role_arn,
                            assumed.access_key_id[:4],
                        )
                    except Exception as e:
                        LOG.error(
                            "Failed to mint task-role credentials for ECS task %s "
                            "(role=%s): %s — SDKs inside the container will see "
                            "NoCredentialsError",
                            task_id, task_role_arn, e, exc_info=True,
                        )
                        # Drop the relative URI so the SDK fails at
                        # credential discovery rather than hitting an
                        # empty endpoint.
                        env_vars.pop(
                            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None,
                        )

                # Build port mappings
                ports = PortMappings()
                host_ports: dict[int, int] = {}
                for pm in cdef.get("portMappings", []):
                    container_port = pm.get("containerPort")
                    if container_port:
                        host_port = pm.get("hostPort") or get_free_tcp_port()
                        ports.add(host_port, container_port)
                        host_ports[container_port] = host_port

                # Ensure image is available
                try:
                    self._ensure_image(image)
                except Exception as e:
                    LOG.warning(
                        "Failed to pull image %s for ECS task %s: %s",
                        image, task_id, e,
                    )
                    continue

                docker_name = self._container_name(cluster_name, task_id, c_name)

                # PARITY-07: Build volume mappings from mountPoints
                volumes = VolumeMappings()
                for mp in cdef.get("mountPoints", []):
                    if isinstance(mp, dict):
                        src_vol = mp.get("sourceVolume", "")
                        container_path = mp.get("containerPath", "")
                        if src_vol and container_path and src_vol in volume_map:
                            host_path = volume_map[src_vol]
                            read_only = mp.get("readOnly", False)
                            # ISSUE-01: Use BindMount so the read-only flag is honored
                            # by the Docker SDK. The legacy tuple form ignored the mode.
                            volumes.append(
                                BindMount(host_path, container_path, read_only=read_only)
                            )

                # PARITY-03: Determine Docker network mode
                docker_network = None
                if network_mode == "host":
                    docker_network = "host"
                elif network_mode == "none":
                    docker_network = "none"
                # Awsvpc handled after container creation 

                # Extract CPU/memory limits from container definition
                cpu_shares = None
                mem_limit = None
                container_cpu = cdef.get("cpu")
                container_memory = cdef.get("memory") or cdef.get("memoryReservation")
                if container_cpu:
                    # ECS cpu units map to Docker cpu_shares (1024 = 1 vCPU)
                    try:
                        cpu_shares = int(container_cpu)
                    except (ValueError, TypeError):
                        pass
                if container_memory:
                    # ECS memory is in MiB
                    try:
                        mem_limit = f"{int(container_memory)}m"
                    except (ValueError, TypeError):
                        pass

                # PARITY-06: Build Docker health check flags from task definition.
                # ECS accepts ["CMD", "exit 0"] or ["CMD-SHELL", "exit 0"] per
                # RegisterTaskDefinition's ``containerDefinitions.healthCheck``
                # contract; we translate both to ``docker create --health-*``
                # CLI flags via ``ContainerConfiguration.additional_flags`` so
                # the resulting container actually has a Healthcheck set, which
                # is what the user observes via ``docker inspect`` and what ECS
                # uses to decide task health. Before this, the command was
                # parsed but discarded — the container started with no health
                # check, making services relying on health never stabilize.
                additional_flags_parts: list[str] = []
                hc = cdef.get("healthCheck")
                if hc and isinstance(hc, dict):
                    hc_command = hc.get("command", [])
                    if isinstance(hc_command, list) and len(hc_command) >= 2:
                        if hc_command[0] == "CMD-SHELL":
                            hc_shell = hc_command[1]
                            additional_flags_parts.append(
                                f"--health-cmd={shlex.quote(hc_shell)}"
                            )
                        elif hc_command[0] == "CMD":
                            # Docker CLI --health-cmd runs through a shell,
                            # so join argv tokens the same way real ECS does.
                            hc_shell = " ".join(shlex.quote(p) for p in hc_command[1:])
                            additional_flags_parts.append(
                                f"--health-cmd={shlex.quote(hc_shell)}"
                            )
                    interval = hc.get("interval")
                    if interval:
                        additional_flags_parts.append(f"--health-interval={int(interval)}s")
                    timeout_s = hc.get("timeout")
                    if timeout_s:
                        additional_flags_parts.append(f"--health-timeout={int(timeout_s)}s")
                    retries = hc.get("retries")
                    if retries:
                        additional_flags_parts.append(f"--health-retries={int(retries)}")
                    start_period = hc.get("startPeriod") or hc.get("start_period")
                    if start_period:
                        additional_flags_parts.append(
                            f"--health-start-period={int(start_period)}s"
                        )
                # #79: Always add host.docker.internal mapping so the task's
                # SDK can reach both the host-bound credentials server and
                # the LocalEmu gateway. On Docker Desktop this is a no-op
                # (the DNS name resolves automatically); on Linux + Docker
                # CE it's required.
                additional_flags_parts.append(
                    "--add-host host.docker.internal:host-gateway"
                )
                additional_flags = " ".join(additional_flags_parts) if additional_flags_parts else None

                # Container config
                container_config = ContainerConfiguration(
                    image_name=image,
                    name=docker_name,
                    env_vars=env_vars,
                    ports=ports,
                    volumes=volumes,
                    command=command if isinstance(command, list) else (
                        [command] if command else None
                    ),
                    detach=True,
                    network=docker_network,
                    cpu_shares=cpu_shares,
                    mem_limit=mem_limit,
                    additional_flags=additional_flags,
                    # #79: NET_ADMIN lets us install an iptables DNAT rule
                    # in the container's netns that redirects
                    # 169.254.170.2:80 → host.docker.internal:<creds_port>.
                    # AWS SDKs only trust a handful of allow-listed hosts
                    # (169.254.170.2, 169.254.170.23, localhost, ::1) for
                    # the container-credentials endpoint, so we *must*
                    # present 169.254.170.2 — pointing FULL_URI directly
                    # at host.docker.internal fails SDK validation.
                    cap_add=["NET_ADMIN"],
                    labels={
                        "localemu.service": "ecs",
                        "localemu.cluster": cluster_name,
                        "localemu.task-arn": effective_arn,
                        "localemu.container-name": c_name,
                        "localemu.network-mode": network_mode,
                        # #79: task-role is persisted on the container so
                        # the on-load reconciler can re-mint creds.
                        "localemu.task-role-arn": task_role_arn or "",
                    },
                )

                LOG.info(
                    "Starting ECS container %s (image=%s, task=%s)",
                    docker_name, image, task_id[:12],
                )

                try:
                    DOCKER_CLIENT.create_container_from_config(container_config)
                    try:
                        DOCKER_CLIENT.start_container(docker_name)
                    except Exception as start_err:
                        # BUG-08: Container start failure — remove the created container
                        LOG.warning(
                            "Failed to start ECS container %s, removing: %s",
                            docker_name, start_err,
                        )
                        try:
                            DOCKER_CLIENT.remove_container(docker_name)
                        except Exception:
                            pass
                        container_info = EcsContainerInfo(
                            container_name=c_name,
                            docker_name=docker_name,
                            image=image,
                            host_ports=host_ports,
                            status="STOPPED",
                            exit_code=1,
                        )
                        task_info.containers.append(container_info)
                        continue

                    # Connect to the VPC network derived
                    # from the task's awsvpcConfiguration.subnets.
                    if network_mode == "awsvpc":
                        awsvpc_cfg = (network_configuration or {}).get(
                            "awsvpcConfiguration", {},
                        )
                        subnet_ids = awsvpc_cfg.get("subnets") or []
                        self._connect_to_vpc_network(
                            docker_name, cluster_name,
                            subnet_ids=subnet_ids,
                            account_id=account_id,
                            region=region,
                        )

                    # #79: Install DNAT so 169.254.170.2:80 inside this
                    # container is redirected to our host-bound task-
                    # credentials server. Done post-start because we need
                    # the container's netns. host.docker.internal resolves
                    # inside the container via --add-host above.
                    if task_role_arn:
                        self._install_task_creds_dnat(docker_name, _creds_port)

                    container_info = EcsContainerInfo(
                        container_name=c_name,
                        docker_name=docker_name,
                        image=image,
                        host_ports=host_ports,
                        status="RUNNING",
                    )
                    task_info.containers.append(container_info)

                    # PARITY-04: Track started time
                    task_info.started_at = time.time()

                    port_info = (
                        f", ports={host_ports}" if host_ports else ""
                    )
                    LOG.info(
                        "ECS container %s running (image=%s%s)",
                        docker_name, image, port_info,
                    )
                except Exception as e:
                    LOG.warning(
                        "Failed to create ECS container %s: %s",
                        docker_name, e,
                    )
                    container_info = EcsContainerInfo(
                        container_name=c_name,
                        docker_name=docker_name,
                        image=image,
                        host_ports=host_ports,
                        status="STOPPED",
                        exit_code=1,
                    )
                    task_info.containers.append(container_info)

            with self._lock:
                self._tasks[effective_arn] = task_info

            results.append(task_info)

        return results

    def _install_task_creds_dnat(self, docker_name: str, creds_port: int) -> None:
        """Install iptables DNAT rule redirecting 169.254.170.2:80 → host:creds_port.

        Runs inside the target container's netns (requires NET_ADMIN).
        Must land before the container's entrypoint issues any AWS SDK
        call; we serialise on docker exec so by the time run_task
        returns, the rule is in place.

        host.docker.internal is resolved at rule-install time via
        ``getent hosts``; if the resolution fails or iptables is absent
        (bare / distroless user images), we log at WARNING and leave
        the container running — the user's AWS SDK calls will then hit
        169.254.170.2 directly and fail at the network layer rather
        than silently talking to real AWS.
        """
        # getent ahostsv4 only returns IPv4 addresses — vital because
        # iptables (nf_tables) rejects IPv6 literals here and Docker
        # Desktop's host.docker.internal resolves to both families.
        script = (
            'set -e; '
            'HOST_IP=$(getent ahostsv4 host.docker.internal 2>/dev/null '
            '| awk \'/STREAM/ {print $1; exit}\'); '
            'if [ -z "$HOST_IP" ]; then '
            '  HOST_IP=$(getent hosts host.docker.internal 2>/dev/null '
            '| awk \'$1 !~ /:/ {print $1; exit}\'); '
            'fi; '
            'if [ -z "$HOST_IP" ]; then echo "host.docker.internal unresolvable" >&2; exit 1; fi; '
            'iptables -t nat -C OUTPUT -d 169.254.170.2 -p tcp --dport 80 '
            f'-j DNAT --to-destination ${{HOST_IP}}:{creds_port} 2>/dev/null '
            '|| iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp --dport 80 '
            f'-j DNAT --to-destination ${{HOST_IP}}:{creds_port}'
        )
        try:
            out, err = DOCKER_CLIENT.exec_in_container(
                docker_name, ["sh", "-c", script],
            )
            LOG.debug(
                "task-creds DNAT installed on %s (stdout=%r stderr=%r)",
                docker_name, out, err,
            )
        except Exception as e:
            LOG.warning(
                "Failed to install task-creds DNAT rule on %s: %s — "
                "AWS SDK calls inside the container will not reach the "
                "LocalEmu task-credentials endpoint",
                docker_name, e,
            )

    def _connect_to_vpc_network(
        self,
        docker_name: str,
        cluster_name: str,
        subnet_ids: list[str] | None = None,
        account_id: str = "",
        region: str = "",
    ) -> None:
        """Connect an awsvpc-mode task container to the right VPC network.

        Previously this shelled out to ``docker network ls`` and
        took the first ``localemu-vpc-*`` result. With multiple VPCs
        that was a silent isolation failure — tasks could land in the
        wrong VPC.

        The subnet IDs from the RunTask request's
        ``networkConfiguration.awsvpcConfiguration.subnets`` are the
        authoritative source of "which VPC should this task be on". We
        resolve the first one that maps to a known VPC via moto and
        attach. If no subnet resolves, we log a warning and leave the
        container on its default network rather than pick an arbitrary
        VPC — correctness over liveness.
        """
        try:
            networks = DOCKER_CLIENT.get_networks(docker_name)
            for net in networks:
                if net.startswith("localemu-vpc-"):
                    LOG.debug(
                        "ECS container %s already on VPC network %s",
                        docker_name, net,
                    )
                    return

            if not subnet_ids:
                LOG.warning(
                    "ECS awsvpc task %s: no subnets provided — "
                    "container will not be attached to any VPC network. "
                    "Provide networkConfiguration.awsvpcConfiguration.subnets "
                    "on RunTask to enable per-VPC isolation.",
                    docker_name,
                )
                return

            from localemu.services.ec2.docker.vpc_network import (
                get_vpc_network_manager,
            )
            vpcm = get_vpc_network_manager()

            vpc_id = None
            for subnet_id in subnet_ids:
                try:
                    resolved = vpcm.get_vpc_id_for_subnet(
                        subnet_id, account_id, region,
                    )
                except Exception:
                    resolved = None
                if resolved:
                    vpc_id = resolved
                    break

            if not vpc_id:
                LOG.warning(
                    "ECS awsvpc task %s: none of subnets=%s resolve to a VPC in %s/%s — "
                    "skipping VPC network attach",
                    docker_name, subnet_ids, account_id, region,
                )
                return

            vpc_network = f"localemu-vpc-{vpc_id}"
            DOCKER_CLIENT.connect_container_to_network(vpc_network, docker_name)
            LOG.info(
                "ECS awsvpc task %s connected to %s (resolved from subnet)",
                docker_name, vpc_network,
            )
        except Exception as e:
            LOG.debug("Failed to connect container %s to VPC network: %s", docker_name, e)

    def stop_task(self, task_arn: str) -> None:
        """Stop and remove all Docker containers for a task."""
        with self._lock:
            task_info = self._tasks.pop(task_arn, None)

        if not task_info:
            LOG.debug("No tracked containers for task %s", task_arn)
            return

        for container in task_info.containers:
            docker_name = container.docker_name
            try:
                DOCKER_CLIENT.stop_container(docker_name, timeout=10)
            except Exception:
                pass
            try:
                DOCKER_CLIENT.remove_container(docker_name)
            except Exception:
                pass
            container.status = "STOPPED"

        task_info.status = "STOPPED"
        # PARITY-04: Track stop time
        task_info.stopped_at = time.time()
        # #79: drop cached task-role credentials so the creds server
        # returns 404 for a stopped task (AWS semantics: creds revoked).
        try:
            from localemu.services.ecs.docker.task_credentials import (
                get_task_credentials_server,
            )
            task_id = task_arn.split("/")[-1]
            get_task_credentials_server().store.revoke(task_id)
        except Exception:
            LOG.debug("Failed to revoke task credentials for %s", task_arn, exc_info=True)
        LOG.info("ECS task %s stopped (%d containers)", task_arn, len(task_info.containers))

    def get_task_status(self, task_arn: str) -> EcsTaskInfo | None:
        """Inspect Docker containers and return ECS-compatible status."""
        with self._lock:
            task_info = self._tasks.get(task_arn)
        if not task_info:
            return None

        all_stopped = True
        for container in task_info.containers:
            try:
                inspect = DOCKER_CLIENT.inspect_container(container.docker_name)
                state = inspect.get("State", {})
                if isinstance(state, dict):
                    running = state.get("Running", False)
                    if running:
                        container.status = "RUNNING"
                        all_stopped = False
                    else:
                        container.status = "STOPPED"
                        container.exit_code = state.get("ExitCode")
                else:
                    # Some backends return state as a string
                    if state == "running":
                        container.status = "RUNNING"
                        all_stopped = False
                    else:
                        container.status = "STOPPED"
            except Exception:
                container.status = "STOPPED"

        if all_stopped and task_info.containers:
            task_info.status = "STOPPED"
            if not task_info.stopped_at:
                task_info.stopped_at = time.time()

        return task_info

    def cleanup_cluster(self, cluster_name: str) -> None:
        """Stop and remove all containers belonging to a cluster."""
        # Normalize to short name — tasks may store the full ARN or short name
        cluster_short = cluster_name.split("/")[-1] if "/" in cluster_name else cluster_name
        with self._lock:
            cluster_tasks = [
                arn for arn, info in self._tasks.items()
                if (info.cluster_name.split("/")[-1] if "/" in info.cluster_name else info.cluster_name) == cluster_short
            ]

        for task_arn in cluster_tasks:
            try:
                self.stop_task(task_arn)
            except Exception as e:
                LOG.debug(
                    "Failed to clean up ECS task %s: %s", task_arn, e
                )

        LOG.info("ECS cluster %s containers cleaned up", cluster_name)

    def cleanup_all(self) -> None:
        """Stop and remove all ECS containers. Called on LocalEmu shutdown
        when persistence is OFF. Destructive — see ``stop_all_for_persistence``
        for the persistence path."""
        LOG.info("Cleaning up ECS Docker containers...")
        with self._lock:
            task_arns = list(self._tasks.keys())

        for task_arn in task_arns:
            try:
                self.stop_task(task_arn)
            except Exception as e:
                LOG.debug("Failed to clean up ECS task %s: %s", task_arn, e)

    def stop_all_for_persistence(self, timeout: int = 10) -> None:
        """Stop (but do NOT remove) every ECS task container.

        Called on LocalEmu shutdown when ``PERSISTENCE=1``. Containers
        stay on disk with their writable layer intact so
        ``EcsStateLifecycleHook.on_after_state_load`` can ``docker start``
        them on the next boot. ``self._tasks`` is kept populated — the
        labels on the containers are the source of truth anyway and
        ``_recover_orphaned_containers`` rebuilds the dict on fresh boot.
        """
        LOG.info("Stopping ECS task containers for persistence (no remove)...")
        with self._lock:
            snapshot = list(self._tasks.values())
        for task_info in snapshot:
            for container in task_info.containers:
                try:
                    DOCKER_CLIENT.stop_container(container.docker_name, timeout=timeout)
                    container.status = "STOPPED"
                except Exception as exc:
                    LOG.debug(
                        "Failed to stop ECS container %s: %s",
                        container.docker_name, exc,
                    )
            task_info.status = "STOPPED"
