"""Docker Database Manager for RDS instances.

Manages the lifecycle of Docker containers running real database engines.
Each CreateDBInstance call starts a MySQL, PostgreSQL, or MariaDB container.
"""

import base64
import logging
import socket
import threading
import time
from dataclasses import dataclass, field

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

from .engine_mapping import (
    get_engine_env_vars,
    get_engine_port,
    resolve_engine_image,
)

# Label carrying the base64-encoded master password. Written at container
# create time so that if the Python process dies and the in-memory
# ``_instances`` dict is lost, we can still recreate a container mounted on
# the same named volume — the password is the only piece that moto's
# DescribeDBInstances response doesn't return (AWS parity: real AWS also
# never echoes it).
MASTER_PASSWORD_LABEL = "localemu.master-password-b64"

LOG = logging.getLogger(__name__)

# Label for identifying RDS containers
RDS_CONTAINER_LABEL = "localemu.service=rds"

# Data directory per engine for volume persistence (BUG-10)
ENGINE_DATA_DIR: dict[str, str] = {
    "mysql": "/var/lib/mysql",
    "postgres": "/var/lib/postgresql/data",
    "mariadb": "/var/lib/mysql",
    "aurora-mysql": "/var/lib/mysql",
    "aurora-postgresql": "/var/lib/postgresql/data",
}

# Image pull locks (same pattern as Lambda and EC2)
# PERF-R2-01: bounded with LRU eviction to prevent unbounded growth
_IMAGE_PULL_LOCKS_MAXSIZE = 64
_image_pull_locks: dict[str, threading.Lock] = {}
_image_pull_locks_lock = threading.Lock()

# DBInstanceClass -> Docker resource limits mapping
# Values are (memory_mb, cpu_shares) — cpu_shares is relative to 1024 = 1 CPU
INSTANCE_CLASS_RESOURCE_MAP: dict[str, tuple[int, int]] = {
    "db.t3.micro": (512, 256),
    "db.t3.small": (1024, 512),
    "db.t3.medium": (2048, 512),
    "db.t3.large": (4096, 1024),
    "db.t3.xlarge": (8192, 2048),
    "db.t3.2xlarge": (16384, 4096),
    "db.t4g.micro": (512, 256),
    "db.t4g.small": (1024, 512),
    "db.t4g.medium": (2048, 512),
    "db.t4g.large": (4096, 1024),
    "db.m5.large": (4096, 1024),
    "db.m5.xlarge": (8192, 2048),
    "db.m5.2xlarge": (16384, 4096),
    "db.m6g.large": (4096, 1024),
    "db.m6g.xlarge": (8192, 2048),
    "db.r5.large": (8192, 1024),
    "db.r5.xlarge": (16384, 2048),
    "db.r6g.large": (8192, 1024),
    "db.r6g.xlarge": (16384, 2048),
}


@dataclass
class RdsContainerInfo:
    """Tracks a running RDS Docker container."""
    db_instance_id: str
    container_name: str
    engine: str
    image: str
    host_port: int
    container_port: int
    master_username: str
    master_password: str
    db_name: str | None = None
    endpoint: str = ""
    status: str = "creating"
    container_ip: str = ""
    vpc_id: str | None = None
    db_instance_class: str = "db.t3.micro"
    networks: list[str] = field(default_factory=list)
    # Aurora-cluster membership. None for standalone DB instances.
    # Persisted as Docker labels so the role survives a LocalEmu
    # restart (see cluster_orchestrator.recover_from_labels in a
    # follow-up commit).
    cluster_id: str | None = None
    is_writer: bool = False
    promotion_tier: int = 1


# Docker labels carrying Aurora-cluster membership across restarts.
CLUSTER_ID_LABEL = "localemu.cluster-id"
IS_WRITER_LABEL = "localemu.is-writer"
PROMOTION_TIER_LABEL = "localemu.promotion-tier"


def cluster_network_name(cluster_id: str) -> str:
    """Per-cluster Docker network name. The writer + readers attach
    here so a standby's ``primary_conninfo`` can reach the writer by
    a stable alias (``<cluster_id>-writer``) regardless of which
    container currently holds that role."""
    return f"localemu-aurora-{cluster_id}"


class _NoopDockerOps:
    """Default :class:`DockerOps` stub. Implements only the operations
    that don't require streaming replication: ``stop_instance_container``
    works today; ``promote_to_writer`` / ``repoint_reader_to_writer`` /
    ``set_writer_network_alias`` log a warning so an early call to
    ``FailoverDBCluster`` surfaces visibly instead of silently
    half-failing."""

    def promote_to_writer(self, instance_id: str) -> None:
        LOG.warning(
            "Aurora failover requested for %s but the replication wiring "
            "is not yet active in this build.",
            instance_id,
        )

    def repoint_reader_to_writer(
        self, reader_instance_id: str, writer_alias: str, port: int,
    ) -> None:
        LOG.warning(
            "repoint_reader_to_writer(%s -> %s:%s) requested but "
            "replication wiring is not in place yet.",
            reader_instance_id, writer_alias, port,
        )

    def stop_instance_container(self, instance_id: str) -> None:
        # Stop is the one we CAN do today; defer to existing path
        try:
            DOCKER_CLIENT.stop_container(_container_name(instance_id))
        except Exception:
            LOG.debug(
                "stop_instance_container(%s) failed; continuing",
                instance_id, exc_info=True,
            )

    def set_writer_network_alias(
        self, cluster_id: str, new_writer_instance_id: str,
    ) -> None:
        LOG.warning(
            "set_writer_network_alias(%s, %s) requested but the "
            "alias-flip path is not in place yet.",
            cluster_id, new_writer_instance_id,
        )


def _container_name(db_instance_id: str) -> str:
    """Container-name convention used across the RDS subsystem. Kept
    at module level so :class:`_NoopDockerOps` can resolve names
    without a manager instance."""
    return f"localemu-rds-{db_instance_id}"


def ensure_cluster_network(cluster_id: str) -> str:
    """Create the cluster's shared Docker bridge if it doesn't exist.

    Idempotent: returns the existing network if we already created
    it earlier in this process or in a prior LocalEmu session.
    Returns the network name.
    """
    name = cluster_network_name(cluster_id)
    try:
        existing = DOCKER_CLIENT.inspect_network(name)
        if existing:
            return name
    except Exception:
        # Falls through to create
        pass
    try:
        DOCKER_CLIENT.create_network(name)
    except Exception as exc:
        # Race: another caller may have just created it. Re-inspect;
        # if it now exists we're fine, otherwise re-raise.
        try:
            if DOCKER_CLIENT.inspect_network(name):
                return name
        except Exception:
            pass
        raise RuntimeError(
            f"failed to create cluster network {name}: {exc}",
        ) from exc
    return name


class DockerDbManager:
    """Manages Docker containers as RDS database instances.

    Each RDS DB instance maps to one Docker container running a real
    database engine (MySQL, PostgreSQL, MariaDB).
    """

    def __init__(self):
        self._instances: dict[str, RdsContainerInfo] = {}
        self._lock = threading.Lock()
        self._recover_orphaned_containers()

    def _recover_orphaned_containers(self) -> None:
        """Scan for labeled RDS containers left from a previous run.

        Includes stopped containers (``all=True``) so persistence's
        stop/start flow can find them. Hydrates master_password and
        master_username from the labels we write at create time.
        """
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=["label=localemu.service=rds"],
                all=True,
            )
        except Exception as exc:
            LOG.debug("Failed to scan for orphaned RDS containers: %s", exc)
            return

        for container in containers:
            labels = container.get("labels", {})
            db_id = labels.get("localemu.db-instance-id")
            name = container.get("name", "")
            if not db_id or db_id in self._instances:
                continue
            try:
                info = self._hydrate_from_container(name, labels)
                if info is not None:
                    self._instances[db_id] = info
                    LOG.info(
                        "Recovered RDS container: %s (port=%s, status=%s)",
                        db_id, info.host_port, info.status,
                    )
            except Exception as exc:
                LOG.debug("Failed to hydrate container %s: %s", db_id, exc)

    def _hydrate_from_container(
        self, container_name: str, labels: dict[str, str]
    ) -> RdsContainerInfo | None:
        """Build an ``RdsContainerInfo`` from a live Docker container.

        Reusable between ``_recover_orphaned_containers`` and
        ``_rds_on_after_state_load`` so the password/username/port/network
        extraction logic is in one place.
        """
        inspect_info = DOCKER_CLIENT.inspect_container(container_name)
        port_bindings = (
            inspect_info.get("HostConfig", {}).get("PortBindings", {})
            or inspect_info.get("NetworkSettings", {}).get("Ports", {})
        )
        host_port = None
        for _port_key, bindings in port_bindings.items():
            if bindings:
                try:
                    host_port = int(bindings[0].get("HostPort", 0)) or None
                except (TypeError, ValueError):
                    host_port = None
                if host_port:
                    break
        if not host_port:
            return None

        engine = labels.get("localemu.engine", "postgres")
        container_port = get_engine_port(engine)

        master_username = labels.get("localemu.master-username", "admin")
        master_password = ""
        encoded = labels.get(MASTER_PASSWORD_LABEL, "")
        if encoded:
            try:
                master_password = base64.b64decode(encoded.encode()).decode()
            except Exception:
                LOG.debug("Failed to decode master password label for %s", container_name)

        # Container IP from the first VPC network we find; fall back to
        # the default IPAddress then to an empty string.
        networks = (inspect_info.get("NetworkSettings") or {}).get("Networks") or {}
        container_ip = ""
        network_list: list[str] = []
        for net_name, net_info in networks.items():
            network_list.append(net_name)
            if not container_ip:
                container_ip = (net_info or {}).get("IPAddress") or ""
        if not container_ip:
            container_ip = (
                (inspect_info.get("NetworkSettings") or {}).get("IPAddress") or ""
            )

        # Status: "available" when the container is running, "stopped" when
        # exited, "creating" otherwise (starting/restarting).
        state = inspect_info.get("State") or {}
        if state.get("Running"):
            status = "available"
        elif str(state.get("Status", "")).lower() == "exited":
            status = "stopped"
        else:
            status = state.get("Status", "creating") or "creating"

        db_instance_id = labels.get("localemu.db-instance-id") or ""
        # Aurora cluster membership (None for standalone instances).
        cluster_id = labels.get(CLUSTER_ID_LABEL) or None
        is_writer = labels.get(IS_WRITER_LABEL, "").lower() == "true"
        try:
            promotion_tier = int(labels.get(PROMOTION_TIER_LABEL, "1") or 1)
        except (TypeError, ValueError):
            promotion_tier = 1
        return RdsContainerInfo(
            db_instance_id=db_instance_id,
            container_name=container_name,
            engine=engine,
            image=(inspect_info.get("Config") or {}).get("Image", ""),
            host_port=host_port,
            container_port=container_port,
            master_username=master_username,
            master_password=master_password,
            status=status,
            container_ip=container_ip,
            vpc_id=None,
            db_instance_class=labels.get("localemu.db-instance-class", "db.t3.micro")
            or "db.t3.micro",
            networks=network_list,
            cluster_id=cluster_id,
            is_writer=is_writer,
            promotion_tier=promotion_tier,
        )

    def _container_name(self, db_instance_id: str) -> str:
        """Generate container name from DB instance identifier."""
        return f"localemu-rds-{db_instance_id}"

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
                LOG.info("Pulling database image %s...", image)
                try:
                    DOCKER_CLIENT.pull_image(image)
                    LOG.info("Image %s pulled successfully", image)
                except Exception as e:
                    raise RuntimeError(f"Failed to pull database image {image}: {e}") from e

    def create_db_instance(
        self,
        db_instance_id: str,
        engine: str,
        engine_version: str | None = None,
        master_username: str = "admin",
        master_password: str = "",
        db_name: str | None = None,
        allocated_storage: int = 20,
        db_instance_class: str = "db.t3.micro",
        port: int | None = None,
        vpc_id: str | None = None,
        subnet_id: str | None = None,
        cluster_id: str | None = None,
        is_writer: bool = False,
        promotion_tier: int = 1,
    ) -> RdsContainerInfo:
        """Create and start a Docker container with a real database.

        Args:
            db_instance_id: RDS DB instance identifier
            engine: Database engine (mysql, postgres, mariadb, aurora-mysql, aurora-postgresql)
            engine_version: Optional engine version
            master_username: Master username for the database
            master_password: Master password
            db_name: Optional initial database name
            allocated_storage: Storage in GB (for metadata only)
            db_instance_class: Instance class (e.g. db.t3.micro) — maps to Docker resource limits
            port: Custom container port (defaults to engine default)
            vpc_id: Optional VPC ID to connect the container to the VPC Docker network

        Returns:
            RdsContainerInfo with connection details
        """
        # Security fix #23: generate random password if none provided
        if not master_password:
            import secrets
            master_password = secrets.token_urlsafe(16)
            LOG.info("Generated random password for RDS instance %s", db_instance_id)

        # BUG-02: Reserve the ID under lock to prevent duplicate containers
        with self._lock:
            if db_instance_id in self._instances:
                raise ValueError(f"DB instance {db_instance_id} already exists")
            self._instances[db_instance_id] = None  # type: ignore[assignment] — sentinel

        try:
            return self._do_create_db_instance(
                db_instance_id, engine, engine_version, master_username,
                master_password, db_name, allocated_storage, db_instance_class,
                port, vpc_id, subnet_id,
                cluster_id=cluster_id, is_writer=is_writer,
                promotion_tier=promotion_tier,
            )
        except Exception:
            # Remove sentinel on failure
            with self._lock:
                if self._instances.get(db_instance_id) is None:
                    self._instances.pop(db_instance_id, None)
            raise

    def _do_create_db_instance(
        self, db_instance_id, engine, engine_version, master_username,
        master_password, db_name, allocated_storage, db_instance_class,
        port, vpc_id, subnet_id=None,
        *, cluster_id: str | None = None, is_writer: bool = False,
        promotion_tier: int = 1,
    ) -> RdsContainerInfo:
        """Internal create — called after ID is reserved under lock."""
        container_name = self._container_name(db_instance_id)
        image = resolve_engine_image(engine, engine_version)
        container_port = port or get_engine_port(engine)
        host_port = get_free_tcp_port()

        LOG.info(
            "Creating RDS instance %s (engine=%s, image=%s, port=%s, class=%s)",
            db_instance_id, engine, image, host_port, db_instance_class,
        )

        # Ensure image is available
        self._ensure_image(image)

        # Build environment variables for the database
        env_vars = get_engine_env_vars(engine, master_username, master_password, db_name)
        env_vars["LOCALEMU_DB_INSTANCE_ID"] = db_instance_id
        env_vars["LOCALEMU_ENGINE"] = engine

        # Port mapping
        ports = PortMappings()
        ports.add(host_port, container_port)

        # Named Docker volume for data persistence (BUG-10).
        # The volume survives container removal, so database files are
        # preserved across LocalEmu restarts when PERSISTENCE=1.
        volumes = VolumeMappings()
        engine_base = engine.lower()
        if engine_base.startswith("aurora-mysql"):
            engine_base = "mysql"
        elif engine_base.startswith("aurora-postgresql"):
            engine_base = "postgres"
        data_dir = ENGINE_DATA_DIR.get(engine_base, "/var/lib/postgresql/data")
        volume_name = f"localemu-rds-{db_instance_id}-data"
        volumes.add((volume_name, data_dir))

        # Resource limits from instance class (QUAL-04)
        mem_limit = None
        cpu_shares = None
        resource_limits = INSTANCE_CLASS_RESOURCE_MAP.get(db_instance_class)
        if resource_limits:
            mem_limit = f"{resource_limits[0]}m"
            cpu_shares = resource_limits[1]
        elif db_instance_class:
            LOG.info(
                "Instance class %s has no resource mapping; running without limits",
                db_instance_class,
            )

        # Container config
        container_labels = {
            "localemu.service": "rds",
            "localemu.db-instance-id": db_instance_id,
            "localemu.engine": engine,
            "localemu.db-instance-class": db_instance_class or "",
            "localemu.master-username": master_username,
            MASTER_PASSWORD_LABEL: base64.b64encode(
                (master_password or "").encode()
            ).decode(),
        }
        if cluster_id:
            container_labels[CLUSTER_ID_LABEL] = cluster_id
            container_labels[IS_WRITER_LABEL] = "true" if is_writer else "false"
            container_labels[PROMOTION_TIER_LABEL] = str(int(promotion_tier))

        # Aurora cluster members run a custom container CMD: writer
        # boots Postgres with the replication-source -c flags; reader
        # runs a bash init that pg_basebackups from the writer before
        # exec'ing into postgres. Standalone instances fall through
        # the image's default CMD.
        custom_command: list[str] | None = None
        repl_password: str | None = None
        if cluster_id:
            from localemu.services.rds.docker.cluster_init import (
                is_postgres_engine, replication_password_for_cluster,
                reader_container_command, writer_postgres_command,
                REPLICATION_USER,
            )
            if is_postgres_engine(engine):
                repl_password = replication_password_for_cluster(
                    cluster_id, master_password or "",
                )
                if is_writer:
                    custom_command = writer_postgres_command(max_readers=16)
                else:
                    custom_command = reader_container_command(
                        writer_alias=f"{cluster_id}-writer",
                        port=container_port,
                        repl_user=REPLICATION_USER,
                        repl_password=repl_password,
                    )
            else:
                LOG.warning(
                    "Aurora cluster member %s uses non-Postgres engine "
                    "%s — streaming replication is only wired for "
                    "Postgres in this build; spawning without "
                    "replication.", db_instance_id, engine,
                )

        container_config = ContainerConfiguration(
            image_name=image,
            name=container_name,
            env_vars=env_vars,
            ports=ports,
            volumes=volumes,
            detach=True,
            mem_limit=mem_limit,
            cpu_shares=cpu_shares,
            labels=container_labels,
            command=custom_command,
        )

        # Create and start (BUG-09: cleanup on start failure).
        # For cluster members, attach the cluster network BEFORE start
        # so the reader's pg_basebackup can resolve the writer alias
        # the moment its CMD runs.
        DOCKER_CLIENT.create_container_from_config(container_config)
        if cluster_id:
            cluster_net = cluster_network_name(cluster_id)
            aliases = [db_instance_id]
            if is_writer:
                aliases.append(f"{cluster_id}-writer")
            try:
                DOCKER_CLIENT.connect_container_to_network(
                    network_name=cluster_net,
                    container_name_or_id=container_name,
                    aliases=aliases,
                )
                LOG.info(
                    "RDS %s pre-attached to cluster network %s "
                    "(aliases=%s)", db_instance_id, cluster_net, aliases,
                )
            except Exception as exc:
                LOG.warning(
                    "RDS %s: failed pre-attach to cluster network %s: %s",
                    db_instance_id, cluster_net, exc,
                )
        try:
            DOCKER_CLIENT.start_container(container_name)
        except Exception:
            try:
                DOCKER_CLIENT.remove_container(container_name)
            except Exception:
                pass
            raise

        # BUG-07: Wait for database to accept connections. Readers do
        # a full pg_basebackup on first start, which can take 30s+ on
        # a fresh writer; extend the timeout for cluster members.
        # For readers, the host port wait is unreliable (docker-proxy
        # binds the port immediately, before pg_basebackup completes),
        # so probe pg_isready *inside* the container instead.
        if cluster_id and not is_writer:
            from localemu.services.rds.docker.cluster_init import (
                _wait_for_postgres_in_container, is_postgres_engine,
            )
            if is_postgres_engine(engine):
                ready = _wait_for_postgres_in_container(
                    container_name, master_username, timeout=240,
                )
                if not ready:
                    LOG.warning(
                        "RDS %s: standby did not finish basebackup "
                        "within 240s", db_instance_id,
                    )
            else:
                self._wait_for_port(host_port, timeout=180)
        else:
            wait_timeout = 180 if cluster_id else 30
            self._wait_for_port(host_port, timeout=wait_timeout)

        # Writer post-init: install replication role + pg_hba grant.
        if cluster_id and is_writer and repl_password is not None:
            try:
                from localemu.services.rds.docker.cluster_init import (
                    REPLICATION_USER, apply_writer_init,
                )
                apply_writer_init(
                    container_name=container_name,
                    master_username=master_username,
                    repl_user=REPLICATION_USER,
                    repl_password=repl_password,
                )
            except Exception:
                LOG.warning(
                    "RDS %s: writer replication init failed; standbys "
                    "may not authenticate", db_instance_id, exc_info=True,
                )

        # Connect to VPC Docker network if specified (QUAL-03).
        # When LOCALEMU_VPC_IP_PINNING is on AND we have a subnet_id,
        # reserve a stable IP from the SubnetAllocator and pass it as
        # ipv4_address so Docker pins the container to that address
        # (closes the moby/libnetwork#1740 race + makes the IP survive
        # restart). Otherwise fall back to today's Docker-auto-IPAM
        # behavior.
        networks = []
        reserved_ip = None  # set when pinning is engaged; used for release on failure
        eni_id_for_rds = None
        if vpc_id:
            vpc_network = f"localemu-vpc-{vpc_id}"
            ipv4_kwarg = None
            from localemu import config as _config
            if _config.LOCALEMU_VPC_IP_PINNING and subnet_id:
                try:
                    from localemu.services.ec2.docker.subnet_allocator import (
                        InsufficientFreeAddressesInSubnet,
                        UnknownSubnet,
                        get_subnet_allocator,
                    )
                    eni_id_for_rds = f"eni-rds-{db_instance_id}"
                    reserved_ip = get_subnet_allocator().reserve(
                        vpc_id=vpc_id, subnet_id=subnet_id,
                        owner_key=eni_id_for_rds,
                    )
                    ipv4_kwarg = str(reserved_ip)
                except (UnknownSubnet, InsufficientFreeAddressesInSubnet) as e:
                    LOG.warning(
                        "RDS %s: cannot pin IP in subnet %s (%s) — "
                        "falling back to Docker auto-IPAM",
                        db_instance_id, subnet_id, e,
                    )
                except Exception:
                    LOG.warning(
                        "RDS %s: allocator reserve raised — fall back to auto-IPAM",
                        db_instance_id, exc_info=True,
                    )
            try:
                DOCKER_CLIENT.connect_container_to_network(
                    network_name=vpc_network,
                    container_name_or_id=container_name,
                    aliases=[db_instance_id],
                    ipv4_address=ipv4_kwarg,
                )
                networks.append(vpc_network)
                LOG.info(
                    "RDS %s connected to VPC network %s%s",
                    db_instance_id, vpc_network,
                    f" (ip={ipv4_kwarg})" if ipv4_kwarg else "",
                )
            except Exception as e:
                LOG.warning(
                    "Failed to connect RDS %s to VPC network %s: %s",
                    db_instance_id, vpc_network, e,
                )
                # Roll back the IP reservation on connect failure
                if reserved_ip is not None:
                    try:
                        from localemu.services.ec2.docker.subnet_allocator import (
                            get_subnet_allocator,
                        )
                        get_subnet_allocator().release(reserved_ip)
                    except Exception:
                        LOG.debug(
                            "RDS %s: rollback release failed",
                            db_instance_id, exc_info=True,
                        )
                    reserved_ip = None

        # Cluster network was already attached pre-start; record it
        # in the networks list so the endpoint resolver can see it.
        if cluster_id:
            networks.append(cluster_network_name(cluster_id))

        # Resolve container IP for endpoint (QUAL-02)
        container_ip = self._resolve_container_ip(container_name, networks)
        endpoint = f"{container_ip}:{host_port}"

        info = RdsContainerInfo(
            db_instance_id=db_instance_id,
            container_name=container_name,
            engine=engine,
            image=image,
            host_port=host_port,
            container_port=container_port,
            master_username=master_username,
            master_password=master_password,
            db_name=db_name,
            endpoint=endpoint,
            status="available",
            container_ip=container_ip,
            vpc_id=vpc_id,
            db_instance_class=db_instance_class or "db.t3.micro",
            networks=networks,
            cluster_id=cluster_id,
            is_writer=is_writer,
            promotion_tier=promotion_tier,
        )

        with self._lock:
            self._instances[db_instance_id] = info

        # Register the RDS ENI in the AddressIndex when pinning succeeded.
        # This makes the IP discoverable via get_eni_for_ip and feeds the
        # SG ipset programmer that the sg_iptables source_groups path
        # will eventually use.
        if reserved_ip is not None and eni_id_for_rds and subnet_id:
            try:
                from localemu.services.ec2.docker.address_index import (
                    get_address_index,
                )
                get_address_index().register_eni(
                    eni_id=eni_id_for_rds,
                    vpc_id=vpc_id,
                    subnet_id=subnet_id,
                    primary_ip=reserved_ip,
                    sg_ids=[],  # RDS SGs come through DBSecurityGroups; future commit
                    instance_id=f"rds:{db_instance_id}",
                    iface_name="eth1",
                )
            except Exception:
                LOG.debug(
                    "RDS %s: index.register_eni failed (non-fatal)",
                    db_instance_id, exc_info=True,
                )

        LOG.info(
            "RDS instance %s available at %s (engine=%s, user=%s, class=%s)",
            db_instance_id, endpoint, engine, master_username, db_instance_class,
        )
        return info

    def _resolve_container_ip(
        self, container_name: str, networks: list[str]
    ) -> str:
        """Get the container IP, preferring the VPC network IP.

        Falls back to Docker bridge gateway, then 'localhost'.
        """
        try:
            if networks:
                return DOCKER_CLIENT.get_container_ipv4_for_network(
                    container_name, networks[0]
                )
            return DOCKER_CLIENT.get_container_ip(container_name)
        except Exception as e:
            LOG.debug("Could not resolve container IP for %s: %s", container_name, e)
            return "localhost"

    def modify_db_instance(
        self,
        db_instance_id: str,
        master_password: str | None = None,
        db_instance_class: str | None = None,
    ) -> RdsContainerInfo | None:
        """Modify a running RDS instance.

        Currently supports password changes by recreating the container
        with updated environment variables.
        """
        info = self._instances.get(db_instance_id)
        if not info:
            LOG.warning("ModifyDBInstance: no Docker container for %s", db_instance_id)
            return None

        if master_password and master_password != info.master_password:
            LOG.info("Updating master password for RDS %s", db_instance_id)
            info.master_password = master_password
            # Update the running container's password via exec
            try:
                self._update_password(info, master_password)
            except Exception as e:
                LOG.warning(
                    "Failed to live-update password for %s: %s", db_instance_id, e
                )

        if db_instance_class and db_instance_class != info.db_instance_class:
            LOG.info(
                "Instance class change for %s (%s -> %s) recorded; "
                "takes effect on next reboot.",
                db_instance_id, info.db_instance_class, db_instance_class,
            )
            info.db_instance_class = db_instance_class

        return info

    def _update_password(self, info: RdsContainerInfo, new_password: str) -> None:
        """Update the master password on a running database container.

        For postgres the ALTER USER must run authenticated:
          - bind to 127.0.0.1 (so TCP / md5 auth is used, not unix peer)
          - connect to the always-existing ``postgres`` DB
          - pass the CURRENT password via ``PGPASSWORD``

        For mysql / mariadb the master user is also the superuser so
        we connect as master_username and present the current password
        via the ``MYSQL_PWD`` env var.
        """
        engine = info.engine.lower()
        if engine.startswith("aurora-mysql"):
            engine = "mysql"
        elif engine.startswith("aurora-postgresql"):
            engine = "postgres"

        if engine == "postgres":
            cmd = [
                "psql", "-h", "127.0.0.1", "-U", info.master_username,
                "-d", "postgres",
                "-c",
                f"ALTER USER {info.master_username} PASSWORD '{new_password}';",
            ]
            env_vars = {"PGPASSWORD": info.master_password}
        elif engine in ("mysql", "mariadb"):
            cmd = [
                "mysql", "-h", "127.0.0.1", "-u", info.master_username,
                "-e",
                f"ALTER USER '{info.master_username}'@'%' IDENTIFIED BY '{new_password}';",
            ]
            env_vars = {"MYSQL_PWD": info.master_password}
        else:
            LOG.warning("Password update not supported for engine %s", engine)
            return

        DOCKER_CLIENT.exec_in_container(
            info.container_name, command=cmd, env_vars=env_vars,
        )

    def delete_db_instance(self, db_instance_id: str) -> None:
        """Delete an RDS instance (stop and remove container)."""
        container_name = self._container_name(db_instance_id)
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=10)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(container_name)
        except Exception:
            pass
        with self._lock:
            self._instances.pop(db_instance_id, None)
        # Release the IPv4 reservation + drop the ENI entry. The ENI ID
        # for RDS is the deterministic ``eni-rds-<db-id>`` synthesized at
        # create time; if the index/allocator never had it (pinning was
        # off when this container was created), the operations are no-ops.
        try:
            from localemu.services.ec2.docker.address_index import (
                get_address_index,
            )
            from localemu.services.ec2.docker.subnet_allocator import (
                get_subnet_allocator,
            )
            eni_id = f"eni-rds-{db_instance_id}"
            removed = get_address_index().delete_eni(eni_id)
            if removed is not None:
                get_subnet_allocator().release(removed.primary_ip)
        except Exception:
            LOG.debug(
                "RDS %s: address-index/allocator cleanup failed",
                db_instance_id, exc_info=True,
            )
        LOG.info("RDS instance %s deleted", db_instance_id)

    @staticmethod
    def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: int = 30) -> bool:
        """Poll a TCP port until it accepts connections or timeout expires (BUG-07)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except OSError:
                time.sleep(0.5)
        LOG.warning("Port %s did not become ready within %ss", port, timeout)
        return False

    def stop_db_instance(self, db_instance_id: str) -> None:
        """Stop an RDS instance."""
        container_name = self._container_name(db_instance_id)
        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=10)
            with self._lock:
                info = self._instances.get(db_instance_id)
                if info:
                    info.status = "stopped"
            LOG.info("RDS instance %s stopped", db_instance_id)
        except Exception as e:
            LOG.warning("Failed to stop RDS instance %s: %s", db_instance_id, e)

    def start_db_instance(self, db_instance_id: str) -> None:
        """Start a stopped RDS instance."""
        container_name = self._container_name(db_instance_id)
        try:
            DOCKER_CLIENT.start_container(container_name)
            with self._lock:
                info = self._instances.get(db_instance_id)
                if info:
                    info.status = "available"
            LOG.info("RDS instance %s started", db_instance_id)
        except Exception as e:
            LOG.warning("Failed to start RDS instance %s: %s", db_instance_id, e)

    def reboot_db_instance(self, db_instance_id: str) -> None:
        """Reboot an RDS instance using Docker restart (BUG-08: atomic, preserves ports)."""
        container_name = self._container_name(db_instance_id)
        try:
            with self._lock:
                info = self._instances.get(db_instance_id)
                if info:
                    info.status = "rebooting"
            DOCKER_CLIENT.restart_container(container_name, timeout=10)
            if info:
                self._wait_for_port(info.host_port, timeout=30)
            with self._lock:
                if info:
                    info.status = "available"
            LOG.info("RDS instance %s rebooted", db_instance_id)
        except Exception as e:
            with self._lock:
                info = self._instances.get(db_instance_id)
                if info:
                    info.status = "available"
            LOG.warning("Failed to reboot RDS instance %s: %s", db_instance_id, e)

    def get_instance_info(self, db_instance_id: str) -> RdsContainerInfo | None:
        """Get container info for a DB instance."""
        return self._instances.get(db_instance_id)

    # -- Snapshot dump / restore -------------------------------------------

    def _wait_for_engine_ready(
        self, info: RdsContainerInfo, timeout: int = 60,
    ) -> bool:
        """Block until the engine inside the container is accepting
        SQL connections. ``_wait_for_port`` only checks the docker-proxy
        host-port bind, which flips before Postgres actually opens
        5432; pg_dump / pg_restore need the engine itself ready."""
        engine = (info.engine or "").lower()
        if engine.startswith("postgres") or engine.startswith("aurora-postgresql"):
            probe = ["pg_isready", "-U", info.master_username, "-h", "127.0.0.1"]
        else:
            probe = [
                "mysqladmin", "ping", "-h", "127.0.0.1",
                "-u", info.master_username,
                f"-p{info.master_password or ''}",
            ]
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                DOCKER_CLIENT.exec_in_container(info.container_name, probe)
                return True
            except Exception:
                time.sleep(1)
        return False

    def dump_database(self, db_instance_id: str) -> bytes:
        """Run the engine's dump tool inside the container and return
        the gzipped bytes. Raises :class:`RuntimeError` if the instance
        is not tracked, the engine isn't supported, or the dump exits
        non-zero."""
        import gzip

        from localemu.services.rds.snapshot_store import (
            is_mysql_family, is_postgres_family,
            mysqldump_command, pg_dump_command,
        )

        info = self._instances.get(db_instance_id)
        if info is None:
            raise RuntimeError(f"unknown db instance {db_instance_id}")
        engine = info.engine or ""
        if is_postgres_family(engine):
            cmd = pg_dump_command(info.master_username, info.db_name)
        elif is_mysql_family(engine):
            cmd = mysqldump_command(info.master_username, info.db_name)
        else:
            raise RuntimeError(
                f"snapshot dump not supported for engine {engine}"
            )
        if not self._wait_for_engine_ready(info):
            raise RuntimeError(
                f"engine in {info.container_name} not ready for dump"
            )
        env = _engine_password_env(engine, info.master_password)
        stdout, stderr = DOCKER_CLIENT.exec_in_container(
            info.container_name, cmd, env_vars=env,
        )
        if not stdout:
            raise RuntimeError(
                f"dump produced no bytes (engine={engine}); "
                f"stderr: {(stderr or b'')[:200]!r}"
            )
        return gzip.compress(stdout, compresslevel=6)

    def restore_database(
        self, db_instance_id: str, gzipped_dump: bytes,
    ) -> None:
        """Pipe ``gzipped_dump`` (gunzipped on the way in) into the
        engine's restore tool inside the freshly-spawned container.
        Uses ``interactive=True`` because the CLI driver only forwards
        stdin to ``docker exec`` when that flag is set."""
        import gzip

        from localemu.services.rds.snapshot_store import (
            is_mysql_family, is_postgres_family,
            mysql_restore_command, pg_restore_command,
        )

        info = self._instances.get(db_instance_id)
        if info is None:
            raise RuntimeError(
                f"unknown db instance {db_instance_id} for restore"
            )
        engine = info.engine or ""
        if is_postgres_family(engine):
            cmd = pg_restore_command(info.master_username, info.db_name)
        elif is_mysql_family(engine):
            cmd = mysql_restore_command(info.master_username, info.db_name)
        else:
            raise RuntimeError(
                f"snapshot restore not supported for engine {engine}"
            )
        if not self._wait_for_engine_ready(info):
            raise RuntimeError(
                f"engine in {info.container_name} not ready for restore"
            )
        env = _engine_password_env(engine, info.master_password)
        raw_dump = gzip.decompress(gzipped_dump)
        _, stderr = DOCKER_CLIENT.exec_in_container(
            info.container_name, cmd, env_vars=env,
            stdin=raw_dump, interactive=True,
        )
        # pg_restore prints harmless errors-with-rc=0 when --clean
        # tries to drop objects that don't exist on a freshly-initdb'd
        # DB; the driver only raises on rc != 0, which is the contract
        # we care about.
        LOG.info(
            "RDS %s restored from snapshot (%d bytes)",
            db_instance_id, len(raw_dump),
        )

    def get_connection_info(self, db_instance_id: str) -> dict | None:
        """Get connection details for a DB instance.

        Returns dict with host, port, username, password, database, engine.
        """
        info = self._instances.get(db_instance_id)
        if not info:
            return None
        return {
            "host": info.container_ip or "localhost",
            "port": info.host_port,
            "username": info.master_username,
            "password": info.master_password,
            "database": info.db_name,
            "engine": info.engine,
            "endpoint": info.endpoint,
        }

    def cleanup_all(self) -> None:
        """Stop and remove all RDS containers. Called on LocalEmu shutdown
        when persistence is OFF. Destructive — containers and their
        writable layers are wiped (named volumes still survive Docker-side).
        """
        LOG.info("Cleaning up RDS Docker containers...")
        with self._lock:
            db_ids = list(self._instances.keys())
        for db_id in db_ids:
            try:
                self.delete_db_instance(db_id)
            except Exception as e:
                LOG.debug("Failed to clean up RDS instance %s: %s", db_id, e)

    def shutdown_all(self, timeout: int = 30) -> None:
        """Stop (but do NOT remove) all RDS containers.

        Called on LocalEmu shutdown when ``PERSISTENCE=1``. Keeps the
        container registered with Docker so ``docker start`` on the next
        ``localemu start`` resumes the exact same container — same writable
        layer, same host port binding, same named volume, same env vars
        (including the master password baked in at create time).

        Does not clear ``self._instances``: on a crash mid-shutdown, the
        in-memory state is still correct and a retry of shutdown or a
        subsequent restore is well-defined.
        """
        LOG.info("Stopping RDS Docker containers (containers preserved)...")
        with self._lock:
            db_ids = list(self._instances.keys())
        for db_id in db_ids:
            name = self._container_name(db_id)
            try:
                DOCKER_CLIENT.stop_container(name, timeout=timeout)
                with self._lock:
                    info = self._instances.get(db_id)
                    if info:
                        info.status = "stopped"
            except Exception as exc:
                LOG.warning("Failed to stop RDS container %s: %s", db_id, exc)


def _engine_password_env(engine: str, password: str | None) -> dict[str, str]:
    """Return the env vars libpq / mysql clients read so the dump and
    restore commands don't leak credentials via the command line."""
    pw = password or ""
    e = (engine or "").lower()
    if e.startswith("postgres") or e.startswith("aurora-postgresql"):
        return {"PGPASSWORD": pw}
    return {"MYSQL_PWD": pw}
