"""RDS provider with Docker-backed database instances.

Wraps Moto's RDS backend and adds Docker container management when
RDS_DOCKER_BACKEND=1. Creates a custom dispatch table that intercepts
specific RDS operations (CreateDBInstance, DeleteDBInstance, etc.)
while routing all other operations directly to Moto.
"""

import hashlib
import logging
import os
import secrets
import string
import threading

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service, ServiceLifecycleHook
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


def _generate_random_password(length: int = 30) -> str:
    """Generate a cryptographically random password for RDS instances.

    Uses the same character set AWS uses for auto-generated passwords:
    printable ASCII characters excluding /, ", @, and space.
    """
    alphabet = string.ascii_letters + string.digits + "!#$%&()*+,-.;<=>?[]^_`{|}~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _rds_endpoint_address(db_id: str, region: str) -> str:
    """Pick the endpoint hostname surfaced by DescribeDBInstances.

    AWS returns ``{db_id}.{hash}.{region}.rds.amazonaws.com``, but that
    hostname does not resolve locally — every ``psql`` / ``mysql`` /
    ``Sequelize`` connection from the host machine then fails with
    "could not translate host name". Defaulting to ``localhost`` makes
    the endpoint immediately usable: the host port (assigned at create
    time) is what carries the actual connection.

    Override with ``RDS_PUBLIC_ENDPOINT_HOST`` when an integration test
    needs the AWS-style hostname (e.g. a third-party tool that parses
    ``*.rds.amazonaws.com`` heuristically). The hash is still emitted
    in that mode so a given db_id maps to a stable hostname.
    """
    override = os.environ.get("RDS_PUBLIC_ENDPOINT_HOST", "").strip()
    if override == "aws-style":
        hash_hex = hashlib.md5(db_id.encode()).hexdigest()[:7]  # noqa: S324
        return f"{db_id}.{hash_hex}.{region}.rds.amazonaws.com"
    return override or "localhost"

# Module-level db_manager singleton (BUG-01: double-checked locking)
_db_manager = None
_db_manager_lock = threading.Lock()


def _init_db_manager():
    """Initialize the Docker DB manager if RDS_DOCKER_BACKEND=1."""
    global _db_manager
    if _db_manager is not None:
        return _db_manager

    with _db_manager_lock:
        if _db_manager is not None:
            return _db_manager

        if os.environ.get("RDS_DOCKER_BACKEND", "").strip() != "1":
            return None

        try:
            from localemu.services.rds.docker.db_manager import DockerDbManager
            from localemu.utils.docker_utils import DOCKER_CLIENT

            if DOCKER_CLIENT.has_docker():
                _db_manager = DockerDbManager()
                LOG.info("RDS Docker backend enabled.")
            else:
                LOG.warning("RDS_DOCKER_BACKEND=1 but Docker is not available.")
        except Exception as e:
            LOG.warning("Failed to initialize RDS Docker backend: %s", e)

        return _db_manager


def _extract_vpc_id_from_subnet_group(context: RequestContext, db_inst: dict) -> str | None:
    """Extract VPC ID from the DB subnet group if present."""
    subnet_group = db_inst.get("DBSubnetGroup")
    if subnet_group and isinstance(subnet_group, dict):
        return subnet_group.get("VpcId")
    return None


def _extract_subnet_id_from_subnet_group(
    context: RequestContext, db_inst: dict,
) -> str | None:
    """Pick a subnet from the DBSubnetGroup for the RDS container's
    address allocation.

    Returns the SubnetIdentifier of the first subnet in the group.
    Single-AZ RDS lands in one subnet; Multi-AZ is handled by design 45
    (separate writer/standby placement) — until that lands, both writer
    and standby would share this subnet anyway.

    Returns None if the DBSubnetGroup is absent or has no subnets. The
    addressing-pinning path in db_manager treats None as 'no pinning',
    falling back to today's Docker-auto-IPAM behavior — which preserves
    the contract that LOCALEMU_VPC_IP_PINNING is opt-in per call site.
    """
    subnet_group = db_inst.get("DBSubnetGroup")
    if not (subnet_group and isinstance(subnet_group, dict)):
        return None
    subnets = subnet_group.get("Subnets") or []
    if not isinstance(subnets, list):
        return None
    for s in subnets:
        if isinstance(s, dict):
            sid = s.get("SubnetIdentifier") or s.get("SubnetId")
            if sid:
                return sid
    return None


def _handle_create_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateDBInstance: let Moto create the record, then start a Docker
    container.

    When the request carries ``DBClusterIdentifier``, the new instance
    joins an Aurora cluster: it inherits the cluster's engine,
    master_username and master_password (so streaming replication will
    work), attaches to the cluster's shared Docker network, and gets
    registered as a reader member with the orchestrator (or as the
    writer if the cluster has no writer yet — matches moto's
    "first cluster member is writer" rule).
    """
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and result.get("DBInstance"):
        db_inst = result["DBInstance"]
        db_id = db_inst.get("DBInstanceIdentifier")
        engine = db_inst.get("Engine", "postgres")
        engine_ver = db_inst.get("EngineVersion")
        master_user = db_inst.get("MasterUsername", "admin")
        db_name = db_inst.get("DBName")
        master_pass = request.get("MasterUserPassword") or _generate_random_password()

        # PARITY-01: Extract additional parameters
        port_str = request.get("Port")
        port = int(port_str) if port_str else None
        db_instance_class = (
            request.get("DBInstanceClass") or "db.t3.micro"
        )
        vpc_id = _extract_vpc_id_from_subnet_group(context, db_inst)
        subnet_id = _extract_subnet_id_from_subnet_group(context, db_inst)
        region = context.region or "us-east-1"

        # Aurora cluster membership detection. Take the cluster
        # identifier from the request OR the moto-derived record (moto
        # records it as DBClusterIdentifier on the instance dict when
        # the parent cluster exists).
        cluster_id = (
            request.get("DBClusterIdentifier")
            or db_inst.get("DBClusterIdentifier")
        )
        is_writer = False
        promotion_tier = 1
        orch = None
        if cluster_id:
            from localemu.services.rds.cluster_orchestrator import (
                get_orchestrator,
            )
            from localemu.services.rds.docker.cluster_init import (
                make_docker_cluster_ops,
            )
            from localemu.services.rds.docker.db_manager import (
                ensure_cluster_network,
            )
            try:
                ensure_cluster_network(cluster_id)
            except Exception as exc:
                LOG.warning(
                    "Aurora cluster %s: failed to ensure network (%s)",
                    cluster_id, exc,
                )
            orch = get_orchestrator(make_docker_cluster_ops())
            topology = orch.topology(cluster_id)
            # "First cluster member is writer" — matches AWS + moto.
            # If the cluster handler already spawned the writer container
            # (under the cluster_id as instance_id), this instance is a
            # reader. Otherwise it becomes the writer.
            is_writer = topology is None or topology.writer is None
            tier_str = request.get("PromotionTier")
            try:
                promotion_tier = int(tier_str) if tier_str else 1
            except (TypeError, ValueError):
                promotion_tier = 1
            # Cluster members inherit the cluster's credentials so
            # replication actually authenticates (the request usually
            # omits MasterUsername/MasterUserPassword on cluster members).
            if topology is not None:
                master_user = topology.master_username
                master_pass = topology.master_password
                engine = topology.engine

        try:
            info = mgr.create_db_instance(
                db_instance_id=db_id,
                engine=engine,
                engine_version=engine_ver,
                master_username=master_user,
                master_password=master_pass,
                db_name=db_name,
                db_instance_class=db_instance_class,
                port=port,
                vpc_id=vpc_id,
                subnet_id=subnet_id,
                cluster_id=cluster_id,
                is_writer=is_writer,
                promotion_tier=promotion_tier,
            )
            if orch is not None and cluster_id:
                try:
                    orch.register_member(
                        cluster_id, db_id, is_writer=is_writer,
                        promotion_tier=promotion_tier,
                        host_port=info.host_port,
                    )
                except KeyError:
                    LOG.warning(
                        "Aurora cluster %s not registered with "
                        "orchestrator; skipping member registration "
                        "for %s",
                        cluster_id, db_id,
                    )
            # PARITY-06: AWS-style endpoint hostname
            endpoint_address = _rds_endpoint_address(db_id, region)
            db_inst.setdefault("Endpoint", {})
            db_inst["Endpoint"]["Address"] = endpoint_address
            db_inst["Endpoint"]["Port"] = info.host_port
            db_inst["DBInstanceStatus"] = "available"
            LOG.info(
                "RDS %s ready at %s:%s (%s, %s)",
                db_id, endpoint_address, info.host_port, engine, db_instance_class,
            )
        except Exception as e:
            LOG.warning("Docker DB failed for %s, marking create-failed: %s", db_id, e)
            # BUG-05: Mark Moto record as failed so state stays consistent
            try:
                db_inst["DBInstanceStatus"] = "create-failed"
            except Exception:
                pass

    return result


def _handle_delete_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteDBInstance: let Moto delete the record, then remove the Docker container.

    PARITY-03: Checks DeletionProtection before allowing deletion.
    If SkipFinalSnapshot is False and no FinalDBSnapshotIdentifier is given,
    AWS raises an error — Moto already handles this, so we only add the
    DeletionProtection check here.
    """
    db_id = request.get("DBInstanceIdentifier")

    # PARITY-03: Check DeletionProtection before proceeding
    if db_id:
        from localemu.aws.api import CommonServiceException as _CSE
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("rds")[context.account_id][context.region]
            moto_db = backend.databases.get(db_id)
            if moto_db and getattr(moto_db, "deletion_protection", False):
                raise _CSE(
                    "InvalidParameterCombination",
                    f"Cannot delete a DB instance when DeletionProtection is enabled for DB instance: {db_id}.",
                    status_code=400,
                )
        except _CSE:
            raise
        except Exception:
            LOG.debug("Could not check DeletionProtection for %s", db_id, exc_info=True)

    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and db_id:
        # If this instance belongs to an Aurora cluster, deregister it
        # from the orchestrator BEFORE removing the container so the
        # reader endpoint map stops handing out a port we're about to
        # kill.
        info = mgr.get_instance_info(db_id)
        if info and info.cluster_id:
            try:
                from localemu.services.rds.cluster_orchestrator import (
                    get_orchestrator,
                )
                from localemu.services.rds.docker.cluster_init import (
                    make_docker_cluster_ops,
                )
                get_orchestrator(make_docker_cluster_ops()).deregister_member(
                    info.cluster_id, db_id,
                )
            except Exception:
                LOG.debug(
                    "Failed to deregister %s from cluster %s; continuing",
                    db_id, info.cluster_id, exc_info=True,
                )
        try:
            mgr.delete_db_instance(db_id)
        except Exception as e:
            LOG.warning("Failed to delete Docker container for RDS %s: %s", db_id, e)

    return result


def _handle_stop_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """StopDBInstance: let Moto update state, then stop the Docker container."""
    db_id = request.get("DBInstanceIdentifier")
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and db_id:
        try:
            mgr.stop_db_instance(db_id)
        except Exception as e:
            LOG.warning("Failed to stop Docker container for RDS %s: %s", db_id, e)

    return result


def _handle_start_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """StartDBInstance: let Moto update state, then start the Docker container."""
    db_id = request.get("DBInstanceIdentifier")
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and db_id:
        try:
            mgr.start_db_instance(db_id)
        except Exception as e:
            LOG.warning("Failed to start Docker container for RDS %s: %s", db_id, e)

    return result


def _handle_describe_db_instances(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DescribeDBInstances: let Moto return records, then patch endpoints."""
    result = call_moto(context)
    region = context.region or "us-east-1"

    mgr = _init_db_manager()
    if mgr and result.get("DBInstances"):
        for db_inst in result["DBInstances"]:
            db_id = db_inst.get("DBInstanceIdentifier")
            info = mgr.get_instance_info(db_id)
            if info:
                endpoint_address = _rds_endpoint_address(db_id, region)
                db_inst.setdefault("Endpoint", {})
                db_inst["Endpoint"]["Address"] = endpoint_address
                db_inst["Endpoint"]["Port"] = info.host_port

    return result


def _handle_reboot_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RebootDBInstance: let Moto update state, then restart the
    Docker container.

    When ``ForceFailover=true`` and the target is the writer of an
    Aurora cluster, AWS triggers a cluster failover instead of just
    bouncing the writer. We mirror that here by promoting the
    lowest-tier reader through the orchestrator (same path as
    FailoverDBCluster).
    """
    db_id = request.get("DBInstanceIdentifier")
    force_failover = str(request.get("ForceFailover") or "").lower() == "true"
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and db_id:
        # Aurora writer + ForceFailover → trigger cluster failover.
        if force_failover:
            info = mgr.get_instance_info(db_id)
            if info and info.cluster_id and info.is_writer:
                try:
                    from localemu.services.rds.cluster_orchestrator import (
                        NoFailoverTargetError, get_orchestrator,
                    )
                    from localemu.services.rds.docker.cluster_init import (
                        make_docker_cluster_ops,
                    )
                    orch = get_orchestrator(make_docker_cluster_ops())
                    new_writer = orch.failover(info.cluster_id)
                    _sync_moto_cluster_writer(
                        context, info.cluster_id, new_writer.instance_id,
                    )
                    LOG.info(
                        "RebootDBInstance ForceFailover %s -> new writer %s",
                        db_id, new_writer.instance_id,
                    )
                    return result
                except NoFailoverTargetError as exc:
                    LOG.warning(
                        "RebootDBInstance ForceFailover %s: no reader "
                        "to promote (%s); falling back to plain reboot",
                        db_id, exc,
                    )
                except Exception:
                    LOG.warning(
                        "RebootDBInstance ForceFailover %s: orchestrator "
                        "failover raised; falling back to plain reboot",
                        db_id, exc_info=True,
                    )
        try:
            mgr.reboot_db_instance(db_id)
        except Exception as e:
            LOG.warning("Failed to reboot Docker container for RDS %s: %s", db_id, e)

    return result


def _handle_modify_db_instance(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """ModifyDBInstance: let Moto update the record, then apply Docker changes."""
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and result.get("DBInstance"):
        db_inst = result["DBInstance"]
        db_id = db_inst.get("DBInstanceIdentifier")
        new_password = request.get("MasterUserPassword")
        new_class = request.get("DBInstanceClass")

        try:
            mgr.modify_db_instance(
                db_instance_id=db_id,
                master_password=new_password,
                db_instance_class=new_class,
            )
        except Exception as e:
            LOG.warning("Docker modify failed for %s: %s", db_id, e)

    return result


def _create_docker_for_restored_instance(
    context: RequestContext, request: ServiceRequest, result: ServiceResponse
) -> ServiceResponse:
    """Shared logic for restore/read-replica: start a Docker container for the new instance."""
    mgr = _init_db_manager()
    if not mgr or not result.get("DBInstance"):
        return result

    db_inst = result["DBInstance"]
    db_id = db_inst.get("DBInstanceIdentifier")
    engine = db_inst.get("Engine", "postgres")
    engine_ver = db_inst.get("EngineVersion")
    master_user = db_inst.get("MasterUsername", "admin")
    db_name = db_inst.get("DBName")
    # Restored instances don't carry the password in Moto response;
    # use the original password from the request or generate a random one
    master_pass = request.get("MasterUserPassword") or _generate_random_password()
    db_instance_class = db_inst.get("DBInstanceClass") or "db.t3.micro"
    port_val = db_inst.get("Endpoint", {}).get("Port")
    port = int(port_val) if port_val else None
    vpc_id = _extract_vpc_id_from_subnet_group(context, db_inst)
    subnet_id = _extract_subnet_id_from_subnet_group(context, db_inst)
    region = context.region or "us-east-1"

    try:
        info = mgr.create_db_instance(
            db_instance_id=db_id,
            engine=engine,
            engine_version=engine_ver,
            master_username=master_user,
            master_password=master_pass,
            db_name=db_name,
            db_instance_class=db_instance_class,
            port=port,
            vpc_id=vpc_id,
            subnet_id=subnet_id,
        )
        endpoint_address = _rds_endpoint_address(db_id, region)
        db_inst.setdefault("Endpoint", {})
        db_inst["Endpoint"]["Address"] = endpoint_address
        db_inst["Endpoint"]["Port"] = info.host_port
        db_inst["DBInstanceStatus"] = "available"
        LOG.info("Restored RDS %s ready at %s:%s", db_id, endpoint_address, info.host_port)
    except Exception as e:
        LOG.warning("Docker DB failed for restored instance %s: %s", db_id, e)

    return result


def _handle_create_db_snapshot(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateDBSnapshot: let Moto persist the metadata, then run the
    engine's dump tool inside the source container and store the
    gzipped output on disk so a later RestoreDBInstanceFromDBSnapshot
    can replay it.

    Closes the "snapshots are metadata-only" audit gap. Synchronous —
    the call returns once the dump is on disk, which is honest to the
    user (DescribeDBSnapshots immediately shows ``available`` with the
    correct size).
    """
    source_id = request.get("DBInstanceIdentifier")
    snapshot_id = request.get("DBSnapshotIdentifier")
    result = call_moto(context)

    mgr = _init_db_manager()
    if not (mgr and source_id and snapshot_id):
        return result
    info = mgr.get_instance_info(source_id)
    if info is None:
        LOG.info(
            "CreateDBSnapshot %s: source %s not tracked by Docker manager; "
            "snapshot is metadata-only",
            snapshot_id, source_id,
        )
        return result

    try:
        from localemu.services.rds.snapshot_store import get_snapshot_store
        dump_bytes = mgr.dump_database(source_id)
        get_snapshot_store().write(
            snapshot_id=snapshot_id,
            engine=info.engine,
            dump_bytes=dump_bytes,
            source_db_instance_id=source_id,
            master_username=info.master_username,
            engine_version=None,
            db_name=info.db_name,
            db_instance_class=info.db_instance_class,
        )
        # Patch moto's snapshot record to reflect the real size.
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("rds")[context.account_id][context.region]
            snap = backend.database_snapshots.get(snapshot_id)
            if snap is not None:
                setattr(snap, "allocated_storage", max(
                    int(len(dump_bytes) / (1024 * 1024)) or 1,
                    int(getattr(snap, "allocated_storage", 1) or 1),
                ))
                setattr(snap, "status", "available")
                setattr(snap, "percent_progress", 100)
        except Exception:
            LOG.debug(
                "CreateDBSnapshot %s: moto patch failed",
                snapshot_id, exc_info=True,
            )
    except Exception:
        LOG.warning(
            "CreateDBSnapshot %s: dump failed; snapshot is "
            "metadata-only", snapshot_id, exc_info=True,
        )

    return result


def _handle_delete_db_snapshot(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteDBSnapshot: let Moto delete the record, then drop the
    on-disk dump. Idempotent: missing dump dir is not an error."""
    snapshot_id = request.get("DBSnapshotIdentifier")
    result = call_moto(context)
    if snapshot_id:
        try:
            from localemu.services.rds.snapshot_store import get_snapshot_store
            get_snapshot_store().delete(snapshot_id)
        except Exception:
            LOG.debug(
                "DeleteDBSnapshot %s: store delete failed",
                snapshot_id, exc_info=True,
            )
    return result


def _handle_restore_db_instance_from_snapshot(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RestoreDBInstanceFromDBSnapshot: let Moto create record, spawn
    a fresh container as today, then replay the snapshot's dump into
    it so the restored instance carries the source's data.

    Falls back cleanly to the old empty-container behaviour when the
    snapshot has no on-disk dump (pre-feature snapshot, or
    CreateDBSnapshot was called before the manager existed)."""
    snapshot_id = request.get("DBSnapshotIdentifier")
    result = call_moto(context)
    result = _create_docker_for_restored_instance(context, request, result)

    mgr = _init_db_manager()
    if not (mgr and snapshot_id and result.get("DBInstance")):
        return result
    new_db_id = result["DBInstance"].get("DBInstanceIdentifier")
    if not new_db_id:
        return result

    try:
        from localemu.services.rds.snapshot_store import get_snapshot_store
        store = get_snapshot_store()
        if not store.has(snapshot_id):
            LOG.info(
                "RestoreDBInstanceFromDBSnapshot %s -> %s: no on-disk "
                "dump for this snapshot; restored instance is empty",
                snapshot_id, new_db_id,
            )
            return result
        dump = store.read_dump(snapshot_id)
        if dump is None:
            return result
        mgr.restore_database(new_db_id, dump)
    except Exception:
        LOG.warning(
            "RestoreDBInstanceFromDBSnapshot %s -> %s: replay failed; "
            "instance is up but empty", snapshot_id, new_db_id,
            exc_info=True,
        )
    return result


def _handle_restore_db_instance_to_point_in_time(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RestoreDBInstanceToPointInTime: let Moto create record, then start Docker container."""
    result = call_moto(context)
    return _create_docker_for_restored_instance(context, request, result)


def _handle_create_db_instance_read_replica(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateDBInstanceReadReplica: spawn a Docker container for the
    new replica and seed it with the source's data via the same
    ``pg_dump | pg_restore`` (postgres) or ``mysqldump | mysql``
    (mysql/mariadb) pipeline the snapshot path uses.

    This is the MVP that closes the "read replica = fresh empty
    container" audit gap: the replica carries the source's schema +
    rows at creation time. Ongoing streaming replication
    (``wal_level=replica`` + replication slot + walreceiver) is a
    follow-up — the source would need a restart to enable
    ``wal_level=replica``, which we don't want to do silently.
    Inherit the source's master credentials so apps that connect
    using the source's password keep working against the replica.
    """
    source_id = request.get("SourceDBInstanceIdentifier")
    result = call_moto(context)

    # Pull the source's master credentials into the moto record for the
    # replica BEFORE spawning the container, so the docker-entrypoint
    # initdb's with the same user/password as the source and the
    # replayed dump's GRANTs match.
    mgr = _init_db_manager()
    source_info = mgr.get_instance_info(source_id) if (mgr and source_id) else None
    if source_info and result.get("DBInstance"):
        db_inst = result["DBInstance"]
        db_inst.setdefault("MasterUsername", source_info.master_username)
        db_inst.setdefault("Engine", source_info.engine)
        if source_info.db_name and not db_inst.get("DBName"):
            db_inst["DBName"] = source_info.db_name
        # Stash the source's master password on the request so
        # _create_docker_for_restored_instance picks it up instead of
        # generating a random one.
        if not request.get("MasterUserPassword"):
            request["MasterUserPassword"] = source_info.master_password

    result = _create_docker_for_restored_instance(context, request, result)

    if not (mgr and source_info and result.get("DBInstance")):
        return result
    replica_id = result["DBInstance"].get("DBInstanceIdentifier")
    if not replica_id:
        return result

    try:
        dump_bytes = mgr.dump_database(source_id)
        mgr.restore_database(replica_id, dump_bytes)
        LOG.info(
            "Read replica %s seeded from source %s (%d bytes)",
            replica_id, source_id, len(dump_bytes),
        )
        # Mark replica relationship on moto's record so DescribeDBInstances
        # surfaces StatusInfos honestly (no continuous replication yet —
        # this is a one-shot data copy).
        try:
            db_inst = result["DBInstance"]
            db_inst["ReadReplicaSourceDBInstanceIdentifier"] = source_id
            db_inst.setdefault("StatusInfos", []).append({
                "StatusType": "read replication",
                "Status": "replicating",
                "Normal": True,
            })
        except Exception:
            LOG.debug(
                "Read replica %s: status surface update failed",
                replica_id, exc_info=True,
            )
    except Exception:
        LOG.warning(
            "Read replica %s: source dump+load failed; "
            "replica is up but empty", replica_id, exc_info=True,
        )

    return result


def _handle_create_db_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateDBCluster: let Moto create the cluster record, spawn the
    initial writer container, register cluster + writer with the
    orchestrator so subsequent CreateDBInstance calls with the same
    DBClusterIdentifier add reader members on the shared Docker
    network.
    """
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and result.get("DBCluster"):
        cluster = result["DBCluster"]
        cluster_id = cluster.get("DBClusterIdentifier")
        engine = cluster.get("Engine", "aurora-postgresql")
        engine_ver = cluster.get("EngineVersion")
        master_user = cluster.get("MasterUsername", "admin")
        db_name = cluster.get("DatabaseName")
        master_pass = request.get("MasterUserPassword") or _generate_random_password()
        port_val = cluster.get("Port")
        port = int(port_val) if port_val else None
        region = context.region or "us-east-1"

        # Aurora topology: ensure the per-cluster Docker network so
        # later readers can resolve the writer by its alias.
        from localemu.services.rds.cluster_orchestrator import (
            get_orchestrator,
        )
        from localemu.services.rds.docker.cluster_init import (
            make_docker_cluster_ops,
        )
        from localemu.services.rds.docker.db_manager import (
            cluster_network_name, ensure_cluster_network,
        )
        try:
            ensure_cluster_network(cluster_id)
        except Exception as exc:
            LOG.warning(
                "Aurora cluster %s: failed to ensure network (%s); "
                "spawning writer without cluster networking",
                cluster_id, exc,
            )
        orch = get_orchestrator(make_docker_cluster_ops())
        orch.register_cluster(
            cluster_id=cluster_id, engine=engine,
            network_name=cluster_network_name(cluster_id),
            master_username=master_user, master_password=master_pass,
        )

        try:
            info = mgr.create_db_instance(
                db_instance_id=cluster_id,
                engine=engine,
                engine_version=engine_ver,
                master_username=master_user,
                master_password=master_pass,
                db_name=db_name,
                port=port,
                cluster_id=cluster_id,
                is_writer=True,
                promotion_tier=1,
            )
            orch.register_member(
                cluster_id, cluster_id, is_writer=True,
                promotion_tier=1, host_port=info.host_port,
            )
            endpoint_address = _rds_endpoint_address(cluster_id, region)
            cluster.setdefault("Endpoint", endpoint_address)
            cluster.setdefault("Port", info.host_port)
            cluster["Status"] = "available"
            reader_address = _rds_endpoint_address(f"{cluster_id}-ro", region)
            cluster.setdefault("ReaderEndpoint", reader_address)
            LOG.info(
                "Aurora cluster %s ready at %s:%s (%s) — writer container "
                "spawned, reader members are added via CreateDBInstance",
                cluster_id, endpoint_address, info.host_port, engine,
            )
        except Exception as e:
            LOG.warning("Docker DB failed for Aurora cluster %s: %s", cluster_id, e)

    return result


def _handle_delete_db_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteDBCluster: let Moto delete the cluster record, then tear
    down every member container (writer + readers) and forget the
    cluster topology.

    AWS rejects ``DeleteDBCluster`` when instances are still attached
    (the user has to delete them first or call with
    ``--skip-final-snapshot --delete-automated-backups``). Moto follows
    the AWS behavior for the cluster record; we mirror that on the
    Docker side by removing every member container the orchestrator
    knows about.
    """
    cluster_id = request.get("DBClusterIdentifier")
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and cluster_id:
        member_ids: list[str] = []
        try:
            from localemu.services.rds.cluster_orchestrator import (
                get_orchestrator,
            )
            from localemu.services.rds.docker.cluster_init import (
                make_docker_cluster_ops,
            )
            orch = get_orchestrator(make_docker_cluster_ops())
            topology = orch.topology(cluster_id)
            if topology is not None:
                member_ids = list(topology.members.keys())
            orch.forget_cluster(cluster_id)
        except Exception:
            LOG.debug(
                "Failed to drain orchestrator state for cluster %s; "
                "falling back to container-name lookup",
                cluster_id, exc_info=True,
            )

        # Tear down member containers. The cluster_id itself doubles as
        # the writer's instance_id (see _handle_create_db_cluster), so
        # it's already in member_ids in the normal path; the fallback
        # branch hits it directly via mgr.delete_db_instance below.
        for member_id in member_ids:
            try:
                mgr.delete_db_instance(member_id)
            except Exception as exc:
                LOG.warning(
                    "Failed to delete Docker container for Aurora "
                    "cluster member %s/%s: %s",
                    cluster_id, member_id, exc,
                )
        if not member_ids:
            try:
                mgr.delete_db_instance(cluster_id)
            except Exception as exc:
                LOG.warning(
                    "Failed to delete Docker container for Aurora "
                    "cluster %s: %s",
                    cluster_id, exc,
                )

    return result


def _sync_moto_cluster_writer(
    context: RequestContext, cluster_id: str, new_writer_instance_id: str,
) -> None:
    """After a successful Docker-side failover, mirror the topology
    change on moto's DBCluster record so DescribeDBClusters surfaces
    the new writer in ``DBClusterMembers``."""
    try:
        import moto.backends as moto_backends
        backend = moto_backends.get_backend("rds")[context.account_id][context.region]
        cluster = backend.clusters.get(cluster_id)
        if cluster is None:
            return
        # moto's DBCluster carries a ``cluster_members`` list of
        # instance ids. The Aurora writer is conventionally the first
        # entry; rearrange the list so the new writer is at index 0.
        members = getattr(cluster, "cluster_members", None)
        if isinstance(members, list) and new_writer_instance_id in members:
            members.remove(new_writer_instance_id)
            members.insert(0, new_writer_instance_id)
    except Exception:
        LOG.debug(
            "moto cluster %s: failed to sync new writer %s",
            cluster_id, new_writer_instance_id, exc_info=True,
        )


def _handle_failover_db_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """FailoverDBCluster: promote the requested reader (or the
    lowest-tier reader if none requested) to writer, then mirror the
    flip on moto's cluster record. Returns moto's response so all the
    ``ResponseMetadata`` etc. comes from the canonical path.
    """
    cluster_id = request.get("DBClusterIdentifier")
    target = request.get("TargetDBInstanceIdentifier") or None
    result = call_moto(context)

    mgr = _init_db_manager()
    if mgr and cluster_id:
        from localemu.aws.api import CommonServiceException as _CSE
        from localemu.services.rds.cluster_orchestrator import (
            NoFailoverTargetError, get_orchestrator,
        )
        from localemu.services.rds.docker.cluster_init import (
            make_docker_cluster_ops,
        )
        orch = get_orchestrator(make_docker_cluster_ops())
        try:
            new_writer = orch.failover(cluster_id, target_instance_id=target)
        except NoFailoverTargetError as exc:
            raise _CSE(
                "InvalidDBClusterStateFault", str(exc), status_code=400,
            )
        except KeyError:
            # Cluster not registered with us — let moto's response stand;
            # nothing more to do.
            return result
        _sync_moto_cluster_writer(context, cluster_id, new_writer.instance_id)
        LOG.info(
            "FailoverDBCluster %s: new writer is %s (port=%s)",
            cluster_id, new_writer.instance_id, new_writer.host_port,
        )

    return result


# Operations we intercept with Docker container management
_INTERCEPTED_OPS = {
    "CreateDBInstance": _handle_create_db_instance,
    "DeleteDBInstance": _handle_delete_db_instance,
    "StopDBInstance": _handle_stop_db_instance,
    "StartDBInstance": _handle_start_db_instance,
    "DescribeDBInstances": _handle_describe_db_instances,
    "RebootDBInstance": _handle_reboot_db_instance,
    "ModifyDBInstance": _handle_modify_db_instance,
    "RestoreDBInstanceFromDBSnapshot": _handle_restore_db_instance_from_snapshot,
    "RestoreDBInstanceToPointInTime": _handle_restore_db_instance_to_point_in_time,
    "CreateDBSnapshot": _handle_create_db_snapshot,
    "DeleteDBSnapshot": _handle_delete_db_snapshot,
    "CreateDBInstanceReadReplica": _handle_create_db_instance_read_replica,
    "CreateDBCluster": _handle_create_db_cluster,
    "DeleteDBCluster": _handle_delete_db_cluster,
    "FailoverDBCluster": _handle_failover_db_cluster,
}


def RdsDispatcher(service_model) -> DispatchTable:
    """Create a dispatch table for RDS.

    Intercepted operations (Create/Delete/Stop/Start/Describe/Reboot)
    go through our Docker container management handlers.
    All other operations route directly to Moto.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


class RdsLifecycleHook(ServiceLifecycleHook):
    """Bridges LocalEmu's persistence engine to the RDS provider.

    Without a non-default ``on_after_state_load`` override the persistence
    engine (``state/persistence.py::_fire_post_load_hooks``) skips the
    service at load time, leaving persisted DB instances with metadata
    but no Docker container.
    """

    def on_after_state_load(self) -> None:  # noqa: D401 — hook
        _rds_on_after_state_load()


def create_rds_service() -> Service:
    """Create the RDS service with Docker-aware dispatch table."""
    from localemu.aws.spec import load_service

    # BUG-13: Initialize Docker DB manager once at service creation
    _init_db_manager()

    service_model = load_service("rds")
    dispatch_table = RdsDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(
        name="rds",
        skeleton=skeleton,
        lifecycle_hook=RdsLifecycleHook(),
    )


# ---------------------------------------------------------------------------
# Post-load reconcile — called from RdsLifecycleHook.on_after_state_load
# ---------------------------------------------------------------------------
def _rds_on_after_state_load() -> None:
    """Reconcile persisted RDS records with the live Docker data plane.

    Runs after ``SaveOrchestrator`` re-hydrates moto's RDS backend. For
    each persisted DB instance we walk through three cases:

    1. Container exists and is running — update moto's endpoint port and
       leave it alone.
    2. Container exists but is stopped — ``docker start``; Docker reuses
       the recorded host port.
    3. Container is gone — recreate against the named volume
       ``localemu-rds-<id>-data`` (which survives ``docker rm``) using the
       master password captured from the label.

    Failures are logged per instance — never raised — so one bad DB
    doesn't block the rest of the load.
    """
    mgr = _init_db_manager()
    if not mgr:
        LOG.debug("RDS Docker backend disabled — skipping post-load reconcile")
        return

    try:
        import moto.backends as mb
        rds = mb.get_backend("rds")
    except Exception:
        LOG.warning("Could not access moto RDS backend", exc_info=True)
        return

    processed = resumed = recreated = failed = 0
    for _acct, region_map in list(rds.items()):
        if not isinstance(region_map, dict):
            continue
        for region, backend in list(region_map.items()):
            databases = getattr(backend, "databases", None) or {}
            for db_id in list(databases.keys()):
                moto_db = databases[db_id]
                processed += 1
                outcome = _restore_one(mgr, db_id, moto_db, region)
                if outcome == "resumed":
                    resumed += 1
                elif outcome == "recreated":
                    recreated += 1
                else:
                    failed += 1
    LOG.info(
        "RDS reconcile: %d processed (resumed=%d, recreated=%d, failed=%d)",
        processed, resumed, recreated, failed,
    )


def _restore_one(mgr, db_id: str, moto_db, region: str) -> str:
    """Reconcile a single persisted RDS instance. Returns one of
    ``"resumed"`` / ``"recreated"`` / ``"failed"``."""
    name = mgr._container_name(db_id)
    existing_info = mgr.get_instance_info(db_id)

    # Probe container state.
    try:
        inspect = DOCKER_CLIENT.inspect_container(name)
        exists = True
        running = bool((inspect.get("State") or {}).get("Running"))
    except Exception:
        exists = False
        running = False

    # Case 1: already running.
    if exists and running:
        info = existing_info or _safe_hydrate(mgr, name)
        if info:
            with mgr._lock:
                mgr._instances[db_id] = info
            _patch_moto_endpoint(moto_db, region, info.host_port)
            LOG.info("RDS %s already running — kept in place", db_id)
            return "resumed"
        LOG.warning("RDS %s running but could not hydrate info", db_id)
        return "failed"

    # Case 2: stopped container → docker start.
    if exists and not running:
        try:
            DOCKER_CLIENT.start_container(name)
        except Exception as exc:
            LOG.warning(
                "docker start localemu-rds-%s failed (%s) — will try to recreate",
                db_id, exc,
            )
            # Best-effort: remove the broken container so the recreate path
            # below can use the same container name.
            try:
                DOCKER_CLIENT.remove_container(name)
            except Exception:
                pass
            exists = False
        else:
            info = existing_info or _safe_hydrate(mgr, name)
            if info:
                mgr._wait_for_port(info.host_port, timeout=60)
                with mgr._lock:
                    mgr._instances[db_id] = info
                    info.status = "available"
                _patch_moto_endpoint(moto_db, region, info.host_port)
                LOG.info("RDS %s resumed on port %s", db_id, info.host_port)
                return "resumed"
            LOG.warning("RDS %s started but hydration failed", db_id)
            return "failed"

    # Case 3: container gone. Try recreate against the named volume.
    volume_name = f"localemu-rds-{db_id}-data"
    if not _docker_volume_exists(volume_name):
        LOG.warning(
            "RDS %s: container missing AND volume %s missing — "
            "marking status incompatible-restore",
            db_id, volume_name,
        )
        _mark_incompatible(moto_db)
        return "failed"

    master_pass = (existing_info.master_password if existing_info else "") or ""
    master_user = (existing_info.master_username if existing_info else "") or "admin"
    if not master_pass:
        LOG.error(
            "RDS %s: container gone, volume present, but no master password "
            "available on the container labels (container was removed before "
            "label could be read). Cannot safely recreate — mark incompatible-restore.",
            db_id,
        )
        _mark_incompatible(moto_db)
        return "failed"

    engine = getattr(moto_db, "engine", "postgres") or "postgres"
    engine_version = getattr(moto_db, "engine_version", None)
    db_name = getattr(moto_db, "db_name", None)
    db_instance_class = (
        getattr(moto_db, "db_instance_class", None) or "db.t3.micro"
    )
    allocated_storage = getattr(moto_db, "allocated_storage", 20) or 20

    try:
        info = mgr.create_db_instance(
            db_instance_id=db_id,
            engine=engine,
            engine_version=engine_version,
            master_username=master_user,
            master_password=master_pass,
            db_name=db_name,
            allocated_storage=allocated_storage,
            db_instance_class=db_instance_class,
            port=None,
            vpc_id=None,
        )
    except Exception:
        LOG.warning("Recreate failed for RDS %s", db_id, exc_info=True)
        _mark_incompatible(moto_db)
        return "failed"

    _patch_moto_endpoint(moto_db, region, info.host_port)
    LOG.info("RDS %s recreated on port %s against existing volume", db_id, info.host_port)
    return "recreated"


def _safe_hydrate(mgr, container_name: str):
    """Wrap ``_hydrate_from_container`` so we can call it without re-reading
    labels from scratch."""
    try:
        inspect = DOCKER_CLIENT.inspect_container(container_name)
    except Exception:
        return None
    labels = (inspect.get("Config") or {}).get("Labels") or {}
    try:
        return mgr._hydrate_from_container(container_name, labels)
    except Exception:
        LOG.debug("Hydrate failed for %s", container_name, exc_info=True)
        return None


def _patch_moto_endpoint(moto_db, region: str, host_port: int) -> None:
    """Update moto's in-memory DB record so subsequent DescribeDBInstances
    calls return the host port of the (possibly recreated) container.

    Moto stores port as ``moto_db.port`` (int). Different moto versions
    spell this slightly differently; try the known shapes gracefully.
    """
    try:
        moto_db.port = int(host_port)
    except Exception:
        pass
    # Some moto versions expose an endpoint dict too.
    try:
        endpoint = getattr(moto_db, "endpoint", None)
        if isinstance(endpoint, dict):
            endpoint["Port"] = int(host_port)
    except Exception:
        pass


def _mark_incompatible(moto_db) -> None:
    """Mark a moto DB record as unreachable so DescribeDBInstances reports
    the truth. Best-effort; moto's field shape varies by version."""
    for attr in ("status", "db_instance_status"):
        if hasattr(moto_db, attr):
            try:
                setattr(moto_db, attr, "incompatible-restore")
            except Exception:
                pass


def _docker_volume_exists(volume_name: str) -> bool:
    """Return True iff a named Docker volume exists. DOCKER_CLIENT doesn't
    expose volume inspection directly, so we reach into the underlying
    docker SDK (the only supported backend for this path)."""
    try:
        import docker

        client = docker.from_env()
        client.volumes.get(volume_name)
        return True
    except Exception:
        return False
