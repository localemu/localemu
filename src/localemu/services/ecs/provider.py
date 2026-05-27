"""ECS provider with Docker-backed task execution.

Wraps Moto's ECS backend and adds Docker container management when
Docker is available. Creates a custom dispatch table that intercepts
specific ECS operations (RunTask, StopTask, etc.) while routing all
other operations directly to Moto.

Architecture (same pattern as EC2 Docker backend):
  1. Moto owns all state: clusters, task definitions, task records, ARNs.
  2. Docker provides execution: real containers from task definitions.
  3. Moto's RunTask requires a registered container instance (EC2 launch type).
     We register a synthetic instance per cluster so Moto's check passes.
"""

import logging
import os
import threading
import time

import moto.backends as moto_backends

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service, ServiceLifecycleHook

LOG = logging.getLogger(__name__)

# Module-level task_manager singleton (BUG-04: double-checked locking)
_task_manager = None
_task_manager_lock = threading.Lock()

# Track synthetic EC2 instance IDs per cluster for cleanup (BUG-03)
_synthetic_instances: dict[str, str] = {}


def _normalize_cluster_name(cluster: str) -> str:
    """Extract short cluster name from ARN or plain name (BUG-12: centralized normalization)."""
    if "/" in cluster:
        return cluster.split("/")[-1]
    return cluster


def _init_task_manager():
    """Initialize the Docker Task Manager.

    Docker backend is enabled by default when Docker is available.
    Set ECS_DOCKER_BACKEND=0 to explicitly disable it.
    """
    global _task_manager
    if _task_manager is not None:
        return _task_manager

    with _task_manager_lock:
        if _task_manager is not None:
            return _task_manager

        # Opt-out instead of opt-in — enabled by default when Docker is available
        if os.environ.get("ECS_DOCKER_BACKEND", "").strip() == "0":
            return None

        try:
            from localemu.services.ecs.docker.task_manager import DockerTaskManager
            from localemu.utils.docker_utils import DOCKER_CLIENT

            if DOCKER_CLIENT.has_docker():
                _task_manager = DockerTaskManager()
                LOG.info("ECS Docker backend enabled (set ECS_DOCKER_BACKEND=0 to disable).")
            else:
                LOG.debug("Docker not available, ECS Docker backend disabled.")
        except Exception as e:
            LOG.warning("Failed to initialize ECS Docker backend: %s", e)

        return _task_manager


def _get_ecs_backend(context: RequestContext):
    """Return the Moto EC2ContainerServiceBackend for the request's account/region.

    Moto's BackendDict is two-level: ``backend[account_id][region]``.
    """
    return moto_backends.get_backend("ecs")[context.account_id][context.region]


def _ensure_synthetic_instance(context: RequestContext, cluster_name: str, launch_type: str = "EC2") -> None:
    """Ensure the cluster has a registered container instance for Moto's RunTask.

    Moto's ``run_task`` raises ``Exception("No instances found in cluster …")``
    when there are no registered container instances.  Since the Docker backend
    runs containers directly via Docker, we create a lightweight synthetic EC2
    instance and register it as a container instance.

    Moto's ``register_container_instance`` validates the ``ec2_instance_id``
    against the EC2 backend, so we must create a real Moto EC2 instance first.

    The call is idempotent — if the cluster already has instances, this is a
    no-op.

    PARITY-02: For FARGATE launch type, skip synthetic instance creation since
    Fargate tasks don't need registered container instances.
    """
    # PARITY-02: FARGATE tasks don't need container instances
    if launch_type and launch_type.upper() == "FARGATE":
        return

    try:
        ecs_backend = _get_ecs_backend(context)
        cluster_key = _normalize_cluster_name(cluster_name)
        if ecs_backend.container_instances.get(cluster_key):
            return  # already has an instance

        # Create a synthetic EC2 instance in Moto (required by register_container_instance)
        ec2_backend = moto_backends.get_backend("ec2")[context.account_id][context.region]
        reservation = ec2_backend.run_instances(
            image_id="ami-localemu-ecs",
            count=1,
            user_data="",
            security_group_names=[],
            instance_type="t3.micro",
            is_instance_type_default=False,
            placement=context.region + "a",
            region_name=context.region,
        )
        ec2_instance_id = reservation.instances[0].id

        ecs_backend.register_container_instance(cluster_key, ec2_instance_id)
        # BUG-03: Track synthetic instance for cleanup on cluster deletion
        _synthetic_instances[cluster_key] = ec2_instance_id
        LOG.debug(
            "Registered synthetic container instance %s for cluster %s",
            ec2_instance_id, cluster_key,
        )
    except (KeyboardInterrupt, SystemExit, MemoryError):
        # BUG-09: Re-raise critical errors that should never be swallowed
        raise
    except Exception as e:
        LOG.warning("Failed to ensure synthetic instance for %s: %s", cluster_name, e)


def _handle_run_task(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RunTask: let Moto create the task record, then start real Docker containers."""
    # PARITY-02: Extract launch type to distinguish FARGATE from EC2
    launch_type = request.get("launchType", "EC2")

    # Ensure Moto has a container instance so its run_task check passes.
    mgr = _init_task_manager()
    if mgr:
        cluster = request.get("cluster") or "default"
        _ensure_synthetic_instance(context, cluster, launch_type=launch_type)

    result = call_moto(context)

    if not mgr:
        return result

    tasks = result.get("tasks", [])
    if not tasks:
        return result

    for task in tasks:
        task_arn = task.get("taskArn", "")
        cluster_arn = task.get("clusterArn", "")
        task_def_arn = task.get("taskDefinitionArn", "")

        # Start with PROVISIONING status
        task["lastStatus"] = "PROVISIONING"
        task["desiredStatus"] = "RUNNING"

        # PARITY-04: Add timing fields
        now_ts = time.time()
        task["createdAt"] = now_ts

        overrides_data = task.get("overrides", {})

        # PARITY-03: Resolve the full task definition to get networkMode, cpu, memory
        full_td = _resolve_full_task_definition(context, task_def_arn)
        network_mode = full_td.get("networkMode", "bridge") if full_td else "bridge"

        # PARITY-04: Add cpu/memory from the task definition
        td_cpu = full_td.get("cpu") if full_td else None
        td_memory = full_td.get("memory") if full_td else None
        if td_cpu:
            task["cpu"] = str(td_cpu)
        if td_memory:
            task["memory"] = str(td_memory)

        # BUG-ECS-04 fix: moto's ``Task.containers`` is hard-coded to
        # ``[Container(task_definition)]`` and ``Container.__init__`` only
        # ever inspects ``task_def.container_definitions[0]``. So a multi-
        # container task definition (e.g. web + sidecar sharing a volume)
        # would lose every container after the first when iterating
        # ``task.get("containers", [])``. Source the launch list from the
        # registered task definition itself, then push synthetic Container
        # entries back into ``task["containers"]`` so DescribeTasks reflects
        # what we actually launched (and downstream PARITY-09 status updates
        # find each container by name).
        registered_defs = _resolve_task_definition(context, task_def_arn)
        container_defs = []
        for src_def in registered_defs:
            cdef = {
                "name": src_def.get("name", ""),
                "image": src_def.get("image", ""),
                "portMappings": src_def.get("portMappings", []),
                "environment": src_def.get("environment", []),
                "command": src_def.get("command"),
            }
            if src_def.get("healthCheck"):
                cdef["healthCheck"] = src_def["healthCheck"]
            if src_def.get("mountPoints"):
                cdef["mountPoints"] = src_def["mountPoints"]
            if src_def.get("cpu"):
                cdef["cpu"] = src_def["cpu"]
            if src_def.get("memory"):
                cdef["memory"] = src_def["memory"]
            if src_def.get("memoryReservation"):
                cdef["memoryReservation"] = src_def["memoryReservation"]
            container_defs.append(cdef)

        # If moto only emitted the first container, append synthetic
        # entries so DescribeTasks shows every running container.
        existing_names = {mc.get("name") for mc in task.get("containers", [])}
        for cdef in container_defs:
            if cdef["name"] and cdef["name"] not in existing_names:
                task.setdefault("containers", []).append({
                    "name": cdef["name"],
                    "image": cdef.get("image", ""),
                    "lastStatus": "PENDING",
                    "containerArn": (
                        f"{task_def_arn}/{cdef['name']}"
                    ),
                })

        # PARITY-07: Extract volumes from task definition
        td_volumes = full_td.get("volumes", []) if full_td else []

        task_definition = {
            "taskDefinitionArn": task_def_arn,
            "containerDefinitions": container_defs,
            # PARITY-03: Pass network mode to Docker task manager
            "networkMode": network_mode,
            # PARITY-07: Pass volumes
            "volumes": td_volumes,
            # #79: task role ARN drives IAM credential minting
            "taskRoleArn": full_td.get("taskRoleArn") if full_td else None,
            "executionRoleArn": full_td.get("executionRoleArn") if full_td else None,
        }

        # Pull networkConfiguration from the RunTask request so the
        # task manager can resolve the real VPC via subnet IDs instead
        # of picking the first localemu-vpc-* network it finds.
        network_configuration = request.get("networkConfiguration") or {}

        try:
            task_infos = mgr.run_task(
                cluster_name=cluster_arn,
                task_definition=task_definition,
                task_arn=task_arn,
                count=1,
                overrides=overrides_data,
                launch_type=launch_type,
                region=context.region,
                network_configuration=network_configuration,
                account_id=context.account_id,
            )

            # Update Moto's response with real container status
            if task_infos:
                ti = task_infos[0]
                task["lastStatus"] = "RUNNING"
                task["desiredStatus"] = "RUNNING"
                # PARITY-04: Add startedAt
                task["startedAt"] = time.time()

                for mc in task.get("containers", []):
                    for ci in ti.containers:
                        if ci.container_name == mc.get("name"):
                            mc["lastStatus"] = ci.status
                            # Add network bindings for mapped ports
                            bindings = []
                            for c_port, h_port in ci.host_ports.items():
                                bindings.append({
                                    "bindIP": "0.0.0.0",
                                    "containerPort": c_port,
                                    "hostPort": h_port,
                                    "protocol": "tcp",
                                })
                            if bindings:
                                mc["networkBindings"] = bindings
                            break

                LOG.info(
                    "ECS task %s started with %d containers",
                    task_arn, len(ti.containers),
                )
        except Exception as e:
            LOG.warning("Docker launch failed for ECS task %s: %s", task_arn, e)

    return result


def _lookup_container_image(
    context: RequestContext, task_def_arn: str, container_name: str
) -> str:
    """Look up a container's image from the Moto task definition store."""
    details = _lookup_task_definition_details(
        context, task_def_arn, container_name
    )
    return details.get("image", "") if details else ""


# Cache of resolved task definitions to avoid repeated Moto lookups
_task_def_cache: dict[str, list[dict]] = {}


def _resolve_task_definition(context: RequestContext, task_def_arn: str) -> list[dict]:
    """Resolve the full containerDefinitions for a task definition ARN.

    Uses Moto's internal backend to look up the registered task definition
    and extract its container definitions as plain dicts.
    """
    if task_def_arn in _task_def_cache:
        return _task_def_cache[task_def_arn]

    container_defs = []
    try:
        td_obj = _find_moto_task_definition(context, task_def_arn)
        if td_obj:
            for cdef in getattr(td_obj, "container_definitions", []):
                if isinstance(cdef, dict):
                    container_defs.append(cdef)
                else:
                    # Convert Moto container definition object to dict
                    d: dict = {}
                    for attr in (
                        "name", "image", "command", "environment",
                        "cpu", "memory", "memoryReservation",
                    ):
                        val = getattr(cdef, attr, None)
                        if val is not None:
                            d[attr] = val
                    # Moto uses port_mappings (snake_case)
                    pm = getattr(cdef, "port_mappings", None) or getattr(cdef, "portMappings", None)
                    if pm is not None:
                        d["portMappings"] = pm
                    # PARITY-06: Extract health check
                    hc = getattr(cdef, "health_check", None) or getattr(cdef, "healthCheck", None)
                    if hc is not None:
                        d["healthCheck"] = hc if isinstance(hc, dict) else {
                            "command": getattr(hc, "command", []),
                            "interval": getattr(hc, "interval", 30),
                            "timeout": getattr(hc, "timeout", 5),
                            "retries": getattr(hc, "retries", 3),
                            "startPeriod": getattr(hc, "start_period", 0),
                        }
                    # PARITY-07: Extract mount points
                    mp = getattr(cdef, "mount_points", None) or getattr(cdef, "mountPoints", None)
                    if mp is not None:
                        d["mountPoints"] = mp
                    container_defs.append(d)
    except Exception as e:
        LOG.debug("Could not look up task definition %s: %s", task_def_arn, e)

    _task_def_cache[task_def_arn] = container_defs
    return container_defs


def _find_moto_task_definition(context: RequestContext, task_def_arn: str):
    """Find the Moto task definition object for a given ARN."""
    try:
        ecs_backend = _get_ecs_backend(context)
        for family_revisions in ecs_backend.task_definitions.values():
            if isinstance(family_revisions, dict):
                items = family_revisions.values()
            elif isinstance(family_revisions, list):
                items = family_revisions
            else:
                items = [family_revisions]

            for td_obj in items:
                td_arn = getattr(td_obj, "arn", None)
                if td_arn == task_def_arn:
                    return td_obj
    except Exception as e:
        LOG.debug("Could not find task definition %s: %s", task_def_arn, e)
    return None


# Cache for full task definitions (networkMode, volumes, cpu, memory)
_full_td_cache: dict[str, dict] = {}


def _resolve_full_task_definition(context: RequestContext, task_def_arn: str) -> dict | None:
    """Resolve the full task definition metadata (networkMode, volumes, cpu, memory).

    PARITY-03/07: Extracts top-level task definition attributes that affect
    Docker container configuration.
    """
    if task_def_arn in _full_td_cache:
        return _full_td_cache[task_def_arn]

    result = {}
    try:
        td_obj = _find_moto_task_definition(context, task_def_arn)
        if td_obj:
            result["networkMode"] = getattr(td_obj, "network_mode", None) or getattr(td_obj, "networkMode", "bridge") or "bridge"
            result["cpu"] = getattr(td_obj, "cpu", None)
            result["memory"] = getattr(td_obj, "memory", None)
            # PARITY-07: Extract volumes
            vols = getattr(td_obj, "volumes", None)
            if vols:
                result["volumes"] = vols if isinstance(vols, list) else []
            # #79: Surface taskRoleArn / executionRoleArn so the Docker
            # task manager can mint IAM credentials for the task.
            result["taskRoleArn"] = (
                getattr(td_obj, "task_role_arn", None)
                or getattr(td_obj, "taskRoleArn", None)
            )
            result["executionRoleArn"] = (
                getattr(td_obj, "execution_role_arn", None)
                or getattr(td_obj, "executionRoleArn", None)
            )
    except Exception as e:
        LOG.debug("Could not resolve full task definition %s: %s", task_def_arn, e)

    _full_td_cache[task_def_arn] = result
    return result


def _lookup_task_definition_details(
    context: RequestContext, task_def_arn: str, container_name: str
) -> dict | None:
    """Look up a specific container's details from a task definition."""
    for cdef in _resolve_task_definition(context, task_def_arn):
        if cdef.get("name") == container_name:
            return cdef
    return None


def _handle_stop_task(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """StopTask: let Moto update the record, then stop Docker containers."""
    # ECS uses JSON protocol — parameters are in the parsed `request` dict,
    # NOT in context.request.values (which is empty for JSON bodies).
    task_arn = request.get("task") or ""
    cluster = request.get("cluster", "default")
    # PARITY-09: Capture the stop reason
    reason = request.get("reason", "")

    result = call_moto(context)

    # PARITY-09: Propagate reason to the response
    if reason and result.get("task"):
        result["task"]["stoppedReason"] = reason

    # Set STOPPING transitional state
    if result.get("task"):
        result["task"]["lastStatus"] = "STOPPING"
        result["task"]["desiredStatus"] = "STOPPED"
        # PARITY-04: Add stoppedAt timestamp
        result["task"]["stoppedAt"] = time.time()

    mgr = _init_task_manager()
    if mgr and task_arn:
        try:
            mgr.stop_task(task_arn)
            # After containers are stopped, update to final STOPPED state
            if result.get("task"):
                result["task"]["lastStatus"] = "STOPPED"
        except Exception as e:
            LOG.warning("Failed to stop Docker containers for ECS task %s: %s", task_arn, e)

    return result


def _handle_describe_tasks(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DescribeTasks: let Moto return records, then enrich with real container status."""
    result = call_moto(context)

    mgr = _init_task_manager()
    if not mgr:
        return result

    for task in result.get("tasks", []):
        task_arn = task.get("taskArn", "")
        task_def_arn = task.get("taskDefinitionArn", "")
        task_info = mgr.get_task_status(task_arn)

        # PARITY-04: Enrich with cpu/memory from task definition even without Docker info
        if task_def_arn:
            full_td = _resolve_full_task_definition(context, task_def_arn)
            if full_td:
                if full_td.get("cpu") and "cpu" not in task:
                    task["cpu"] = str(full_td["cpu"])
                if full_td.get("memory") and "memory" not in task:
                    task["memory"] = str(full_td["memory"])

        if not task_info:
            continue

        task["lastStatus"] = task_info.status
        # PARITY-04: Add timing fields from task info
        if task_info.created_at:
            task["createdAt"] = task_info.created_at
        if task_info.started_at:
            task["startedAt"] = task_info.started_at
        if task_info.stopped_at:
            task["stoppedAt"] = task_info.stopped_at

        for mc in task.get("containers", []):
            for ci in task_info.containers:
                if ci.container_name == mc.get("name"):
                    mc["lastStatus"] = ci.status
                    if ci.exit_code is not None:
                        mc["exitCode"] = ci.exit_code
                    # BUG-ECS-05 fix: populate networkBindings on every
                    # DescribeTasks call. Moto's Container model does not
                    # carry port bindings, so without this re-projection
                    # the field is dropped on the second call (real AWS
                    # always returns it for tasks with portMappings).
                    if ci.host_ports:
                        mc["networkBindings"] = [
                            {
                                "bindIP": "0.0.0.0",
                                "containerPort": c_port,
                                "hostPort": h_port,
                                "protocol": "tcp",
                            }
                            for c_port, h_port in ci.host_ports.items()
                        ]
                    break

    return result


def _handle_create_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateCluster: let Moto handle it, then register a synthetic instance."""
    result = call_moto(context)
    cluster_name = result.get("cluster", {}).get("clusterName", "")
    LOG.info("ECS cluster created: %s", cluster_name)

    if _init_task_manager() and cluster_name:
        _ensure_synthetic_instance(context, cluster_name)

    return result


def _handle_delete_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteCluster: let Moto delete the record, then cleanup any remaining containers."""
    cluster_name = request.get("cluster", "")
    result = call_moto(context)

    mgr = _init_task_manager()
    if mgr and cluster_name:
        try:
            mgr.cleanup_cluster(cluster_name)
        except Exception as e:
            LOG.warning("Failed to clean up containers for ECS cluster %s: %s", cluster_name, e)

    # BUG-03: Terminate synthetic EC2 instance for this cluster
    cluster_short = _normalize_cluster_name(cluster_name)
    ec2_instance_id = _synthetic_instances.pop(cluster_short, None)
    if ec2_instance_id:
        try:
            ec2_backend = moto_backends.get_backend("ec2")[context.account_id][context.region]
            ec2_backend.terminate_instances([ec2_instance_id])
            LOG.debug("Terminated synthetic EC2 instance %s for cluster %s", ec2_instance_id, cluster_short)
        except Exception as e:
            LOG.debug("Failed to terminate synthetic instance %s: %s", ec2_instance_id, e)

    # BUG-02: Invalidate task definition caches on cluster deletion
    _task_def_cache.clear()
    _full_td_cache.clear()

    return result


def _handle_register_task_definition(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """RegisterTaskDefinition: invalidate cache after Moto registers the definition."""
    result = call_moto(context)
    # BUG-ECS-01 fix: invalidate task def cache on new registration
    td_arn = result.get("taskDefinition", {}).get("taskDefinitionArn")
    if td_arn:
        _task_def_cache.pop(td_arn, None)
        _full_td_cache.pop(td_arn, None)
    return result


def _handle_deregister_task_definition(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeregisterTaskDefinition: invalidate cache when definition removed."""
    result = call_moto(context)
    td_arn = result.get("taskDefinition", {}).get("taskDefinitionArn")
    if td_arn:
        _task_def_cache.pop(td_arn, None)
        _full_td_cache.pop(td_arn, None)
    return result


# ---------------------
# Service management
# ---------------------

# Track service -> task ARNs mapping for desired count reconciliation
_service_tasks: dict[str, list[str]] = {}
_service_tasks_lock = threading.Lock()


def _handle_create_service(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateService: let Moto create the service record, then launch desiredCount tasks."""
    result = call_moto(context)

    mgr = _init_task_manager()
    service_data = result.get("service")
    if not mgr or not service_data:
        return result

    desired_count = service_data.get("desiredCount", 0)
    task_def_arn = service_data.get("taskDefinition", "")
    cluster_arn = service_data.get("clusterArn", "")
    service_arn = service_data.get("serviceArn", "")
    launch_type = service_data.get("launchType", "EC2")

    if desired_count > 0 and task_def_arn:
        # BUG-ECS-03 fix: pass the full cluster ARN to the task manager so
        # the ``localemu.cluster`` Docker label matches what RunTask writes
        # (the ARN). Using the short name here made label-scoped docker
        # queries (e.g. by ops tooling) skip every service-started
        # container, even though RunTask-launched containers were findable.
        # Moto's ``run_task`` accepts either form; we still normalise to the
        # short name for the ``_ensure_synthetic_instance`` lookup against
        # moto's internal dict which is keyed by short name.
        cluster_short = _normalize_cluster_name(cluster_arn) if cluster_arn else "default"
        cluster_label = cluster_arn or cluster_short
        _ensure_synthetic_instance(context, cluster_short, launch_type=launch_type)

        task_arns = _run_service_tasks(
            context, cluster_label, task_def_arn, desired_count, launch_type,
            network_configuration=service_data.get("networkConfiguration"),
        )
        with _service_tasks_lock:
            _service_tasks[service_arn] = task_arns

        service_data["runningCount"] = len(task_arns)
        service_data["status"] = "ACTIVE"
        LOG.info(
            "ECS service %s created with %d/%d tasks",
            service_data.get("serviceName"), len(task_arns), desired_count,
        )

    return result


def _handle_update_service(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """UpdateService: let Moto update the record, then scale Docker tasks."""
    result = call_moto(context)

    mgr = _init_task_manager()
    service_data = result.get("service")
    if not mgr or not service_data:
        return result

    service_arn = service_data.get("serviceArn", "")
    desired_count = service_data.get("desiredCount", 0)
    task_def_arn = service_data.get("taskDefinition", "")
    cluster_arn = service_data.get("clusterArn", "")
    launch_type = service_data.get("launchType", "EC2")

    with _service_tasks_lock:
        current_task_arns = _service_tasks.get(service_arn, [])
        current_count = len(current_task_arns)

    if desired_count > current_count:
        # Scale up — see BUG-ECS-03: label tasks with the cluster ARN (not
        # the short name) so they are discoverable via docker-label queries
        # and match RunTask's labelling.
        cluster_label = cluster_arn or _normalize_cluster_name(cluster_arn or "default")
        new_arns = _run_service_tasks(
            context, cluster_label, task_def_arn, desired_count - current_count, launch_type,
            network_configuration=service_data.get("networkConfiguration"),
        )
        with _service_tasks_lock:
            _service_tasks.setdefault(service_arn, []).extend(new_arns)
        LOG.info("ECS service %s scaled up: %d -> %d tasks", service_arn, current_count, desired_count)

    elif desired_count < current_count:
        # Scale down — stop excess tasks
        to_stop = current_count - desired_count
        with _service_tasks_lock:
            arns_to_stop = _service_tasks.get(service_arn, [])[-to_stop:]
            _service_tasks[service_arn] = _service_tasks.get(service_arn, [])[:-to_stop]

        for task_arn in arns_to_stop:
            try:
                mgr.stop_task(task_arn)
            except Exception as e:
                LOG.debug("Failed to stop task %s during scale-down: %s", task_arn, e)
        LOG.info("ECS service %s scaled down: %d -> %d tasks", service_arn, current_count, desired_count)

    service_data["runningCount"] = desired_count
    return result


def _handle_delete_service(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteService: let Moto delete the record, then stop all service tasks."""
    # Identify the service ARN before Moto deletes
    cluster = request.get("cluster", "default")
    service_name = request.get("service", "")

    result = call_moto(context)

    mgr = _init_task_manager()
    if not mgr:
        return result

    # Find matching service ARN
    service_arn = None
    with _service_tasks_lock:
        for arn in list(_service_tasks.keys()):
            if service_name in arn:
                service_arn = arn
                break
        task_arns = _service_tasks.pop(service_arn, []) if service_arn else []

    for task_arn in task_arns:
        try:
            mgr.stop_task(task_arn)
        except Exception as e:
            LOG.debug("Failed to stop service task %s: %s", task_arn, e)

    if task_arns:
        LOG.info("ECS service deleted, stopped %d tasks", len(task_arns))

    return result


def _run_service_tasks(
    context: RequestContext,
    cluster_name: str,
    task_def_arn: str,
    count: int,
    launch_type: str,
    network_configuration: dict | None = None,
) -> list[str]:
    """Run N tasks for a service, returning the task ARNs created.

    BUG-ECS-02 fix: ``_resolve_full_task_definition`` only exposes top-level
    task-def fields (networkMode, cpu, memory, volumes) — *not* the container
    definitions. Before this fix we pulled ``containerDefinitions`` out of
    that dict and got an empty list every time, so CreateService/UpdateService
    would create moto task records but never launch a Docker container. Use
    ``_resolve_task_definition`` for the per-container details and the full-td
    helper strictly for top-level attributes. Also forward the service's
    ``networkConfiguration`` to moto's ``run_task`` — moto requires it on
    awsvpc task definitions and would otherwise raise.
    """
    task_arns = []
    for _ in range(count):
        try:
            ecs_backend = _get_ecs_backend(context)
            moto_tasks = ecs_backend.run_task(
                cluster_str=cluster_name,
                task_definition_str=task_def_arn,
                count=1,
                overrides=None,
                started_by="ecs-service-scheduler",
                tags=None,
                launch_type=launch_type,
                networking_configuration=network_configuration,
            )
            if not moto_tasks:
                continue

            for moto_task in moto_tasks:
                task_arn = moto_task.task_arn
                task_arns.append(task_arn)

                # Now start the Docker container
                mgr = _init_task_manager()
                if not mgr:
                    continue

                full_td = _resolve_full_task_definition(context, task_def_arn) or {}
                container_defs = _resolve_task_definition(context, task_def_arn)
                if not container_defs:
                    LOG.warning(
                        "Service task %s: could not resolve containerDefinitions "
                        "for %s — no Docker container will be launched",
                        task_arn, task_def_arn,
                    )
                    continue

                network_mode = full_td.get("networkMode", "bridge")
                td_volumes = full_td.get("volumes", [])

                task_definition = {
                    "taskDefinitionArn": task_def_arn,
                    "containerDefinitions": container_defs,
                    "networkMode": network_mode,
                    "volumes": td_volumes,
                }

                try:
                    mgr.run_task(
                        cluster_name=cluster_name,
                        task_definition=task_definition,
                        task_arn=task_arn,
                        count=1,
                        overrides={},
                        launch_type=launch_type,
                        region=context.region,
                        network_configuration=network_configuration,
                        account_id=context.account_id,
                    )
                except Exception as e:
                    LOG.warning("Docker launch failed for service task %s: %s", task_arn, e)

        except Exception as e:
            LOG.warning("Failed to run service task: %s", e)

    return task_arns


# Operations we intercept with Docker container management
_INTERCEPTED_OPS = {
    "RunTask": _handle_run_task,
    "StopTask": _handle_stop_task,
    "DescribeTasks": _handle_describe_tasks,
    "CreateCluster": _handle_create_cluster,
    "DeleteCluster": _handle_delete_cluster,
    "RegisterTaskDefinition": _handle_register_task_definition,
    "DeregisterTaskDefinition": _handle_deregister_task_definition,
    "CreateService": _handle_create_service,
    "UpdateService": _handle_update_service,
    "DeleteService": _handle_delete_service,
}


def EcsDispatcher(service_model) -> DispatchTable:
    """Create a dispatch table for ECS.

    Intercepted operations (RunTask, StopTask, DescribeTasks, etc.)
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


def _iter_ecs_backends():
    """Yield ``(account_id, region, backend)`` for every instantiated ECS
    moto backend. Mirrors the pattern SaveOrchestrator uses."""
    try:
        bd = moto_backends.get_backend("ecs")
    except Exception:
        return
    for acct, region_map in list(bd.items()):
        if not isinstance(region_map, dict):
            continue
        for region, backend in list(region_map.items()):
            yield acct, region, backend


def _ecs_on_after_state_load() -> None:
    """Reconcile persisted ECS records with the live Docker daemon.

    Runs after ``SaveOrchestrator`` re-hydrates moto's ECS backend. For
    each persisted task we:

    1. Rebuild the module-level ``_synthetic_instances`` and
       ``_service_tasks`` mappings from moto (these are runtime caches,
       not persisted state).
    2. Resume every task whose containers still exist on the host via
       ``docker start`` — their writable layer, env vars, and port
       bindings all survive the restart.

    Tasks whose containers are missing (user ran ``docker rm``, image
    pruned) are logged as data-loss; moto's record is left as-is so
    ``DescribeTasks`` still returns the persisted view. Re-launching
    from the task definition is possible future work — for now we
    prefer honest "container gone" over silently starting a fresh
    container that doesn't match what the user left behind.
    """
    # Clear module-level caches — moto rewrote the state under us.
    _task_def_cache.clear()
    _full_td_cache.clear()
    _synthetic_instances.clear()
    _service_tasks.clear()

    # Force-init the task manager (it re-scans Docker labels on __init__
    # via `_recover_orphaned_containers`). ``ECS_DOCKER_BACKEND=0`` short-
    # circuits this — in that mode there are no containers to reconcile.
    mgr = _init_task_manager()
    if not mgr:
        LOG.debug("ECS Docker backend disabled — skipping post-load reconcile")
        return

    # Step 1: rebuild synthetic EC2 instance mapping from moto.
    for _acct, _region, backend in _iter_ecs_backends():
        container_instances = getattr(backend, "container_instances", {}) or {}
        for cluster_name, instances in container_instances.items():
            if not instances:
                continue
            first = next(iter(instances.values()), None)
            ec2_id = getattr(first, "ec2_instance_id", None)
            if ec2_id:
                _synthetic_instances[_normalize_cluster_name(cluster_name)] = ec2_id

    # Step 2: reconcile every persisted task against tracked containers.
    resumed = missing = skipped = 0
    for _acct, _region, backend in _iter_ecs_backends():
        tasks = getattr(backend, "tasks", {}) or {}
        for _cluster_arn, cluster_tasks in tasks.items():
            for task_id, task in list(cluster_tasks.items()):
                status = (getattr(task, "last_status", "") or "").upper()
                if status in ("STOPPED", "DEPROVISIONING"):
                    skipped += 1
                    continue
                task_arn = getattr(task, "task_arn", None) or task_id
                tracked = mgr._tasks.get(task_arn) if hasattr(mgr, "_tasks") else None
                if not tracked:
                    LOG.warning(
                        "ECS task %s: persisted but no tracked container on host "
                        "(data loss)",
                        task_arn,
                    )
                    missing += 1
                    continue
                if _resume_task_containers(tracked):
                    resumed += 1
                else:
                    missing += 1

    # Step 3: rebuild _service_tasks from moto. Required so the scheduler
    # (and DescribeServices) return accurate counts.
    for _acct, _region, backend in _iter_ecs_backends():
        services = getattr(backend, "services", {}) or {}
        tasks = getattr(backend, "tasks", {}) or {}
        for cluster_arn, cluster_services in services.items():
            cluster_tasks = tasks.get(cluster_arn, {}) or {}
            for service_arn, service in cluster_services.items():
                service_name = getattr(service, "name", "") or ""
                group_tag = f"service:{service_name}" if service_name else ""
                live = [
                    getattr(t, "task_arn", None) or tid
                    for tid, t in cluster_tasks.items()
                    if (getattr(t, "started_by", "") == "ecs-service-scheduler"
                        and (not group_tag or getattr(t, "group", "") == group_tag)
                        and (getattr(t, "last_status", "") or "").upper() != "STOPPED")
                ]
                if live:
                    _service_tasks[service_arn] = live

    LOG.info(
        "ECS reconcile: resumed=%d, missing=%d, skipped=%d",
        resumed, missing, skipped,
    )


def _resume_task_containers(task_info) -> bool:
    """Start every stopped container in ``task_info``. Returns True if
    the task has at least one running container after the pass."""
    from localemu.utils.docker_utils import DOCKER_CLIENT

    any_running = False
    for container in getattr(task_info, "containers", []):
        docker_name = getattr(container, "docker_name", None)
        if not docker_name:
            continue
        try:
            inspect = DOCKER_CLIENT.inspect_container(docker_name)
            running = bool((inspect.get("State") or {}).get("Running"))
        except Exception:
            LOG.warning(
                "ECS container %s missing during restore — marking stopped",
                docker_name,
            )
            container.status = "STOPPED"
            continue
        if running:
            container.status = "RUNNING"
            any_running = True
            continue
        try:
            DOCKER_CLIENT.start_container(docker_name)
            container.status = "RUNNING"
            any_running = True
            LOG.info("Resumed ECS container %s", docker_name)
        except Exception as exc:
            LOG.warning(
                "docker start %s failed: %s — container left stopped",
                docker_name, exc,
            )
            container.status = "STOPPED"
    if any_running:
        task_info.status = "RUNNING"
    return any_running


class EcsStateLifecycleHook(ServiceLifecycleHook):
    """Bridges LocalEmu's persistence engine + state-reset flow to the ECS
    provider.

    ``on_before_state_reset`` clears module-level caches and destroys the
    Docker task manager so a reset returns the provider to cold-start.

    ``on_after_state_load`` is the persistence path: reconcile persisted
    moto records with the live Docker daemon. Containers that survived
    shutdown get ``docker start``ed; containers that are gone get
    re-launched from their task definition.
    """

    def on_before_state_reset(self) -> None:
        global _task_manager
        _task_def_cache.clear()
        _full_td_cache.clear()
        _synthetic_instances.clear()
        _service_tasks.clear()
        if _task_manager:
            try:
                _task_manager.cleanup_all()
            except Exception as e:
                LOG.debug("Failed to clean up ECS containers on state reset: %s", e)
            _task_manager = None

    def on_after_state_reset(self) -> None:
        pass

    def on_after_state_load(self) -> None:
        _ecs_on_after_state_load()


# Module-level lifecycle hook instance
_lifecycle_hook = EcsStateLifecycleHook()


def _patch_moto_eni_private_dns_name() -> None:
    """Give moto's ``NetworkInterface`` a settable ``private_dns_name``.

    Two requirements collide here. Fargate RunTask synthesizes a task
    ENI directly without going through moto's full ``__init__`` flow
    and emits attachment details that include ``privateDnsName``; the
    moto attribute was unset and the dictionary build raised an
    ``AttributeError``. Standard ``RunInstances`` paths in newer moto
    builds DO go through ``__init__`` and assign
    ``self.private_dns_name = generate_dns_from_ip(...)`` directly when
    the subnet's VPC has ``enable_dns_hostnames=True``.

    A pure read-only ``property`` covered the Fargate case but blocked
    the assignment in standard RunInstances with
    ``AttributeError: property '_private_dns_name' of 'NetworkInterface'
    object has no setter`` (Python 3.13 surfaces the getter function's
    name in the error, which is why the log said ``_private_dns_name``
    rather than ``private_dns_name``).

    The settable form below covers both: if moto's __init__ assigned a
    value, the getter returns it; otherwise the getter derives the name
    from the IPv4 address in AWS's ``ip-10-1-1-22.ec2.internal`` shape.
    """
    try:
        from moto.ec2.models.elastic_network_interfaces import NetworkInterface
    except Exception:
        return
    if getattr(NetworkInterface, "_localemu_private_dns_patched", False):
        return

    _STORAGE_ATTR = "_localemu_private_dns_name"

    def _getter(self):
        stored = getattr(self, _STORAGE_ATTR, None)
        if stored:
            return stored
        ip = getattr(self, "private_ip_address", None) or ""
        if not ip:
            return ""
        return "ip-" + ip.replace(".", "-") + ".ec2.internal"

    def _setter(self, value):
        object.__setattr__(self, _STORAGE_ATTR, value)

    NetworkInterface.private_dns_name = property(_getter, _setter)
    NetworkInterface._localemu_private_dns_patched = True


def _patch_moto_resource_requirements_none_safe() -> None:
    """Make moto's _calculate_task_resource_requirements survive None memory.

    AWS lets a Fargate task definition specify cpu/memory at the TASK level
    and omit them per-container. Moto's calculator does

        resource_requirements["MEMORY"] += container_definition.get(
            "memory", container_definition.get("memoryReservation"),
        )

    which evaluates to ``int + None`` when both keys are missing, raising
    ``TypeError: unsupported operand type(s) for +=: 'int' and 'NoneType'``
    and bubbling up as a 500 InternalError on RunTask.

    Idempotent — guarded by a module flag so re-imports / hot-reload do
    not stack the patch.
    """
    try:
        import moto.ecs.models as _m
    except Exception:
        return
    if getattr(_m, "_localemu_resource_req_patched", False):
        return

    def _safe_calc(task_definition):
        req = {"CPU": 0, "MEMORY": 0, "PORTS": [], "PORTS_UDP": []}
        for cdef in task_definition.container_definitions:
            req["CPU"] += cdef.get("cpu", cdef.get("Cpu", 0)) or 0
            mem = (
                cdef.get("Memory")
                or cdef.get("MemoryReservation")
                or cdef.get("memory")
                or cdef.get("memoryReservation")
                or 0
            )
            req["MEMORY"] += int(mem)
            port_key = "PortMappings" if "PortMappings" in cdef else "portMappings"
            for pm in cdef.get(port_key, []) or []:
                host_port = pm.get("hostPort") or pm.get("HostPort")
                proto = (pm.get("protocol") or pm.get("Protocol") or "tcp").lower()
                if host_port:
                    (req["PORTS_UDP"] if proto == "udp" else req["PORTS"]).append(int(host_port))
        return req

    _m.EC2ContainerServiceBackend._calculate_task_resource_requirements = staticmethod(_safe_calc)
    _m._localemu_resource_req_patched = True


def create_ecs_service() -> Service:
    """Create the ECS service with Docker-aware dispatch table."""
    from localemu.aws.spec import load_service

    _patch_moto_resource_requirements_none_safe()
    _patch_moto_eni_private_dns_name()
    service_model = load_service("ecs")
    dispatch_table = EcsDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="ecs", skeleton=skeleton, lifecycle_hook=_lifecycle_hook)
