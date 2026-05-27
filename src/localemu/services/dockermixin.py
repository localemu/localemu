"""Shared helpers for services whose data plane is a set of Docker containers.

LocalEmu services that back user-visible resources with Docker containers
(EC2 instances, RDS DB instances, ECS tasks) all face the same persistence
problem: on ``localemu stop`` the control-plane record is saved via dill,
but the container is destroyed. On ``localemu start`` the record is reloaded
but the container is gone, so the data is unreachable.

The fix is the same for all three: stop the container on shutdown (don't
remove), start it on load. This module provides the handful of helpers each
service needs to do that cleanly, without each one re-implementing label-
based discovery, reconciliation, and the three-way join between moto records,
in-memory runtime caches, and live Docker state.

EKS is deliberately *not* a client of this module — k3d owns its own
stop/start primitives and reconciliation lives at the cluster level, not
the container level.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# Canonical label all LocalEmu-managed service containers carry. Individual
# services add a service-specific value (``localemu.service=ec2`` etc.) plus
# a stable resource-id label (``localemu.instance-id``, ``localemu.db-instance-id``,
# ``localemu.task-arn``).
SERVICE_LABEL = "localemu.service"


@dataclass
class ContainerSnapshot:
    """Live Docker state for one container we manage.

    Built from ``DOCKER_CLIENT.list_containers`` + ``inspect_container`` so
    the caller has a single place to read container name, labels, current
    run state, port bindings, and network attachments without re-inspecting.
    """

    name: str
    id: str
    running: bool
    exited: bool
    image: str
    labels: dict[str, str]
    port_bindings: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    networks: dict[str, dict[str, Any]] = field(default_factory=dict)
    inspect: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int | None:
        state = self.inspect.get("State") or {}
        ec = state.get("ExitCode")
        return int(ec) if ec is not None else None

    def host_port_for(self, container_port: str) -> int | None:
        """Return the host-side port bound to ``container_port`` (e.g. ``"22/tcp"``)."""
        bindings = self.port_bindings.get(container_port) or []
        if bindings:
            try:
                return int(bindings[0].get("HostPort") or 0) or None
            except (TypeError, ValueError):
                return None
        return None


def discover_service_containers(
    service_name: str,
    id_label: str,
    include_stopped: bool = True,
) -> dict[str, ContainerSnapshot]:
    """Return ``{resource_id: ContainerSnapshot}`` for all Docker containers
    labeled ``localemu.service=<service_name>``.

    ``resource_id`` is read from the ``id_label`` label — for example
    ``localemu.instance-id`` for EC2 or ``localemu.db-instance-id`` for RDS.
    Containers without that label are skipped with a debug log (shouldn't
    happen for containers LocalEmu created itself).

    When ``include_stopped`` is True (the default, what persistence wants)
    the listing includes Exited containers. Callers that only care about
    live containers can pass False.
    """
    result: dict[str, ContainerSnapshot] = {}
    try:
        containers = DOCKER_CLIENT.list_containers(
            filter=[f"label={SERVICE_LABEL}={service_name}"],
            all=include_stopped,
        )
    except Exception:
        LOG.warning(
            "Could not list %s containers — Docker unavailable?",
            service_name, exc_info=True,
        )
        return result

    for c in containers:
        labels = c.get("labels") or {}
        resource_id = labels.get(id_label)
        if not resource_id:
            LOG.debug("Container %s has no %s label — skipping", c.get("name"), id_label)
            continue
        name = c.get("name") or ""
        cid = c.get("id") or ""
        try:
            inspect = DOCKER_CLIENT.inspect_container(name or cid)
        except Exception:
            LOG.debug("inspect_container(%s) failed — skipping", name, exc_info=True)
            continue
        state = inspect.get("State") or {}
        port_bindings = (
            (inspect.get("HostConfig") or {}).get("PortBindings") or {}
        )
        networks = (inspect.get("NetworkSettings") or {}).get("Networks") or {}
        result[resource_id] = ContainerSnapshot(
            name=name,
            id=cid,
            running=bool(state.get("Running")),
            exited=str(state.get("Status", "")).lower() == "exited",
            image=(inspect.get("Config") or {}).get("Image", ""),
            labels=labels,
            port_bindings=dict(port_bindings),
            networks=dict(networks),
            inspect=inspect,
        )
    return result


def stop_containers_by_label(service_name: str, timeout: int = 10) -> int:
    """Stop (but do NOT remove) every container carrying
    ``localemu.service=<service_name>``. Returns the count that stopped
    cleanly.

    Intended for use in ``on_infra_shutdown`` hooks when persistence is on —
    preserves the container, its writable layer, and its attached volumes
    for ``docker start`` on the next ``localemu start``.
    """
    stopped = 0
    try:
        containers = DOCKER_CLIENT.list_containers(
            filter=[f"label={SERVICE_LABEL}={service_name}"],
            all=False,  # only running containers need stopping
        )
    except Exception:
        LOG.warning(
            "Could not enumerate %s containers for stop — Docker unavailable?",
            service_name, exc_info=True,
        )
        return 0

    for c in containers:
        name = c.get("name") or c.get("id") or ""
        if not name:
            continue
        try:
            DOCKER_CLIENT.stop_container(name, timeout=timeout)
            stopped += 1
        except Exception as exc:
            LOG.debug("stop %s failed: %s", name, exc)
    if stopped:
        LOG.info("Stopped %d %s container(s) (writable layer preserved)",
                 stopped, service_name)
    return stopped


def docker_start_safe(container_name: str) -> tuple[bool, str | None]:
    """``docker start`` with a sane failure contract.

    Returns ``(ok, error_message)``. ``ok=False`` means the container exists
    but refused to start — caller decides whether to fall back to recreate-
    from-scratch. Does NOT raise on common failures (port conflict, missing
    network) — those are expected during reconciliation and callers need to
    branch on them.
    """
    try:
        DOCKER_CLIENT.start_container(container_name)
        return True, None
    except Exception as exc:
        msg = str(exc)
        LOG.warning("docker start %s failed: %s", container_name, msg)
        return False, msg


@dataclass
class ReconcileCounts:
    """Aggregate outcome of a reconcile pass."""
    resumed: int = 0       # container was already running or docker started
    recreated: int = 0     # container was missing/broken — service re-created
    failed: int = 0        # reconcile threw; instance in a bad state
    orphaned: int = 0      # live container with no matching record — destroyed/logged

    def log(self, service: str) -> None:
        LOG.info(
            "%s reconcile: resumed=%d, recreated=%d, failed=%d, orphaned=%d",
            service, self.resumed, self.recreated, self.failed, self.orphaned,
        )


def reconcile(
    service_name: str,
    id_label: str,
    record_ids: list[str],
    on_record_with_container: Callable[[str, ContainerSnapshot], str],
    on_record_without_container: Callable[[str], str],
    on_orphan_container: Callable[[str, ContainerSnapshot], None] | None = None,
) -> ReconcileCounts:
    """Drive the three-way reconcile between persisted records and live Docker state.

    ``record_ids`` — resource IDs present in the persisted control-plane
    state (moto, native store, etc.). These should survive the restart.

    ``on_record_with_container(resource_id, snapshot)`` is called once per
    record whose container is still on the host. Must return one of:
    ``"resumed"`` (docker-start succeeded or already running) or
    ``"failed"`` (container unrecoverable — caller already logged).

    ``on_record_without_container(resource_id)`` is called per record whose
    container is missing (user ran ``docker rm``, image pruned, etc.). Must
    return ``"recreated"`` or ``"failed"``.

    ``on_orphan_container`` (optional) is called per live container whose
    resource ID is NOT in ``record_ids`` — user-deleted records or a
    foreign instance leaked one in. Default action is to log a warning; the
    caller can pass a function that ``docker rm``'s them instead.

    Returns a ``ReconcileCounts`` summary. Exceptions from callbacks are
    caught, logged, and counted as ``failed`` so one bad record doesn't
    abort the whole reconcile.
    """
    counts = ReconcileCounts()
    live = discover_service_containers(service_name, id_label, include_stopped=True)

    for resource_id in record_ids:
        snap = live.pop(resource_id, None)
        try:
            if snap is not None:
                outcome = on_record_with_container(resource_id, snap)
            else:
                outcome = on_record_without_container(resource_id)
        except Exception:
            LOG.warning(
                "Reconcile %s.%s failed — marking failed", service_name, resource_id,
                exc_info=True,
            )
            counts.failed += 1
            continue
        if outcome == "resumed":
            counts.resumed += 1
        elif outcome == "recreated":
            counts.recreated += 1
        else:
            counts.failed += 1

    # Anything left in ``live`` is a container with no matching record.
    for orphan_id, snap in live.items():
        if on_orphan_container is None:
            LOG.warning(
                "Orphan %s container %s (resource_id=%s) — left alone",
                service_name, snap.name, orphan_id,
            )
        else:
            try:
                on_orphan_container(orphan_id, snap)
            except Exception:
                LOG.warning(
                    "Orphan handler for %s %s raised — leaving container alone",
                    service_name, snap.name, exc_info=True,
                )
        counts.orphaned += 1

    return counts
