"""Apply VPC route-table changes to running instance containers.

Real AWS implements route tables at the VPC SDN layer: every instance
in a subnet sees its packets transparently steered to the configured
gateways, NAT gateways, instance targets, peering connections, etc.
LocalEmu emulates this by installing concrete ``ip route`` entries
inside each EC2 container, so a route whose target is another instance
("instance-target route" - the building block for the Quiet Router /
MITM scenarios) actually redirects traffic the way the route table
says it should.

Scope: * **Instance-target routes**. Routes whose ``Target`` is another EC2
  instance. Other target types (IGW, NAT-GW, TGW, peering, VPC
  endpoint, virtual-private-gateway, carrier-gateway, egress-only IGW)
  already have their own LocalEmu data planes; this module deliberately
  does NOT touch them. They go through their existing code paths
  unchanged.

* **Route-table associations**. Each subnet binds to one route table
  via either an explicit association or the VPC's "main" association
  fallback. When the binding changes (``AssociateRouteTable`` /
  ``DisassociateRouteTable`` / ``ReplaceRouteTableAssociation``), the
  instance-target routes from the previous table are removed and the
  new table's routes are installed.

* **Container-restart persistence**. Every applied route is written to
  ``/var/lib/localemu/instance-routes.txt`` inside the container. The
  entrypoint script replays the file on every boot so a
  ``docker restart`` doesn't silently drop the route.

* **Newly-launched instances**. When ``ec2:RunInstances`` lands a
  fresh container in a subnet that already has instance-target routes
  on its route table, those routes are installed on the new container
  too - without this, a route configured before the launch would only
  ever apply to instances that happened to exist at the moment the
  route was created.

Concurrency: each container operation is best-effort, idempotent
(``ip route replace`` and ``-D`` are both safe to repeat), and never
raises - a missing tool inside the container must not fail the AWS
API call that triggered the apply.
"""
from __future__ import annotations

import logging
import shlex

LOG = logging.getLogger(__name__)


_MARKER_PATH = "/var/lib/localemu/instance-routes.txt"


# ---------------------------------------------------------------------------
# Lookup helpers - moto-side state inspection
# ---------------------------------------------------------------------------


def _ec2_backend(account_id: str, region: str):
    try:
        import moto.backends as moto_backends

        return moto_backends.get_backend("ec2")[account_id][region]
    except Exception:
        LOG.debug(
            "instance_routes: no ec2 backend for account=%s region=%s",
            account_id, region,
        )
        return None


def get_subnets_for_route_table(
    route_table_id: str, account_id: str, region: str,
) -> list[str]:
    """All subnets bound to ``route_table_id``.

    Explicit associations come first; subnets without an explicit
    association fall back to the VPC's main route table - the same
    rule real AWS applies. Returns an empty list when the route table
    is unknown.
    """
    backend = _ec2_backend(account_id, region)
    if backend is None:
        return []
    rt = _get_route_table(backend, route_table_id)
    if rt is None:
        return []
    out: list[str] = []
    # Explicit subnet associations are stored as {association_id: subnet_id}.
    for sub_id in (rt.associations or {}).values():
        if sub_id and sub_id not in out:
            out.append(sub_id)
    # When this route table is the VPC's main one, every subnet WITHOUT
    # an explicit association on a different table inherits it.
    if rt.main_association_id is not None:
        out.extend(_subnets_inheriting_main_route_table(backend, rt))
    return out


def get_instance_target_routes(
    route_table_id: str, account_id: str, region: str,
) -> list[tuple[str, str]]:
    """Returns ``[(destination_cidr, target_instance_id), ...]``."""
    backend = _ec2_backend(account_id, region)
    if backend is None:
        return []
    rt = _get_route_table(backend, route_table_id)
    if rt is None:
        return []
    out: list[tuple[str, str]] = []
    for route in (rt.routes or {}).values():
        dest = getattr(route, "destination_cidr_block", None)
        instance = getattr(route, "instance", None)
        if dest and instance is not None and getattr(instance, "id", None):
            out.append((dest, instance.id))
    return out


def get_containers_in_subnet(
    subnet_id: str, account_id: str, region: str,
) -> list[tuple[str, str]]:
    """Return ``[(instance_id, container_name), ...]`` for running instances."""
    backend = _ec2_backend(account_id, region)
    if backend is None:
        return []
    out: list[tuple[str, str]] = []
    instances = _all_instances(backend)
    for inst in instances:
        if getattr(inst, "subnet_id", None) != subnet_id:
            continue
        state = getattr(inst, "_state", None) or getattr(inst, "state", None)
        state_name = getattr(state, "name", None) if state is not None else None
        if state_name and state_name not in ("running", "pending"):
            continue
        iid = getattr(inst, "id", None)
        if not iid:
            continue
        out.append((iid, container_name_for_instance(iid)))
    return out


def resolve_instance_private_ip(
    instance_id: str, account_id: str, region: str,
) -> str | None:
    backend = _ec2_backend(account_id, region)
    if backend is None:
        return None
    inst = _get_instance(backend, instance_id)
    if inst is None:
        return None
    return getattr(inst, "private_ip_address", None)


def container_name_for_instance(instance_id: str) -> str:
    return f"localemu-ec2-{instance_id}"


# ---------------------------------------------------------------------------
# Container apply / remove
# ---------------------------------------------------------------------------


def apply_route_to_container(
    container_name: str, destination_cidr: str, gateway_ip: str,
) -> bool:
    """Install / replace an ``ip route`` entry + persist via the marker.

    Returns ``False`` when the container isn't running (the marker
    write still happens via the offline log path so the next boot
    picks it up).
    """
    if not _container_running(container_name):
        LOG.debug(
            "instance_routes: container %s not running; route %s via %s "
            "will be picked up by the entrypoint at next start",
            container_name, destination_cidr, gateway_ip,
        )
        return False
    _exec(
        container_name,
        ["sh", "-c",
         # ``ip route replace`` is idempotent: adds if missing, replaces
         # if present. We swallow stderr because some minimal images
         # don't have iproute2 installed and we'd rather not noise the
         # localemu logs with every missing-tool warning.
         f"command -v ip >/dev/null 2>&1 && "
         f"ip route replace {shlex.quote(destination_cidr)} via {shlex.quote(gateway_ip)} 2>/dev/null "
         f"|| true"],
    )
    _persist_marker_add(container_name, destination_cidr, gateway_ip)
    return True


def remove_route_from_container(
    container_name: str, destination_cidr: str,
) -> bool:
    if not _container_running(container_name):
        return False
    _exec(
        container_name,
        ["sh", "-c",
         f"command -v ip >/dev/null 2>&1 && "
         f"ip route del {shlex.quote(destination_cidr)} 2>/dev/null "
         f"|| true"],
    )
    _persist_marker_remove(container_name, destination_cidr)
    return True


def reset_routes_on_container(container_name: str) -> bool:
    """Drop every LocalEmu-managed route + clear the marker.

    Used when a subnet's route-table binding changes - we wipe the
    previous binding's routes before applying the new ones.
    """
    if not _container_running(container_name):
        return False
    # Read the marker, delete each route, then clear the marker.
    _exec(
        container_name,
        ["sh", "-c",
         f"if [ -f {_MARKER_PATH} ] && command -v ip >/dev/null 2>&1; then "
         f"  while read -r dest gw; do "
         f"    [ -n \"$dest\" ] && ip route del \"$dest\" 2>/dev/null || true; "
         f"  done < {_MARKER_PATH}; "
         f"fi; "
         f"mkdir -p $(dirname {_MARKER_PATH}) 2>/dev/null || true; "
         f": > {_MARKER_PATH}"],
    )
    return True


# ---------------------------------------------------------------------------
# Orchestration: when a route changes, fan out to every affected container
# ---------------------------------------------------------------------------


def apply_route_table_to_subnet_containers(
    route_table_id: str, subnet_id: str, account_id: str, region: str,
) -> int:
    """Install every instance-target route from this RT on every running
    container in this subnet. Containers running the router instance
    itself are skipped (an instance doesn't route packets through
    itself).

    Returns the number of (container, route) pairs applied.
    """
    routes = get_instance_target_routes(route_table_id, account_id, region)
    if not routes:
        return 0
    containers = get_containers_in_subnet(subnet_id, account_id, region)
    if not containers:
        return 0
    applied = 0
    for dest_cidr, target_iid in routes:
        target_ip = resolve_instance_private_ip(target_iid, account_id, region)
        if not target_ip:
            LOG.debug(
                "instance_routes: route %s -> %s has no resolvable private IP; skipping",
                dest_cidr, target_iid,
            )
            continue
        for inst_iid, cname in containers:
            if inst_iid == target_iid:
                # Don't loop a router's packets through itself.
                continue
            if apply_route_to_container(cname, dest_cidr, target_ip):
                applied += 1
    return applied


def on_route_table_change(
    *, route_table_id: str, account_id: str, region: str,
) -> int:
    """Replay the route table's instance-target routes across every
    affected subnet's containers. Called from the AWS-API hook layer
    after ``moto`` accepts a ``CreateRoute`` / ``ReplaceRoute`` /
    ``AssociateRouteTable`` change.
    """
    subnets = get_subnets_for_route_table(route_table_id, account_id, region)
    applied = 0
    for sub_id in subnets:
        applied += apply_route_table_to_subnet_containers(
            route_table_id=route_table_id,
            subnet_id=sub_id,
            account_id=account_id,
            region=region,
        )
    return applied


def on_route_delete(
    *, route_table_id: str, destination_cidr: str,
    account_id: str, region: str,
) -> int:
    """Remove ``destination_cidr`` from every container in every subnet
    bound to ``route_table_id``."""
    subnets = get_subnets_for_route_table(route_table_id, account_id, region)
    removed = 0
    for sub_id in subnets:
        for _iid, cname in get_containers_in_subnet(sub_id, account_id, region):
            if remove_route_from_container(cname, destination_cidr):
                removed += 1
    return removed


def on_instance_launch(
    *, instance_id: str, subnet_id: str, account_id: str, region: str,
) -> int:
    """Apply the subnet's currently-bound route table's instance-target
    routes to the freshly-launched ``instance_id``.

    Called from ``vm_manager.create_instance`` after the container has
    started, so the new instance picks up routes a prior
    ``CreateRoute`` already installed on its siblings.
    """
    rt_id = _resolve_route_table_for_subnet(subnet_id, account_id, region)
    if rt_id is None:
        return 0
    routes = get_instance_target_routes(rt_id, account_id, region)
    if not routes:
        return 0
    cname = container_name_for_instance(instance_id)
    applied = 0
    for dest_cidr, target_iid in routes:
        if target_iid == instance_id:
            continue
        target_ip = resolve_instance_private_ip(target_iid, account_id, region)
        if not target_ip:
            continue
        if apply_route_to_container(cname, dest_cidr, target_ip):
            applied += 1
    return applied


def on_subnet_rebound_to_route_table(
    *, subnet_id: str, account_id: str, region: str,
) -> int:
    """Wipe the previous routes off every container in the subnet, then
    apply the current binding's routes. Used for both
    ``AssociateRouteTable`` (subnet bound to a different RT than the
    main one) and ``DisassociateRouteTable`` (subnet falls back to the
    main RT).
    """
    for _iid, cname in get_containers_in_subnet(subnet_id, account_id, region):
        reset_routes_on_container(cname)
    rt_id = _resolve_route_table_for_subnet(subnet_id, account_id, region)
    if rt_id is None:
        return 0
    return apply_route_table_to_subnet_containers(
        route_table_id=rt_id,
        subnet_id=subnet_id,
        account_id=account_id,
        region=region,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _resolve_route_table_for_subnet(
    subnet_id: str, account_id: str, region: str,
) -> str | None:
    """Return the route table id that applies to ``subnet_id`` today."""
    backend = _ec2_backend(account_id, region)
    if backend is None:
        return None
    subnet = _get_subnet(backend, subnet_id)
    if subnet is None:
        return None
    vpc_id = getattr(subnet, "vpc_id", None) or _vpc_id_of(subnet)
    # Explicit association on any route table wins.
    rts = getattr(backend, "route_tables", {}) or {}
    main: str | None = None
    for rt_id, rt in rts.items():
        if subnet_id in (rt.associations or {}).values():
            return rt_id
        if getattr(rt, "vpc_id", None) == vpc_id and rt.main_association_id is not None:
            main = rt_id
    return main


def _subnets_inheriting_main_route_table(backend, main_rt) -> list[str]:
    """Subnets in the same VPC that have no explicit association anywhere - they inherit the main route table."""
    vpc_id = getattr(main_rt, "vpc_id", None)
    if not vpc_id:
        return []
    explicit_subnets: set[str] = set()
    for rt in (getattr(backend, "route_tables", {}) or {}).values():
        for sub in (rt.associations or {}).values():
            if sub:
                explicit_subnets.add(sub)
    out: list[str] = []
    subnets = getattr(backend, "subnets", {})
    iterable_subnets = _flat_subnets(subnets)
    for sub in iterable_subnets:
        sub_id = getattr(sub, "id", None)
        sub_vpc_id = getattr(sub, "vpc_id", None) or _vpc_id_of(sub)
        if sub_id and sub_vpc_id == vpc_id and sub_id not in explicit_subnets:
            out.append(sub_id)
    return out


def _get_route_table(backend, route_table_id: str):
    rts = getattr(backend, "route_tables", None)
    if isinstance(rts, dict):
        return rts.get(route_table_id)
    return None


def _get_subnet(backend, subnet_id: str):
    subnets = getattr(backend, "subnets", None)
    if isinstance(subnets, dict):
        direct = subnets.get(subnet_id)
        if direct is not None:
            return direct
        for entry in subnets.values():
            if isinstance(entry, dict):
                cand = entry.get(subnet_id)
                if cand is not None:
                    return cand
    return None


def _flat_subnets(subnets) -> list:
    out = []
    if isinstance(subnets, dict):
        for entry in subnets.values():
            if isinstance(entry, dict):
                out.extend(entry.values())
            else:
                out.append(entry)
    return out


def _get_instance(backend, instance_id: str):
    # ``moto`` reservations -> instances
    res = getattr(backend, "reservations", None) or {}
    for reservation in (res.values() if isinstance(res, dict) else res):
        for inst in getattr(reservation, "instances", []) or []:
            if getattr(inst, "id", None) == instance_id:
                return inst
    # Fallback: direct dict
    if hasattr(backend, "get_instance"):
        try:
            return backend.get_instance(instance_id)
        except Exception:
            return None
    return None


def _all_instances(backend) -> list:
    out: list = []
    res = getattr(backend, "reservations", None) or {}
    for reservation in (res.values() if isinstance(res, dict) else res):
        for inst in getattr(reservation, "instances", []) or []:
            out.append(inst)
    return out


def _vpc_id_of(obj) -> str | None:
    vpc = getattr(obj, "vpc", None)
    if vpc is not None:
        return getattr(vpc, "id", None) or getattr(vpc, "vpc_id", None)
    return None


def _container_running(container_name: str) -> bool:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT
        return bool(DOCKER_CLIENT.is_container_running(container_name))
    except Exception:
        return False


def _exec(container_name: str, argv: list[str]) -> None:
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT
        DOCKER_CLIENT.exec_in_container(container_name, argv)
    except Exception as exc:
        LOG.debug(
            "instance_routes: exec_in_container(%s, %s) failed: %s",
            container_name, argv, exc,
        )


def _persist_marker_add(container_name: str, dest: str, gw: str) -> None:
    line = f"{dest} {gw}"
    line_q = shlex.quote(line)
    marker_q = shlex.quote(_MARKER_PATH)
    _exec(
        container_name,
        ["sh", "-c",
         f"mkdir -p $(dirname {marker_q}) 2>/dev/null || true; "
         f"touch {marker_q}; "
         # Replace any existing line for the same destination, then append.
         f"dest_re=$(echo {shlex.quote(dest)} | sed 's/[][\\.*^$/]/\\\\&/g'); "
         f"grep -v -E \"^$dest_re \" {marker_q} > {marker_q}.tmp 2>/dev/null || true; "
         f"mv {marker_q}.tmp {marker_q} 2>/dev/null || true; "
         f"echo {line_q} >> {marker_q}"],
    )


def _persist_marker_remove(container_name: str, dest: str) -> None:
    marker_q = shlex.quote(_MARKER_PATH)
    _exec(
        container_name,
        ["sh", "-c",
         f"if [ -f {marker_q} ]; then "
         f"  dest_re=$(echo {shlex.quote(dest)} | sed 's/[][\\.*^$/]/\\\\&/g'); "
         f"  grep -v -E \"^$dest_re \" {marker_q} > {marker_q}.tmp 2>/dev/null || true; "
         f"  mv {marker_q}.tmp {marker_q} 2>/dev/null || true; "
         f"fi"],
    )
