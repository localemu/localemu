"""Dependency-aware ordering of resources for import replay.

Snapshots embed :class:`Ref` objects wherever one resource points at
another (e.g. a Lambda's ``role`` field carrying a reference to an IAM
role). Replaying a snapshot naively — in collection order — will fail
whenever a dependent resource is created before its dependency. This
module builds a DAG from those refs and orders the resources with Kahn's
algorithm so that every resource appears after all of its dependencies.

Cycles are a hard error here (contrast with the reference *resolver*,
which merely warns): attempting to replay a cyclic dependency would
deadlock or fail arbitrarily. We surface the participating resources via
:class:`CycleError` so the caller can report them precisely.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from localemu.export.ir import Ref, Resource, Snapshot


class CycleError(Exception):
    """Raised when the resource dependency graph contains a cycle.

    ``resources`` holds the resources that participate in the cycle (i.e.
    those still having unresolved predecessors after Kahn's algorithm
    completes). The message lists them in a stable, human-readable form.
    """

    def __init__(self, resources: list[Resource]) -> None:
        self.resources = resources
        names = ", ".join(f"{r.service}:{r.resource_type}:{r.resource_id}" for r in resources)
        super().__init__(f"dependency cycle detected among resources: {names}")


def _resource_key(resource: Resource) -> tuple[str, str, str]:
    """Stable identity tuple for DAG nodes."""
    return (resource.service, resource.resource_type, resource.resource_id)


def _ref_key(ref: Ref) -> tuple[str, str, str]:
    return (ref.service, ref.resource_type, ref.resource_id)


def _collect_refs(value: Any, out: list[Ref]) -> None:
    """Recursively harvest every :class:`Ref` embedded in ``value``."""
    if isinstance(value, Ref):
        out.append(value)
        return
    if isinstance(value, dict):
        for v in value.values():
            _collect_refs(v, out)
        return
    if isinstance(value, list) or isinstance(value, tuple):
        for v in value:
            _collect_refs(v, out)


def _build_graph(
    snapshot: Snapshot,
) -> tuple[dict[tuple[str, str, str], Resource], dict[tuple[str, str, str], set[tuple[str, str, str]]]]:
    """Return ``(nodes, edges)`` where edges map node -> set of its prerequisites."""
    nodes: dict[tuple[str, str, str], Resource] = {}
    for r in snapshot.resources:
        nodes[_resource_key(r)] = r

    edges: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
    for r in snapshot.resources:
        src = _resource_key(r)
        refs: list[Ref] = []
        _collect_refs(r.attributes, refs)
        for ref in refs:
            dst = _ref_key(ref)
            if dst == src:
                continue
            if dst not in nodes:
                # Dangling ref — dependency is external or missing; ignore
                # for topo purposes. Handler will resolve (or fail) later.
                continue
            edges[src].add(dst)
    return nodes, edges


def topo_sort(snapshot: Snapshot) -> list[Resource]:
    """Return ``snapshot.resources`` ordered so that dependencies precede dependents.

    Implementation: Kahn's algorithm. Ties are broken by the
    ``(service, resource_type, resource_id)`` tuple for determinism — two
    runs over the same snapshot yield the same order, which is useful for
    test assertions and log diffing.

    Raises:
        CycleError: If the dependency graph has a cycle.
    """
    nodes, edges = _build_graph(snapshot)

    # Kahn's algorithm expects an in-degree per node. Our ``edges`` map
    # already captures "node -> prerequisites", so in-degree is just the
    # size of each node's edge set.
    in_degree: dict[tuple[str, str, str], int] = {key: len(edges.get(key, set())) for key in nodes}

    # Reverse adjacency: for each prerequisite, which nodes depend on it?
    dependents: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
    for node, prereqs in edges.items():
        for p in prereqs:
            dependents[p].add(node)

    ready: deque[tuple[str, str, str]] = deque(
        sorted(key for key, deg in in_degree.items() if deg == 0)
    )
    ordered: list[Resource] = []

    while ready:
        key = ready.popleft()
        ordered.append(nodes[key])
        # Emit dependents in deterministic order.
        for dep in sorted(dependents.get(key, set())):
            in_degree[dep] -= 1
            if in_degree[dep] == 0:
                ready.append(dep)

    if len(ordered) != len(nodes):
        remaining = [nodes[k] for k, deg in in_degree.items() if deg > 0]
        raise CycleError(remaining)

    return ordered


def group_by_level(snapshot: Snapshot) -> list[list[Resource]]:
    """Partition the topologically sorted resources into parallel waves.

    Each wave contains resources whose prerequisites are all satisfied by
    earlier waves; hence the resources within a wave have no intra-wave
    dependencies and can be created concurrently. This is the unit of
    parallelism :class:`~localemu.export.importer.replay.ImportRunner`
    consumes.

    Raises:
        CycleError: If the dependency graph has a cycle.
    """
    nodes, edges = _build_graph(snapshot)

    in_degree: dict[tuple[str, str, str], int] = {key: len(edges.get(key, set())) for key in nodes}
    dependents: dict[tuple[str, str, str], set[tuple[str, str, str]]] = defaultdict(set)
    for node, prereqs in edges.items():
        for p in prereqs:
            dependents[p].add(node)

    waves: list[list[Resource]] = []
    current = sorted(key for key, deg in in_degree.items() if deg == 0)
    placed = 0

    while current:
        wave_resources = [nodes[k] for k in current]
        waves.append(wave_resources)
        placed += len(current)

        next_level: list[tuple[str, str, str]] = []
        for key in current:
            for dep in dependents.get(key, set()):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    next_level.append(dep)
        current = sorted(next_level)

    if placed != len(nodes):
        remaining = [nodes[k] for k, deg in in_degree.items() if deg > 0]
        raise CycleError(remaining)

    return waves
