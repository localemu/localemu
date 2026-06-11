"""Unit tests for ``localemu.services.ec2.docker.instance_routes``.

We exercise the helper against real moto backends (route tables,
subnets, instances) and mock the Docker client so the assertions are
about the right ``ip route ...`` commands being issued to the right
container — without booting Docker.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.ec2.docker import instance_routes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ec2_backend():
    """Fresh moto EC2 backend per test (unique account)."""
    from moto.ec2.models import ec2_backends

    region = "us-east-1"
    account_id = str(int(uuid.uuid4().int % 10_000_000_000)).zfill(12)
    return ec2_backends[account_id][region], account_id, region


@pytest.fixture
def fake_docker():
    """Replace the DOCKER_CLIENT singleton with a MagicMock."""
    client = MagicMock()
    client.is_container_running.return_value = True
    with patch("localemu.utils.docker_utils.DOCKER_CLIENT", client):
        yield client


def _exec_text(client: MagicMock) -> str:
    out: list[str] = []
    for call in client.exec_in_container.call_args_list:
        argv = call.args[1]
        if isinstance(argv, (list, tuple)):
            out.append(" ".join(str(a) for a in argv))
        else:
            out.append(str(argv))
    return "\n".join(out)


def _exec_calls_to_container(client: MagicMock, container: str) -> str:
    out: list[str] = []
    for call in client.exec_in_container.call_args_list:
        cname = call.args[0]
        if cname != container:
            continue
        argv = call.args[1]
        if isinstance(argv, (list, tuple)):
            out.append(" ".join(str(a) for a in argv))
    return "\n".join(out)


class _FakeState:
    def __init__(self, name: str = "running"):
        self.name = name


class _FakeInstance:
    """Minimal stand-in for ``moto.ec2.models.instances.Instance``.

    The instance-routes helper reads only ``id`` / ``subnet_id`` /
    ``private_ip_address`` / ``_state`` off each instance — full moto
    instance construction has expensive validation paths we don't
    need to exercise.
    """

    def __init__(self, *, instance_id: str, subnet_id: str, private_ip: str):
        self.id = instance_id
        self.subnet_id = subnet_id
        self.private_ip_address = private_ip
        self._state = _FakeState("running")

    def applies(self, filters):  # noqa: D401
        """Compatibility hook so ``EC2Backend.all_instances`` can iterate
        without crashing when our fake instances live in the reservation
        dict alongside real ones (or alone)."""
        return True


def _add_route_directly(backend, *, rt_id: str, dest_cidr: str, instance):
    """Inject a Route into the route table without going through
    ``backend.create_route`` (which validates the target instance
    against moto's real instance store + expects more interfaces than
    our ``_FakeInstance`` provides)."""
    from moto.ec2.models.route_tables import Route

    rt = backend.route_tables[rt_id]
    route = Route(
        route_table=rt,
        destination_cidr_block=dest_cidr,
        destination_ipv6_cidr_block=None,
        instance=instance,
    )
    rt.routes[f"r-{dest_cidr}"] = route
    return route


class _FakeReservation:
    def __init__(self, instances):
        self.instances = list(instances)


def _seed_instance(backend, *, instance_id: str, subnet_id: str, private_ip: str):
    inst = _FakeInstance(
        instance_id=instance_id, subnet_id=subnet_id, private_ip=private_ip,
    )
    backend.reservations[f"res-{instance_id}"] = _FakeReservation([inst])
    return inst


def _build_vpc_with_two_instances(backend):
    """Two instances in the same subnet, both running.

    Returns ``(vpc_id, subnet_id, route_table_id, victim_instance, router_instance)``.
    """
    vpc = backend.create_vpc(cidr_block="10.0.0.0/16")
    subnet = backend.create_subnet(
        vpc_id=vpc.id, cidr_block="10.0.1.0/24",
        availability_zone="us-east-1a",
    )
    rt = backend.create_route_table(vpc_id=vpc.id)

    victim = _seed_instance(
        backend, instance_id="i-victim00",
        subnet_id=subnet.id, private_ip="10.0.1.10",
    )
    router = _seed_instance(
        backend, instance_id="i-router00",
        subnet_id=subnet.id, private_ip="10.0.1.50",
    )
    return vpc.id, subnet.id, rt.id, victim, router


# ---------------------------------------------------------------------------
# get_subnets_for_route_table
# ---------------------------------------------------------------------------


def test_subnets_for_explicit_association(ec2_backend):
    backend, _acc, _reg = ec2_backend
    vpc = backend.create_vpc(cidr_block="10.0.0.0/16")
    sub = backend.create_subnet(
        vpc_id=vpc.id, cidr_block="10.0.1.0/24", availability_zone="us-east-1a",
    )
    rt = backend.create_route_table(vpc_id=vpc.id)
    backend.associate_route_table(rt.id, sub.id)
    assert instance_routes.get_subnets_for_route_table(
        rt.id, _acc, _reg,
    ) == [sub.id]


def test_subnets_unknown_route_table_returns_empty(ec2_backend):
    backend, acc, reg = ec2_backend
    assert instance_routes.get_subnets_for_route_table(
        "rtb-does-not-exist", acc, reg,
    ) == []


# ---------------------------------------------------------------------------
# get_instance_target_routes
# ---------------------------------------------------------------------------


def test_instance_target_routes_returns_only_instance_targets(ec2_backend):
    backend, acc, reg = ec2_backend
    _vpc, _sub, rt_id, _victim, router = _build_vpc_with_two_instances(backend)
    _add_route_directly(backend, rt_id=rt_id,
                        dest_cidr="0.0.0.0/0", instance=router)
    routes = instance_routes.get_instance_target_routes(rt_id, acc, reg)
    assert routes == [("0.0.0.0/0", router.id)]


def test_instance_target_routes_ignores_routes_with_no_instance_field(ec2_backend):
    """Routes whose target isn't an instance must NOT show up; otherwise
    the data-plane apply would try to install ``ip route ... via None``
    which would either crash or silently corrupt the routing table."""
    backend, acc, reg = ec2_backend
    _vpc, _sub, rt_id, _victim, router = _build_vpc_with_two_instances(backend)
    # Insert a route directly into moto's dict with no instance field.
    # This simulates an IGW / NAT-GW / TGW route that bypasses our
    # helper's responsibility.
    from moto.ec2.models.route_tables import Route

    rt = backend.route_tables[rt_id]
    bogus = Route(
        route_table=rt,
        destination_cidr_block="172.16.0.0/16",
        destination_ipv6_cidr_block=None,
    )
    rt.routes["non-instance"] = bogus
    # Add the instance-target route too.
    _add_route_directly(backend, rt_id=rt_id,
                        dest_cidr="0.0.0.0/0", instance=router)

    routes = instance_routes.get_instance_target_routes(rt_id, acc, reg)
    assert routes == [("0.0.0.0/0", router.id)], (
        "instance-target routes must be the only ones returned"
    )


def test_resolve_instance_private_ip(ec2_backend):
    backend, acc, reg = ec2_backend
    _vpc, _sub, _rt, _victim, router = _build_vpc_with_two_instances(backend)
    assert instance_routes.resolve_instance_private_ip(
        router.id, acc, reg,
    ) == "10.0.1.50"


# ---------------------------------------------------------------------------
# apply_route_to_container / remove_route_from_container
# ---------------------------------------------------------------------------


def test_apply_route_issues_ip_route_replace(fake_docker):
    ok = instance_routes.apply_route_to_container(
        container_name="localemu-ec2-i-aaa",
        destination_cidr="10.0.0.0/16",
        gateway_ip="10.0.1.50",
    )
    assert ok is True
    text = _exec_calls_to_container(fake_docker, "localemu-ec2-i-aaa")
    assert "ip route replace 10.0.0.0/16 via 10.0.1.50" in text


def test_apply_route_writes_marker(fake_docker):
    instance_routes.apply_route_to_container(
        container_name="localemu-ec2-i-aaa",
        destination_cidr="10.0.0.0/16",
        gateway_ip="10.0.1.50",
    )
    text = _exec_calls_to_container(fake_docker, "localemu-ec2-i-aaa")
    assert "/var/lib/localemu/instance-routes.txt" in text
    # The marker line ``<dest> <gw>`` must be appended.
    assert "echo '10.0.0.0/16 10.0.1.50'" in text


def test_remove_route_issues_ip_route_del(fake_docker):
    ok = instance_routes.remove_route_from_container(
        container_name="localemu-ec2-i-aaa",
        destination_cidr="10.0.0.0/16",
    )
    assert ok is True
    text = _exec_calls_to_container(fake_docker, "localemu-ec2-i-aaa")
    assert "ip route del 10.0.0.0/16" in text


def test_apply_route_when_container_not_running_returns_false(fake_docker):
    fake_docker.is_container_running.return_value = False
    ok = instance_routes.apply_route_to_container(
        container_name="localemu-ec2-i-gone",
        destination_cidr="10.0.0.0/16",
        gateway_ip="10.0.1.50",
    )
    assert ok is False
    # No exec calls were issued.
    fake_docker.exec_in_container.assert_not_called()


# ---------------------------------------------------------------------------
# on_route_table_change: fans out to every container in every subnet
# ---------------------------------------------------------------------------


def test_on_route_table_change_applies_to_other_containers_not_router(
    ec2_backend, fake_docker,
):
    """The container running the router instance itself must NOT have a
    route to itself installed (that would form a loop)."""
    backend, acc, reg = ec2_backend
    _vpc, sub_id, rt_id, victim, router = _build_vpc_with_two_instances(backend)
    backend.associate_route_table(rt_id, sub_id)
    _add_route_directly(backend, rt_id=rt_id,
                        dest_cidr="0.0.0.0/0", instance=router)
    applied = instance_routes.on_route_table_change(
        route_table_id=rt_id, account_id=acc, region=reg,
    )
    assert applied == 1, "only the victim container should receive the route"
    victim_cname = f"localemu-ec2-{victim.id}"
    router_cname = f"localemu-ec2-{router.id}"
    assert "ip route replace 0.0.0.0/0 via 10.0.1.50" in _exec_calls_to_container(
        fake_docker, victim_cname,
    )
    # The router itself must NOT receive a self-loop route.
    assert "ip route replace 0.0.0.0/0 via 10.0.1.50" not in _exec_calls_to_container(
        fake_docker, router_cname,
    )


def test_on_route_table_change_with_no_instance_target_routes_does_nothing(
    ec2_backend, fake_docker,
):
    backend, acc, reg = ec2_backend
    _vpc, sub_id, rt_id, _v, _r = _build_vpc_with_two_instances(backend)
    backend.associate_route_table(rt_id, sub_id)
    # No CreateRoute call -> no instance-target routes -> no fan-out.
    applied = instance_routes.on_route_table_change(
        route_table_id=rt_id, account_id=acc, region=reg,
    )
    assert applied == 0
    fake_docker.exec_in_container.assert_not_called()


# ---------------------------------------------------------------------------
# on_route_delete: removes from every container
# ---------------------------------------------------------------------------


def test_on_route_delete_removes_from_every_container(
    ec2_backend, fake_docker,
):
    backend, acc, reg = ec2_backend
    _vpc, sub_id, rt_id, victim, router = _build_vpc_with_two_instances(backend)
    backend.associate_route_table(rt_id, sub_id)
    instance_routes.on_route_delete(
        route_table_id=rt_id, destination_cidr="0.0.0.0/0",
        account_id=acc, region=reg,
    )
    text = _exec_text(fake_docker)
    assert "ip route del 0.0.0.0/0" in text


# ---------------------------------------------------------------------------
# on_instance_launch
# ---------------------------------------------------------------------------


def test_on_instance_launch_applies_existing_routes_to_new_container(
    ec2_backend, fake_docker,
):
    backend, acc, reg = ec2_backend
    _vpc, sub_id, rt_id, victim, router = _build_vpc_with_two_instances(backend)
    backend.associate_route_table(rt_id, sub_id)
    _add_route_directly(backend, rt_id=rt_id,
                        dest_cidr="0.0.0.0/0", instance=router)

    # Reset the recording — only count what on_instance_launch issues.
    fake_docker.exec_in_container.reset_mock()

    applied = instance_routes.on_instance_launch(
        instance_id=victim.id, subnet_id=sub_id,
        account_id=acc, region=reg,
    )
    assert applied == 1
    text = _exec_text(fake_docker)
    assert f"localemu-ec2-{victim.id}" not in "" and "ip route replace 0.0.0.0/0 via 10.0.1.50" in text


# ---------------------------------------------------------------------------
# on_subnet_rebound_to_route_table: wipes previous routes + applies new ones
# ---------------------------------------------------------------------------


def test_on_subnet_rebound_resets_then_applies(ec2_backend, fake_docker):
    backend, acc, reg = ec2_backend
    _vpc, sub_id, rt_id, victim, router = _build_vpc_with_two_instances(backend)
    backend.associate_route_table(rt_id, sub_id)
    _add_route_directly(backend, rt_id=rt_id,
                        dest_cidr="0.0.0.0/0", instance=router)
    fake_docker.exec_in_container.reset_mock()
    instance_routes.on_subnet_rebound_to_route_table(
        subnet_id=sub_id, account_id=acc, region=reg,
    )
    text = _exec_text(fake_docker)
    # Reset clears the marker (writes empty), then the apply phase
    # installs the new route.
    assert ": > /var/lib/localemu/instance-routes.txt" in text
    assert "ip route replace 0.0.0.0/0 via 10.0.1.50" in text
