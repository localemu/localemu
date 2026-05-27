"""`localemu vpc-ip` debug command for the addressing redesign.

Surfaces the three views of a container's IP — SubnetAllocator,
AddressIndex, and the live Docker bridge — side by side. Critical
diagnostic during the LOCALEMU_VPC_IP_PINNING migration window when
the three views can drift.

Usage:
    localemu vpc-ip [INSTANCE_ID_OR_CONTAINER]
        Show the addressing view for a single instance/container.

    localemu vpc-ip --all
        Show every container in every LocalEmu VPC bridge.

    localemu vpc-ip --output json
        Emit JSON instead of the table.
"""
from __future__ import annotations

import json as _json

import click


@click.command(name="vpc-ip")
@click.argument("target", required=False)
@click.option("--all", "show_all", is_flag=True, help="Show every container")
@click.option(
    "--output", "fmt", type=click.Choice(["table", "json"]),
    default="table", help="Output format",
)
def vpc_ip(target: str | None, show_all: bool, fmt: str) -> None:
    """Show the addressing-redesign view of a container or instance."""
    try:
        rows = _gather_rows(target, show_all)
    except Exception as exc:
        raise click.ClickException(f"vpc-ip failed: {exc}") from exc

    if fmt == "json":
        click.echo(_json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        click.echo("No matching containers / ENIs.")
        return

    # Simple aligned table
    headers = [
        "INSTANCE", "ENI", "VPC", "SUBNET",
        "ALLOC_IP", "INDEX_IP", "DOCKER_IP", "DRIFT",
    ]
    widths = [max(len(h), max((len(str(r.get(h.lower(), "")))
                               for r in rows), default=0))
              for h in headers]
    click.echo("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    click.echo("  ".join("-" * w for w in widths))
    for r in rows:
        line = "  ".join(
            str(r.get(h.lower(), "")).ljust(w)
            for h, w in zip(headers, widths)
        )
        # Highlight drift in red when stdout is a TTY
        if r.get("drift") and click.get_text_stream("stdout").isatty():
            line = click.style(line, fg="red")
        click.echo(line)


def _gather_rows(target: str | None, show_all: bool) -> list[dict]:
    """Walk the allocator, index, and Docker; return a row dict per ENI."""
    from localemu.services.ec2.docker.address_index import (
        get_address_index,
    )
    from localemu.services.ec2.docker.subnet_allocator import (
        get_subnet_allocator,
    )

    allocator = get_subnet_allocator()
    index = get_address_index()
    rows: list[dict] = []

    # Build the set of ENIs to walk
    candidates = []
    if show_all or not target:
        candidates = list(index.all_enis())
    else:
        # Try to resolve target as ENI id, instance id, or container name
        e = index.get_eni(target)
        if e is not None:
            candidates = [e]
        else:
            # Resolve instance->ENIs
            enis = index.get_enis_for_instance(target)
            if enis:
                candidates = enis
            else:
                # Container name like 'localemu-ec2-i-abc' or
                # 'localemu-rds-db-foo' — strip the prefix to get the
                # logical id and look that up
                for prefix in ("localemu-ec2-", "localemu-rds-"):
                    if target.startswith(prefix):
                        logical = target[len(prefix):]
                        enis = index.get_enis_for_instance(logical)
                        if not enis:
                            enis = index.get_enis_for_instance(
                                f"rds:{logical}",
                            )
                        if enis:
                            candidates = enis
                            break

    for e in candidates:
        alloc_entry = allocator.lookup(e.primary_ip)
        alloc_ip = (
            str(e.primary_ip) if alloc_entry is not None else "—"
        )
        docker_ip = _probe_docker_ip(e)
        drift = (
            (alloc_ip != "—" and alloc_ip != str(e.primary_ip))
            or (docker_ip and docker_ip != str(e.primary_ip))
        )
        rows.append({
            "instance": e.instance_id or "—",
            "eni": e.eni_id,
            "vpc": e.vpc_id,
            "subnet": e.subnet_id,
            "alloc_ip": alloc_ip,
            "index_ip": str(e.primary_ip),
            "docker_ip": docker_ip or "—",
            "drift": "YES" if drift else "",
        })
    return rows


def _probe_docker_ip(eni) -> str | None:
    """Best-effort: ask Docker what IP the container actually has on
    the VPC bridge right now."""
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT
        container_name = _container_name_for(eni)
        if not container_name:
            return None
        net = f"localemu-vpc-{eni.vpc_id}"
        return DOCKER_CLIENT.get_container_ipv4_for_network(container_name, net)
    except Exception:
        return None


def _container_name_for(eni) -> str | None:
    """Map an ENI back to its Docker container name."""
    if not eni.instance_id:
        return None
    iid = eni.instance_id
    if iid.startswith("rds:"):
        return f"localemu-rds-{iid[4:]}"
    return f"localemu-ec2-{iid}"


def register(cli_group) -> None:
    """Attach the vpc-ip command to a click group. Idempotent."""
    cli_group.add_command(vpc_ip)
