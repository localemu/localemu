"""LocalEmu CLI - the main entry point for the localemu command."""

import os
import signal
import socket
import sys

import click


def _is_port_in_use(port: int) -> bool:
    """Check if a port is in use by attempting to connect to it.

    Uses connect() instead of bind() to correctly detect when any address
    (0.0.0.0 or 127.0.0.1) is already listening on the port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return True  # Connection succeeded — something is listening
        except (ConnectionRefusedError, OSError):
            return False  # Nothing listening


@click.group()
@click.version_option(package_name="localemu")
def cli():
    """LocalEmu - A free, open-source AWS cloud emulator.

    \b
    Quick start:
      localemu start          Start LocalEmu
      localemu status         Show running services
      localemu services       List all supported services
      localemu services s3    Show S3 operations
    """
    pass


@cli.command()
@click.option("-d", "--detached", is_flag=True, help="Start in detached (background) mode")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=4566, type=int, help="Port to listen on")
def start(detached, host, port):
    """Start LocalEmu."""
    os.environ.setdefault("GATEWAY_LISTEN", f"{host}:{port}")

    if _is_port_in_use(port):
        click.echo(
            f"Error: Port {port} is already in use.\n"
            f"Another LocalEmu instance may be running. Use 'localemu stop' first,\n"
            f"or start on a different port: localemu start --port {port + 1}"
        )
        sys.exit(1)

    if detached:
        click.echo("Starting LocalEmu in detached mode...")
        import subprocess

        proc = subprocess.Popen(
            [sys.executable, "-m", "localemu.runtime.main"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        click.echo(f"LocalEmu started (PID: {proc.pid})")
        return

    from localemu.runtime.main import main as runtime_main

    runtime_main()


@cli.command()
def stop():
    """Stop LocalEmu."""
    import subprocess

    # Find LocalEmu processes (both foreground and detached).
    # Use full-match anchored patterns to avoid matching unrelated processes
    # that happen to contain similar substrings.
    #
    # NOTE: macOS/BSD ``pgrep`` uses POSIX Extended Regular Expressions (ERE)
    # which does NOT support the Perl-style ``\s`` whitespace shorthand. Using
    # ``\s+`` silently fails to match on macOS (it looks for a literal ``s``).
    # ``[[:space:]]+`` is POSIX-portable and works on macOS, BSD, and Linux.
    patterns = [
        r"python.*-m[[:space:]]+localemu\.runtime\.main",
        r"python.*localemu[[:space:]]+start",
    ]
    all_pids = set()
    my_pid = os.getpid()
    my_ppid = os.getppid()

    for pattern in patterns:
        result = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True,
        )
        for pid in result.stdout.strip().split("\n"):
            pid = pid.strip()
            if not pid:
                continue
            pid_int = int(pid)
            # Never kill ourselves or our parent
            if pid_int in (my_pid, my_ppid):
                continue
            all_pids.add(pid_int)

    if not all_pids:
        click.echo("LocalEmu is not running.")
        return

    # Graceful shutdown: SIGTERM first, wait for clean socket release
    for pid in all_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    # Wait for processes to exit gracefully (up to 10 seconds)
    import time
    for _ in range(20):
        time.sleep(0.5)
        still_alive = set()
        for pid in all_pids:
            try:
                os.kill(pid, 0)  # Check if process exists (signal 0 = no-op)
                still_alive.add(pid)
            except ProcessLookupError:
                pass
        if not still_alive:
            break
    else:
        # Force kill only as a last resort after 10s of graceful waiting
        for pid in still_alive:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(1)

    click.echo("LocalEmu stopped.")


@cli.command()
@click.option("--port", default=4566, type=int, help="Port to check (default: 4566)")
def status(port):
    """Check LocalEmu status and running services."""
    import requests

    endpoint = os.environ.get("LOCALEMU_ENDPOINT", f"http://localhost:{port}")
    try:
        resp = requests.get(f"{endpoint}/_localemu/health", timeout=2)
        data = resp.json()
        click.echo(f"LocalEmu is running (version: {data.get('version', 'unknown')})")
        click.echo()
        services = data.get("services", {})
        for name, state in sorted(services.items()):
            if state == "available":
                symbol = click.style("✓", fg="green")
                label = click.style(state, fg="green")
            elif state == "running":
                symbol = click.style("○", fg="yellow")
                label = click.style(state, fg="yellow")
            elif state == "error":
                symbol = click.style("✗", fg="red")
                label = click.style(state, fg="red")
            else:
                symbol = click.style("○", dim=True)
                label = click.style(state, dim=True)
            click.echo(f"  {symbol} {name}: {label}")
    except requests.ConnectionError:
        click.echo(f"LocalEmu is not running (connection refused on {endpoint}).")
        sys.exit(1)
    except requests.Timeout:
        click.echo(f"LocalEmu is not responding (timeout connecting to {endpoint}).")
        sys.exit(1)
    except requests.RequestException as e:
        click.echo(f"Could not reach LocalEmu at {endpoint}: {e}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error checking LocalEmu status: {e}")
        sys.exit(1)


@cli.command()
@click.argument("service_name", required=False)
def services(service_name):
    """List supported services, or show operations for a specific service.

    \b
    Examples:
      localemu services          List all services
      localemu services s3       Show S3 operations
      localemu services lambda   Show Lambda operations
      localemu services ecs      Show ECS operations
    """
    from botocore.session import Session

    session = Session()
    available = sorted(session.get_available_services())

    # Load our registered services from plux.ini
    from importlib.metadata import entry_points

    our_eps = entry_points(group="localemu.aws.provider")
    our_services = sorted(set(ep.name.split(":")[0] for ep in our_eps))

    if not service_name:
        click.echo(f"LocalEmu supports {len(our_services)} AWS services:\n")
        # Print in columns
        col_width = max(len(s) for s in our_services) + 4
        cols = 4
        for i in range(0, len(our_services), cols):
            row = our_services[i : i + cols]
            click.echo("  " + "".join(s.ljust(col_width) for s in row))
        click.echo(f"\nRun 'localemu services <name>' to see operations for a service.")
        return

    # Show operations for a specific service
    svc = service_name.lower().strip()
    if svc not in our_services:
        # Try fuzzy match
        matches = [s for s in our_services if svc in s]
        if matches:
            click.echo(f"Did you mean: {', '.join(matches)}?")
        else:
            click.echo(f"Service '{svc}' not found. Run 'localemu services' to see all.")
        sys.exit(1)

    try:
        model = session.get_service_model(svc)
        ops = sorted(model.operation_names)
        click.echo(f"{svc} - {len(ops)} operations:\n")
        for op in ops:
            click.echo(f"  {op}")
    except Exception as e:
        click.echo(f"Could not load service model for '{svc}': {e}")
        sys.exit(1)


@cli.command(context_settings={"ignore_unknown_options": True})
@click.argument("instance_id", required=False)
@click.option("--list", "list_instances", is_flag=True, help="List running EC2 instances")
@click.argument("extra_args", nargs=-1, type=click.UNPROCESSED)
def ssh(instance_id, list_instances, extra_args):
    """SSH into a Docker-backed EC2 instance.

    \b
    Examples:
      localemu ssh i-0abc123         Interactive shell
      localemu ssh i-0abc123 ls -la  Run a command
      localemu ssh --list            List running instances
    """
    import subprocess

    if list_instances:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                "label=localemu.service=ec2",
                "--format",
                "table {{.Names}}\t{{.Status}}\t{{.Ports}}",
            ],
            capture_output=True,
            text=True,
        )
        click.echo(result.stdout if result.stdout else "No EC2 instances running.")
        return

    if not instance_id:
        click.echo("Usage: localemu ssh <instance-id>")
        click.echo("       localemu ssh --list")
        raise SystemExit(1)

    container_name = f"localemu-ec2-{instance_id}"

    if extra_args:
        os.execvp("docker", ["docker", "exec", "-it", container_name] + list(extra_args))
    else:
        # Try /bin/bash first, fall back to /bin/sh for Alpine-based images
        result = subprocess.run(
            ["docker", "exec", container_name, "test", "-x", "/bin/bash"],
            capture_output=True,
        )
        shell = "/bin/bash" if result.returncode == 0 else "/bin/sh"
        os.execvp("docker", ["docker", "exec", "-it", container_name, shell])


def _register_export_commands() -> None:
    """Attach the export/import commands from localemu.export.cli.

    Kept in a helper so that an import failure (e.g. during partial installs
    or in test environments) degrades gracefully: the rest of the CLI still
    works, and the reason is logged.
    """
    try:
        from localemu.export.cli import export_cmd
        from localemu.export.cli import import_snapshot as import_cmd

        cli.add_command(export_cmd, name="export")
        cli.add_command(import_cmd, name="import")
    except Exception as exc:  # pragma: no cover - defensive
        import logging

        logging.getLogger(__name__).debug(
            "Export CLI commands unavailable: %s", exc, exc_info=True
        )


def _register_addressing_debug_command() -> None:
    """Attach the `localemu vpc-ip` debug command."""
    try:
        from localemu.cli.vpc_ip import register as register_vpc_ip
        register_vpc_ip(cli)
    except Exception as exc:  # pragma: no cover - defensive
        import logging
        logging.getLogger(__name__).debug(
            "vpc-ip CLI command unavailable: %s", exc, exc_info=True,
        )


_register_export_commands()
_register_addressing_debug_command()


def main():
    cli()


if __name__ == "__main__":
    main()
