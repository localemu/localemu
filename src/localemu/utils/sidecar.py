"""Reach a sidecar container from the LocalEmu process.

A sidecar publishes its port on the Docker host (``-p <host_port>:<port>``).
When LocalEmu itself runs in a container, ``127.0.0.1:<host_port>`` is that
container, not the host, so the check never succeeds. The sidecar's own address
on the Docker network is reachable from there. On the other hand, Docker
Desktop does not route to container addresses from the host, where the
published port is the one that works. So both are tried, container address
first.
"""
from __future__ import annotations

import logging
import socket
import time

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


def sidecar_endpoints(
    container_name: str, container_port: int | None, host_port: int | None,
) -> list[tuple[str, int]]:
    """``(host, port)`` pairs a sidecar may answer on, best first."""
    endpoints: list[tuple[str, int]] = []
    if container_port:
        try:
            if ip := DOCKER_CLIENT.get_container_ip(container_name):
                endpoints.append((ip, container_port))
        except Exception:
            pass
    if host_port:
        endpoints.append(("127.0.0.1", host_port))
    return endpoints


def wait_for_sidecar_port(
    container_name: str,
    container_port: int | None,
    host_port: int | None,
    timeout: float = 30,
    interval: float = 0.5,
    settle: float = 0.0,
) -> tuple[str, int] | None:
    """Poll until one of the sidecar's endpoints accepts a TCP connection.

    Returns the endpoint that answered, or ``None`` on timeout. ``settle`` is an
    extra pause after the first accepted connection, for engines that bind the
    socket before they are ready to serve.
    """
    deadline = time.monotonic() + timeout
    while True:
        for host, port in sidecar_endpoints(container_name, container_port, host_port):
            try:
                with socket.create_connection((host, port), timeout=2):
                    if settle:
                        time.sleep(settle)
                    return host, port
            except OSError:
                pass
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)
