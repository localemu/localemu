"""Per-VPC IMDS sidecar.

VPC Docker networks are created ``--internal=true`` so the EC2
containers attached to them have NO route to the host gateway —
``host.docker.internal`` resolves but is unreachable, and IMDS calls
from EC2 containers fall through. The previous "set
``AWS_EC2_METADATA_SERVICE_ENDPOINT=http://host.docker.internal:<port>``"
mechanism worked only outside VPCs.

Solution: one sidecar container per VPC, dual-homed (VPC network +
default bridge). It listens on its VPC IP and forwards every IMDS
request to the host's ``ImdsServer``, adding an ``X-Localemu-Source-Ip``
header so the host can identify the caller by container VPC IP.

Lifecycle
---------
``ensure_imds_sidecar(vpc_id, host_imds_port)`` is idempotent:
returns the sidecar's VPC IP, building+starting the container only
when missing. Called from ``DockerVmManager.create_instance`` before
the EC2 container starts so the env var
``AWS_EC2_METADATA_SERVICE_ENDPOINT`` can point at the right address.

``cleanup_for_vpc(vpc_id)`` tears down the sidecar; called from
``VpcNetworkManager.delete_vpc_network``.
"""

from __future__ import annotations

import logging
import textwrap
import threading
import time

from localemu.utils.container_utils.container_client import ContainerConfiguration
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


# Tiny Python relay that we copy into the sidecar container and run
# in foreground. Forwards every HTTP request to the upstream IMDS
# (the host's ImdsServer reachable via host.docker.internal because
# the sidecar is also attached to the default bridge), adding an
# ``X-Localemu-Source-Ip`` header carrying the caller's VPC IP so
# ``ImdsServer.resolve_instance`` can identify the caller. We use the
# in-container address via this script (no socat / no apt-get install)
# because every modern base image already ships a usable Python.
_RELAY_SCRIPT = textwrap.dedent(r"""
    import http.client
    import os
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    UPSTREAM_HOST = os.environ.get("LOCALEMU_IMDS_UPSTREAM_HOST", "host.docker.internal")
    UPSTREAM_PORT = int(os.environ.get("LOCALEMU_IMDS_UPSTREAM_PORT", "0"))


    class Relay(BaseHTTPRequestHandler):
        def _forward(self, method):
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length", "connection",
                                             "transfer-encoding")}
            headers["X-Localemu-Source-Ip"] = self.client_address[0]
            body = b""
            cl = self.headers.get("Content-Length")
            if cl:
                body = self.rfile.read(int(cl))
            try:
                conn = http.client.HTTPConnection(
                    UPSTREAM_HOST, UPSTREAM_PORT, timeout=5,
                )
                conn.request(method, self.path, body=body, headers=headers)
                resp = conn.getresponse()
                resp_body = resp.read()
            except Exception as exc:
                self.send_error(502, "imds-relay: " + str(exc))
                return
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "connection",
                                 "content-length"):
                    continue
                self.send_header(k, v)
            body_bytes = resp_body or b""
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        def do_GET(self):
            self._forward("GET")

        def do_PUT(self):
            self._forward("PUT")

        def log_message(self, *args, **kwargs):
            pass


    if __name__ == "__main__":
        srv = ThreadingHTTPServer(("0.0.0.0", 80), Relay)
        srv.serve_forever()
""").strip() + "\n"


def _sidecar_name(vpc_id: str) -> str:
    return f"localemu-imds-{vpc_id}"


_lock = threading.Lock()
# vpc_id -> sidecar VPC IP
_sidecar_ips: dict[str, str] = {}


def _wait_for_ip(container: str, network: str, timeout: int = 10) -> str | None:
    deadline = time.time() + timeout
    backoff = 0.2
    while time.time() < deadline:
        try:
            ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container_name_or_id=container, container_network=network,
            )
            if ip:
                return ip
        except Exception:
            pass
        time.sleep(backoff)
        backoff = min(backoff * 2, 1.5)
    return None


def ensure_imds_sidecar(vpc_id: str, host_imds_port: int) -> str | None:
    """Make sure the per-VPC IMDS sidecar is running. Returns its VPC IP.

    Idempotent: when the sidecar already exists for this VPC, just
    returns the cached IP. Returns ``None`` when the sidecar can't be
    created (e.g. Docker is unreachable) — callers fall back to the
    legacy ``host.docker.internal`` env-var path which works for
    non-VPC instances.
    """
    with _lock:
        cached = _sidecar_ips.get(vpc_id)
        if cached:
            return cached

        name = _sidecar_name(vpc_id)
        vpc_network = f"localemu-vpc-{vpc_id}"

        # Reuse an already-running sidecar from a previous LocalEmu run.
        try:
            existing = DOCKER_CLIENT.list_containers(
                filter=[f"name={name}"], all=True,
            )
        except Exception:
            existing = []
        for c in existing:
            cname = c.get("name") or ""
            if cname == name:
                # Make sure it's running
                try:
                    DOCKER_CLIENT.start_container(name)
                except Exception:
                    pass
                ip = _wait_for_ip(name, vpc_network, timeout=10)
                if ip:
                    _sidecar_ips[vpc_id] = ip
                    return ip
                # Stale / broken — remove and re-create
                try:
                    DOCKER_CLIENT.remove_container(name, force=True)
                except Exception:
                    pass
                break

        try:
            cfg = ContainerConfiguration(
                image_name="python:3.12-alpine",
                name=name,
                command=["python", "-c", _RELAY_SCRIPT],
                env_vars={
                    "LOCALEMU_IMDS_UPSTREAM_HOST": "host.docker.internal",
                    "LOCALEMU_IMDS_UPSTREAM_PORT": str(host_imds_port),
                },
                # Sidecar joins the default bridge first (so it can
                # reach host.docker.internal), then we attach it to the
                # VPC network below. host-gateway mapping ensures
                # host.docker.internal resolves on the bridge.
                additional_flags="--add-host host.docker.internal:host-gateway",
                detach=True,
                labels={
                    "localemu.service": "imds-sidecar",
                    "localemu.vpc-id": vpc_id,
                },
            )
            try:
                DOCKER_CLIENT.inspect_image("python:3.12-alpine")
            except Exception:
                LOG.info("Pulling python:3.12-alpine for IMDS sidecar (one-time)…")
                DOCKER_CLIENT.pull_image("python:3.12-alpine")

            DOCKER_CLIENT.create_container_from_config(cfg)
            DOCKER_CLIENT.start_container(name)
            DOCKER_CLIENT.connect_container_to_network(vpc_network, name)
        except Exception:
            LOG.warning(
                "Failed to start IMDS sidecar for VPC %s",
                vpc_id, exc_info=True,
            )
            try:
                DOCKER_CLIENT.remove_container(name, force=True)
            except Exception:
                pass
            return None

        ip = _wait_for_ip(name, vpc_network, timeout=15)
        if ip:
            _sidecar_ips[vpc_id] = ip
            LOG.info(
                "IMDS sidecar for VPC %s up at %s (relays to host:%s)",
                vpc_id, ip, host_imds_port,
            )
            return ip

        LOG.warning(
            "IMDS sidecar for VPC %s started but no VPC IP visible after 15s",
            vpc_id,
        )
        return None


def cleanup_for_vpc(vpc_id: str) -> None:
    """Stop + remove the per-VPC sidecar. Called from VPC delete."""
    with _lock:
        _sidecar_ips.pop(vpc_id, None)
    try:
        DOCKER_CLIENT.remove_container(_sidecar_name(vpc_id), force=True)
    except Exception:
        pass


def cleanup_all() -> None:
    """Tear down every IMDS sidecar — called on full LocalEmu shutdown
    when persistence is OFF."""
    with _lock:
        ids = list(_sidecar_ips.keys())
        _sidecar_ips.clear()
    for vpc_id in ids:
        try:
            DOCKER_CLIENT.remove_container(_sidecar_name(vpc_id), force=True)
        except Exception:
            pass
