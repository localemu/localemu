"""
VPC Endpoint emulation via Docker proxy containers.

VPC Endpoints allow containers in private (--internal) Docker networks
to reach LocalEmu services (S3, DynamoDB, SQS, etc.) without internet
access.  The mechanism: a lightweight socat proxy container that bridges
the private network and the host.

Architecture:
  Private container (--internal, no host access)
      ↓ connects to proxy IP:4566
  Endpoint proxy (dual-homed: default bridge + internal network)
      ↓ socat TCP forward
  LocalEmu on host (host.docker.internal:4566)

Gateway Endpoints (S3, DynamoDB): route-table entries — single proxy
Interface Endpoints (SQS, SNS, etc.): ENI with private IP — same proxy
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading

from localemu.utils.container_utils.container_client import ContainerConfiguration
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


# Pre-baked proxy image. socat is built into the image on the LocalEmu host
# (where the internet works) instead of installed at container start via
# ``apk add``. The proxy container then runs in the VPC's --internal=true
# network and does not need outbound connectivity — running `apk add` at
# container start would fail on every VPC without an IGW route, leaving
# the proxy up but silently forwarding nothing.
_PROXY_IMAGE = "localemu/vpc-endpoint:latest"

_PROXY_DOCKERFILE = """\
FROM alpine:3.19
RUN apk add --no-cache socat \\
    && rm -rf /var/cache/apk/*
LABEL org.localemu.image-role="vpc-endpoint-proxy"
LABEL org.opencontainers.image.source="https://github.com/localemu/localemu"
LABEL org.opencontainers.image.description="LocalEmu VPC Endpoint socat proxy"
"""

_proxy_image_lock = threading.Lock()


def _proxy_image_available() -> bool:
    try:
        DOCKER_CLIENT.inspect_image(_PROXY_IMAGE)
        return True
    except Exception:
        return False


def _ensure_proxy_image() -> bool:
    """Build :data:`_PROXY_IMAGE` if not already present. Idempotent and
    thread-safe; mirrors the flow-log sidecar's _ensure_image so the two
    Docker-side helpers stay shaped the same way."""
    if _proxy_image_available():
        return True
    with _proxy_image_lock:
        if _proxy_image_available():
            return True
        try:
            LOG.info("Building %s (one-time, includes socat)…", _PROXY_IMAGE)
            with tempfile.TemporaryDirectory(prefix="localemu-vpce-img-") as ctx:
                dockerfile_path = os.path.join(ctx, "Dockerfile")
                with open(dockerfile_path, "w") as f:
                    f.write(_PROXY_DOCKERFILE)
                DOCKER_CLIENT.build_image(
                    dockerfile_path=dockerfile_path,
                    image_name=_PROXY_IMAGE,
                    context_path=ctx,
                )
            LOG.info("Built %s successfully", _PROXY_IMAGE)
            return True
        except Exception:
            LOG.warning(
                "VPC Endpoint proxy image build failed; falling back to "
                "runtime apk add (will not work without internet access)",
                exc_info=True,
            )
            return False


class VpcEndpointManager:
    """Manages VPC Endpoint proxy containers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # endpoint_id → {container_name, vpc_id, service_name, proxy_ip, gateway_port}
        self._endpoints: dict[str, dict] = {}
        # gateway_port → endpoint_id, for the IAM enforcement handler chain's
        # reverse lookup (see aws.handlers.vpc_endpoint). Separate from
        # _endpoints so that lookup never needs to hold self._lock across a
        # full dict scan on every request.
        self._port_to_endpoint: dict[int, str] = {}

    def create_endpoint(
        self, endpoint_id: str, vpc_id: str, service_name: str,
    ) -> str | None:
        """Create a VPC Endpoint proxy container.

        The proxy container starts on the default bridge network (for
        host access), then joins the VPC's internal network.  It runs
        socat to forward port 4566 from the private network to
        host.docker.internal:4566 on the host.

        Args:
            endpoint_id: The VPC Endpoint ID (vpce-xxx)
            vpc_id: The VPC to serve
            service_name: AWS service (e.g. com.amazonaws.us-east-1.s3)

        Returns:
            The proxy's IP on the VPC network, or None on failure.
        """
        container_name = f"localemu-vpce-{endpoint_id}"
        vpc_network = f"localemu-vpc-{vpc_id}"

        # Each endpoint gets its own dedicated gateway listener port instead
        # of every proxy forwarding to the shared edge port. This is how the
        # IAM enforcement handler chain later tells which endpoint a request
        # arrived through (aws:SourceVpce / aws:SourceVpc).
        #
        # Source-IP based attribution (matching the proxy's bridge-network
        # IP against the connecting socket's peer address) was the original
        # design and was live-tested instead: on Docker Desktop, vpnkit NATs
        # ALL container->host traffic to 127.0.0.1 before it reaches the
        # gateway, so every proxy's traffic is indistinguishable by source
        # IP - that approach cannot work on this platform. The listening
        # port a connection arrives on, by contrast, survives that NAT
        # untouched, so it's the one signal available.
        #
        # Only available when the gateway is served by the Twisted runtime
        # server (the default `GATEWAY_SERVER`); on other backends
        # (hypercorn, the werkzeug dev server) the endpoint is still fully
        # created and usable, it just won't populate aws:SourceVpce/
        # aws:SourceVpc for traffic through it.
        gateway_port = self._register_gateway_port(endpoint_id)

        try:
            # Determine the host address for socat forwarding.
            # Try host-gateway first (works on Docker Desktop and modern Linux).
            # If that fails, fall back to the Docker bridge gateway IP.
            host_addr = "host.docker.internal"
            add_host_flag = "--add-host host.docker.internal:host-gateway"
            try:
                # Probe if host-gateway is supported (works on Docker
                # Desktop and modern Linux) by running a throwaway
                # alpine container through DOCKER_CLIENT — no direct
                # shell-out to `docker`. run_container raises on
                # non-zero exit, which is our negative signal.
                DOCKER_CLIENT.run_container(
                    "alpine:3.19",
                    additional_flags="--add-host host.docker.internal:host-gateway",
                    command=["getent", "hosts", "host.docker.internal"],
                    remove=True,
                )
            except Exception:
                # Fallback: use Docker bridge gateway IP (typically 172.17.0.1)
                try:
                    bridge_info = DOCKER_CLIENT.inspect_network("bridge")
                    ipam_config = bridge_info.get("IPAM", {}).get("Config", [{}])
                    gateway = ipam_config[0].get("Gateway", "172.17.0.1") if ipam_config else "172.17.0.1"
                    host_addr = gateway
                    add_host_flag = f"--add-host host.docker.internal:{gateway}"
                    LOG.info("Using Docker bridge gateway %s as host address for VPC endpoints", gateway)
                except Exception:
                    host_addr = "172.17.0.1"
                    add_host_flag = "--add-host host.docker.internal:172.17.0.1"

            # Start on default bridge (has host access via host.docker.internal).
            # Use the baked image with socat pre-installed; only fall back to
            # alpine + runtime apk add if the build itself failed. The
            # fallback path keeps the legacy behaviour for hosts that can
            # still reach apk mirrors at container-start time.
            # Forward to the endpoint's own dedicated gateway port when one
            # was registered, so the request is attributable; fall back to
            # the shared edge port (pre-existing behaviour, no attribution)
            # when it wasn't (non-Twisted backend, or registration failed).
            target_port = gateway_port or 4566
            if _ensure_proxy_image():
                image_name = _PROXY_IMAGE
                command = [
                    "sh", "-c",
                    f"socat TCP-LISTEN:4566,fork,reuseaddr TCP:{host_addr}:{target_port} & "
                    f"socat TCP-LISTEN:443,fork,reuseaddr TCP:{host_addr}:{target_port} & "
                    "while true; do sleep 3600; done",
                ]
            else:
                image_name = "alpine:3.19"
                command = [
                    "sh", "-c",
                    "apk add --no-cache socat >/dev/null 2>&1; "
                    f"socat TCP-LISTEN:4566,fork,reuseaddr TCP:{host_addr}:{target_port} & "
                    f"socat TCP-LISTEN:443,fork,reuseaddr TCP:{host_addr}:{target_port} & "
                    "while true; do sleep 3600; done",
                ]
            config = ContainerConfiguration(
                image_name=image_name,
                name=container_name,
                command=command,
                additional_flags=add_host_flag,
                detach=True,
                labels={
                    "localemu.service": "vpc-endpoint",
                    "localemu.endpoint-id": endpoint_id,
                    "localemu.vpc-id": vpc_id,
                    "localemu.service-name": service_name,
                },
            )
            DOCKER_CLIENT.create_container_from_config(config)
            DOCKER_CLIENT.start_container(container_name)

            # Connect to VPC's internal network
            DOCKER_CLIENT.connect_container_to_network(vpc_network, container_name)

            # Use exponential backoff starting at 0.2s instead of flat 1s
            import time
            proxy_ip = None
            backoff = 0.2
            for _ in range(10):
                try:
                    proxy_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                        container_name, vpc_network
                    )
                    if proxy_ip:
                        break
                except Exception:
                    pass
                time.sleep(backoff)
                backoff = min(backoff * 2, 3.0)  # Cap at 3s

            # Generate a proper DNS name for the endpoint
            # Format: vpce-{id}.{service}.{region}.vpce.amazonaws.com
            service_short = service_name.rsplit(".", 1)[-1] if "." in service_name else service_name
            region_part = service_name.split(".")[-2] if service_name.count(".") >= 3 else "us-east-1"
            dns_name = f"{endpoint_id}.{service_short}.{region_part}.vpce.localemu.cloud"

            with self._lock:
                self._endpoints[endpoint_id] = {
                    "container_name": container_name,
                    "vpc_id": vpc_id,
                    "service_name": service_name,
                    "proxy_ip": proxy_ip,
                    "dns_name": dns_name,
                    "gateway_port": gateway_port,
                }
                if gateway_port:
                    self._port_to_endpoint[gateway_port] = endpoint_id

            LOG.info(
                "VPC Endpoint %s created for %s in VPC %s (proxy=%s, dns=%s)",
                endpoint_id, service_name, vpc_id, proxy_ip, dns_name,
            )
            return proxy_ip

        except Exception as e:
            LOG.warning("Failed to create VPC Endpoint %s: %s", endpoint_id, e)
            # Clean up any partially created resources ()
            try:
                DOCKER_CLIENT.stop_container(container_name, timeout=5)
            except Exception:
                pass
            try:
                DOCKER_CLIENT.remove_container(container_name)
            except Exception:
                pass
            if gateway_port:
                self._unregister_gateway_port(gateway_port)
            return None

    def delete_endpoint(self, endpoint_id: str) -> None:
        """Remove a VPC Endpoint proxy container."""
        with self._lock:
            ep = self._endpoints.pop(endpoint_id, None)
            if not ep:
                return
            container_name = ep["container_name"]
            gateway_port = ep.get("gateway_port")
            if gateway_port:
                self._port_to_endpoint.pop(gateway_port, None)

        try:
            DOCKER_CLIENT.stop_container(container_name, timeout=5)
        except Exception:
            pass
        try:
            DOCKER_CLIENT.remove_container(container_name)
        except Exception:
            pass

        if gateway_port:
            self._unregister_gateway_port(gateway_port)

        LOG.info("VPC Endpoint %s deleted", endpoint_id)

    def _register_gateway_port(self, endpoint_id: str) -> int | None:
        """Ask the running gateway server for a dedicated listener port for
        this endpoint. Returns None (never raises) if the current
        `GATEWAY_SERVER` backend doesn't support dynamic listeners, or if
        registration fails for any other reason - the endpoint is still
        created either way, just without IAM attribution for traffic
        through it. See the long comment at the call site in
        ``create_endpoint`` for why this exists.
        """
        try:
            from localemu.runtime import get_current_runtime

            server = get_current_runtime().components.runtime_server
            add_dynamic_listener = getattr(server, "add_dynamic_listener", None)
            if add_dynamic_listener is None:
                LOG.debug(
                    "VPC Endpoint %s: gateway server %s has no dynamic-listener "
                    "support - aws:SourceVpce/aws:SourceVpc won't be populated "
                    "for traffic through this endpoint",
                    endpoint_id, type(server).__name__,
                )
                return None
            return add_dynamic_listener()
        except Exception:
            LOG.debug(
                "VPC Endpoint %s: failed to register a dedicated gateway port",
                endpoint_id, exc_info=True,
            )
            return None

    def _unregister_gateway_port(self, gateway_port: int) -> None:
        try:
            from localemu.runtime import get_current_runtime

            server = get_current_runtime().components.runtime_server
            remove_dynamic_listener = getattr(server, "remove_dynamic_listener", None)
            if remove_dynamic_listener:
                remove_dynamic_listener(gateway_port)
        except Exception:
            LOG.debug("Failed to tear down gateway port %s", gateway_port, exc_info=True)

    def get_endpoint_id_for_port(self, gateway_port: int) -> str | None:
        """Reverse lookup used by the IAM enforcement handler chain: given
        the local port a request's connection was accepted on
        (``environ['SERVER_PORT']``), return which VPC endpoint (if any)
        owns that port."""
        return self._port_to_endpoint.get(gateway_port)

    def get_vpc_id_for_endpoint(self, endpoint_id: str) -> str | None:
        """Return the VPC ID a given endpoint belongs to, for aws:SourceVpc."""
        with self._lock:
            ep = self._endpoints.get(endpoint_id)
            return ep["vpc_id"] if ep else None

    def get_endpoint_ip(self, endpoint_id: str) -> str | None:
        """Return the proxy IP for a VPC Endpoint."""
        with self._lock:
            ep = self._endpoints.get(endpoint_id)
            return ep["proxy_ip"] if ep else None

    def get_endpoint_dns(self, endpoint_id: str) -> str | None:
        """Return the DNS name for a VPC Endpoint ()."""
        with self._lock:
            ep = self._endpoints.get(endpoint_id)
            return ep.get("dns_name") if ep else None

    def get_endpoints_for_vpc(self, vpc_id: str) -> list[dict]:
        """Return all VPC Endpoints for a VPC."""
        with self._lock:
            return [
                {"endpoint_id": eid, **ep}
                for eid, ep in self._endpoints.items()
                if ep["vpc_id"] == vpc_id
            ]

    def cleanup_all(self) -> None:
        """Remove all VPC Endpoint proxy containers."""
        with self._lock:
            endpoint_ids = list(self._endpoints.keys())
        for eid in endpoint_ids:
            self.delete_endpoint(eid)


# Module-level singleton
_endpoint_manager: VpcEndpointManager | None = None
_endpoint_lock = threading.Lock()


def get_vpc_endpoint_manager() -> VpcEndpointManager:
    global _endpoint_manager
    if _endpoint_manager is None:
        with _endpoint_lock:
            if _endpoint_manager is None:
                _endpoint_manager = VpcEndpointManager()
    return _endpoint_manager
