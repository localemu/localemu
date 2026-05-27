"""Instance Metadata Service (IMDS) for Docker-backed EC2 instances.

Provides a centralized HTTP server that responds to IMDS queries from
EC2 containers. Each container reaches this server via the
AWS_EC2_METADATA_SERVICE_ENDPOINT env var set at container creation.

The server identifies which instance is making the request by matching
the source IP of the HTTP connection against a registry of container IPs.

Supports both IMDSv1 (plain GET) and IMDSv2 (token-based PUT/GET).
"""

import http.client
import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = logging.getLogger(__name__)

# HTTP header the per-instance proxy adds when forwarding to IMDS so
# the handler can identify the caller regardless of the source IP
# Docker Desktop's gateway NAT shows us .
STAMP_HEADER = "X-Localemu-Instance-Id"

# ---------------------------------------------------------------------------
# IMDS directory listings
# ---------------------------------------------------------------------------

_META_DATA_TOP_LEVEL = "\n".join([
    "ami-id",
    "hostname",
    "iam/",
    "instance-id",
    "instance-type",
    "local-hostname",
    "local-ipv4",
    "mac",
    "placement/",
    "public-hostname",
    "public-ipv4",
    "public-keys/",
])

_PLACEMENT_LISTING = "\n".join([
    "availability-zone",
    "region",
])

_IAM_LISTING = "\n".join([
    "info",
    "security-credentials/",
])


_CRED_REFRESH_WINDOW_SECONDS = 15 * 60  # refresh when ≤ 15 min remaining
_CRED_DURATION_SECONDS = 6 * 60 * 60  # 6 hours, matching real-AWS EC2 IMDS
_cred_lock = threading.Lock()


def _mint_iam_credentials(account_id: str, region: str, instance_id: str,
                           iam_role_name: str) -> dict | None:
    """Issue a fresh STS AssumeRole for the instance profile role.

    Returns the AWS-HMAC dict shape that IMDS serializes, or None if
    the STS call fails (caller falls back to whatever's cached).
    """
    try:
        from datetime import datetime, timedelta, timezone
        from moto.sts.models import sts_backends
        sts_backend = sts_backends[account_id]["global"]
        role_arn = f"arn:aws:iam::{account_id}:role/{iam_role_name}"
        assumed = sts_backend.assume_role(
            region_name=region or "us-east-1",
            role_session_name=f"ec2-{instance_id}",
            role_arn=role_arn,
            policy=None,
            duration=_CRED_DURATION_SECONDS,
            external_id=None,
        )
        now = datetime.now(timezone.utc)
        return {
            "Code": "Success",
            "LastUpdated": now.isoformat(),
            "Type": "AWS-HMAC",
            "AccessKeyId": assumed.access_key_id,
            "SecretAccessKey": assumed.secret_access_key,
            "Token": assumed.session_token,
            "Expiration": (now + timedelta(
                seconds=_CRED_DURATION_SECONDS,
            )).isoformat(),
        }
    except Exception:
        LOG.debug(
            "imds: STS re-mint failed for %s/%s", instance_id,
            iam_role_name, exc_info=True,
        )
        return None


def _refresh_iam_credentials_if_needed(metadata: dict) -> dict | None:
    """Return live IAM credentials for the instance, re-minting via
    STS when the cached set is within the refresh window.

    The cached value lives in ``metadata["iam_credentials"]`` and is
    mutated in place on refresh, so the next IMDS request hits the
    fresh set without re-issuing. Returns None when no role is
    configured (caller's 404 path).
    """
    cached = metadata.get("iam_credentials")
    iam_role_name = metadata.get("iam_role_name")
    if not iam_role_name:
        # No role attached — cached must already be None (per the
        # vm_manager mint path); honor 404 contract.
        return cached
    if cached:
        try:
            from datetime import datetime, timezone
            expiry_iso = cached.get("Expiration", "")
            expiry = datetime.fromisoformat(expiry_iso)
            remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
            if remaining > _CRED_REFRESH_WINDOW_SECONDS:
                return cached
        except (ValueError, TypeError):
            # Malformed Expiration → treat as needing refresh
            pass
    # Either no cache or within the refresh window: re-mint.
    with _cred_lock:
        fresh = _mint_iam_credentials(
            account_id=metadata.get("account_id") or "000000000000",
            region=metadata.get("region") or "us-east-1",
            instance_id=metadata.get("instance_id") or "",
            iam_role_name=iam_role_name,
        )
        if fresh is not None:
            metadata["iam_credentials"] = fresh
            return fresh
        return cached


def _lookup_public_ipv4(metadata: dict) -> str:
    """Resolve the instance's current public-ipv4 at request time.

    Returns the associated Elastic IP (live lookup against moto's EC2
    state) if one is attached, otherwise "127.0.0.1" so the existing
    SSH-via-host-port workflow keeps working. Reading moto on every
    request is intentional: a user can ``associate-address`` AFTER
    container boot and expect the next IMDS curl to reflect it
    without needing to rebuild the metadata snapshot.
    """
    instance_id = metadata.get("instance_id")
    account_id = metadata.get("account_id") or "000000000000"
    region = metadata.get("region") or "us-east-1"
    if not instance_id:
        return "127.0.0.1"
    try:
        import moto.backends as moto_backends
        backend = moto_backends.get_backend("ec2")[account_id][region]
        # ElasticAddressBackend stores attachments under .addresses
        for addr in getattr(backend, "addresses", []):
            inst = getattr(addr, "instance", None)
            if inst is not None and getattr(inst, "id", None) == instance_id:
                if addr.public_ip:
                    return addr.public_ip
    except Exception:
        LOG.debug(
            "imds: EIP lookup failed for %s; falling back to 127.0.0.1",
            instance_id, exc_info=True,
        )
    return "127.0.0.1"


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class ImdsRequestHandler(BaseHTTPRequestHandler):
    """Handles IMDS HTTP requests from EC2 containers."""

    # -- HTTP verbs ---------------------------------------------------------

    def do_GET(self):  # noqa: N802
        server: ImdsServer = self.server  # type: ignore[assignment]

        # Identification priority:
        # 1. ``X-Localemu-Instance-Id`` — direct, from per-instance proxy .
        # 2. ``X-Localemu-Source-Ip`` — VPC IP forwarded by the per-VPC
        # IMDS sidecar so we can map back to instance via _ip_to_instance.
        # 3. Source IP of the connection — works only when the caller
        # is reachable to us directly (rare with Docker Desktop NAT).
        stamped_id = self.headers.get(STAMP_HEADER)
        if stamped_id and stamped_id in server.metadata_store:
            instance_id = stamped_id
        else:
            forwarded_ip = self.headers.get("X-Localemu-Source-Ip")
            instance_id = None
            if forwarded_ip:
                instance_id = server.resolve_instance(forwarded_ip)
            if not instance_id:
                instance_id = server.resolve_instance(self.client_address[0])
        if not instance_id:
            self.send_error(404, "Instance not found for this IP")
            return

        metadata = server.metadata_store.get(instance_id, {})

        # IMDSv2 enforcement
        if server.require_imdsv2:
            token = self.headers.get("X-aws-ec2-metadata-token")
            if not token or not server.validate_token(token):
                self.send_error(401, "Unauthorized – IMDSv2 token required")
                return

        path = self.path
        # Normalise: strip trailing slash *except* for directory-listing paths
        if path.endswith("/") and path != "/" and not self._is_directory_path(path):
            path = path.rstrip("/")

        response = self._route(path, metadata)
        if response is None:
            self.send_error(404, "Not Found")
            return

        if isinstance(response, dict):
            body = json.dumps(response).encode()
            content_type = "application/json"
        else:
            body = str(response).encode()
            content_type = "text/plain"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):  # noqa: N802
        if self.path == "/latest/api/token":
            server: ImdsServer = self.server  # type: ignore[assignment]
            ttl = int(self.headers.get("X-aws-ec2-metadata-token-ttl-seconds", "300"))
            token = server.create_token(ttl)
            body = token.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-aws-ec2-metadata-token-ttl-seconds", str(ttl))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")

    # -- Routing ------------------------------------------------------------

    @staticmethod
    def _is_directory_path(path: str) -> bool:
        """Return True for paths that are directory listings (end with /)."""
        return path in {
            "/latest/meta-data/",
            "/latest/meta-data/placement/",
            "/latest/meta-data/iam/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/public-keys/",
        }

    def _route(self, path: str, metadata: dict):
        """Resolve *path* to a response body (str, dict, or None)."""
        # Simple scalar lookups
        scalar_routes = {
            "/latest/meta-data/instance-id": metadata.get("instance_id"),
            "/latest/meta-data/instance-type": metadata.get("instance_type"),
            "/latest/meta-data/ami-id": metadata.get("ami_id"),
            "/latest/meta-data/local-ipv4": metadata.get("private_ip"),
            "/latest/meta-data/public-ipv4": _lookup_public_ipv4(metadata),
            "/latest/meta-data/hostname": metadata.get("hostname"),
            "/latest/meta-data/local-hostname": metadata.get("hostname"),
            "/latest/meta-data/public-hostname": "localhost",
            "/latest/meta-data/mac": metadata.get("mac", "02:42:ac:11:00:02"),
            "/latest/meta-data/placement/availability-zone": metadata.get("az"),
            "/latest/meta-data/placement/region": metadata.get("region"),
            "/latest/user-data": metadata.get("user_data", ""),
        }
        if path in scalar_routes:
            return scalar_routes[path]

        # Directory listings
        if path == "/latest/meta-data/" or path == "/latest/meta-data":
            return _META_DATA_TOP_LEVEL
        if path == "/latest/meta-data/placement/" or path == "/latest/meta-data/placement":
            return _PLACEMENT_LISTING
        if path == "/latest/meta-data/iam/" or path == "/latest/meta-data/iam":
            return _IAM_LISTING

        # IAM security-credentials
        if path == "/latest/meta-data/iam/security-credentials/" or path == "/latest/meta-data/iam/security-credentials":
            return metadata.get("iam_role_name", "")
        if path.startswith("/latest/meta-data/iam/security-credentials/"):
            return self._get_iam_credentials(metadata)

        # IAM info
        if path == "/latest/meta-data/iam/info":
            return self._get_iam_info(metadata)

        # Instance identity document
        if path == "/latest/dynamic/instance-identity/document":
            return self._build_identity_document(metadata)

        # Public keys
        if path == "/latest/meta-data/public-keys/" or path == "/latest/meta-data/public-keys":
            key_name = metadata.get("key_name")
            if key_name:
                return f"0={key_name}"
            return ""
        if path == "/latest/meta-data/public-keys/0/openssh-key":
            return metadata.get("public_key", "")

        return None

    # -- Response builders --------------------------------------------------

    @staticmethod
    def _build_identity_document(metadata: dict) -> dict:
        return {
            "accountId": metadata.get("account_id", "000000000000"),
            "architecture": "x86_64",
            "availabilityZone": metadata.get("az", "us-east-1a"),
            "imageId": metadata.get("ami_id", ""),
            "instanceId": metadata.get("instance_id", ""),
            "instanceType": metadata.get("instance_type", "t2.micro"),
            "region": metadata.get("region", "us-east-1"),
            "version": "2017-09-30",
            "privateIp": metadata.get("private_ip", ""),
        }

    @staticmethod
    def _get_iam_credentials(metadata: dict) -> dict | None:
        """Return IAM credentials for the instance, or None if no role is attached.

        Returns None when no role is configured (handler returns 404).
        Otherwise resolves the live credentials via
        :func:`_refresh_iam_credentials_if_needed`, which re-mints
        through STS when the cached set is within 15 minutes of
        expiry. This matches real-AWS IMDS behavior — SDKs poll IMDS
        and expect rotation well before the Expiration timestamp,
        otherwise long-lived workloads inside the instance hit
        ExpiredToken once the cached 6-hour session lapses.
        """
        return _refresh_iam_credentials_if_needed(metadata)

    @staticmethod
    def _get_iam_info(metadata: dict) -> dict:
        role_name = metadata.get("iam_role_name", "")
        instance_profile_arn = metadata.get(
            "instance_profile_arn",
            f"arn:aws:iam::{metadata.get('account_id', '000000000000')}:instance-profile/{role_name}" if role_name else "",
        )
        return {
            "Code": "Success",
            "InstanceProfileArn": instance_profile_arn,
            "InstanceProfileId": metadata.get("instance_profile_id", "AIPA000000000EXAMPLE"),
        }

    # -- Logging suppression ------------------------------------------------

    def log_message(self, format, *args):  # noqa: A002
        """Suppress default stderr access logs; use module logger at DEBUG."""
        LOG.debug("IMDS %s %s", self.client_address[0], format % args)


# ---------------------------------------------------------------------------
# IMDS Server
# ---------------------------------------------------------------------------


class ImdsServer:
    """Centralized IMDS server for all Docker-backed EC2 instances.

    Lifecycle:
        server = ImdsServer()
        server.start()
        server.register_instance(instance_id, container_ip, metadata_dict)
        ...
        server.deregister_instance(instance_id)
        server.stop()
    """

    def __init__(self, port: int = 0, require_imdsv2: bool = False):
        self.metadata_store: dict[str, dict] = {}
        self._ip_to_instance: dict[str, str] = {}
        self._tokens: dict[str, float] = {}
        self._lock = threading.Lock()
        self._requested_port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.require_imdsv2 = require_imdsv2
        # Per-instance proxy ports for macOS multi-instance support.
        # instance_id -> PerInstanceImdsPortProxy.
        self._proxies: dict[str, PerInstanceImdsPortProxy] = {}

    # -- Public API ---------------------------------------------------------

    def start(self) -> None:
        """Bind and start serving in a daemon thread."""
        # Bind to 127.0.0.1 to prevent external access.
        # Docker containers reach IMDS via host.docker.internal which maps
        # to 127.0.0.1 on macOS Docker Desktop. On Linux, the Docker bridge
        # gateway routes to the host's loopback as well when using
        # --add-host host.docker.internal:host-gateway.
        self._server = HTTPServer(("127.0.0.1", self._requested_port), ImdsRequestHandler)

        # Attach helpers so the handler can call back into us via self.server
        self._server.resolve_instance = self.resolve_instance  # type: ignore[attr-defined]
        self._server.metadata_store = self.metadata_store  # type: ignore[attr-defined]
        self._server.require_imdsv2 = self.require_imdsv2  # type: ignore[attr-defined]
        self._server.create_token = self.create_token  # type: ignore[attr-defined]
        self._server.validate_token = self.validate_token  # type: ignore[attr-defined]

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="ec2-imds",
            daemon=True,
        )
        self._thread.start()
        LOG.info("IMDS server started on port %d", self.port)

    def stop(self) -> None:
        """Shutdown the HTTP server and wait for the thread to finish."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        LOG.info("IMDS server stopped")

    @property
    def port(self) -> int:
        """Return the port the server is listening on (0 before start)."""
        if self._server:
            return self._server.server_address[1]
        return 0

    # -- Instance registry --------------------------------------------------

    def register_instance(self, instance_id: str, container_ip: str, metadata: dict) -> None:
        """Register an EC2 instance so IMDS queries from its IP are answered."""
        with self._lock:
            self.metadata_store[instance_id] = metadata
            self._ip_to_instance[container_ip] = instance_id
        LOG.debug("IMDS registered instance %s at IP %s", instance_id, container_ip)

    def deregister_instance(self, instance_id: str) -> None:
        """Remove an EC2 instance from the IMDS registry."""
        with self._lock:
            self.metadata_store.pop(instance_id, None)
            self._ip_to_instance = {
                ip: iid for ip, iid in self._ip_to_instance.items() if iid != instance_id
            }
        LOG.debug("IMDS deregistered instance %s", instance_id)

    def resolve_instance(self, client_ip: str) -> str | None:
        """Map a client IP to an instance ID, or None.

        On macOS with Docker Desktop, containers connect to
        host.docker.internal which routes through the Docker VM.  The
        source IP seen by the IMDS server is the Docker gateway
        (e.g. 192.168.65.x) or 127.0.0.1, NOT the container's bridge
        IP.

        The single-instance fallback is now gated behind
        the IMDS_SINGLE_INSTANCE_FALLBACK environment variable.  When
        multiple instances exist, the fallback is never used regardless
        of the flag, preventing metadata leakage across instances.
        """
        import os

        with self._lock:
            # Exact IP match (works when networking is direct)
            iid = self._ip_to_instance.get(client_ip)
            if iid:
                return iid

            # Only fall back to the single registered instance
            # when explicitly opted in via environment variable. This prevents
            # metadata leakage when multiple instances share the IMDS server.
            if (
                len(self._ip_to_instance) == 1
                and os.environ.get("IMDS_SINGLE_INSTANCE_FALLBACK", "").lower()
                in ("1", "true", "yes")
            ):
                return next(iter(self._ip_to_instance.values()))

            return None

    # -- IMDSv2 tokens ------------------------------------------------------

    def create_token(self, ttl: int) -> str:
        """Issue a new IMDSv2 session token with the given TTL in seconds."""
        token = uuid.uuid4().hex
        with self._lock:
            self._tokens[token] = time.time() + ttl
            # Purge expired tokens periodically (every 100 creates)
            if len(self._tokens) % 100 == 0:
                now = time.time()
                expired = [t for t, exp in self._tokens.items() if now > exp]
                for t in expired:
                    del self._tokens[t]
        return token

    def validate_token(self, token: str) -> bool:
        """Return True if *token* is valid and not expired."""
        with self._lock:
            expiry = self._tokens.get(token)
            if expiry is None:
                return False
            if time.time() > expiry:
                del self._tokens[token]
                return False
            return True

    # -- Per-instance IMDS ports ------------------------------------

    def allocate_port_for_instance(
        self, instance_id: str, requested_port: int = 0,
    ) -> int:
        """Allocate a dedicated 127.0.0.1 port for this instance's IMDS.

        A small proxy server listens on that port and stamps
        ``X-Localemu-Instance-Id`` on every forwarded request so the
        main IMDS handler can identify the caller by header, even when
        source-IP identification is unreliable (Docker Desktop's
        gateway NAT). Calling this multiple times for the same
        instance_id is idempotent — the same port is returned.

        When ``requested_port`` is non-zero, the proxy tries to bind
        to that specific port first (persistence path: on restore we
        read the container's baked-in
        ``AWS_EC2_METADATA_SERVICE_ENDPOINT`` env var and pass that
        port here so the new proxy matches what the container expects).
        If the port is unavailable, we fall back to a random port and
        the proxy logs a warning.
        """
        with self._lock:
            existing = self._proxies.get(instance_id)
        if existing is not None:
            return existing.port
        if not self._server:
            raise RuntimeError("IMDS server must be started before allocating per-instance ports")
        proxy = PerInstanceImdsPortProxy(
            instance_id=instance_id,
            upstream_port=self.port,
            requested_port=requested_port,
        )
        proxy.start()
        with self._lock:
            # Second-check under lock to avoid a race.
            existing = self._proxies.get(instance_id)
            if existing is not None:
                # Another thread already allocated — throw this one away.
                proxy.stop()
                return existing.port
            self._proxies[instance_id] = proxy
        return proxy.port

    def release_port_for_instance(self, instance_id: str) -> None:
        """Tear down the per-instance proxy, if any."""
        with self._lock:
            proxy = self._proxies.pop(instance_id, None)
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:
                LOG.debug("Failed to stop per-instance IMDS proxy for %s", instance_id)


# -------------------------------------------------------------------------
# PerInstanceImdsPortProxy 
# -------------------------------------------------------------------------


class _StampingProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler that forwards every request to the upstream IMDS
    server, adding the ``X-Localemu-Instance-Id`` header so the IMDS
    handler can identify the caller by header instead of source IP."""

    # Populated by PerInstanceImdsPortProxy at init time.
    upstream_port: int  # type: ignore[assignment]
    instance_id: str  # type: ignore[assignment]

    def _forward(self, method: str) -> None:
        body = None
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 0:
            body = self.rfile.read(content_length)
        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        headers[STAMP_HEADER] = self.instance_id

        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", self.upstream_port, timeout=5,
            )
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
        except Exception as exc:
            LOG.debug("IMDS proxy forwarding failed for %s: %s", self.path, exc)
            self.send_error(502, "IMDS proxy forwarding failed")
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass

        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in ("transfer-encoding", "connection"):
                continue
            self.send_header(k, v)
        self.end_headers()
        if resp_body:
            self.wfile.write(resp_body)

    def do_GET(self):  # noqa: N802
        self._forward("GET")

    def do_PUT(self):  # noqa: N802
        self._forward("PUT")

    def log_message(self, format, *args):  # noqa: A002
        LOG.debug("IMDS-proxy[%s] %s", self.instance_id, format % args)


class PerInstanceImdsPortProxy:
    """Per-instance IMDS port proxy.

    Each EC2 instance the vm_manager creates gets one of these. The
    container's ``AWS_EC2_METADATA_SERVICE_ENDPOINT`` points to this
    proxy's port, and the proxy stamps the instance ID before
    forwarding so the real IMDS handler can identify the caller
    without relying on source IP.
    """

    def __init__(
        self, instance_id: str, upstream_port: int, requested_port: int = 0,
    ) -> None:
        self.instance_id = instance_id
        self.upstream_port = upstream_port
        self._requested_port = requested_port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler_cls = type(
            "_StampHandler",
            (_StampingProxyHandler,),
            {
                "upstream_port": self.upstream_port,
                "instance_id": self.instance_id,
            },
        )
        try:
            self._server = HTTPServer(
                ("127.0.0.1", self._requested_port), handler_cls,
            )
        except OSError as exc:
            if self._requested_port:
                LOG.warning(
                    "Per-instance IMDS proxy for %s: requested port %d unavailable (%s); "
                    "falling back to a random port — the container's baked-in "
                    "AWS_EC2_METADATA_SERVICE_ENDPOINT will not resolve until the "
                    "instance is re-created",
                    self.instance_id, self._requested_port, exc,
                )
                self._server = HTTPServer(("127.0.0.1", 0), handler_cls)
            else:
                raise
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"imds-proxy-{self.instance_id}",
            daemon=True,
        )
        self._thread.start()
        LOG.debug(
            "Per-instance IMDS proxy for %s listening on 127.0.0.1:%d",
            self.instance_id, self.port,
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            try:
                self._server.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return self._server.server_address[1]
