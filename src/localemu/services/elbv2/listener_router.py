"""Real HTTP / HTTPS listener router for ELBv2 Application Load Balancers.

Runs a lightweight HTTP reverse proxy per listener on a locally-allocated
TCP port, round-robin forwarding incoming requests to the healthy targets
of the associated target group. TCP health checks run on a background
thread and update per-target health state.

Scope:
- HTTP listeners: plain HTTP reverse proxy.
- HTTPS listeners: real TLS termination using LocalEmu's self-signed
  certificate (``utils/ssl.py``); decrypted request is forwarded as
  HTTP to the target with ``X-Forwarded-Proto: https``.
- Round-robin across healthy targets (falls back to all registered if none
  are healthy yet, so initial requests don't 503 while health checks warm up).
- Stickiness and WebSocket upgrade handling are not implemented.
"""

from __future__ import annotations

import http.client
import http.server
import logging
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from itertools import count
from typing import Optional

from localemu.services.elbv2.stickiness import (
    AWSALB_COOKIE,
    StickyStore,
    build_set_cookie,
    fresh_cookie_id,
    parse_awsalb_cookie,
    read_stickiness_config,
)

LOG = logging.getLogger(__name__)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def _is_websocket_upgrade(headers) -> bool:
    """RFC 6455: a WebSocket handshake has ``Upgrade: websocket`` and
    ``Connection: Upgrade`` (case-insensitive, Connection may be a
    comma-separated list)."""
    upgrade = (headers.get("Upgrade") or "").strip().lower()
    if upgrade != "websocket":
        return False
    connection = (headers.get("Connection") or "").lower()
    return "upgrade" in [t.strip() for t in connection.split(",")]


def _pipe_sockets(a, b) -> None:
    """Bidirectional byte pump between two sockets until either closes.

    Used for WebSocket frame tunneling: once both ends have agreed on
    101 Switching Protocols, the LB is just a TCP relay. Spawns one
    daemon thread per direction; the call blocks on the join so the
    BaseHTTPRequestHandler keeps the connection open for the duration.
    """
    def _copy(src, dst):
        try:
            src.settimeout(None)
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=_copy, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_copy, args=(b, a), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()


@dataclass
class Target:
    target_id: str  # instance-id or IP, OR a Lambda function ARN
    port: int
    host: str  # resolved host/IP to connect to (empty for Lambda targets)
    health: str = "initial"  # initial | healthy | unhealthy
    lambda_arn: Optional[str] = None  # set when this target is a Lambda function


@dataclass
class TargetGroup:
    arn: str
    name: str
    protocol: str = "HTTP"
    port: int = 80
    health_check_port: Optional[int] = None
    targets: dict[str, Target] = field(default_factory=dict)
    sticky_store: StickyStore = field(default_factory=StickyStore)
    _rr_counter: "count" = field(default_factory=lambda: count(0))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def pick_target(self) -> Optional[Target]:
        with self._lock:
            all_targets = list(self.targets.values())
        if not all_targets:
            return None
        healthy = [t for t in all_targets if t.health == "healthy"]
        pool = healthy if healthy else all_targets
        idx = next(self._rr_counter) % len(pool)
        return pool[idx]

    def target_by_key(self, key: str) -> Optional[Target]:
        """O(1) lookup used by the sticky-cookie path. Returns None
        if the target has been deregistered since the cookie was
        issued — the proxy then re-picks via round-robin."""
        with self._lock:
            return self.targets.get(key)

    def target_key(self, target: Target) -> str:
        """The same composite key used in ``targets`` (Id:Port)."""
        return f"{target.target_id}:{target.port}"


@dataclass
class Listener:
    arn: str
    lb_arn: str
    protocol: str
    port: int
    target_group_arn: str
    server: Optional[http.server.ThreadingHTTPServer] = None
    thread: Optional[threading.Thread] = None


@dataclass
class Rule:
    """An ELBv2 listener rule.

    Mirrors the subset of the ELBv2 ``Rule`` shape that the proxy is
    actually able to act on. ``conditions`` is the raw list of dicts
    boto/moto returns (``Field`` + one of HostHeaderConfig /
    PathPatternConfig / HttpHeaderConfig / QueryStringConfig /
    SourceIpConfig). ``actions`` is the raw DefaultActions-shaped list
    (Type + per-type config block).

    Priority comparison matches the ELBv2 contract: ``"default"`` is
    always evaluated LAST; everything else sorts as a positive integer
    ascending (lower number = higher precedence).
    """

    arn: str
    listener_arn: str
    priority: str  # "default" or stringified positive int
    conditions: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)

    @property
    def priority_key(self) -> int:
        if self.priority == "default":
            return 10_000_000  # last
        try:
            return int(self.priority)
        except ValueError:
            return 10_000_000


def _path_pattern_match(pattern: str, path: str) -> bool:
    """ALB path-pattern matching.

    Supports ``*`` (zero or more characters, including slashes) and ``?``
    (exactly one character) wildcards — that is the documented ALB
    semantics, NOT shell-glob's ``*`` (which doesn't cross ``/``). The
    request path is matched without its query string.
    """
    import re

    path_only = path.split("?", 1)[0]
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(regex, path_only) is not None


def _host_header_match(pattern: str, host: str) -> bool:
    """ALB host-header matching. Same wildcard semantics as path-patterns,
    plus the standard ``*.example.com`` use case. Host is compared
    case-insensitively per RFC 3986."""
    import re

    host = host.split(":", 1)[0].lower()
    pat = pattern.lower()
    regex = "^" + re.escape(pat).replace(r"\*", "[^.]*").replace(r"\?", ".") + "$"
    if re.match(regex, host) is not None:
        return True
    # Also accept the broader ``*`` wildcard semantics (matches dots too),
    # because real ALBs do — the documented behaviour differs between
    # host header (no-dot) and path pattern (any-char), but in practice
    # ALB hosts also accept dot-spanning ``*`` for many configurations.
    broad = "^" + re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(broad, host) is not None


def _condition_matches(cond: dict, *, host: str, path: str, headers, source_ip: str) -> bool:
    """Evaluate a single ELBv2 RuleCondition dict against the request."""
    field = (cond.get("Field") or "").lower()
    if field == "host-header":
        values = (cond.get("HostHeaderConfig") or {}).get("Values") or cond.get("Values") or []
        return any(_host_header_match(v, host) for v in values)
    if field == "path-pattern":
        values = (cond.get("PathPatternConfig") or {}).get("Values") or cond.get("Values") or []
        return any(_path_pattern_match(v, path) for v in values)
    if field == "http-header":
        cfg = cond.get("HttpHeaderConfig") or {}
        name = cfg.get("HttpHeaderName") or ""
        values = cfg.get("Values") or []
        actual = headers.get(name, "")
        return any(_path_pattern_match(v, actual) for v in values)
    if field == "source-ip":
        import ipaddress

        values = (cond.get("SourceIpConfig") or {}).get("Values") or []
        try:
            ip = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        for cidr in values:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    if field == "query-string":
        cfg = cond.get("QueryStringConfig") or {}
        kvs = cfg.get("Values") or []
        from urllib.parse import parse_qsl

        qs = path.split("?", 1)[1] if "?" in path else ""
        params = parse_qsl(qs, keep_blank_values=True)
        for kv in kvs:
            key = kv.get("Key")
            val = kv.get("Value")
            for pk, pv in params:
                if key is not None and not _path_pattern_match(key, pk):
                    continue
                if val is not None and not _path_pattern_match(val, pv):
                    continue
                return True
        return False
    # Unknown / unhandled fields default to "doesn't match" so the rule
    # is conservative — falling through to the listener's default action
    # is the AWS-compatible behaviour.
    return False


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    # Injected by server subclass
    _router: "ListenerRouter" = None  # type: ignore[assignment]
    _listener_arn: str = ""

    # Silence the default stderr logging
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        LOG.debug("elbv2-listener %s - " + format, self._listener_arn, *args)

    def _select_target_group_arn(self, listener: Listener) -> tuple[str, Optional[dict]]:
        """Walk rules in priority order; return the chosen target-group
        ARN plus the matched action dict (or None for the default-path
        fallback). Non-forward actions short-circuit by returning their
        action dict with an empty TG ARN — the caller renders the
        response directly without proxying."""
        host = self.headers.get("Host", "")
        rules = self._router.rules.get(self._listener_arn) or []
        for rule in sorted(rules, key=lambda r: r.priority_key):
            # An empty conditions list with priority "default" matches everything;
            # any other rule with no conditions cannot match (real ALB rejects it).
            if not rule.conditions and rule.priority != "default":
                continue
            all_match = all(
                _condition_matches(
                    c,
                    host=host,
                    path=self.path,
                    headers=self.headers,
                    source_ip=self.client_address[0],
                )
                for c in rule.conditions
            ) if rule.conditions else True
            if not all_match:
                continue
            for action in rule.actions:
                a_type = (action.get("Type") or "").lower()
                if a_type == "forward":
                    tg_arn = action.get("TargetGroupArn") or ""
                    if not tg_arn:
                        fw = action.get("ForwardConfig") or {}
                        tgs = fw.get("TargetGroups") or []
                        if tgs:
                            tg_arn = tgs[0].get("TargetGroupArn", "")
                    if tg_arn:
                        return tg_arn, None
                elif a_type in {"fixed-response", "redirect"}:
                    return "", action
            # If the matched rule had no actionable action (e.g. authenticate-*
            # is unsupported), fall through to the next rule.
        return listener.target_group_arn, None

    def _render_action(self, action: dict, listener: Listener) -> None:
        a_type = (action.get("Type") or "").lower()
        if a_type == "fixed-response":
            cfg = action.get("FixedResponseConfig") or {}
            status = int(cfg.get("StatusCode") or 200)
            body = (cfg.get("MessageBody") or "").encode("utf-8")
            content_type = cfg.get("ContentType") or "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
            return
        if a_type == "redirect":
            cfg = action.get("RedirectConfig") or {}
            status = 301 if cfg.get("StatusCode") == "HTTP_301" else 302
            scheme = (cfg.get("Protocol") or "#{protocol}").replace(
                "#{protocol}", listener.protocol.lower()
            ).lower()
            host = (cfg.get("Host") or "#{host}").replace(
                "#{host}", self.headers.get("Host", "").split(":", 1)[0]
            )
            port = (cfg.get("Port") or "#{port}").replace(
                "#{port}", str(listener.port)
            )
            req_path = self.path.split("?", 1)[0]
            req_query = self.path.split("?", 1)[1] if "?" in self.path else ""
            path = (cfg.get("Path") or "#{path}").replace("#{path}", req_path)
            query = (cfg.get("Query") or "#{query}").replace("#{query}", req_query)
            url = f"{scheme}://{host}:{port}{path}"
            if query:
                url += "?" + query
            self.send_response(status)
            self.send_header("Location", url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # Anything else (authenticate-cognito, etc) just falls through to 503.
        self.send_error(503, f"Unsupported action type {a_type}")

    def _handle(self) -> None:
        listener = self._router.listeners.get(self._listener_arn)
        if not listener:
            self.send_error(503, "Listener not available")
            return

        chosen_tg_arn, terminal_action = self._select_target_group_arn(listener)
        if terminal_action is not None:
            self._render_action(terminal_action, listener)
            return

        tg = self._router.target_groups.get(chosen_tg_arn)
        if not tg:
            self.send_error(503, "No target group")
            return

        # Sticky-target resolution: when stickiness is enabled and the
        # request carries a valid AWSALB cookie mapping to a live
        # target, route there. Otherwise pick fresh and remember the
        # mapping so the response can emit Set-Cookie.
        sticky_cfg = read_stickiness_config(chosen_tg_arn)
        sticky_active = (
            sticky_cfg.enabled and sticky_cfg.type == "lb_cookie"
        )
        sticky_cookie_to_emit: Optional[str] = None
        target: Optional[Target] = None
        if sticky_active:
            existing_cookie = parse_awsalb_cookie(
                self.headers.get("Cookie", ""),
            )
            if existing_cookie:
                pin = tg.sticky_store.lookup(existing_cookie)
                if pin is not None:
                    target = tg.target_by_key(pin.target_key)
                    if target is None:
                        # Target was deregistered — drop the stale pin
                        # and fall through to fresh selection. Per AWS:
                        # a new cookie gets minted in this case.
                        tg.sticky_store.forget(existing_cookie)
        if target is None:
            target = tg.pick_target()
            if target is not None and sticky_active:
                sticky_cookie_to_emit = fresh_cookie_id()
                tg.sticky_store.remember(
                    sticky_cookie_to_emit,
                    tg.target_key(target),
                    sticky_cfg.cookie_duration,
                )
        if not target:
            self.send_error(503, "No registered targets")
            return

        try:
            body_len = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            body_len = 0
        body = self.rfile.read(body_len) if body_len > 0 else None

        # WebSocket Upgrade tunneling. ALB supports the HTTP/1.1
        # Upgrade contract — the LB MUST forward the Upgrade headers
        # verbatim, expect a 101 Switching Protocols back from the
        # target, and then pipe bytes bidirectionally for the
        # lifetime of the connection. No re-balancing mid-stream;
        # the connection is pinned to the picked target.
        if _is_websocket_upgrade(self.headers):
            return self._handle_websocket(target, listener, body)

        # Lambda target group: invoke the function directly via boto3 with
        # the AWS-documented ALB→Lambda event shape, then translate the
        # function's response (statusCode/headers/body/isBase64Encoded)
        # back to an HTTP response. The HTTPConnection-based proxy path
        # cannot reach a function ARN.
        if target.lambda_arn:
            return self._handle_lambda_target(
                target, chosen_tg_arn, listener, body,
            )

        try:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=30)
            headers = {
                k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP
            }
            headers["X-Forwarded-For"] = self.client_address[0]
            headers["X-Forwarded-Proto"] = listener.protocol.lower()
            headers["X-Forwarded-Port"] = str(listener.port)
            conn.request(self.command, self.path, body=body, headers=headers)
            upstream = conn.getresponse()
            self.send_response(upstream.status, upstream.reason)
            for k, v in upstream.getheaders():
                if k.lower() in _HOP_BY_HOP:
                    continue
                self.send_header(k, v)
            if sticky_cookie_to_emit is not None:
                self.send_header(
                    "Set-Cookie",
                    build_set_cookie(
                        sticky_cookie_to_emit,
                        sticky_cfg.cookie_duration,
                        secure=listener.protocol.upper() == "HTTPS",
                    ),
                )
            data = upstream.read()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)
            conn.close()
        except Exception as e:
            LOG.debug("Upstream proxy error to %s:%s - %s", target.host, target.port, e)
            try:
                self.send_error(502, f"Bad Gateway: {e}")
            except Exception:
                pass

    def _handle_websocket(
        self, target: "Target", listener: "Listener",
        body: Optional[bytes],
    ) -> None:
        """Proxy an HTTP/1.1 WebSocket Upgrade.

        Opens a raw TCP socket to the picked target, replays the
        request line + headers verbatim (including ``Upgrade``,
        ``Connection``, ``Sec-WebSocket-*``), forwards any pre-buffered
        body bytes, reads the response status + headers, and — if the
        target returns ``101 Switching Protocols`` — splices both
        sockets bidirectionally until either end closes.

        Backend protocol is plain TCP (no TLS); the AWS contract is
        that ALB terminates client TLS and the target receives
        plain HTTP/WS. Same shape as the existing reverse proxy.
        """
        upstream = None
        try:
            upstream = socket.create_connection(
                (target.host, target.port), timeout=30,
            )
            # Build the upstream request: keep all original headers
            # (Upgrade / Connection / Sec-WebSocket-Key /
            # Sec-WebSocket-Version / Sec-WebSocket-Protocol) verbatim
            # — those are the handshake. Strip only Host (we set our
            # own) and Content-Length (no body on the GET).
            request_lines = [
                f"{self.command} {self.path} HTTP/1.1",
                f"Host: {target.host}:{target.port}",
                f"X-Forwarded-For: {self.client_address[0]}",
                f"X-Forwarded-Proto: {listener.protocol.lower()}",
                f"X-Forwarded-Port: {listener.port}",
            ]
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in ("host", "content-length"):
                    continue
                if lk in ("x-forwarded-for", "x-forwarded-proto", "x-forwarded-port"):
                    continue
                request_lines.append(f"{k}: {v}")
            wire = ("\r\n".join(request_lines) + "\r\n\r\n").encode("latin-1")
            upstream.sendall(wire)
            if body:
                upstream.sendall(body)

            # Read the response head until \r\n\r\n. The body of a 101
            # is empty by definition; for non-101 we copy what we read
            # plus drain the rest into the client.
            header_buf = b""
            while b"\r\n\r\n" not in header_buf:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                header_buf += chunk
                if len(header_buf) > 65536:
                    break

            # Splice the head straight to the client; the BaseHTTPRequest
            # Handler hasn't called send_response yet so we own the
            # wire from here.
            self.wfile.write(header_buf)
            self.wfile.flush()

            status_line = header_buf.split(b"\r\n", 1)[0]
            is_101 = b" 101 " in status_line or status_line.endswith(b" 101")
            if not is_101:
                # Backend declined the upgrade; the response head is
                # already on the wire. We do not propagate the
                # remaining body here because a non-101 response
                # makes the connection un-WebSocket; closing the
                # client side cleanly is the AWS-parity behavior.
                return

            # Splice phase. Two pipes — client→upstream and
            # upstream→client — joined until either side closes.
            _pipe_sockets(self.connection, upstream)
        except Exception as e:
            LOG.debug(
                "elbv2-listener websocket proxy error to %s:%s - %s",
                target.host, target.port, e,
            )
            try:
                self.send_error(502, f"Bad Gateway (websocket): {e}")
            except Exception:
                pass
        finally:
            try:
                if upstream is not None:
                    upstream.close()
            except Exception:
                pass

    def _handle_lambda_target(
        self, target: "Target", tg_arn: str, listener: "Listener",
        body: Optional[bytes],
    ) -> None:
        """ALB → Lambda forward.

        Builds the AWS-documented ELB Lambda event payload and invokes
        the function via the internal boto3 client. Parses ``statusCode``
        / ``headers`` / ``body`` / ``isBase64Encoded`` from the Lambda
        response and writes them back as the HTTP response.
        """
        import base64 as _b64
        import json as _json
        from urllib.parse import urlsplit, parse_qs

        try:
            from localemu.aws.connect import connect_to
            from localemu.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
        except Exception:
            self.send_error(502, "Bad Gateway: cannot reach LocalEmu Lambda client")
            return

        # Build the ELB-shaped Lambda event.
        split = urlsplit(self.path)
        path = split.path or "/"
        qs_raw = parse_qs(split.query, keep_blank_values=True)
        qs_single = {k: v[0] for k, v in qs_raw.items()}
        # Headers: lowercased single-string values (ALB→Lambda contract).
        hdr_single = {k.lower(): v for k, v in self.headers.items()}
        # Detect binary body so we can base64-flag it. Heuristic: not-text.
        is_b64 = False
        body_field = ""
        if body is not None:
            try:
                body_field = body.decode("utf-8")
            except Exception:
                body_field = _b64.b64encode(body).decode("ascii")
                is_b64 = True
        event = {
            "requestContext": {"elb": {"targetGroupArn": tg_arn}},
            "httpMethod": self.command,
            "path": path,
            "queryStringParameters": qs_single,
            "headers": hdr_single,
            "body": body_field,
            "isBase64Encoded": is_b64,
        }

        # Extract account/region from the ARN: arn:aws:lambda:<region>:<account>:function:<name>
        try:
            _, _, _, region, account_id, _, fn_name = target.lambda_arn.split(":", 6)
        except Exception:
            self.send_error(502, f"Bad Gateway: malformed Lambda ARN {target.lambda_arn!r}")
            return

        try:
            clients = connect_to(
                aws_access_key_id=account_id,
                aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                region_name=region,
            )
            resp = clients.lambda_.invoke(
                FunctionName=target.lambda_arn,
                InvocationType="RequestResponse",
                Payload=_json.dumps(event).encode("utf-8"),
            )
            raw = resp["Payload"].read()
        except Exception as e:
            LOG.debug("ALB→Lambda invoke failed for %s: %s", target.lambda_arn, e)
            try:
                self.send_error(502, f"Bad Gateway: Lambda invoke failed: {e}")
            except Exception:
                pass
            return

        try:
            payload = _json.loads(raw or b"{}")
        except Exception:
            self.send_error(502, "Bad Gateway: Lambda returned non-JSON payload")
            return

        status = int(payload.get("statusCode") or 200)
        headers = payload.get("headers") or {}
        out_body = payload.get("body") or ""
        if payload.get("isBase64Encoded"):
            try:
                out_bytes = _b64.b64decode(out_body)
            except Exception:
                out_bytes = b""
        else:
            out_bytes = (
                out_body.encode("utf-8") if isinstance(out_body, str)
                else bytes(out_body) if out_body else b""
            )

        self.send_response(status)
        for k, v in headers.items():
            if k.lower() in _HOP_BY_HOP:
                continue
            self.send_header(str(k), str(v))
        self.send_header("Content-Length", str(len(out_bytes)))
        self.end_headers()
        if out_bytes:
            self.wfile.write(out_bytes)

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()


def _localemu_cert_path() -> str:
    """Path to LocalEmu's self-signed cert PEM (key + cert in one file).

    Lazy-imports the SSL helper so listener_router stays importable in
    environments where the cert dir hasn't been initialised yet (e.g. the
    unit-test fast path); :func:`install_predefined_cert_if_available`
    generates the file on demand.
    """
    from localemu.utils.ssl import (
        get_cert_pem_file_path,
        install_predefined_cert_if_available,
    )

    install_predefined_cert_if_available()
    return get_cert_pem_file_path()


def _allocate_port() -> int:
    """Allocate an ephemeral TCP port by binding to :0 and releasing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))  # noqa: S104
        return s.getsockname()[1]


def _tcp_ping(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class ListenerRouter:
    """Singleton registry for ELBv2 load balancers, listeners, and target groups."""

    def __init__(self) -> None:
        self.load_balancers: dict[str, dict] = {}  # arn -> metadata
        self.listeners: dict[str, Listener] = {}
        self.target_groups: dict[str, TargetGroup] = {}
        # listener_arn -> list[Rule], evaluated in priority order on each request
        self.rules: dict[str, list[Rule]] = {}
        # rule_arn -> Rule (for O(1) modify/delete)
        self._rules_by_arn: dict[str, Rule] = {}
        self._lock = threading.RLock()
        self._health_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------ Load balancers ------------
    def register_lb(self, arn: str, name: str, dns_name: str, scheme: str, lb_type: str) -> None:
        with self._lock:
            self.load_balancers[arn] = {
                "arn": arn, "name": name, "dns_name": dns_name,
                "scheme": scheme, "type": lb_type,
            }

    # ------------ Target groups ------------
    def register_target_group(self, tg: TargetGroup) -> None:
        with self._lock:
            self.target_groups[tg.arn] = tg
            self._ensure_health_thread()

    def add_targets(self, tg_arn: str, targets: list[dict]) -> None:
        tg = self.target_groups.get(tg_arn)
        if not tg:
            return
        with tg._lock:
            for t in targets:
                tid = t.get("Id") or ""
                port = int(t.get("Port") or tg.port)
                # Lambda targets are AWS function ARNs — they are NOT routable
                # hostnames; trying to ``HTTPConnection(arn, port)`` raises
                # ``'idna' codec can't encode characters in position 0-63:
                # label too long``. Detect them here and let the forward
                # path branch on ``Target.lambda_arn``.
                if tid.startswith("arn:aws:lambda:") or tid.startswith("arn:aws-us-gov:lambda:") or tid.startswith("arn:aws-cn:lambda:"):
                    tg.targets[f"{tid}:{port}"] = Target(
                        target_id=tid, port=port, host="", lambda_arn=tid,
                    )
                    continue
                # For emulation, assume "Id" is either an IP or a hostname reachable locally.
                host = tid if _looks_like_host(tid) else "127.0.0.1"
                key = f"{tid}:{port}"
                tg.targets[key] = Target(target_id=tid, port=port, host=host)

    def remove_targets(self, tg_arn: str, targets: list[dict]) -> None:
        tg = self.target_groups.get(tg_arn)
        if not tg:
            return
        with tg._lock:
            for t in targets:
                tid = t.get("Id") or ""
                port = int(t.get("Port") or tg.port)
                tg.targets.pop(f"{tid}:{port}", None)

    def describe_target_health(self, tg_arn: str) -> list[dict]:
        tg = self.target_groups.get(tg_arn)
        if not tg:
            return []
        out = []
        with tg._lock:
            for t in tg.targets.values():
                # Active probe before responding so describe reflects current state.
                ok = _tcp_ping(t.host, tg.health_check_port or t.port)
                t.health = "healthy" if ok else "unhealthy"
                state = t.health
                reason = "Target.HealthyThresholdCount" if state == "healthy" else "Target.FailedHealthChecks"
                out.append({
                    "Target": {"Id": t.target_id, "Port": t.port},
                    "HealthCheckPort": str(tg.health_check_port or t.port),
                    "TargetHealth": {
                        "State": state,
                        "Reason": reason,
                        "Description": f"Target is {state}",
                    },
                })
        return out

    # ------------ Listeners ------------
    def start_listener(
        self, lb_arn: str, listener_arn: str, protocol: str, requested_port: int,
        target_group_arn: str,
    ) -> int:
        """Start an HTTP/HTTPS listener on a locally-allocated port, return actual port.

        HTTPS listeners terminate TLS using LocalEmu's self-signed
        certificate (``utils/ssl.get_cert_pem_file_path()``) — the same
        PEM served by the main gateway, so test clients only have to
        trust one root. Without this wrap, a TLS ClientHello on the
        listener port is interpreted as plain HTTP and the server
        replies with a 400 that the TLS client can't parse.
        """
        port = _allocate_port()

        class _Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

        listener = Listener(
            arn=listener_arn, lb_arn=lb_arn, protocol=protocol,
            port=requested_port, target_group_arn=target_group_arn,
        )

        handler_cls = type(
            f"ProxyHandler_{listener_arn[-8:]}",
            (_ProxyHandler,),
            {"_router": self, "_listener_arn": listener_arn},
        )

        try:
            server = _Server(("0.0.0.0", port), handler_cls)  # noqa: S104
        except OSError as e:
            LOG.warning("Could not bind listener %s on port %s: %s", listener_arn, port, e)
            return 0

        if (protocol or "").upper() in {"HTTPS", "TLS"}:
            try:
                cert_pem_path = _localemu_cert_path()
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(certfile=cert_pem_path)
                server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            except Exception as e:
                LOG.warning(
                    "Could not enable TLS on listener %s (%s); falling back to plain HTTP",
                    listener_arn, e,
                )

        thread = threading.Thread(
            target=server.serve_forever, name=f"elbv2-listener-{listener_arn[-8:]}",
            daemon=True,
        )
        thread.start()
        listener.server = server
        listener.thread = thread
        with self._lock:
            self.listeners[listener_arn] = listener
        LOG.info(
            "ELBv2 listener %s bound to 0.0.0.0:%s (advertised %s/%s)",
            listener_arn, port, protocol, requested_port,
        )
        return port

    # ------------ Listener rules ------------
    def register_rule(
        self,
        *,
        rule_arn: str,
        listener_arn: str,
        priority: str,
        conditions: list[dict],
        actions: list[dict],
    ) -> None:
        rule = Rule(
            arn=rule_arn,
            listener_arn=listener_arn,
            priority=str(priority),
            conditions=list(conditions or []),
            actions=list(actions or []),
        )
        with self._lock:
            # Drop any prior version of this rule first so modify-flows work.
            self._rules_by_arn[rule_arn] = rule
            existing = [r for r in self.rules.get(listener_arn, []) if r.arn != rule_arn]
            existing.append(rule)
            self.rules[listener_arn] = existing

    def remove_rule(self, rule_arn: str) -> None:
        with self._lock:
            rule = self._rules_by_arn.pop(rule_arn, None)
            if not rule:
                return
            remaining = [
                r for r in self.rules.get(rule.listener_arn, []) if r.arn != rule_arn
            ]
            if remaining:
                self.rules[rule.listener_arn] = remaining
            else:
                self.rules.pop(rule.listener_arn, None)

    def set_rule_priorities(self, mapping: dict[str, str]) -> None:
        """Update rule priorities in-place. ``mapping`` is rule_arn -> priority."""
        with self._lock:
            for rule_arn, priority in mapping.items():
                rule = self._rules_by_arn.get(rule_arn)
                if rule:
                    rule.priority = str(priority)

    def stop_listener(self, listener_arn: str) -> None:
        with self._lock:
            listener = self.listeners.pop(listener_arn, None)
            # Drop the rule table for this listener so a re-created listener
            # with the same ARN starts clean.
            for rule_arn in [
                r.arn for r in self.rules.get(listener_arn, [])
            ]:
                self._rules_by_arn.pop(rule_arn, None)
            self.rules.pop(listener_arn, None)
        if listener and listener.server:
            try:
                listener.server.shutdown()
                listener.server.server_close()
            except Exception:
                LOG.debug("Error stopping listener %s", listener_arn, exc_info=True)

    # ------------ Health check loop ------------
    def _ensure_health_thread(self) -> None:
        if self._health_thread and self._health_thread.is_alive():
            return
        self._health_thread = threading.Thread(
            target=self._health_loop, name="elbv2-health", daemon=True,
        )
        self._health_thread.start()

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            try:
                with self._lock:
                    tgs = list(self.target_groups.values())
                for tg in tgs:
                    with tg._lock:
                        targets = list(tg.targets.values())
                    for t in targets:
                        ok = _tcp_ping(t.host, tg.health_check_port or t.port, timeout=1.5)
                        t.health = "healthy" if ok else "unhealthy"
            except Exception:
                LOG.debug("Health loop iteration error", exc_info=True)
            self._stop.wait(10.0)


def _looks_like_host(s: str) -> bool:
    """Heuristic: return True if s looks like an IP or hostname (not an i-xxx instance id)."""
    if not s:
        return False
    if s.startswith("i-"):
        return False
    if "." in s or ":" in s:
        return True
    return False


# Singleton
_router_singleton: Optional[ListenerRouter] = None
_singleton_lock = threading.Lock()


def get_router() -> ListenerRouter:
    global _router_singleton
    if _router_singleton is not None:
        return _router_singleton
    with _singleton_lock:
        if _router_singleton is None:
            _router_singleton = ListenerRouter()
    return _router_singleton
