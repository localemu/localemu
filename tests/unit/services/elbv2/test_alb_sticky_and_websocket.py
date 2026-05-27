"""End-to-end integration tests for the ELBv2 listener proxy:

  * ``lb_cookie`` stickiness — a series of HTTP requests carrying the
    AWSALB cookie all land on the same target.
  * WebSocket Upgrade — a real WebSocket client handshakes through
    the listener to a real ws-echo backend and exchanges bytes.

These tests stand up the listener via boto3 against moto, then hit
the real ListenerRouter's HTTP server directly (no LocalEmu runtime
required). They live in tests/unit/ because they don't need Docker.
"""
from __future__ import annotations

import base64
import hashlib
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
import pytest
from moto import mock_aws

from localemu.services.elbv2.listener_router import (
    ListenerRouter, TargetGroup,
)
from localemu.services.elbv2.stickiness import AWSALB_COOKIE


# ---------------------------------------------------------------------------
# Helpers — minimal HTTP and WebSocket backends
# ---------------------------------------------------------------------------

class _IdEchoHandler(BaseHTTPRequestHandler):
    """Each backend reports its own port so the test can verify which
    target served a given request — that's all stickiness needs."""

    def log_message(self, *a, **kw):  # silence stderr
        pass

    def do_GET(self):
        body = f"port={self.server.server_address[1]}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_echo_backend() -> tuple[ThreadingHTTPServer, threading.Thread]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _IdEchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


def _free_listener_port() -> int:
    """The router allocates a port internally; we just need a target
    port that's free at the time of registration."""
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


@pytest.fixture
def two_backends_and_listener():
    """Spin up two echo backends, register them in a target group, start
    one HTTP listener via the real ListenerRouter — return enough refs
    for the test to drive HTTP requests at the listener.

    Stickiness is enabled on the TG up front so the listener honors it.
    The whole fixture body runs under ``mock_aws`` so the listener's
    runtime call to ``read_stickiness_config`` (which queries moto)
    sees the same backend that minted the ARN.
    """
    ctx = mock_aws()
    ctx.start()
    router = ListenerRouter()
    backend_a = backend_b = None
    listener_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/sticky/abc/def"
    try:
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")
        tg_meta = elbv2.create_target_group(
            Name="sticky-tg", Protocol="HTTP", Port=80,
            VpcId=vpc["VpcId"], TargetType="ip",
        )["TargetGroups"][0]
        elbv2.modify_target_group_attributes(
            TargetGroupArn=tg_meta["TargetGroupArn"],
            Attributes=[
                {"Key": "stickiness.enabled", "Value": "true"},
                {"Key": "stickiness.type", "Value": "lb_cookie"},
                {"Key": "stickiness.lb_cookie.duration_seconds", "Value": "3600"},
            ],
        )
        tg_arn = tg_meta["TargetGroupArn"]

        backend_a, _ = _start_echo_backend()
        backend_b, _ = _start_echo_backend()
        port_a = backend_a.server_address[1]
        port_b = backend_b.server_address[1]

        tg = TargetGroup(arn=tg_arn, name="sticky-tg", protocol="HTTP", port=80)
        router.register_target_group(tg)
        router.add_targets(tg_arn, [
            {"Id": "127.0.0.1", "Port": port_a},
            {"Id": "127.0.0.1", "Port": port_b},
        ])
        for t in tg.targets.values():
            t.health = "healthy"

        lb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/sticky/abc"
        router.register_lb(
            lb_arn, "sticky", "sticky.localhost", "internet-facing", "application",
        )
        actual_port = router.start_listener(
            lb_arn, listener_arn, "HTTP", 0, tg_arn,
        )
        yield {
            "router": router, "listener_arn": listener_arn,
            "tg_arn": tg_arn, "tg": tg,
            "listener_port": actual_port,
            "port_a": port_a, "port_b": port_b,
        }
    finally:
        try:
            router.stop_listener(listener_arn)
        except Exception:
            pass
        if backend_a:
            backend_a.shutdown()
        if backend_b:
            backend_b.shutdown()
        ctx.stop()


# ---------------------------------------------------------------------------
# Stickiness E2E
# ---------------------------------------------------------------------------

def _http_request(port: int, path: str, cookie: str | None = None,
                   timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: 127.0.0.1:{port}",
            "Connection: close",
        ]
        if cookie:
            lines.append(f"Cookie: {cookie}")
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        s.settimeout(timeout)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status_line, _, header_block = head.partition(b"\r\n")
    status = int(status_line.split(b" ")[1])
    headers: dict[str, str] = {}
    for line in header_block.split(b"\r\n"):
        if b":" in line:
            k, _, v = line.partition(b":")
            headers.setdefault(k.decode().strip(), v.decode().strip())
    return status, headers, body


class TestStickyCookiePinsToOneTarget:
    def test_first_request_emits_set_cookie(self, two_backends_and_listener):
        env = two_backends_and_listener
        status, headers, body = _http_request(env["listener_port"], "/")
        assert status == 200, body
        sc = headers.get("Set-Cookie", "")
        assert AWSALB_COOKIE in sc, f"expected AWSALB cookie; got {sc!r}"

    def test_cookied_requests_pin_to_one_backend(self, two_backends_and_listener):
        env = two_backends_and_listener
        # First request: capture the cookie + which backend served us
        _, headers, body = _http_request(env["listener_port"], "/")
        cookie_val = headers["Set-Cookie"].split(";")[0]  # "AWSALB=opaque"
        first_port = int(body.decode().split("=")[1])
        assert first_port in (env["port_a"], env["port_b"])

        # 20 follow-up requests with the cookie all hit the same backend
        for _ in range(20):
            _, _, b = _http_request(
                env["listener_port"], "/", cookie=cookie_val,
            )
            assert int(b.decode().split("=")[1]) == first_port

    def test_no_cookie_round_robins(self, two_backends_and_listener):
        """Without the AWSALB cookie the LB falls through to round-robin
        — over many requests we hit BOTH backends."""
        env = two_backends_and_listener
        seen = set()
        for _ in range(10):
            _, _, b = _http_request(env["listener_port"], "/")
            seen.add(int(b.decode().split("=")[1]))
            if len(seen) == 2:
                break
        assert seen == {env["port_a"], env["port_b"]}, (
            f"non-sticky requests should round-robin both backends; "
            f"saw {seen}"
        )

    def test_stale_cookie_target_gone_falls_back(self, two_backends_and_listener):
        """When the pinned target is deregistered, the LB picks a fresh
        target AND mints a new cookie."""
        env = two_backends_and_listener
        _, headers, body = _http_request(env["listener_port"], "/")
        cookie_val = headers["Set-Cookie"].split(";")[0]
        first_port = int(body.decode().split("=")[1])

        # Deregister the pinned target — the OTHER one should answer
        # subsequent requests, with a fresh Set-Cookie attached.
        env["router"].remove_targets(env["tg_arn"], [
            {"Id": "127.0.0.1", "Port": first_port},
        ])

        status, new_headers, new_body = _http_request(
            env["listener_port"], "/", cookie=cookie_val,
        )
        assert status == 200
        assert "Set-Cookie" in new_headers, (
            "stale cookie should mint a fresh AWSALB"
        )
        assert int(new_body.decode().split("=")[1]) != first_port


# ---------------------------------------------------------------------------
# WebSocket E2E — bring up a tiny ws-echo server and verify the
# listener tunnels frames through it.
# ---------------------------------------------------------------------------

def _ws_accept_key(client_key: str) -> str:
    """RFC 6455 §1.3: the server's Sec-WebSocket-Accept is
    base64(sha1(client_key + magic_guid))."""
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(
        hashlib.sha1((client_key + GUID).encode()).digest(),
    ).decode()


def _ws_echo_backend() -> ThreadingHTTPServer:
    """A trivial WebSocket server that accepts the handshake and
    echoes back any data it receives, frame-by-frame, without
    interpreting the frame structure (we just pipe bytes)."""
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def do_GET(self):
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = _ws_accept_key(key)
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            ).encode()
            self.wfile.write(resp); self.wfile.flush()
            # Echo loop: read raw bytes (frame headers + payloads —
            # the test doesn't bother decoding frames, it just expects
            # whatever the client wrote to come back).
            sock = self.connection
            sock.settimeout(5.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    sock.sendall(chunk)
            except Exception:
                pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _ws_handshake_and_echo(listener_port: int, payload: bytes) -> bytes:
    """Open a TCP connection to the listener, do an RFC 6455 handshake,
    send ONE WebSocket text frame containing ``payload``, read the
    echoed frame back, return its payload."""
    s = socket.create_connection(("127.0.0.1", listener_port), timeout=5)
    s.settimeout(5)
    try:
        client_key = base64.b64encode(b"12345678901234567890" * 1).decode()
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{listener_port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {client_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        s.sendall(req)
        # Read response head
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        assert b" 101 " in buf, (
            f"WS handshake did not return 101: {buf!r}"
        )
        # Send a single masked text frame: 0x81 (FIN + text), 0x80|len,
        # 4-byte mask, masked payload. Per RFC 6455.
        mask = b"ABCD"
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
        s.sendall(frame)
        # Read echoed frame: header (2 bytes) + payload (no mask back).
        head = s.recv(2)
        assert head[0] == 0x81, head
        # Server echo from our ws backend is the raw mask + masked
        # bytes (we copy verbatim). So strip the same way.
        rest = b""
        while len(rest) < len(mask) + len(masked):
            chunk = s.recv(64)
            if not chunk:
                break
            rest += chunk
        recv_mask = rest[:4]
        recv_payload_masked = rest[4:4 + len(payload)]
        return bytes(
            b ^ recv_mask[i % 4]
            for i, b in enumerate(recv_payload_masked)
        )
    finally:
        s.close()


class TestWebSocketUpgradeTunnels:
    def test_handshake_and_echo_through_listener(self):
        router = ListenerRouter()
        backend = _ws_echo_backend()
        port = backend.server_address[1]
        tg_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/ws/abcd"
        tg = TargetGroup(arn=tg_arn, name="ws", protocol="HTTP", port=80)
        router.register_target_group(tg)
        router.add_targets(tg_arn, [{"Id": "127.0.0.1", "Port": port}])
        for t in tg.targets.values():
            t.health = "healthy"
        listener_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/ws/abc/def"
        lb_arn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/ws/abc"
        router.register_lb(
            lb_arn, "ws", "ws.localhost", "internet-facing", "application",
        )
        listener_port = router.start_listener(
            lb_arn, listener_arn, "HTTP", 0, tg_arn,
        )
        try:
            echoed = _ws_handshake_and_echo(
                listener_port, b"hello-websocket",
            )
            assert echoed == b"hello-websocket"
        finally:
            router.stop_listener(listener_arn)
            backend.shutdown()
