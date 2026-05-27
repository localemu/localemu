"""ELBv2 HTTPS listeners must actually terminate TLS.

The old listener_router opened ``http.server.ThreadingHTTPServer`` for
every listener regardless of protocol; an HTTPS:443 listener bound a
plain HTTP socket on 443, and the first TLS ClientHello from a real
ALB client was interpreted as garbage HTTP and replied with an HTTP/1.x
400 — silently breaking every HTTPS test.

This test wires up a target on a free port, starts an HTTPS listener
in front of it, and verifies a real ``requests``-style TLS GET goes
through and the X-Forwarded-Proto header reflects ``https``.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import threading
import urllib.request
from contextlib import closing
from typing import Optional


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Target(http.server.BaseHTTPRequestHandler):
    """Trivial echo target — records the X-Forwarded-Proto header it sees."""

    last_xff_proto: Optional[str] = None

    def log_message(self, *_, **__):  # noqa: D401
        return  # silence

    def do_GET(self):  # noqa: N802
        type(self).last_xff_proto = self.headers.get("X-Forwarded-Proto")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def _start_target() -> tuple[http.server.ThreadingHTTPServer, int]:
    port = _free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def test_https_listener_terminates_tls_and_proxies_to_target():
    from localemu.services.elbv2.listener_router import ListenerRouter

    target_server, target_port = _start_target()
    tg_arn = "arn:aws:elasticloadbalancing:::targetgroup/tg-e3/abc"
    try:
        from localemu.services.elbv2.listener_router import TargetGroup

        router = ListenerRouter()
        router.register_target_group(
            TargetGroup(arn=tg_arn, name="tg-e3", protocol="HTTP", port=target_port)
        )
        router.add_targets(tg_arn, [{"Id": "127.0.0.1", "Port": target_port}])
        listener_port = router.start_listener(
            lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb-e3",
            listener_arn="arn:aws:elasticloadbalancing:::listener/lb-e3/443",
            protocol="HTTPS",
            requested_port=443,
            target_group_arn=tg_arn,
        )
        assert listener_port > 0

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"https://127.0.0.1:{listener_port}/anything"
        with urllib.request.urlopen(url, context=ctx, timeout=5) as resp:  # noqa: S310
            body = resp.read()
            assert resp.status == 200
            assert body == b"ok"

        assert _Target.last_xff_proto == "https"
    finally:
        try:
            router.stop_listener(
                "arn:aws:elasticloadbalancing:::listener/lb-e3/443"
            )
        except Exception:
            pass
        target_server.shutdown()
        target_server.server_close()
