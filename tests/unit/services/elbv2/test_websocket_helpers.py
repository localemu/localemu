"""Tests for the WebSocket helpers in listener_router.

The full tunneling path is exercised by the ALB E2E
(test_alb_websocket_e2e.py) — a real client connects to a real
ws-echo backend through the listener. Here we pin the pure
predicates so behavior under odd header shapes is documented.
"""
from __future__ import annotations

import socket
import threading
import time

from localemu.services.elbv2.listener_router import (
    _is_websocket_upgrade, _pipe_sockets,
)


class _Headers(dict):
    """Tiny case-insensitive headers shim for the tests — mimics
    BaseHTTPRequestHandler's headers object enough for .get()."""
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class TestIsWebsocketUpgrade:
    def test_proper_upgrade(self):
        assert _is_websocket_upgrade(_Headers({
            "Upgrade": "websocket",
            "Connection": "Upgrade",
        })) is True

    def test_case_insensitive_upgrade_value(self):
        assert _is_websocket_upgrade(_Headers({
            "Upgrade": "WebSocket",
            "Connection": "upgrade",
        })) is True

    def test_connection_with_multiple_tokens(self):
        """Browsers often send ``Connection: keep-alive, Upgrade``."""
        assert _is_websocket_upgrade(_Headers({
            "Upgrade": "websocket",
            "Connection": "keep-alive, Upgrade",
        })) is True

    def test_missing_upgrade(self):
        assert _is_websocket_upgrade(_Headers({
            "Connection": "Upgrade",
        })) is False

    def test_missing_connection(self):
        assert _is_websocket_upgrade(_Headers({
            "Upgrade": "websocket",
        })) is False

    def test_wrong_upgrade_protocol(self):
        """``Upgrade: h2c`` is HTTP/2 cleartext, not WebSocket."""
        assert _is_websocket_upgrade(_Headers({
            "Upgrade": "h2c",
            "Connection": "Upgrade",
        })) is False

    def test_plain_keepalive_does_not_count(self):
        """The most important negative — standard HTTP/1.1 keep-alive
        must NOT trigger the WebSocket tunnel path."""
        assert _is_websocket_upgrade(_Headers({
            "Connection": "keep-alive",
        })) is False


class TestPipeSockets:
    def test_bidirectional_pump_then_close(self):
        """Use socketpair × 2 to simulate a client ↔ LB and LB ↔ backend
        connection. Spin _pipe_sockets in a thread, write on one end,
        confirm bytes appear on the other."""
        client, lb_to_client = socket.socketpair()
        lb_to_upstream, upstream = socket.socketpair()

        # _pipe_sockets pipes between (lb_to_client) and (lb_to_upstream).
        t = threading.Thread(
            target=_pipe_sockets, args=(lb_to_client, lb_to_upstream),
            daemon=True,
        )
        t.start()

        try:
            client.sendall(b"hello-from-client")
            time.sleep(0.05)
            got = upstream.recv(64)
            assert got == b"hello-from-client"

            upstream.sendall(b"reply-from-upstream")
            time.sleep(0.05)
            got = client.recv(64)
            assert got == b"reply-from-upstream"
        finally:
            client.close(); upstream.close()
            t.join(timeout=2)
        assert not t.is_alive(), "pipe should have terminated on close"
