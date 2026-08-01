"""``PortMuxBridge`` : SMUX v1 stream lifecycle.

Docker is stubbed with an in-process ``stream_factory`` : each
``SYN`` opens a plain ``socketpair`` whose child end is served by a
tiny in-thread echo (or fixed-response) responder. That exercises
the real SMUX decode + PSH chunking + FIN emission without needing
a container.
"""
from __future__ import annotations

import socket
import threading

import pytest

from localemu.services.ssm.port_mux_bridge import PortMuxBridge
from localemu.services.ssm.smux_v1 import (
    CMD_FIN,
    CMD_NOP,
    CMD_PSH,
    CMD_SYN,
    SmuxDecoder,
    encode_frame,
)


def _make_factory(responder):
    """Return a ``stream_factory`` that runs ``responder(child_sock)`` in a
    daemon thread on the child end of a fresh socketpair.
    """
    def factory(container_name: str, target_port: int):
        parent_sock, child_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM,
        )
        t = threading.Thread(target=responder, args=(child_sock,), daemon=True)
        t.start()
        return 0, parent_sock  # pid=0 → bridge skips waitpid
    return factory


def _drain_all(bridge: PortMuxBridge, timeout: float = 1.0) -> bytes:
    """Poll ``bridge`` until no readable stream fds or timeout hit."""
    import select
    import time

    end = time.monotonic() + timeout
    out = bytearray()
    while time.monotonic() < end:
        fds = bridge.readable_fds()
        if not fds:
            break
        rlist, _, _ = select.select(fds, [], [], 0.05)
        if not rlist:
            continue
        for chunk in bridge.drain_stream_reads(rlist):
            out.extend(chunk)
    return bytes(out)


# ----- SYN → open stream ----------------------------------------------


def test_syn_opens_stream_and_readable_fd_appears():
    factory = _make_factory(lambda sock: sock.recv(1024))  # noop reader
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    assert bridge.readable_fds() == []
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    assert len(bridge.readable_fds()) == 1
    bridge.close_all()


def test_duplicate_syn_is_idempotent():
    factory = _make_factory(lambda sock: sock.recv(1024))
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    assert len(bridge.readable_fds()) == 1
    bridge.close_all()


# ----- PSH → forwards bytes to target ---------------------------------


def test_psh_forwards_payload_to_stream_end():
    received = bytearray()

    def responder(sock):
        # Read once, echo nothing back - we only assert the forwarded bytes.
        chunk = sock.recv(4096)
        received.extend(chunk)
        sock.close()

    factory = _make_factory(responder)
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=7))
    bridge.feed_from_plugin(encode_frame(CMD_PSH, sid=7, payload=b"HELLO-TARGET"))
    # Give the responder thread a moment.
    import time
    for _ in range(20):
        if received:
            break
        time.sleep(0.02)
    assert bytes(received) == b"HELLO-TARGET"
    bridge.close_all()


def test_psh_on_unknown_sid_is_silently_dropped():
    bridge = PortMuxBridge("c", 8000, stream_factory=_make_factory(lambda s: s.recv(0)))
    # No SYN before this - must not raise, must not open a stream.
    bridge.feed_from_plugin(encode_frame(CMD_PSH, sid=99, payload=b"lost"))
    assert bridge.readable_fds() == []
    bridge.close_all()


# ----- responder → PSH frames back to plugin --------------------------


def test_target_response_comes_back_as_psh_frames_with_matching_sid():
    def responder(sock):
        sock.recv(1024)  # drain request
        sock.sendall(b"HTTP/1.0 200 OK\r\n\r\nHELLO")

    factory = _make_factory(responder)
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=42))
    bridge.feed_from_plugin(encode_frame(CMD_PSH, sid=42, payload=b"GET /\r\n\r\n"))
    wire = _drain_all(bridge)
    # The wire may contain one or more PSH frames + one FIN when the
    # responder closes the socket.
    dec = SmuxDecoder()
    frames = dec.feed(wire)
    psh = b"".join(f.payload for f in frames if f.cmd == CMD_PSH and f.sid == 42)
    assert psh == b"HTTP/1.0 200 OK\r\n\r\nHELLO"
    fin = [f for f in frames if f.cmd == CMD_FIN and f.sid == 42]
    assert fin, "expected a FIN when responder closed the socket"
    bridge.close_all()


def test_large_response_is_chunked_into_multiple_psh_frames():
    payload = b"a" * (0x10000 + 100)  # 65,636 bytes > MAX_PAYLOAD (0xFFFF)

    def responder(sock):
        sock.recv(1024)
        sock.sendall(payload)

    factory = _make_factory(responder)
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    bridge.feed_from_plugin(encode_frame(CMD_PSH, sid=1, payload=b"go"))
    wire = _drain_all(bridge, timeout=2.0)
    dec = SmuxDecoder()
    frames = dec.feed(wire)
    psh = [f for f in frames if f.cmd == CMD_PSH and f.sid == 1]
    assert len(psh) >= 2
    assert b"".join(f.payload for f in psh) == payload
    bridge.close_all()


# ----- FIN → half-close and NOP → ignored -----------------------------


def test_fin_half_closes_writes_to_stream():
    saw_eof = threading.Event()

    def responder(sock):
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                saw_eof.set()
                sock.close()
                return

    factory = _make_factory(responder)
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    bridge.feed_from_plugin(encode_frame(CMD_PSH, sid=1, payload=b"data"))
    bridge.feed_from_plugin(encode_frame(CMD_FIN, sid=1))
    assert saw_eof.wait(timeout=1.0), "responder should have seen EOF after FIN"
    bridge.close_all()


def test_nop_is_ignored():
    bridge = PortMuxBridge("c", 8000, stream_factory=_make_factory(lambda s: None))
    # No exception, no stream opened.
    bridge.feed_from_plugin(encode_frame(CMD_NOP, sid=0))
    assert bridge.readable_fds() == []
    bridge.close_all()


# ----- close_all is idempotent + cleans up state ----------------------


def test_close_all_drops_all_stream_state():
    factory = _make_factory(lambda sock: sock.recv(1024))
    bridge = PortMuxBridge("c", 8000, stream_factory=factory)
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=1))
    bridge.feed_from_plugin(encode_frame(CMD_SYN, sid=2))
    assert len(bridge.readable_fds()) == 2
    bridge.close_all()
    assert bridge.readable_fds() == []
    bridge.close_all()  # idempotent


# ----- protocol error propagates --------------------------------------


def test_bad_version_byte_from_plugin_raises_protocol_error():
    bridge = PortMuxBridge("c", 8000, stream_factory=_make_factory(lambda s: None))
    with pytest.raises(Exception):
        bridge.feed_from_plugin(b"\x02\x00\x00\x00\x00\x00\x00\x00")
