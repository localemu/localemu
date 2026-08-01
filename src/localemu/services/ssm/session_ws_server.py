"""WebSocket server bridging ``aws ssm start-session`` to ``docker exec``.

Implements the server side of the AWS Session Manager binary protocol
(see :mod:`session_manager`). Each accepted WS connection is matched to
a session via ``SessionId`` in the URL path, validated against the
``TokenValue`` sent in the first text frame, then bridged to a
``docker exec -it <container> /bin/bash`` PTY.

Design choices
--------------
* **Dedicated TCP server**, not muxed onto the LocalEmu gateway. The
  gateway is hypercorn-based with bespoke routing; pulling a WS handler
  through it would be invasive. Allocating a single host port at
  service start (``ssm-session-ws``) gives a stable wss endpoint that
  the SSM API can hand out in ``StreamUrl``.
* **Sans-IO framing via ``wsproto``**: works with the stdlib socket
  loop, no extra runtime dependency added (``wsproto`` already in the
  environment).
* **One thread per connection**: WS connections are stateful, low
  fan-out (a developer's terminal) and need pseudo-real-time I/O.
  asyncio adds complexity without buying anything here.
* **PTY via ``pty.fork`` + ``docker exec -it``**: a real PTY on the
  host is forked, ``docker exec -it`` attaches the container's stdin/
  stdout to it. Window-size changes flow through ``ioctl(TIOCSWINSZ)``.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import pty
import select
import socket
import socketserver
import struct
import termios
import threading
from typing import Optional
from urllib.parse import parse_qs, urlparse

import wsproto
from wsproto.connection import ConnectionType
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
    TextMessage,
)

from localemu.services.ssm.port_mux_bridge import PortMuxBridge
from localemu.services.ssm.session_manager import (
    ClientMessage,
    MT_ACKNOWLEDGE,
    MT_INPUT_STREAM_DATA,
    PT_HANDSHAKE_RESPONSE,
    PT_OUTPUT,
    PT_SIZE,
    acknowledge_frame,
    channel_closed_frame,
    get_session_registry,
    handshake_complete_frame,
    handshake_request_frame,
    output_data_frame,
)

LOG = logging.getLogger(__name__)


# Default bind: any free local port. Override via ``SSM_SESSION_WS_PORT``
# for stable URLs across restarts (e.g. when a load-balancer in front
# of LocalEmu pins a target port).
def _resolve_bind_port() -> int:
    raw = os.environ.get("SSM_SESSION_WS_PORT", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            LOG.warning("Invalid SSM_SESSION_WS_PORT=%r, picking a free port", raw)
    return 0  # 0 = let the OS pick a free one


class _WsConnectionHandler(socketserver.BaseRequestHandler):
    """One per accepted TCP connection."""

    server: "SessionWsServer"

    def handle(self) -> None:
        sock: socket.socket = self.request
        try:
            ws = wsproto.WSConnection(ConnectionType.SERVER)
            session_id = self._do_handshake(sock, ws)
            if session_id is None:
                return
            sess = self._authenticate(sock, ws, session_id)
            if sess is None:
                return
            self._bridge(sock, ws, sess)
        except Exception:
            LOG.warning("SSM Session WS handler failed", exc_info=True)
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    # ------------------------------------------------------------------
    # Phase 1: HTTP/Upgrade
    # ------------------------------------------------------------------

    def _do_handshake(self, sock: socket.socket, ws: wsproto.WSConnection) -> str | None:
        """Read the HTTP request, validate the path, accept the upgrade.

        Returns the SessionId parsed from the URL, or None on rejection.
        """
        data = b""
        sock.settimeout(10.0)
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            data += chunk
            if len(data) > 16384:
                self._send_raw(sock, b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                return None

        ws.receive_data(data)
        request: Request | None = None
        for evt in ws.events():
            if isinstance(evt, Request):
                request = evt
                break
        if request is None:
            self._send_raw(sock, b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return None

        # Expected target: /v1/data-channel/<SessionId>?role=publish_subscribe
        parsed = urlparse(request.target)
        path = parsed.path
        prefix = "/v1/data-channel/"
        if not path.startswith(prefix):
            self._reject(sock, ws, 404, "unknown channel")
            return None
        session_id = path[len(prefix):]
        if not session_id:
            self._reject(sock, ws, 400, "missing sessionId")
            return None
        # Role check is informational - AWS only uses publish_subscribe.
        qs = parse_qs(parsed.query)
        role = (qs.get("role") or [""])[0]
        if role and role != "publish_subscribe":
            LOG.info("SSM WS: unexpected role=%r for session %s", role, session_id)

        sock.sendall(ws.send(AcceptConnection()))
        return session_id

    @staticmethod
    def _send_raw(sock: socket.socket, body: bytes) -> None:
        try:
            sock.sendall(body)
        except OSError:
            pass

    def _reject(
        self, sock: socket.socket, ws: wsproto.WSConnection,
        status: int, reason: str,
    ) -> None:
        # wsproto can't synthesize an arbitrary HTTP error response after
        # parsing a Request; send a hand-built one.
        body = reason.encode()
        self._send_raw(
            sock,
            (
                f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Content-Type: text/plain\r\n\r\n"
            ).encode() + body,
        )

    # ------------------------------------------------------------------
    # Phase 2: validate TokenValue in the first text frame
    # ------------------------------------------------------------------

    def _authenticate(
        self, sock: socket.socket, ws: wsproto.WSConnection, session_id: str,
    ):
        """Read one TEXT frame with ``OpenDataChannelInput``, validate token.

        Also responds to WebSocket Ping control frames with Pong. The
        session-manager-plugin fires ``StartPings`` immediately after the
        WebSocket upgrade completes (see aws/session-manager-plugin
        src/communicator/websocketchannel.go#StartPings), so the first
        Ping typically arrives BEFORE the client's OpenDataChannel auth
        text frame. ``wsproto`` does not auto-Pong. If we swallow the
        Ping the plugin's ReadDeadline eventually fires and the session
        stalls.
        """
        sock.settimeout(15.0)
        buf = ""
        while True:
            for evt in ws.events():
                if isinstance(evt, TextMessage):
                    buf += evt.data
                    if evt.message_finished:
                        try:
                            payload = json.loads(buf)
                        except json.JSONDecodeError:
                            self._close_ws(sock, ws, 1003, "bad json")
                            return None
                        token = payload.get("TokenValue", "")
                        sess = get_session_registry().get(session_id)
                        if sess is None or sess.token_value != token:
                            self._close_ws(sock, ws, 4401, "invalid token")
                            return None
                        return sess
                elif isinstance(evt, Ping):
                    try:
                        sock.sendall(ws.send(Pong(payload=evt.payload)))
                    except OSError:
                        return None
                elif isinstance(evt, CloseConnection):
                    return None
            chunk = sock.recv(4096)
            if not chunk:
                return None
            ws.receive_data(chunk)

    # ------------------------------------------------------------------
    # Phase 3: handshake (SessionType=Standard_Stream) + bidirectional pipe
    # ------------------------------------------------------------------

    def _bridge(self, sock: socket.socket, ws: wsproto.WSConnection, sess) -> None:
        """Bidirectional pipe: WS binary ↔ docker exec PTY.

        Sequence-number contract (matches real amazon-ssm-agent /
        session-manager-plugin, verified against
        aws/session-manager-plugin src/datachannel/streaming.go) :

        * ``output_stream_data`` frames the server sends to the plugin
          carry a strictly monotonic sequence number starting at 0.
          The plugin's ``HandleOutputMessage`` gates dispatch on
          ``outputMessage.SequenceNumber == ExpectedSequenceNumber``;
          any gap parks the frame in an IncomingMessageBuffer and no
          handler runs. That means ``handshake_complete`` MUST arrive
          at seq=1 (the next after ``handshake_request`` at seq=0),
          shell output at seq=2, and so on. If we mixed ACK sequence
          numbers into this counter the plugin would freeze waiting
          for a seq that never arrives.

        * ``acknowledge`` frames the server sends back for the plugin's
          own frames carry ``SequenceNumber = 0`` unconditionally
          (see plugin ``SerializeClientMessageWithAcknowledgeContent``).
          They are dispatched by MessageId in ``HandleAcknowledgeMessage``,
          not by sequence.
        """
        session_type = getattr(sess, "session_type", "Standard_Stream")
        session_properties = getattr(sess, "session_properties", None)

        # Port sessions get a dedicated bridge : the plugin's MUX port
        # forwarder wraps every tunnel byte in SMUX v1 framing, so we
        # cannot reuse the shell path's single-fd tunnel. See
        # :mod:`port_mux_bridge` for the protocol implementation.
        if session_type == "Port":
            self._bridge_port(sock, ws, sess, session_properties)
            return
        self._bridge_shell(sock, ws, sess, session_type, session_properties)

    def _bridge_shell(
        self,
        sock: socket.socket,
        ws: wsproto.WSConnection,
        sess,
        session_type: str,
        session_properties: Optional[dict],
    ) -> None:
        """The ``Standard_Stream`` shell path : WS ↔ ``docker exec -it`` PTY."""
        pid, pty_fd = self._spawn_docker_exec(sess.container_name)
        try:
            stream_out_seq = 0  # strictly monotonic, output_stream_data only
            in_seq_ack = 0
            # Send handshake-request as the first output_stream_data frame.
            sock.sendall(ws.send(BytesMessage(
                handshake_request_frame(
                    stream_out_seq,
                    session_type=session_type,
                    properties=session_properties,
                ).serialize(),
            )))
            stream_out_seq += 1

            sock.setblocking(False)
            sock.settimeout(None)
            os.set_blocking(pty_fd, False)

            handshake_done = False

            while True:
                rlist, _, _ = select.select([sock, pty_fd], [], [], 1.0)

                # WS → PTY
                if sock in rlist:
                    chunk = b""
                    try:
                        chunk = sock.recv(65536)
                    except BlockingIOError:
                        chunk = b""
                    if not chunk:
                        break
                    ws.receive_data(chunk)
                    for evt in ws.events():
                        if isinstance(evt, BytesMessage):
                            try:
                                msg = ClientMessage.deserialize(evt.data)
                            except Exception:
                                continue
                            # The plugin's own outbound ``acknowledge``
                            # frames must NOT be ACK'd back (real
                            # amazon-ssm-agent doesn't either - ACKs
                            # are fire-and-forget on both ends,
                            # matched by MessageId+SequenceNumber, not
                            # by counter-ACK). ACKing an ACK triggers
                            # a plugin ``SetOnMessage`` re-entry that
                            # dereferences ``portSessionType`` state
                            # before it is fully initialised - the
                            # WS receive goroutine panics and no
                            # further messages get processed.
                            if msg.message_type == MT_ACKNOWLEDGE:
                                continue
                            sock.sendall(ws.send(BytesMessage(
                                acknowledge_frame(msg, 0).serialize(),
                            )))
                            if msg.payload_type == PT_HANDSHAKE_RESPONSE:
                                sock.sendall(ws.send(BytesMessage(
                                    handshake_complete_frame(
                                        stream_out_seq,
                                    ).serialize(),
                                )))
                                stream_out_seq += 1
                                handshake_done = True
                                continue
                            if not handshake_done:
                                continue
                            if msg.message_type == MT_INPUT_STREAM_DATA \
                                    and msg.payload_type == PT_OUTPUT:
                                try:
                                    os.write(pty_fd, msg.payload)
                                except OSError:
                                    pass
                                in_seq_ack = max(in_seq_ack, msg.sequence_number)
                            elif msg.payload_type == PT_SIZE:
                                self._resize_pty(pty_fd, msg.payload)
                        elif isinstance(evt, CloseConnection):
                            return
                        elif isinstance(evt, Ping):
                            sock.sendall(ws.send(Pong(payload=evt.payload)))

                # PTY → WS
                if handshake_done and pty_fd in rlist:
                    try:
                        data = os.read(pty_fd, 65536)
                    except BlockingIOError:
                        data = b""
                    except OSError:
                        break
                    if not data:
                        break
                    frame = output_data_frame(stream_out_seq, data)
                    sock.sendall(ws.send(BytesMessage(frame.serialize())))
                    stream_out_seq += 1

                # Reap the exec child when it exits.
                try:
                    wpid, _status = os.waitpid(pid, os.WNOHANG)
                    if wpid == pid:
                        try:
                            data = os.read(pty_fd, 65536)
                            if data:
                                sock.sendall(ws.send(BytesMessage(
                                    output_data_frame(
                                        stream_out_seq, data,
                                    ).serialize(),
                                )))
                                stream_out_seq += 1
                        except OSError:
                            pass
                        break
                except ChildProcessError:
                    break
        finally:
            try:
                os.close(pty_fd)
            except OSError:
                pass
            try:
                sock.sendall(ws.send(BytesMessage(
                    channel_closed_frame(0, sess.session_id, "session ended").serialize(),
                )))
                sock.sendall(ws.send(CloseConnection(code=1000, reason="bye")))
            except OSError:
                pass
            get_session_registry().remove(sess.session_id)
            try:
                os.kill(pid, 9)
            except (OSError, ProcessLookupError):
                pass

    def _bridge_port(
        self,
        sock: socket.socket,
        ws: wsproto.WSConnection,
        sess,
        session_properties: Optional[dict],
    ) -> None:
        """``Port`` (SMUX v1 mux) path : plugin wraps every tunnel byte
        in an ``xtaci/smux`` header and multiplexes multiple local
        connections onto one WebSocket. We speak the same wire.

        Layout, from the plugin (verified against
        ``session-manager-plugin/src/sessionmanagerplugin/session/portsession/muxportforwarding.go``
        + ``xtaci/smux/frame.go``) :

            | ver(1) | cmd(1) | length(2 LE) | sid(4 LE) | payload |

        Commands: SYN=0, FIN=1, PSH=2, NOP=3. Each new local TCP
        connection on the plugin side is a fresh ``sid``. We open a
        ``docker exec -i nc 127.0.0.1 <port>`` per ``sid``, splice its
        stdout into PSH frames, and its stdin from received PSH data.
        """
        target_port = int((session_properties or {}).get("portNumber", "0"))
        bridge = PortMuxBridge(
            container_name=sess.container_name,
            target_port=target_port,
        )
        try:
            stream_out_seq = 0
            in_seq_ack = 0
            sock.sendall(ws.send(BytesMessage(
                handshake_request_frame(
                    stream_out_seq,
                    session_type="Port",
                    properties=session_properties,
                ).serialize(),
            )))
            stream_out_seq += 1

            sock.setblocking(False)
            sock.settimeout(None)

            handshake_done = False

            while True:
                stream_fds = bridge.readable_fds()
                rlist, _, _ = select.select(
                    [sock, *stream_fds], [], [], 1.0,
                )

                # WS -> bridge
                if sock in rlist:
                    chunk = b""
                    try:
                        chunk = sock.recv(65536)
                    except BlockingIOError:
                        chunk = b""
                    if not chunk:
                        break
                    ws.receive_data(chunk)
                    for evt in ws.events():
                        if isinstance(evt, BytesMessage):
                            try:
                                msg = ClientMessage.deserialize(evt.data)
                            except Exception:
                                continue
                            # See ``_bridge_shell`` for the rationale.
                            # For Port sessions the drop-ACK-on-ACK
                            # rule is not optional : ACKing an ACK
                            # tickles a nil-deref panic in the
                            # plugin's ``MuxPortForwarding``
                            # ``SetOnMessage`` handler while its
                            # ``muxClient`` is still being wired up.
                            if msg.message_type == MT_ACKNOWLEDGE:
                                continue
                            sock.sendall(ws.send(BytesMessage(
                                acknowledge_frame(msg, 0).serialize(),
                            )))
                            if msg.payload_type == PT_HANDSHAKE_RESPONSE:
                                sock.sendall(ws.send(BytesMessage(
                                    handshake_complete_frame(
                                        stream_out_seq,
                                    ).serialize(),
                                )))
                                stream_out_seq += 1
                                handshake_done = True
                                continue
                            if not handshake_done:
                                continue
                            if msg.message_type == MT_INPUT_STREAM_DATA \
                                    and msg.payload_type == PT_OUTPUT:
                                # Feed the mux decoder ; may spawn new
                                # streams, forward data, or close streams.
                                bridge.feed_from_plugin(msg.payload)
                                in_seq_ack = max(in_seq_ack, msg.sequence_number)
                        elif isinstance(evt, CloseConnection):
                            return
                        elif isinstance(evt, Ping):
                            sock.sendall(ws.send(Pong(payload=evt.payload)))

                # streams -> WS
                if handshake_done:
                    for outbound in bridge.drain_stream_reads(rlist):
                        sock.sendall(ws.send(BytesMessage(
                            output_data_frame(
                                stream_out_seq, outbound,
                            ).serialize(),
                        )))
                        stream_out_seq += 1
        finally:
            bridge.close_all()
            try:
                sock.sendall(ws.send(BytesMessage(
                    channel_closed_frame(
                        0, sess.session_id, "session ended",
                    ).serialize(),
                )))
                sock.sendall(ws.send(CloseConnection(code=1000, reason="bye")))
            except OSError:
                pass
            get_session_registry().remove(sess.session_id)

    @staticmethod
    def _close_ws(sock: socket.socket, ws: wsproto.WSConnection, code: int, reason: str) -> None:
        try:
            sock.sendall(ws.send(CloseConnection(code=code, reason=reason)))
        except OSError:
            pass

    @staticmethod
    def _spawn_docker_exec(container_name: str) -> tuple[int, int]:
        """``pty.fork`` + ``docker exec -it`` so the shell sees a real TTY."""
        pid, fd = pty.fork()
        if pid == 0:
            # Child - replace with docker exec
            try:
                os.execvp("docker", [
                    "docker", "exec", "-it", container_name,
                    "/bin/sh", "-c",
                    # bash if present, fall back to sh; ``-i`` for prompt.
                    "if command -v bash >/dev/null 2>&1; then exec bash -i; else exec sh -i; fi",
                ])
            except Exception as exc:
                os.write(2, f"[localemu] docker exec failed: {exc}\n".encode())
                os._exit(127)
        return pid, fd

    @staticmethod
    def _resize_pty(fd: int, payload: bytes) -> None:
        """Honor a Size frame from the plugin (cols/rows JSON)."""
        try:
            data = json.loads(payload)
            cols = int(data.get("cols") or 80)
            rows = int(data.get("rows") or 24)
            fcntl.ioctl(fd, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except Exception:
            LOG.debug("PTY resize failed", exc_info=True)


class _ThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class SessionWsServer:
    """Singleton: bind once at SSM service start, expose ``port``."""

    def __init__(self) -> None:
        self._server: _ThreadingTcpServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int | None = None

    @property
    def port(self) -> int:
        return self._port or 0

    def start(self) -> int:
        if self._server is not None:
            return self.port
        port = _resolve_bind_port()
        srv = _ThreadingTcpServer(("0.0.0.0", port), _WsConnectionHandler)
        srv.server_obj = self  # type: ignore[attr-defined]
        self._server = srv
        self._port = srv.server_address[1]
        self._thread = threading.Thread(
            target=srv.serve_forever,
            name="ssm-session-ws",
            daemon=True,
        )
        self._thread.start()
        LOG.info(
            "SSM Session Manager WebSocket server listening on port %d",
            self._port,
        )
        return self._port

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                LOG.debug("WS server shutdown error", exc_info=True)
        self._server = None
        self._thread = None
        self._port = None


_singleton: SessionWsServer | None = None
_singleton_lock = threading.Lock()


def get_ws_server() -> SessionWsServer:
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SessionWsServer()
    return _singleton
