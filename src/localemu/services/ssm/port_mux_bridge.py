"""SMUX v1 mux state for one SSM Port session.

The session-manager-plugin opens one SMUX stream per accepted local
TCP connection. Each stream identifier (``sid``) needs its own tunnel
to the target instance's ``127.0.0.1:<portNumber>``. LocalEmu spawns
one ``docker exec -i <container> nc 127.0.0.1 <port>`` subprocess per
``sid`` - cheap and lets each stream close independently.

Why not one shared subprocess with an in-process fan-in?

* The target port at ``127.0.0.1:<portNumber>`` is a TCP socket - one
  logical connection per stream is the semantics the plugin
  (and any real HTTP/TCP server) expects.
* ``docker exec`` spawns a lightweight container-side process ;
  runtime cost per stream is dominated by the connect handshake to
  the target, which we would pay in any design.
* One subprocess per stream isolates lifecycle : a FIN on one stream
  doesn't need any bookkeeping ; we just close its stdin.

The bridge is single-threaded ; the caller (:mod:`session_ws_server`)
drives it from its ``select`` loop by :

* handing incoming plugin bytes to :meth:`feed_from_plugin`,
* asking for readable stream fds via :meth:`readable_fds` and
  passing back the ready set to :meth:`drain_stream_reads`,
* calling :meth:`close_all` in a ``finally`` block.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple

from localemu.services.ssm.smux_v1 import (
    CMD_FIN,
    CMD_NOP,
    CMD_PSH,
    CMD_SYN,
    SmuxDecoder,
    SmuxProtocolError,
    chunk_and_encode_psh,
    encode_frame,
)

LOG = logging.getLogger(__name__)

# 64 KB stream read. Anything bigger than :data:`MAX_PAYLOAD` will be
# chunked into multiple PSH frames by :func:`chunk_and_encode_psh`, so
# the value only affects syscall count, not wire fragmentation.
_READ_CHUNK = 65536


@dataclass(slots=True)
class _Stream:
    """One live SMUX stream + its ``docker exec -i nc`` subprocess."""

    sid: int
    pid: int
    # The parent end of the socketpair whose fd is fed to select().
    # We stash it here so garbage collection cannot close the fd out
    # from under the loop.
    parent_sock: socket.socket
    closed_write: bool = False
    closed_read: bool = False


# Factory signature : ``(container_name, target_port) -> (pid, parent_sock)``.
# ``pid`` may be 0 when the strategy doesn't fork a real subprocess
# (unit tests). ``parent_sock`` is a non-blocking AF_UNIX socketpair
# end that behaves like the target-side TCP connection.
StreamFactory = Callable[[str, int], Tuple[int, socket.socket]]


class PortMuxBridge:
    """Owns the SMUX v1 mux state for one Port session.

    :param container_name: ``localemu-ec2-<iid>`` - the target
        container that hosts the port we forward to.
    :param target_port: the ``portNumber`` from the
        ``AWS-StartPortForwardingSession`` document parameters.
    :param stream_factory: strategy for spawning one target-side TCP
        connection. Defaults to ``docker exec -i <container> nc
        127.0.0.1 <target_port>``. Unit tests inject a fake that
        just returns a socketpair.
    """

    def __init__(
        self,
        container_name: str,
        target_port: int,
        stream_factory: Optional[StreamFactory] = None,
    ) -> None:
        self._container = container_name
        self._target_port = int(target_port)
        self._decoder = SmuxDecoder()
        self._streams: dict[int, _Stream] = {}
        self._fd_to_sid: dict[int, int] = {}
        self._factory: StreamFactory = (
            stream_factory or _docker_exec_stream_factory
        )

    # ---- inbound (plugin -> target) --------------------------------

    def feed_from_plugin(self, data: bytes) -> None:
        """Decode + dispatch plugin bytes.

        Fatal :class:`SmuxProtocolError` is logged and re-raised so the
        caller can close the WS session ; the plugin is not going to
        recover from a framing mismatch.
        """
        try:
            frames = self._decoder.feed(data)
        except SmuxProtocolError:
            LOG.exception(
                "SMUX framing broke on port session for %s:%d",
                self._container, self._target_port,
            )
            raise
        for frame in frames:
            if frame.cmd == CMD_SYN:
                self._open_stream(frame.sid)
            elif frame.cmd == CMD_PSH:
                self._push_stream(frame.sid, frame.payload)
            elif frame.cmd == CMD_FIN:
                self._half_close_stream(frame.sid)
            elif frame.cmd == CMD_NOP:
                # xtaci/smux fires NOPs as a keep-alive when the peer
                # has been silent for the keepalive interval. Nothing
                # to do - the WebSocket layer already has its own
                # Ping/Pong which our _authenticate + _bridge honour.
                pass
            else:
                LOG.debug(
                    "SMUX: dropping unknown cmd=%d sid=%d bytes=%d",
                    frame.cmd, frame.sid, len(frame.payload),
                )

    # ---- outbound (target -> plugin) --------------------------------

    def readable_fds(self) -> list[int]:
        """Return the stream fds the caller should include in ``select``."""
        return [
            stream.parent_sock.fileno()
            for stream in self._streams.values()
            if not stream.closed_read
        ]

    def drain_stream_reads(self, ready_fds: Iterable) -> list[bytes]:
        """Return a list of serialized SMUX frames to send back to the plugin.

        For every stream fd in ``ready_fds`` :

        * Read up to :data:`_READ_CHUNK` bytes.
        * A non-empty read is wrapped in one-or-more ``PSH`` frames
          (chunked if larger than the wire ``uint16`` length).
        * A zero-byte read is treated as EOF from ``nc`` : we emit a
          ``FIN`` and mark the stream as read-closed. The subprocess
          gets reaped when the caller invokes :meth:`close_all`.

        ``ready_fds`` may include the WS sock and other unrelated
        entries ; we filter to the ones we own.
        """
        out: list[bytes] = []
        # Snapshot : ``self._streams`` may mutate on close.
        for stream in list(self._streams.values()):
            fd = stream.parent_sock.fileno()
            if fd not in ready_fds and stream.parent_sock not in ready_fds:
                continue
            if stream.closed_read:
                continue
            try:
                chunk = stream.parent_sock.recv(_READ_CHUNK)
            except (BlockingIOError, ConnectionResetError):
                continue
            except OSError:
                chunk = b""
            if not chunk:
                # EOF from the container-side ``nc``.
                stream.closed_read = True
                out.append(encode_frame(CMD_FIN, stream.sid))
                continue
            out.extend(chunk_and_encode_psh(stream.sid, chunk))
        # Wrap each SMUX frame as the payload of ONE ``output_stream_data``
        # ClientMessage (the caller does that framing) - but we only
        # return the SMUX bytes here. Concatenating multiple frames into
        # one WS message is legal ; the plugin's decoder will pull them
        # apart because SMUX has its own length field.
        if len(out) <= 1:
            return out
        return [b"".join(out)]

    # ---- teardown ---------------------------------------------------

    def close_all(self) -> None:
        """Reap every stream subprocess + close every parent socket."""
        for stream in list(self._streams.values()):
            self._close_stream_now(stream)
        self._streams.clear()
        self._fd_to_sid.clear()

    # ---- internals --------------------------------------------------

    def _open_stream(self, sid: int) -> None:
        if sid in self._streams:
            # xtaci/smux never reuses an sid ; a duplicate SYN means
            # the peer got confused. Ignore ; keep the existing stream.
            LOG.debug("SMUX: duplicate SYN for sid=%d ; ignored", sid)
            return
        try:
            pid, parent_sock = self._factory(self._container, self._target_port)
        except Exception:
            LOG.exception(
                "SMUX: failed to spawn stream for sid=%d %s:%d",
                sid, self._container, self._target_port,
            )
            return
        parent_sock.setblocking(False)
        self._streams[sid] = _Stream(
            sid=sid, pid=pid, parent_sock=parent_sock,
        )
        self._fd_to_sid[parent_sock.fileno()] = sid

    def _push_stream(self, sid: int, data: bytes) -> None:
        stream = self._streams.get(sid)
        if stream is None:
            LOG.debug("SMUX: PSH on unknown sid=%d ; dropping", sid)
            return
        if stream.closed_write or not data:
            return
        try:
            stream.parent_sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            stream.closed_write = True

    def _half_close_stream(self, sid: int) -> None:
        stream = self._streams.get(sid)
        if stream is None:
            return
        stream.closed_write = True
        try:
            stream.parent_sock.shutdown(socket.SHUT_WR)
        except OSError:
            # Peer already gone.
            pass

    def _close_stream_now(self, stream: _Stream) -> None:
        self._fd_to_sid.pop(stream.parent_sock.fileno(), None)
        try:
            stream.parent_sock.close()
        except OSError:
            pass
        if stream.pid <= 0:
            # In-process factory (tests) has no child to reap.
            return
        try:
            os.kill(stream.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        try:
            os.waitpid(stream.pid, 0)
        except (ChildProcessError, OSError):
            pass


def _docker_exec_stream_factory(
    container_name: str, target_port: int,
) -> Tuple[int, socket.socket]:
    """Spawn ``docker exec -i <container> nc 127.0.0.1 <target_port>``.

    The child sees the socketpair end as both stdin and stdout ;
    stderr goes to ``/dev/null`` so ``nc`` diagnostics can't leak
    into the tunnel bytes.

    ``fork+dup2+execvp`` is used instead of ``subprocess.Popen`` because
    Popen's ``stdin=fd, stdout=fd`` with the SAME fd for both is
    unreliable across CPython versions (its internal dup logic
    assumes distinct source fds when ``close_fds=True``).
    """
    parent_sock, child_sock = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_STREAM,
    )
    pid = os.fork()
    if pid == 0:
        try:
            parent_sock.close()
            os.dup2(child_sock.fileno(), 0)
            os.dup2(child_sock.fileno(), 1)
            dev_null = os.open(os.devnull, os.O_WRONLY)
            os.dup2(dev_null, 2)
            child_sock.close()
            os.execvp("docker", [
                "docker", "exec", "-i", container_name,
                "nc", "127.0.0.1", str(target_port),
            ])
        except Exception as exc:
            os.write(
                2, f"[localemu] port-mux exec failed: {exc}\n".encode(),
            )
            os._exit(127)
    child_sock.close()
    return pid, parent_sock
