"""SMUX v1 wire codec (xtaci/smux compatible).

The AWS session-manager-plugin's ``MuxPortForwarding`` wraps every
tunnel byte in an SMUX v1 frame when the target agent version is
above ``3.0.196.0`` (see ``session-manager-plugin/src/version/`` +
``sessionmanagerplugin/session/portsession/muxportforwarding.go``).

The wire is documented in ``xtaci/smux/frame.go`` and is a stable
public protocol :

* **Header - 8 bytes, little-endian for multi-byte fields**::

      | ver (1)  | cmd (1)  | length (u16 LE) | sid (u32 LE) |

* **Version**: ``1`` (this module targets v1 only ; v2 adds
  ``UPD`` window updates and an incompatible version byte).
* **Commands**:

  * ``SYN`` (0)  : open a new stream identified by ``sid``. Payload empty.
  * ``FIN`` (1)  : half-close ``sid``. Payload empty.
  * ``PSH`` (2)  : payload is ``length`` raw bytes to append to ``sid``.
  * ``NOP`` (3)  : keep-alive. Ignored on receipt.

* **Length**: ``uint16`` little-endian. Max data per PSH is
  ``0xFFFF`` bytes. Consumers of this module MUST fragment larger
  writes across several PSH frames (see :func:`chunk_and_encode_psh`).

* **Stream identifier**: ``uint32`` little-endian, allocated by the
  side that sends the ``SYN``. There is no requirement to use
  odd/even ranges (unlike HTTP/2). LocalEmu just echoes whatever
  ``sid`` the plugin picked when sending back its PSH frames.

This module is pure codec : no I/O, no threading, no docker.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

SMUX_VERSION = 1
HEADER_SIZE = 8
MAX_PAYLOAD = 0xFFFF  # uint16 length field

CMD_SYN = 0
CMD_FIN = 1
CMD_PSH = 2
CMD_NOP = 3

_CMD_NAMES = {
    CMD_SYN: "SYN",
    CMD_FIN: "FIN",
    CMD_PSH: "PSH",
    CMD_NOP: "NOP",
}


@dataclass(slots=True)
class SmuxFrame:
    """One decoded SMUX v1 frame."""

    cmd: int
    sid: int
    payload: bytes = b""

    def __repr__(self) -> str:  # pragma: no cover - debug help
        name = _CMD_NAMES.get(self.cmd, f"cmd={self.cmd}")
        return f"SmuxFrame({name}, sid={self.sid}, len={len(self.payload)})"


def encode_frame(cmd: int, sid: int, payload: bytes = b"") -> bytes:
    """Serialize one SMUX v1 frame.

    :raises ValueError: if ``payload`` exceeds :data:`MAX_PAYLOAD`.
        Callers must split large PSH payloads themselves ; see
        :func:`chunk_and_encode_psh`.
    """
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(
            f"SMUX payload too large: {len(payload)} > {MAX_PAYLOAD}",
        )
    if sid < 0 or sid > 0xFFFFFFFF:
        raise ValueError(f"SMUX sid out of uint32 range: {sid}")
    if cmd < 0 or cmd > 0xFF:
        raise ValueError(f"SMUX cmd out of byte range: {cmd}")
    return struct.pack(
        "<BBHI", SMUX_VERSION, cmd, len(payload), sid,
    ) + payload


def chunk_and_encode_psh(sid: int, data: bytes) -> Iterator[bytes]:
    """Yield ``PSH`` frames covering ``data``, chunked at :data:`MAX_PAYLOAD`.

    Empty ``data`` yields nothing (an empty PSH would send a header
    with length=0 for no reason).
    """
    if not data:
        return
    view = memoryview(data)
    for offset in range(0, len(view), MAX_PAYLOAD):
        chunk = bytes(view[offset:offset + MAX_PAYLOAD])
        yield encode_frame(CMD_PSH, sid, chunk)


class SmuxDecoder:
    """Streaming decoder : ``feed(bytes)`` -> ``list[SmuxFrame]``.

    Handles arbitrary fragmentation. Partial frames at the tail of
    ``feed`` are kept in an internal buffer until the next call.
    Frames with an unknown ``version`` byte raise
    :class:`SmuxProtocolError` - a mismatched version means the peer
    is speaking a different mux and there is no recovery. Unknown
    ``cmd`` values are surfaced as :class:`SmuxFrame` instances so
    the caller can decide (log-and-drop is the intended policy).
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[SmuxFrame]:
        out: list[SmuxFrame] = []
        if data:
            self._buf.extend(data)
        while True:
            if len(self._buf) < HEADER_SIZE:
                return out
            ver = self._buf[0]
            if ver != SMUX_VERSION:
                raise SmuxProtocolError(
                    f"unsupported SMUX version byte {ver!r} (want {SMUX_VERSION})",
                )
            cmd = self._buf[1]
            length = int.from_bytes(self._buf[2:4], "little")
            sid = int.from_bytes(self._buf[4:8], "little")
            total = HEADER_SIZE + length
            if len(self._buf) < total:
                return out
            payload = bytes(self._buf[HEADER_SIZE:total])
            del self._buf[:total]
            out.append(SmuxFrame(cmd=cmd, sid=sid, payload=payload))

    @property
    def buffered(self) -> int:
        """Number of bytes queued waiting for more of a partial frame."""
        return len(self._buf)


class SmuxProtocolError(ValueError):
    """Raised when the peer emits bytes that cannot be an SMUX v1 frame.

    Fatal for the session : recovery would need out-of-band framing
    the plugin doesn't provide.
    """
