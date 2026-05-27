"""SSM Session Manager — session registry + binary ClientMessage codec.

Implements just enough of the AWS Session Manager protocol to give an
interactive ``Standard_Stream`` shell from ``aws ssm start-session
--target i-xxx``.

The wire format is documented in the open-source plugin source:
https://github.com/aws/session-manager-plugin

ClientMessage binary frame layout (big-endian, 116-byte fixed header):

* ``HeaderLength`` uint32 (4)              — always 116
* ``MessageType`` 32 bytes ASCII, null-padded
* ``SchemaVersion`` uint32 (4)             — 1
* ``CreatedDate`` uint64 (8)               — epoch ms
* ``SequenceNumber`` int64 (8)             — monotonic per-direction
* ``Flags`` uint64 (8)                     — bit0=SYN, bit1=FIN
* ``MessageId`` 16 raw UUID bytes
* ``PayloadDigest`` 32 SHA-256 of payload
* ``PayloadType`` uint32 (4)               — see PayloadType enum
* ``PayloadLength`` uint32 (4)
* ``Payload`` variable bytes
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger(__name__)


# --- ClientMessage codec ---------------------------------------------------

# 4 (HeaderLength) + 32 (MessageType) + 4 (SchemaVersion) + 8 (CreatedDate) +
# 8 (SequenceNumber) + 8 (Flags) + 16 (MessageId) + 32 (PayloadDigest) +
# 4 (PayloadType) + 4 (PayloadLength) = 120.
_HEADER_LEN = 120
_MESSAGE_TYPE_LEN = 32
_SCHEMA_VERSION = 1

# MessageType strings (32 bytes, null-padded).
MT_INPUT_STREAM_DATA = "input_stream_data"
MT_OUTPUT_STREAM_DATA = "output_stream_data"
MT_ACKNOWLEDGE = "acknowledge"
MT_CHANNEL_CLOSED = "channel_closed"
MT_PAUSE_PUBLICATION = "pause_publication"
MT_START_PUBLICATION = "start_publication"

# PayloadType enum from src/message/clientmessage.go.
PT_OUTPUT = 1
PT_ERROR = 2
PT_SIZE = 3
PT_PARAMETER = 4
PT_HANDSHAKE_REQUEST = 5
PT_HANDSHAKE_RESPONSE = 6
PT_HANDSHAKE_COMPLETE = 7
PT_ENC_CHALLENGE_REQUEST = 8
PT_ENC_CHALLENGE_RESPONSE = 9
PT_FLAG = 10
PT_STDERR = 11
PT_EXIT_CODE = 12


@dataclass(slots=True)
class ClientMessage:
    """One frame of the SSM Session Manager binary protocol."""

    message_type: str
    sequence_number: int
    payload: bytes
    payload_type: int = PT_OUTPUT
    flags: int = 0  # bit0=SYN, bit1=FIN
    message_id: bytes = b""
    created_date: int = 0  # epoch ms; assigned if 0 at serialize time

    def serialize(self) -> bytes:
        if not self.message_id:
            self.message_id = uuid.uuid4().bytes
        if not self.created_date:
            self.created_date = int(time.time() * 1000)
        mtype = self.message_type.encode("ascii")[:_MESSAGE_TYPE_LEN]
        mtype = mtype.ljust(_MESSAGE_TYPE_LEN, b"\x00")
        digest = hashlib.sha256(self.payload).digest()
        header = struct.pack(
            ">I", _HEADER_LEN,
        ) + mtype + struct.pack(
            ">I Q q Q",
            _SCHEMA_VERSION,
            self.created_date,
            self.sequence_number,
            self.flags,
        ) + self.message_id + digest + struct.pack(
            ">I I", self.payload_type, len(self.payload),
        )
        assert len(header) == _HEADER_LEN, len(header)
        return header + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> "ClientMessage":
        if len(data) < _HEADER_LEN:
            raise ValueError(f"frame too short: {len(data)} < {_HEADER_LEN}")
        (header_len,) = struct.unpack(">I", data[0:4])
        if header_len != _HEADER_LEN:
            raise ValueError(f"unexpected HeaderLength {header_len}")
        mtype = data[4:4 + _MESSAGE_TYPE_LEN].rstrip(b"\x00").decode("ascii", "replace")
        off = 4 + _MESSAGE_TYPE_LEN
        (_schema, created, seq, flags) = struct.unpack(">I Q q Q", data[off:off + 28])
        off += 28
        message_id = data[off:off + 16]
        off += 16
        # digest is data[off:off+32] — caller can verify if it wants.
        off += 32
        (payload_type, payload_len) = struct.unpack(">I I", data[off:off + 8])
        off += 8
        payload = data[off:off + payload_len]
        return cls(
            message_type=mtype,
            sequence_number=seq,
            flags=flags,
            payload_type=payload_type,
            payload=payload,
            message_id=message_id,
            created_date=created,
        )


def acknowledge_frame(received: ClientMessage, ack_seq: int) -> ClientMessage:
    """Build an ``acknowledge`` frame for a received message."""
    body = json.dumps({
        "AcknowledgedMessageType": received.message_type,
        "AcknowledgedMessageId": str(uuid.UUID(bytes=received.message_id)),
        "AcknowledgedMessageSequenceNumber": received.sequence_number,
        "IsSequentialMessage": True,
    }).encode()
    return ClientMessage(
        message_type=MT_ACKNOWLEDGE,
        sequence_number=ack_seq,
        payload=body,
        payload_type=PT_OUTPUT,
    )


def handshake_request_frame(seq: int) -> ClientMessage:
    """First frame the server sends after the JSON open-channel auth.

    Plugin will not accept stdin until ``HandshakeComplete`` arrives, so
    the sequence is: server sends HandshakeRequest → plugin ACKs it →
    plugin sends HandshakeResponse → server ACKs it → server sends
    HandshakeComplete → plugin ACKs it.
    """
    body = json.dumps({
        "AgentVersion": "3.3.0.0-localemu",
        "RequestedClientActions": [
            {
                "ActionType": "SessionType",
                "ActionParameters": {
                    "SessionType": "Standard_Stream",
                    "Properties": None,
                },
            },
        ],
    }).encode()
    return ClientMessage(
        message_type=MT_OUTPUT_STREAM_DATA,
        sequence_number=seq,
        payload=body,
        payload_type=PT_HANDSHAKE_REQUEST,
        flags=1,  # SYN
    )


def handshake_complete_frame(seq: int) -> ClientMessage:
    body = json.dumps({
        "HandshakeTimeToComplete": 1_000_000_000,  # ns
        "CustomerMessage": "",
    }).encode()
    return ClientMessage(
        message_type=MT_OUTPUT_STREAM_DATA,
        sequence_number=seq,
        payload=body,
        payload_type=PT_HANDSHAKE_COMPLETE,
    )


def output_data_frame(seq: int, data: bytes) -> ClientMessage:
    return ClientMessage(
        message_type=MT_OUTPUT_STREAM_DATA,
        sequence_number=seq,
        payload=data,
        payload_type=PT_OUTPUT,
    )


def channel_closed_frame(seq: int, session_id: str, message: str) -> ClientMessage:
    body = json.dumps({
        "MessageType": "channel_closed",
        "MessageId": str(uuid.uuid4()),
        "DestinationId": session_id,
        "SessionId": session_id,
        "SchemaVersion": 1,
        "CreatedDate": str(int(time.time() * 1000)),
        "Output": message,
    }).encode()
    return ClientMessage(
        message_type=MT_CHANNEL_CLOSED,
        sequence_number=seq,
        payload=body,
        payload_type=PT_OUTPUT,
        flags=2,  # FIN
    )


# --- Session registry ------------------------------------------------------


@dataclass
class Session:
    """In-memory record for a single Session Manager session."""

    session_id: str
    token_value: str
    target_instance_id: str
    container_name: str
    account_id: str
    region: str
    created_at: float = field(default_factory=time.time)


class SessionRegistry:
    """Process-singleton: holds in-flight sessions keyed by SessionId."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(
        self,
        target_instance_id: str,
        container_name: str,
        account_id: str,
        region: str,
    ) -> Session:
        # Mirrors AWS shape: ``user-<random-hex>``. The CLI doesn't parse
        # the format; it's purely informational.
        session_id = f"localemu-{secrets.token_hex(8)}"
        token_value = secrets.token_urlsafe(48)
        sess = Session(
            session_id=session_id,
            token_value=token_value,
            target_instance_id=target_instance_id,
            container_name=container_name,
            account_id=account_id,
            region=region,
        )
        with self._lock:
            self._sessions[session_id] = sess
        return sess

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.pop(session_id, None)

    def list(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())


_registry: SessionRegistry | None = None
_registry_lock = threading.Lock()


def get_session_registry() -> SessionRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = SessionRegistry()
    return _registry
