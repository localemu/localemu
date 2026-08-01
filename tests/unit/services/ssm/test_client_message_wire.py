"""Wire-format tests for the SSM Session Manager binary protocol.

The header carries a ``HeaderLength`` field at bytes 0..3. Real
amazon-ssm-agent writes the value ``AgentMessage_PayloadLengthOffset =
116`` (the byte offset at which the ``PayloadLength`` field starts,
i.e. 120 minus the 4 bytes of PayloadLength itself). The plugin's
deserializer computes the payload slice as
``input[headerLength + PayloadLengthLength(4) :]``, so writing any
other value shifts the plugin's payload window and breaks the SHA-256
payload-digest verification.

Prior to fix, LocalEmu wrote ``120`` here, which the plugin
interpreted as "skip 124 header bytes", chopping the first 4 bytes
off every payload. ``Validate()`` failed silently, the plugin never
processed our handshake_request, ``IsSessionTypeSet`` never yielded,
``aws ssm start-session`` blocked forever on "Starting session with
SessionId : ...".

Source: aws/amazon-ssm-agent/agent/session/contracts/agentmessage.go
"""
from __future__ import annotations

import hashlib
import struct

import pytest

from localemu.services.ssm.session_manager import (
    MT_OUTPUT_STREAM_DATA,
    PT_HANDSHAKE_REQUEST,
    ClientMessage,
    handshake_complete_frame,
    handshake_request_frame,
    output_data_frame,
)


# Layout constants, matching aws/amazon-ssm-agent's clientmessage.go.
_HEADER_LEN_OFFSET_ON_WIRE = 0            # bytes 0..3
_MESSAGE_TYPE_OFFSET = 4                  # bytes 4..35
_MESSAGE_TYPE_LEN = 32
_SCHEMA_VERSION_OFFSET = 36               # bytes 36..39
_CREATED_DATE_OFFSET = 40                 # bytes 40..47
_SEQUENCE_NUMBER_OFFSET = 48              # bytes 48..55
_FLAGS_OFFSET = 56                        # bytes 56..63
_MESSAGE_ID_OFFSET = 64                   # bytes 64..79
_PAYLOAD_DIGEST_OFFSET = 80               # bytes 80..111
_PAYLOAD_TYPE_OFFSET = 112                # bytes 112..115
_PAYLOAD_LENGTH_OFFSET = 116              # bytes 116..119
_PAYLOAD_OFFSET = 120                     # bytes 120..

# What the HeaderLength field carries on the wire.
_WIRE_HEADER_LEN = 116


def test_serialized_frame_writes_wire_header_length_116():
    """The four bytes at offset 0 must decode to 116, not 120.

    Real amazon-ssm-agent writes ``AgentMessage_PayloadLengthOffset =
    116``; the plugin's Payload deserialization is
    ``input[headerLength + 4 :]``, so 116 lands the payload at byte
    120 (correct), while 120 lands it at byte 124 (skips 4 bytes and
    breaks SHA-256).
    """
    frame = ClientMessage(
        message_type="output_stream_data",
        sequence_number=0,
        payload=b"hello",
        payload_type=1,
        flags=0,
    ).serialize()

    (header_len_field,) = struct.unpack(">I", frame[0:4])
    assert header_len_field == _WIRE_HEADER_LEN, (
        f"HeaderLength field on the wire is {header_len_field}; the plugin "
        f"decoder expects {_WIRE_HEADER_LEN}. Anything else breaks SHA-256 "
        f"payload-digest verification (see aws/amazon-ssm-agent "
        f"AgentMessage_PayloadLengthOffset)."
    )


def test_serialized_frame_places_payload_at_byte_120():
    """The plugin computes payload_start = header_len_field + 4 = 120.

    That's where LocalEmu must place the payload bytes.
    """
    payload = b"abcdefghij"
    frame = ClientMessage(
        message_type="output_stream_data",
        sequence_number=0,
        payload=payload,
        payload_type=1,
    ).serialize()

    assert frame[_PAYLOAD_OFFSET : _PAYLOAD_OFFSET + len(payload)] == payload


def test_serialized_frame_payload_digest_matches_sha256_of_payload():
    """The plugin's Validate() rejects the frame if the SHA-256 stored
    at bytes 80..111 does not match ``sha256(payload)`` computed from
    the payload slice the plugin extracts.

    The two match only when the payload offset is right - which is
    only the case when the HeaderLength wire value is 116.
    """
    payload = b"the-quick-brown-fox-jumps-over-the-lazy-dog"
    frame = ClientMessage(
        message_type="output_stream_data",
        sequence_number=0,
        payload=payload,
        payload_type=1,
    ).serialize()

    stored_digest = frame[_PAYLOAD_DIGEST_OFFSET : _PAYLOAD_DIGEST_OFFSET + 32]
    plugin_view_of_payload = frame[_PAYLOAD_OFFSET :]  # this is what the plugin reads
    computed_digest = hashlib.sha256(plugin_view_of_payload).digest()

    assert stored_digest == computed_digest


def test_deserialize_roundtrips_a_serialized_frame():
    """Round-trip covers the serialize path and the deserialize path
    with matching constants.
    """
    original = ClientMessage(
        message_type="input_stream_data",
        sequence_number=42,
        payload=b"round-trip",
        payload_type=1,
        flags=1,
        created_date=1_700_000_000_000,
    )
    original.message_id = b"\x11" * 16  # fixed for reproducibility

    encoded = original.serialize()
    decoded = ClientMessage.deserialize(encoded)

    assert decoded.message_type == original.message_type
    assert decoded.sequence_number == original.sequence_number
    assert decoded.payload == original.payload
    assert decoded.payload_type == original.payload_type
    assert decoded.flags == original.flags
    assert decoded.message_id == original.message_id
    assert decoded.created_date == original.created_date


def test_deserialize_rejects_frame_with_wrong_wire_header_length():
    """A frame with HeaderLength=120 in the wire field must be
    rejected - a compliant agent NEVER writes 120 there.
    """
    good = ClientMessage(
        message_type="output_stream_data",
        sequence_number=0,
        payload=b"x",
        payload_type=1,
    ).serialize()

    # Patch bytes 0..3 to encode 120 instead of 116.
    bad = struct.pack(">I", 120) + good[4:]

    with pytest.raises(ValueError, match=r"unexpected HeaderLength"):
        ClientMessage.deserialize(bad)


def test_handshake_request_frame_shape():
    """The handshake_request the server sends first must be an
    ``output_stream_data`` message with ``payload_type=5`` and payload
    JSON that declares SessionType=Standard_Stream. Anything else and
    the plugin's ``ProcessSessionTypeHandshakeAction`` rejects.
    """
    import json

    frame_bytes = handshake_request_frame(0).serialize()
    parsed = ClientMessage.deserialize(frame_bytes)

    assert parsed.message_type == MT_OUTPUT_STREAM_DATA
    assert parsed.payload_type == PT_HANDSHAKE_REQUEST
    body = json.loads(parsed.payload)
    actions = body.get("RequestedClientActions") or []
    assert any(
        a.get("ActionType") == "SessionType"
        and (a.get("ActionParameters") or {}).get("SessionType")
        == "Standard_Stream"
        for a in actions
    ), body


def test_output_data_frame_carries_the_exact_payload():
    """Shell output must round-trip byte-for-byte."""
    payload = b"root@ip-10-0-0-3:/# ls\r\n"
    frame_bytes = output_data_frame(7, payload).serialize()
    parsed = ClientMessage.deserialize(frame_bytes)
    assert parsed.payload == payload
    assert parsed.sequence_number == 7


def test_handshake_complete_frame_shape():
    frame_bytes = handshake_complete_frame(3).serialize()
    parsed = ClientMessage.deserialize(frame_bytes)
    assert parsed.message_type == MT_OUTPUT_STREAM_DATA
    assert parsed.payload_type == 7  # PT_HANDSHAKE_COMPLETE
    assert parsed.sequence_number == 3


def test_deserialize_handles_space_padded_message_type_from_plugin():
    """Real session-manager-plugin right-pads MessageType with SPACE
    bytes (0x20) instead of NUL. If we only strip nulls the equality
    comparison in _bridge (``msg.message_type == MT_INPUT_STREAM_DATA``)
    fails silently and the plugin's keyboard input never reaches the
    docker exec PTY.
    """
    # Build a valid frame but pad MessageType with 0x20 the way the
    # real plugin serialize path does (see plugin
    # src/message/messageparser.go SerializeClientMessage).
    payload = b"h"
    hdr_wire_len = 116
    mtype = b"input_stream_data".ljust(32, b" ")  # space-padded
    header = struct.pack(">I", hdr_wire_len) + mtype + struct.pack(
        ">I Q q Q", 1, 1_700_000_000_000, 0, 0,
    ) + b"\x22" * 16 + hashlib.sha256(payload).digest() + struct.pack(
        ">I I", 1, len(payload),
    )
    assert len(header) == _PAYLOAD_OFFSET  # 120

    parsed = ClientMessage.deserialize(header + payload)
    assert parsed.message_type == "input_stream_data"  # no trailing spaces
