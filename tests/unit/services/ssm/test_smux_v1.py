"""SMUX v1 codec.

Pins the wire format LocalEmu speaks to the session-manager-plugin's
``MuxPortForwarding``. Byte-for-byte reference values are taken from
``xtaci/smux/frame.go`` and validated against the frames observed on
the wire during instrumentation.
"""
from __future__ import annotations

import pytest

from localemu.services.ssm.smux_v1 import (
    CMD_FIN,
    CMD_NOP,
    CMD_PSH,
    CMD_SYN,
    HEADER_SIZE,
    MAX_PAYLOAD,
    SMUX_VERSION,
    SmuxDecoder,
    SmuxFrame,
    SmuxProtocolError,
    chunk_and_encode_psh,
    encode_frame,
)


# ----- encode ------------------------------------------------------


def test_encode_syn_matches_reference_wire_bytes():
    """SYN opening stream 3 : ``01 00 00 00 03 00 00 00`` (little-endian).

    Reference : the very first frame the plugin emits on a port
    session, captured verbatim via instrumentation before this
    fix.
    """
    assert encode_frame(CMD_SYN, sid=3) == b"\x01\x00\x00\x00\x03\x00\x00\x00"


def test_encode_psh_matches_reference_wire_bytes():
    """PSH sid=3 len=78 with an HTTP GET header.

    Reference: second frame the plugin emitted. Header is
    ``01 02 4E 00 03 00 00 00`` where ``4E 00`` is uint16 LE = 78 =
    len("GET / HTTP/1.1\\r\\n...\\r\\n\\r\\n").
    """
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 127.0.0.1:18013\r\n"
        b"User-Agent: curl/8.7.1\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    assert len(payload) == 78
    wire = encode_frame(CMD_PSH, sid=3, payload=payload)
    assert wire[:HEADER_SIZE] == b"\x01\x02\x4E\x00\x03\x00\x00\x00"
    assert wire[HEADER_SIZE:] == payload


def test_encode_fin_carries_zero_length():
    assert encode_frame(CMD_FIN, sid=42) == b"\x01\x01\x00\x00\x2A\x00\x00\x00"


def test_encode_nop_zero_payload():
    assert encode_frame(CMD_NOP, sid=0) == b"\x01\x03\x00\x00\x00\x00\x00\x00"


def test_encode_rejects_oversized_payload():
    with pytest.raises(ValueError):
        encode_frame(CMD_PSH, sid=1, payload=b"x" * (MAX_PAYLOAD + 1))


def test_encode_rejects_negative_sid():
    with pytest.raises(ValueError):
        encode_frame(CMD_PSH, sid=-1, payload=b"data")


def test_encode_rejects_too_large_sid():
    with pytest.raises(ValueError):
        encode_frame(CMD_PSH, sid=0x1_0000_0000, payload=b"data")


# ----- chunk_and_encode_psh ---------------------------------------


def test_chunk_and_encode_psh_yields_nothing_for_empty():
    assert list(chunk_and_encode_psh(sid=1, data=b"")) == []


def test_chunk_and_encode_psh_single_frame_when_small():
    frames = list(chunk_and_encode_psh(sid=7, data=b"hello"))
    assert len(frames) == 1
    assert frames[0] == encode_frame(CMD_PSH, sid=7, payload=b"hello")


def test_chunk_and_encode_psh_splits_at_max_payload():
    """One 200 KiB blob must fan out into ceil(200KiB / 64KiB - 1) = 4 frames
    given ``MAX_PAYLOAD == 0xFFFF``.
    """
    big = b"a" * (200 * 1024)
    frames = list(chunk_and_encode_psh(sid=9, data=big))
    total = sum(len(f) - HEADER_SIZE for f in frames)
    assert total == len(big)
    for f in frames[:-1]:
        assert len(f) - HEADER_SIZE == MAX_PAYLOAD


# ----- decode ------------------------------------------------------


def test_decoder_single_frame():
    d = SmuxDecoder()
    out = d.feed(encode_frame(CMD_SYN, sid=1))
    assert out == [SmuxFrame(cmd=CMD_SYN, sid=1, payload=b"")]
    assert d.buffered == 0


def test_decoder_multi_frame_one_feed():
    d = SmuxDecoder()
    wire = encode_frame(CMD_SYN, sid=1) + encode_frame(
        CMD_PSH, sid=1, payload=b"abc",
    )
    out = d.feed(wire)
    assert [(f.cmd, f.sid, f.payload) for f in out] == [
        (CMD_SYN, 1, b""),
        (CMD_PSH, 1, b"abc"),
    ]


def test_decoder_holds_partial_header():
    """Header split across two feeds : no frame emitted until complete."""
    d = SmuxDecoder()
    wire = encode_frame(CMD_PSH, sid=5, payload=b"data")
    assert d.feed(wire[:3]) == []
    assert d.buffered == 3
    out = d.feed(wire[3:])
    assert out == [SmuxFrame(cmd=CMD_PSH, sid=5, payload=b"data")]
    assert d.buffered == 0


def test_decoder_holds_partial_payload():
    """Header arrives, payload arrives byte by byte."""
    d = SmuxDecoder()
    wire = encode_frame(CMD_PSH, sid=5, payload=b"HELLO")
    assert d.feed(wire[:HEADER_SIZE]) == []
    # Feed payload one byte at a time.
    for i in range(HEADER_SIZE, len(wire) - 1):
        assert d.feed(wire[i:i + 1]) == []
    out = d.feed(wire[-1:])
    assert out == [SmuxFrame(cmd=CMD_PSH, sid=5, payload=b"HELLO")]


def test_decoder_rejects_unknown_version():
    d = SmuxDecoder()
    with pytest.raises(SmuxProtocolError):
        d.feed(b"\x02\x02\x00\x00\x01\x00\x00\x00")


def test_decoder_surfaces_unknown_cmd_for_caller_policy():
    """Unknown cmds are not fatal ; caller decides (log-and-drop is used
    by the port bridge). Ensures we don't lose bytes past the header.
    """
    d = SmuxDecoder()
    # cmd=9 is unallocated ; length=3 payload "xyz"
    wire = b"\x01\x09\x03\x00\x0A\x00\x00\x00xyz"
    out = d.feed(wire)
    assert out == [SmuxFrame(cmd=9, sid=10, payload=b"xyz")]


def test_decoder_roundtrip_psh_wire_matches_encoder():
    d = SmuxDecoder()
    frames = list(chunk_and_encode_psh(sid=13, data=b"payload-data"))
    decoded = d.feed(b"".join(frames))
    assert len(decoded) == 1
    assert decoded[0].cmd == CMD_PSH
    assert decoded[0].sid == 13
    assert decoded[0].payload == b"payload-data"


def test_decoder_smux_version_constant_locked_at_v1():
    """v2 is a distinct wire (adds ``UPD``, bumps the version byte).
    Any bump of ``SMUX_VERSION`` needs an intentional spec update.
    """
    assert SMUX_VERSION == 1
