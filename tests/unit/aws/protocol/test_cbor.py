"""Unit tests for the LocalEmu CBOR codec wrapper.

The wrapper at ``aws/protocol/_cbor.py`` exists because AWS Kinesis breaks
RFC 8949 for tag 1 (epoch datetime): instead of seconds with floating
millis, AWS uses an integer count of milliseconds. AWS SDKs further
assume the encoded value is an integer (CBOR is typed) and reject floats.

These tests verify the quirk is applied transparently on both the encode
and decode side, using the public ``loads`` / ``dumps`` of this module,
and that the AWS-quirk does not break stock-spec encoding for naive
non-datetime payloads.
"""
from __future__ import annotations

from datetime import UTC, datetime

import cbor2
import pytest

from localemu.aws.protocol._cbor import (
    CBORDecodeError,
    CBOREncodeValueError,
    CBORTag,
    dumps,
    loads,
)


def _inspect_tag(raw: bytes) -> tuple[int, object]:
    """Decode ``raw`` while overriding tag handlers so the caller gets
    back the (tag, payload) pair instead of cbor2's native conversion.

    cbor2 6.x's stock ``loads`` decodes tag 0 / tag 1 into a Python
    :class:`datetime` automatically, hiding the underlying CBOR tag
    structure from inspection. The tests below need to assert against
    the raw CBOR shape (tag number + payload), so we install pass-
    through semantic decoders for those tags.
    """
    return cbor2.loads(
        raw,
        semantic_decoders={
            0: lambda v, _i=False: (0, v),
            1: lambda v, _i=False: (1, v),
        },
    )


class TestDecodeAwsEpochDatetime:
    def test_tag1_with_integer_milliseconds_decodes_to_utc_datetime(self):
        dt = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        millis = int(dt.timestamp() * 1000)
        raw = cbor2.dumps(CBORTag(1, millis))
        out = loads(raw)
        assert isinstance(out, datetime)
        assert out == dt

    def test_tag1_with_fractional_milliseconds_preserves_micros(self):
        # Spec calls for seconds; AWS encodes millis. So 1500ms = 1.5s.
        raw = cbor2.dumps(CBORTag(1, 1500))
        out = loads(raw)
        assert out == datetime(1970, 1, 1, 0, 0, 1, 500_000, tzinfo=UTC)

    def test_decode_value_error_on_garbage_tag1(self):
        # Tag 1 with a non-numeric payload should raise CBORDecodeError.
        raw = cbor2.dumps(CBORTag(1, "not-a-number"))
        with pytest.raises(CBORDecodeError):
            loads(raw)


class TestEncodeAwsDatetime:
    def test_aware_utc_datetime_becomes_tag1_integer_millis(self):
        dt = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        raw = dumps(dt, datetime_as_timestamp=True)
        tag_num, payload = _inspect_tag(raw)
        assert tag_num == 1
        assert payload == int(dt.timestamp() * 1000)
        # CBOR is typed: AWS-SDK assumption is integer, never float.
        assert isinstance(payload, int)

    def test_microsecond_precision_rounds_to_millis(self):
        # AWS rounds DOWN to integer millis (drops sub-millis micros).
        dt = datetime(2026, 5, 21, 12, 0, 0, 654_321, tzinfo=UTC)
        raw = dumps(dt, datetime_as_timestamp=True)
        tag_num, payload = _inspect_tag(raw)
        assert tag_num == 1
        base = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        # 654321 micros = 654.321 ms; int() truncates to 654.
        assert payload == int(base.timestamp() * 1000) + 654

    def test_naive_datetime_with_no_default_timezone_raises(self):
        dt = datetime(2026, 5, 21, 12, 0, 0)  # naive
        with pytest.raises(CBOREncodeValueError):
            dumps(dt, datetime_as_timestamp=True)

    def test_naive_datetime_with_default_timezone_applies_it(self):
        dt_naive = datetime(2026, 5, 21, 12, 0, 0)
        dt_utc = dt_naive.replace(tzinfo=UTC)
        raw = dumps(dt_naive, datetime_as_timestamp=True, timezone=UTC)
        tag_num, payload = _inspect_tag(raw)
        assert tag_num == 1
        assert payload == int(dt_utc.timestamp() * 1000)

    def test_non_timestamp_mode_emits_iso_string_tag0(self):
        dt = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        raw = dumps(dt, datetime_as_timestamp=False)
        tag_num, payload = _inspect_tag(raw)
        assert tag_num == 0
        assert payload == "2026-05-21T12:00:00Z"


class TestRoundTrip:
    def test_dumps_then_loads_roundtrips_to_equivalent_datetime(self):
        dt = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        roundtripped = loads(dumps(dt, datetime_as_timestamp=True))
        assert roundtripped == dt

    def test_dumps_then_loads_with_microseconds_preserves_to_millis(self):
        # AWS quirk: micros below the millisecond boundary are lost.
        dt = datetime(2026, 5, 21, 12, 0, 0, 654_321, tzinfo=UTC)
        roundtripped = loads(dumps(dt, datetime_as_timestamp=True))
        # millis-truncated form
        assert roundtripped == datetime(2026, 5, 21, 12, 0, 0, 654_000, tzinfo=UTC)

    def test_payload_with_no_datetime_passes_through_unchanged(self):
        # Verifies the AWS encoder does not corrupt non-datetime payloads.
        payload = {"hello": "world", "items": [1, 2, 3], "ok": True}
        assert loads(dumps(payload)) == payload


class TestCallerEncoderOverride:
    def test_caller_encoder_can_extend_without_losing_aws_datetime(self):
        # If a caller passes their own ``encoders={SomeType: handler}``,
        # the wrapper merges with the AWS datetime encoder rather than
        # replacing it.
        class MyType:
            def __init__(self, x):
                self.x = x

        def encode_mytype(encoder, value):
            encoder.encode(value.x)

        payload = {"d": datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC), "m": MyType(42)}
        raw = dumps(payload, datetime_as_timestamp=True, encoders={MyType: encode_mytype})
        # Decode back: the datetime quirk must still apply, AND MyType must decode as 42.
        out = loads(raw)
        assert out["d"] == datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        assert out["m"] == 42

    def test_caller_can_override_datetime_encoder_entirely(self):
        # Caller-provided encoder for ``datetime`` wins over AWS one
        # (their explicit choice).
        emitted: list = []

        def encode_dt(encoder, value):
            emitted.append("CALLER-WINS")
            encoder.encode(value.isoformat())

        dt = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
        raw = dumps(dt, datetime_as_timestamp=True, encoders={datetime: encode_dt})
        assert emitted == ["CALLER-WINS"]
        # And the decoded value is the ISO string the caller wrote, NOT
        # an AWS-quirked tag.
        assert cbor2.loads(raw) == "2026-05-21T12:00:00+00:00"
