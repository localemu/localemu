"""CBOR codec wrapper for LocalEmu, with AWS Kinesis quirk baked in.

AWS Kinesis emits CBOR streams that break RFC 8949 for tag 1 (epoch
datetime): instead of seconds with floating-point millisecond precision,
AWS uses an integer count of milliseconds. AWS SDKs further assume the
encoded value is an integer (CBOR is typed) and reject floats.

See https://github.com/aws/aws-sdk-java-v2/issues/4661

This module pins those encoders/decoders into module-level dicts and
exposes :func:`loads` / :func:`dumps` wrappers that pass them through
to :mod:`cbor2`'s public per-call hook API (``semantic_decoders=`` on
:func:`cbor2.loads`, ``encoders=`` on :func:`cbor2.dumps`).

The wrapper works with both cbor2 5.x and 6.x. Earlier LocalEmu code
patched private modules (``cbor2._decoder.semantic_decoders``,
``cbor2._encoder.default_encoders``) which existed only in 5.x's
pure-Python implementation; cbor2 6.x ships a C-only build and the
private modules are gone.
"""
from __future__ import annotations

from calendar import timegm
from datetime import UTC, datetime
from typing import Any

import cbor2
from cbor2 import CBORDecodeError, CBOREncodeValueError, CBORTag

__all__ = [
    "loads",
    "dumps",
    "CBORDecodeError",
    "CBOREncodeValueError",
    "CBORTag",
]


def _decode_aws_epoch_datetime(value, immutable: bool = False) -> datetime:
    """Decode CBOR tag 1 as AWS sends it: integer milliseconds since the epoch.

    cbor2 6.x invokes ``semantic_decoders`` callables with
    ``(decoded_tag_payload, immutable_flag)``. For tag 1 the payload is
    the integer count of milliseconds. The ``immutable`` flag is part
    of cbor2's broader immutability tracking and has no effect on a
    :class:`datetime` (already immutable).
    """
    try:
        return datetime.fromtimestamp(value / 1000, UTC)
    except (OverflowError, OSError, ValueError, TypeError) as exc:
        raise CBORDecodeError("error decoding datetime from epoch") from exc


def _encode_aws_datetime(encoder, value: datetime) -> None:
    """Encode :class:`datetime` as CBOR tag 1 with integer milliseconds.

    Mirrors the AWS Kinesis convention: integer count of milliseconds
    since the epoch, not the RFC 8949 floating-point-seconds form.
    """
    if not value.tzinfo:
        # cbor2 6.x exposes the configured default timezone via
        # ``encoder.timezone`` (same attribute name as 5.x).
        default_tz = getattr(encoder, "timezone", None)
        if default_tz is not None:
            value = value.replace(tzinfo=default_tz)
        else:
            raise CBOREncodeValueError(
                f"naive datetime {value!r} encountered and no default timezone has been set"
            )

    if getattr(encoder, "datetime_as_timestamp", False):
        if not value.microsecond:
            timestamp: float = timegm(value.utctimetuple())
        else:
            timestamp = timegm(value.utctimetuple()) + value.microsecond / 1_000_000

        # AWS uses an integer count of milliseconds. AWS SDKs assume the
        # encoded type is integer (CBOR is typed) and reject floats.
        # cbor2 6.x: encode_semantic takes ``(tag, value)`` positionally
        # (the 5.x style of passing a pre-built CBORTag is gone).
        encoder.encode_semantic(1, int(timestamp * 1000))
    else:
        datestring = value.isoformat().replace("+00:00", "Z")
        encoder.encode_semantic(0, datestring)


_AWS_SEMANTIC_DECODERS: dict[int, Any] = {1: _decode_aws_epoch_datetime}
_AWS_ENCODERS: dict[type, Any] = {datetime: _encode_aws_datetime}


def loads(data: bytes) -> Any:
    """Decode CBOR bytes with the AWS tag-1 quirk applied."""
    return cbor2.loads(data, semantic_decoders=_AWS_SEMANTIC_DECODERS)


def dumps(obj: Any, **kwargs: Any) -> bytes:
    """Encode an object to CBOR bytes with the AWS datetime quirk applied.

    Caller-provided ``encoders`` are merged in and take precedence for
    overlapping types, so callers can extend the mapping without losing
    the AWS datetime quirk for any type they do not specify.
    """
    user_encoders = kwargs.pop("encoders", None) or {}
    merged = {**_AWS_ENCODERS, **user_encoders}
    return cbor2.dumps(obj, encoders=merged, **kwargs)
