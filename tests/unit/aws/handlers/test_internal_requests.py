"""Auth-gating tests for :class:`InternalRequestParamsEnricher`.

The DTO header ``x-localemu-data`` is a LocalEmu-internal primitive that lets
service-to-service hops forward identity context (source_arn, service
principal) which downstream code uses to short-circuit IAM enforcement.
Accepting it from arbitrary external HTTP clients is a privilege-escalation
vector, so acceptance requires a matching
:data:`INTERNAL_REQUEST_AUTH_TOKEN`, regenerated per process.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from localemu.aws.connect import (
    INTERNAL_REQUEST_AUTH_HEADER,
    INTERNAL_REQUEST_AUTH_TOKEN,
    INTERNAL_REQUEST_PARAMS_HEADER,
)
from localemu.aws.handlers.internal_requests import InternalRequestParamsEnricher


def _ctx(headers: dict, remote_addr: str = "203.0.113.7") -> SimpleNamespace:
    """Minimal RequestContext stand-in carrying just the headers map and a
    remote_addr that the enricher logs on rejection."""
    request = SimpleNamespace(headers=headers, remote_addr=remote_addr)
    return SimpleNamespace(request=request, internal_request_params=None)


class TestAuthGating:
    def test_valid_token_accepts_dto(self):
        dto = {"service_principal": "lambda", "source_arn": "arn:aws:lambda:::function:foo"}
        ctx = _ctx(
            {
                INTERNAL_REQUEST_PARAMS_HEADER: json.dumps(dto),
                INTERNAL_REQUEST_AUTH_HEADER: INTERNAL_REQUEST_AUTH_TOKEN,
            }
        )
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert dict(ctx.internal_request_params) == dto

    def test_forged_dto_without_token_is_dropped(self):
        forged = {"service_principal": "iam", "source_arn": "arn:aws:iam::999999999999:root"}
        ctx = _ctx({INTERNAL_REQUEST_PARAMS_HEADER: json.dumps(forged)})
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert ctx.internal_request_params is None

    def test_forged_dto_with_wrong_token_is_dropped(self):
        forged = {"service_principal": "iam"}
        ctx = _ctx(
            {
                INTERNAL_REQUEST_PARAMS_HEADER: json.dumps(forged),
                INTERNAL_REQUEST_AUTH_HEADER: "AAAA" * 16,
            }
        )
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert ctx.internal_request_params is None

    def test_no_dto_header_is_noop(self):
        ctx = _ctx({})
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert ctx.internal_request_params is None

    def test_malformed_dto_with_valid_token_is_dropped(self):
        ctx = _ctx(
            {
                INTERNAL_REQUEST_PARAMS_HEADER: "{not-json",
                INTERNAL_REQUEST_AUTH_HEADER: INTERNAL_REQUEST_AUTH_TOKEN,
            }
        )
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert ctx.internal_request_params is None

    def test_empty_token_is_dropped(self):
        # Defensive: a deployment that explicitly sets
        # LOCALEMU_INTERNAL_AUTH_TOKEN="" must never match an empty Auth header.
        # The module-level token is regenerated to 64 hex chars in that case,
        # so the falsy-string check inside compare_digest can't be sidestepped.
        assert len(INTERNAL_REQUEST_AUTH_TOKEN) == 64
        ctx = _ctx(
            {
                INTERNAL_REQUEST_PARAMS_HEADER: json.dumps({"service_principal": "lambda"}),
                INTERNAL_REQUEST_AUTH_HEADER: "",
            }
        )
        InternalRequestParamsEnricher()(MagicMock(), ctx, MagicMock())
        assert ctx.internal_request_params is None
