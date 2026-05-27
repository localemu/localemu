import logging
from types import MappingProxyType

from localemu.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..connect import (
    INTERNAL_REQUEST_AUTH_HEADER,
    INTERNAL_REQUEST_AUTH_TOKEN,
    INTERNAL_REQUEST_PARAMS_HEADER,
    load_dto,
)

LOG = logging.getLogger(__name__)


class InternalRequestParamsEnricher(Handler):
    """
    Set the internal call DTO on the request context.

    The ``x-localemu-data`` header is a LocalEmu-internal primitive — it lets
    a service-to-service hop forward identity context (source_arn, service
    principal, account override) that downstream code uses to short-circuit
    IAM checks. Accepting it from arbitrary external clients lets an attacker
    impersonate any caller and bypass IAM enforcement, so we require a
    matching :data:`INTERNAL_REQUEST_AUTH_TOKEN` produced by the in-process
    :class:`InternalClientFactory`. Unauthenticated DTOs are dropped on the
    floor; the request then proceeds as a normal external call.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        header = context.request.headers.get(INTERNAL_REQUEST_PARAMS_HEADER)
        if not header:
            return

        auth = context.request.headers.get(INTERNAL_REQUEST_AUTH_HEADER, "")
        if not _constant_time_eq(auth, INTERNAL_REQUEST_AUTH_TOKEN):
            LOG.warning(
                "Dropping forged %s header from %s: missing/invalid auth token",
                INTERNAL_REQUEST_PARAMS_HEADER,
                context.request.remote_addr or "<unknown>",
            )
            return

        try:
            dto = MappingProxyType(load_dto(header))
        except Exception as e:
            LOG.error(
                "Error loading request parameters '%s', Error: %s",
                header,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            return

        context.internal_request_params = dto


def _constant_time_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
