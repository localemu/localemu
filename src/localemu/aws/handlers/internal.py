"""Handler for routing internal localemu resources under /_localemu."""

import logging

from werkzeug.exceptions import NotFound

from localemu import constants
from localemu.http import Response
from localemu.runtime import events
from localemu.services.internal import LocalemuResources

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class LocalemuResourceHandler(Handler):
    """
    Adapter to serve LocalemuResources as a Handler.
    """

    resources: LocalemuResources

    def __init__(self, resources: LocalemuResources = None) -> None:
        from localemu.services.internal import get_internal_apis

        self.resources = resources or get_internal_apis()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        try:
            # serve
            response.update_from(self.resources.dispatch(context.request))
            chain.stop()
        except NotFound:
            path = context.request.path
            if path.startswith(constants.INTERNAL_RESOURCE_PATH + "/"):
                # only return 404 if we're accessing an internal resource, otherwise fall back to the other handlers
                LOG.warning("Unable to find resource handler for path: %s", path)
                chain.respond(404)


class RuntimeShutdownHandler(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if events.infra_stopped.is_set():
            chain.respond(503)
        elif events.infra_stopping.is_set():
            # if we're in the process of shutting down the infrastructure, only accept internal calls, or calls to
            # internal APIs
            if context.is_internal_call:
                return
            if context.request.path.startswith("/_localemu"):
                return
            chain.respond(503)
