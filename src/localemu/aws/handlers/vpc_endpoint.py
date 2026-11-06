import logging

from localemu.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class VpcEndpointContextEnricher(Handler):
    """Tags the request context with the VPC endpoint it arrived through,
    if any, so the IAM enforcement handler can populate aws:SourceVpce /
    aws:SourceVpc and evaluate the endpoint's own policy.

    Each VPC Interface endpoint's proxy forwards to its own dedicated
    gateway listener port instead of everyone sharing the main edge port
    (see ``localemu.services.ec2.docker.vpc_endpoint``) - the local port a
    connection was accepted on is the one signal that survives Docker
    Desktop's NAT of all container->host traffic to 127.0.0.1, which ruled
    out source-IP based attribution.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        context.vpc_endpoint_id = None

        server_port = context.request.environ.get("SERVER_PORT")
        if not server_port:
            return
        try:
            local_port = int(server_port)
        except (TypeError, ValueError):
            return

        try:
            from localemu.services.ec2.docker.vpc_endpoint import get_vpc_endpoint_manager

            context.vpc_endpoint_id = get_vpc_endpoint_manager().get_endpoint_id_for_port(local_port)
        except Exception:
            LOG.debug("VPC endpoint attribution lookup failed for port %s", local_port, exc_info=True)
