import logging

from werkzeug.routing import Rule

from localemu.config import LAMBDA_DOCKER_NETWORK
from localemu.runtime import hooks
from localemu.services.edge import ROUTER
from localemu.services.lambda_.custom_endpoints import LambdaCustomEndpoints

LOG = logging.getLogger(__name__)

CUSTOM_ROUTER_RULES: list[Rule] = []


@hooks.on_infra_start()
def validate_configuration() -> None:
    if LAMBDA_DOCKER_NETWORK == "host":
        LOG.warning(
            "The configuration LAMBDA_DOCKER_NETWORK=host is currently not supported with the new lambda provider."
        )


@hooks.on_infra_start()
def register_custom_endpoints() -> None:
    global CUSTOM_ROUTER_RULES
    CUSTOM_ROUTER_RULES = ROUTER.add(LambdaCustomEndpoints())


@hooks.on_infra_shutdown()
def remove_custom_endpoints() -> None:
    ROUTER.remove(CUSTOM_ROUTER_RULES)
