from rolo.gateway import CompositeHandler

from localemu.services.apigateway.analytics import invocation_counter

from .analytics import IntegrationUsageCounter
from .api_key_validation import ApiKeyValidationHandler
from .authorizer import AuthorizerHandler
from .gateway_exception import GatewayExceptionHandler
from .throttle import ThrottleHandler
from .integration import IntegrationHandler
from .integration_request import IntegrationRequestHandler
from .integration_response import IntegrationResponseHandler
from .method_request import MethodRequestHandler
from .method_response import MethodResponseHandler
from .parse import InvocationRequestParser
from .resource_router import InvocationRequestRouter
from .response_enricher import InvocationResponseEnricher

parse_request = InvocationRequestParser()
modify_request = CompositeHandler()
route_request = InvocationRequestRouter()
preprocess_request = CompositeHandler()
# Register handlers in the preprocess_request chain (after routing, before method request validation):
# 1. Throttle handler: enforce per-stage rate limiting
preprocess_request.handlers.append(ThrottleHandler())
# 2. Authorizer handler: invoke Lambda/Cognito authorizers
preprocess_request.handlers.append(AuthorizerHandler())
method_request_handler = MethodRequestHandler()
integration_request_handler = IntegrationRequestHandler()
integration_handler = IntegrationHandler()
integration_response_handler = IntegrationResponseHandler()
method_response_handler = MethodResponseHandler()
gateway_exception_handler = GatewayExceptionHandler()
api_key_validation_handler = ApiKeyValidationHandler()
response_enricher = InvocationResponseEnricher()
usage_counter = IntegrationUsageCounter(counter=invocation_counter)
