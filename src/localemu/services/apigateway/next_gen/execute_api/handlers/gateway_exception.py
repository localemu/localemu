import json
import logging
import re

from rolo import Response
from werkzeug.datastructures import Headers

from localemu.constants import APPLICATION_JSON
from localemu.services.apigateway.next_gen.execute_api.api import (
    RestApiGatewayExceptionHandler,
    RestApiGatewayHandlerChain,
)
from localemu.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localemu.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
    BaseGatewayException,
    get_gateway_response_or_default,
)
from localemu.services.apigateway.next_gen.execute_api.variables import (
    GatewayResponseContextVarsError,
)

LOG = logging.getLogger(__name__)

# Pattern to match $context.error.<field> in gateway response templates
_CONTEXT_VAR_PATTERN = re.compile(r"\$context\.error\.(\w+)")


class GatewayExceptionHandler(RestApiGatewayExceptionHandler):
    """
    Exception handler that serializes the Gateway Exceptions into Gateway Responses
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        exception: Exception,
        context: RestApiInvocationContext,
        response: Response,
    ):
        if not isinstance(exception, BaseGatewayException):
            LOG.warning(
                "Non Gateway Exception raised: %s",
                exception,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            response.update_from(
                Response(response=f"Error in apigateway invocation: {exception}", status="500")
            )
            return

        LOG.info("Error raised during invocation: %s", exception.type)
        self.set_error_context(exception, context)
        error = self.create_exception_response(exception, context)
        if error:
            response.update_from(error)

    @staticmethod
    def set_error_context(exception: BaseGatewayException, context: RestApiInvocationContext):
        context.context_variables["error"] = GatewayResponseContextVarsError(
            message=exception.message,
            messageString=exception.message,
            responseType=exception.type,
            validationErrorString="",  # TODO
        )

    def create_exception_response(
        self, exception: BaseGatewayException, context: RestApiInvocationContext
    ):
        gateway_response = get_gateway_response_or_default(
            exception.type, context.deployment.rest_api.gateway_responses
        )

        content = self._build_response_content(exception, gateway_response, context)

        headers = self._build_response_headers(exception, gateway_response, context)

        status_code = gateway_response.get("statusCode")
        if not status_code:
            status_code = exception.status_code or 500

        response = Response(response=content, headers=headers, status=status_code)
        return response

    @staticmethod
    def _render_gateway_template(template: str, error_context: dict) -> str:
        """Render a gateway response template by substituting $context.error.* variables.
        Gateway response templates use simple variable substitution (not full VTL).
        """
        def replace_var(match: re.Match) -> str:
            field_name = match.group(1)
            value = error_context.get(field_name, "")
            # JSON-encode the value for proper embedding in templates
            return json.dumps(value) if isinstance(value, str) else str(value)

        return _CONTEXT_VAR_PATTERN.sub(replace_var, template)

    @staticmethod
    def _build_response_content(
        exception: BaseGatewayException,
        gateway_response: dict = None,
        context: RestApiInvocationContext = None,
    ) -> str:
        # Apply user-configured (non-default) responseTemplates if available.
        # Default gateway responses always carry the standard template
        # '{"message":$context.error.messageString}', which must NOT override
        # exception-specific formatting (e.g. AccessDeniedError uses uppercase "Message").
        if gateway_response and context and not gateway_response.get("defaultResponse"):
            response_templates = gateway_response.get("responseTemplates", {})
            if template := response_templates.get(APPLICATION_JSON):
                error_context = context.context_variables.get("error", {})
                try:
                    return GatewayExceptionHandler._render_gateway_template(
                        template, error_context
                    )
                except Exception:
                    LOG.debug("Failed to render gateway response template, using default")

        # Fallback: use the default template behavior
        if isinstance(exception, AccessDeniedError):
            return json.dumps({"Message": exception.message}, separators=(",", ":"))

        return json.dumps({"message": exception.message})

    @staticmethod
    def _build_response_headers(
        exception: BaseGatewayException,
        gateway_response: dict = None,
        context: RestApiInvocationContext = None,
    ) -> dict:
        headers = Headers({"Content-Type": APPLICATION_JSON, "x-amzn-ErrorType": exception.code})

        # Apply user-configured responseParameters to the headers
        if gateway_response:
            response_params = gateway_response.get("responseParameters", {})
            for param_key, param_value in response_params.items():
                # Response parameters have the format: gatewayresponse.header.<header-name>
                if param_key.startswith("gatewayresponse.header."):
                    header_name = param_key[len("gatewayresponse.header."):]
                    # Strip surrounding single quotes from static values
                    resolved_value = param_value.strip("'")
                    # Resolve $context.error.* variables in header values
                    if context and "$context.error." in resolved_value:
                        error_context = context.context_variables.get("error", {})
                        resolved_value = _CONTEXT_VAR_PATTERN.sub(
                            lambda m: error_context.get(m.group(1), ""),
                            resolved_value,
                        )
                    headers[header_name] = resolved_value

        return headers
