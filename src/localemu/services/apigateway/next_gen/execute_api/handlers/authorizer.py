"""
Lambda authorizer handler for V1 next-gen REST API invocations.

This handler is responsible for invoking Lambda authorizers (TOKEN and REQUEST types)
when configured on a method, and populating the authorization context accordingly.
"""

import json
import logging

from localemu.aws.connect import connect_to
from localemu.http import Response
from localemu.utils.aws.arns import extract_region_from_arn
from localemu.utils.aws.client_types import ServicePrincipal
from localemu.utils.strings import to_str

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..gateway_response import AuthorizerFailureError, UnauthorizedError

LOG = logging.getLogger(__name__)


class AuthorizerHandler(RestApiGatewayHandler):
    """
    Invokes Lambda authorizers (TOKEN / REQUEST) when the method's authorizationType is CUSTOM.
    Cognito User Pools authorizers (authorizationType=COGNITO_USER_POOLS) are validated by
    checking the token against the configured user pool.

    This handler runs as part of the preprocess_request CompositeHandler, after routing
    has determined the resource_method and before method request validation.
    """

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        method = context.resource_method
        if not method:
            return

        auth_type = (method.get("authorizationType") or "NONE").upper()
        if auth_type == "NONE":
            return

        authorizer_id = method.get("authorizerId")
        if not authorizer_id:
            # authorizationType is set but no authorizer ID — skip
            return

        authorizers = context.deployment.rest_api.authorizers
        authorizer = authorizers.get(authorizer_id)
        if not authorizer:
            LOG.warning("Authorizer %s not found in deployment", authorizer_id)
            raise AuthorizerFailureError("Authorizer configuration error")

        authorizer_type = (authorizer.get("type") or "").upper()

        if authorizer_type == "TOKEN":
            self._invoke_token_authorizer(context, authorizer)
        elif authorizer_type == "REQUEST":
            self._invoke_request_authorizer(context, authorizer)
        elif authorizer_type == "COGNITO_USER_POOLS":
            self._validate_cognito_authorizer(context, authorizer)
        else:
            LOG.debug("Unknown authorizer type: %s", authorizer_type)

    def _invoke_token_authorizer(
        self, context: RestApiInvocationContext, authorizer: dict
    ):
        """Invoke a TOKEN-type Lambda authorizer."""
        # Get the token from the configured identity source header
        identity_source = authorizer.get("identitySource", "method.request.header.Authorization")
        header_name = identity_source.replace("method.request.header.", "")
        token = context.invocation_request["headers"].get(header_name)

        if not token:
            raise UnauthorizedError("Unauthorized")

        # Build the authorizer event
        event = {
            "type": "TOKEN",
            "authorizationToken": token,
            "methodArn": self._build_method_arn(context),
        }

        result = self._invoke_authorizer_lambda(context, authorizer, event)
        self._apply_authorizer_result(context, result)

    def _invoke_request_authorizer(
        self, context: RestApiInvocationContext, authorizer: dict
    ):
        """Invoke a REQUEST-type Lambda authorizer."""
        invocation_request = context.invocation_request

        # Build the authorizer event
        event = {
            "type": "REQUEST",
            "methodArn": self._build_method_arn(context),
            "resource": context.resource.get("path", ""),
            "path": invocation_request.get("raw_path", ""),
            "httpMethod": invocation_request["http_method"],
            "headers": dict(invocation_request["headers"]),
            "queryStringParameters": invocation_request.get("query_string_parameters") or {},
            "pathParameters": invocation_request.get("path_parameters") or {},
            "stageVariables": context.stage_variables or {},
            "requestContext": context.context_variables,
        }

        result = self._invoke_authorizer_lambda(context, authorizer, event)
        self._apply_authorizer_result(context, result)

    def _validate_cognito_authorizer(
        self, context: RestApiInvocationContext, authorizer: dict
    ):
        """Validate the authorization token against a Cognito User Pool.

        The token is cryptographically verified against the issuing pool's
        RSA key (the same key served at the pool's JWKS endpoint): signature,
        expiry, and that the token was issued by one of the pools configured
        on the authorizer (``providerARNs``). On success the decoded claims
        are exposed under ``requestContext.authorizer.claims``, matching AWS.
        """
        from localemu.services.cognito_idp.verify import (
            TokenVerificationError,
            verify_cognito_token,
        )

        identity_source = authorizer.get("identitySource", "method.request.header.Authorization")
        header_name = identity_source.replace("method.request.header.", "")
        token = context.invocation_request["headers"].get(header_name)

        if not token:
            raise UnauthorizedError("Unauthorized")

        # Restrict accepted tokens to the user pool(s) this authorizer trusts.
        # ARN form: arn:aws:cognito-idp:{region}:{account}:userpool/{pool_id}
        provider_arns = authorizer.get("providerARNs") or []
        allowed_pool_ids = [arn.rsplit("/", 1)[-1] for arn in provider_arns if "/" in arn]

        try:
            claims = verify_cognito_token(
                token, allowed_pool_ids=allowed_pool_ids or None
            )
        except TokenVerificationError as exc:
            LOG.debug("Cognito authorizer rejected token: %s", exc)
            raise UnauthorizedError("Unauthorized") from exc

        # AWS exposes the verified Cognito claims to the integration under
        # requestContext.authorizer.claims.
        ctx_auth = context.context_variables.setdefault("authorizer", {})
        ctx_auth["claims"] = claims
        ctx_auth.setdefault(
            "principalId", claims.get("sub") or claims.get("cognito:username")
        )

    def _invoke_authorizer_lambda(
        self, context: RestApiInvocationContext, authorizer: dict, event: dict
    ) -> dict:
        """Invoke the Lambda function configured for the authorizer and return the result."""
        authorizer_uri = authorizer.get("authorizerUri", "")

        # Extract function ARN from the authorizer URI
        # Format: arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{function_arn}/invocations
        function_arn = ""
        if ":lambda:path" in authorizer_uri:
            function_arn = (
                authorizer_uri.split(":lambda:path")[1]
                .split("functions/")[1]
                .split("/invocations")[0]
            )

        if not function_arn:
            LOG.warning("Could not extract Lambda function ARN from authorizer URI: %s", authorizer_uri)
            raise AuthorizerFailureError("Authorizer configuration error")

        credentials = authorizer.get("authorizerCredentials")
        region = extract_region_from_arn(function_arn)

        try:
            if credentials:
                lambda_client = connect_to.with_assumed_role(
                    role_arn=credentials,
                    region_name=region,
                    service_principal=ServicePrincipal.apigateway,
                    session_name="BackplaneAssumeRoleSession",
                ).lambda_
            else:
                lambda_client = connect_to(region_name=region).lambda_

            result = lambda_client.request_metadata(
                service_principal=ServicePrincipal.apigateway,
            ).invoke(
                FunctionName=function_arn,
                Payload=json.dumps(event).encode("utf-8"),
                InvocationType="RequestResponse",
            )

            payload = result.get("Payload")
            if payload:
                response_str = to_str(payload.read())
                return json.loads(response_str)
            return {}

        except Exception as e:
            LOG.warning("Lambda authorizer invocation failed: %s", e)
            raise AuthorizerFailureError("Authorizer configuration error") from e

    def _apply_authorizer_result(self, context: RestApiInvocationContext, result: dict):
        """Apply the authorizer result to the invocation context."""
        if not result:
            raise UnauthorizedError("Unauthorized")

        # Check the policy document
        policy = result.get("policyDocument", {})
        statements = policy.get("Statement", [])

        is_allowed = False
        for statement in statements:
            effect = statement.get("Effect", "").lower()
            if effect == "allow":
                is_allowed = True
                break

        if not is_allowed:
            raise UnauthorizedError("User is not authorized to access this resource")

        # Apply the authorizer context to the invocation context variables
        authorizer_context = result.get("context", {})
        if authorizer_context:
            context.context_variables["authorizer"] = authorizer_context

        # If the authorizer returns a principalId, set it in the context
        if principal_id := result.get("principalId"):
            if "authorizer" not in context.context_variables:
                context.context_variables["authorizer"] = {}
            context.context_variables["authorizer"]["principalId"] = principal_id

        # If a usageIdentifierKey is provided, set it for API key source = AUTHORIZER
        if usage_key := result.get("usageIdentifierKey"):
            if "authorizer" not in context.context_variables:
                context.context_variables["authorizer"] = {}
            context.context_variables["authorizer"]["usageIdentifierKey"] = usage_key

    @staticmethod
    def _build_method_arn(context: RestApiInvocationContext) -> str:
        """Build the method ARN that the authorizer receives."""
        region = context.region or "us-east-1"
        account_id = context.account_id or ""
        api_id = context.api_id or ""
        stage = context.stage or ""
        method = context.invocation_request["http_method"]
        path = context.resource.get("path", "/") if context.resource else "/"
        # Remove leading slash for ARN format
        path = path.lstrip("/") or "*"
        return f"arn:aws:execute-api:{region}:{account_id}:{api_id}/{stage}/{method}/{path}"
