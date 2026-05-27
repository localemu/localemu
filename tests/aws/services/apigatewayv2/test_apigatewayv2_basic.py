"""Tests for API Gateway V2 (HTTP API) CRUD operations.

Covers CreateApi, GetApi, GetApis, DeleteApi, CreateRoute, GetRoutes,
CreateIntegration, GetIntegration, CreateStage, GetStages, and
CreateDeployment through the LocalEmu apigatewayv2 provider.
"""

import pytest
from botocore.exceptions import ClientError


class TestApiGatewayV2Crud:
    """CRUD tests for API Gateway V2 HTTP APIs."""

    def test_create_and_get_api(self, aws_client):
        """Create an HTTP API and verify it can be retrieved by ID."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            create_resp = client.create_api(
                Name="test-http-api",
                ProtocolType="HTTP",
                Description="Test HTTP API for CRUD verification",
            )
            api_id = create_resp["ApiId"]
            assert api_id
            assert create_resp["Name"] == "test-http-api"
            assert create_resp["ProtocolType"] == "HTTP"
            assert create_resp["Description"] == "Test HTTP API for CRUD verification"

            # GetApi should return the same API
            get_resp = client.get_api(ApiId=api_id)
            assert get_resp["ApiId"] == api_id
            assert get_resp["Name"] == "test-http-api"
            assert get_resp["ProtocolType"] == "HTTP"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_get_apis_lists_created_api(self, aws_client):
        """CreateApi should make the API appear in GetApis listing."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            create_resp = client.create_api(
                Name="test-list-api",
                ProtocolType="HTTP",
            )
            api_id = create_resp["ApiId"]

            apis_resp = client.get_apis()
            api_ids = [a["ApiId"] for a in apis_resp["Items"]]
            assert api_id in api_ids
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_delete_api(self, aws_client):
        """DeleteApi should remove the API so GetApi raises NotFoundException."""
        client = aws_client.apigatewayv2
        create_resp = client.create_api(
            Name="test-delete-api",
            ProtocolType="HTTP",
        )
        api_id = create_resp["ApiId"]

        # Delete should succeed
        client.delete_api(ApiId=api_id)

        # GetApi should now fail
        with pytest.raises(ClientError) as exc_info:
            client.get_api(ApiId=api_id)
        assert exc_info.value.response["Error"]["Code"] in (
            "NotFoundException",
            "404",
        )

    def test_delete_api_not_found(self, aws_client):
        """DeleteApi on a non-existent API should raise an error."""
        client = aws_client.apigatewayv2
        with pytest.raises(ClientError):
            client.delete_api(ApiId="nonexistent-api-id-99999")

    def test_create_api_with_cors(self, aws_client):
        """Create an HTTP API with CORS configuration."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            create_resp = client.create_api(
                Name="test-cors-api",
                ProtocolType="HTTP",
                CorsConfiguration={
                    "AllowOrigins": ["https://example.com"],
                    "AllowMethods": ["GET", "POST"],
                    "AllowHeaders": ["Content-Type"],
                    "MaxAge": 3600,
                },
            )
            api_id = create_resp["ApiId"]

            get_resp = client.get_api(ApiId=api_id)
            cors = get_resp.get("CorsConfiguration", {})
            assert "https://example.com" in cors.get("AllowOrigins", [])
            assert "GET" in cors.get("AllowMethods", [])
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)


class TestApiGatewayV2Routes:
    """Tests for API Gateway V2 route management."""

    def test_create_route_and_get_routes(self, aws_client):
        """Create a route with method+path and verify it appears in GetRoutes."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-route-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            route_resp = client.create_route(
                ApiId=api_id,
                RouteKey="GET /items",
            )
            route_id = route_resp["RouteId"]
            assert route_id
            assert route_resp["RouteKey"] == "GET /items"

            # GetRoutes should list the route
            routes_resp = client.get_routes(ApiId=api_id)
            route_keys = [r["RouteKey"] for r in routes_resp["Items"]]
            assert "GET /items" in route_keys
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_multiple_routes(self, aws_client):
        """Create multiple routes on the same API and verify all are listed."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-multi-route-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            route_keys_to_create = [
                "GET /users",
                "POST /users",
                "GET /users/{userId}",
                "DELETE /users/{userId}",
                "$default",
            ]
            for rk in route_keys_to_create:
                client.create_route(ApiId=api_id, RouteKey=rk)

            routes_resp = client.get_routes(ApiId=api_id)
            created_keys = {r["RouteKey"] for r in routes_resp["Items"]}
            for rk in route_keys_to_create:
                assert rk in created_keys, f"Route key {rk} not found in {created_keys}"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_route_with_any_method(self, aws_client):
        """Create a route with ANY method wildcard."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-any-route-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            route_resp = client.create_route(
                ApiId=api_id,
                RouteKey="ANY /proxy/{proxy+}",
            )
            assert route_resp["RouteKey"] == "ANY /proxy/{proxy+}"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)


class TestApiGatewayV2Integrations:
    """Tests for API Gateway V2 integration management."""

    def test_create_integration_aws_proxy(self, aws_client):
        """Create an AWS_PROXY integration and retrieve it."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-integration-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            integration_resp = client.create_integration(
                ApiId=api_id,
                IntegrationType="AWS_PROXY",
                IntegrationUri="arn:aws:lambda:us-east-1:000000000000:function:my-function",
                PayloadFormatVersion="2.0",
            )
            integration_id = integration_resp["IntegrationId"]
            assert integration_id
            assert integration_resp["IntegrationType"] == "AWS_PROXY"
            assert "my-function" in integration_resp["IntegrationUri"]
            assert integration_resp["PayloadFormatVersion"] == "2.0"

            # GetIntegration should return the same details
            get_resp = client.get_integration(
                ApiId=api_id,
                IntegrationId=integration_id,
            )
            assert get_resp["IntegrationId"] == integration_id
            assert get_resp["IntegrationType"] == "AWS_PROXY"
            assert get_resp["PayloadFormatVersion"] == "2.0"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_integration_http_proxy(self, aws_client):
        """Create an HTTP_PROXY integration and retrieve it."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-http-proxy-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            integration_resp = client.create_integration(
                ApiId=api_id,
                IntegrationType="HTTP_PROXY",
                IntegrationUri="https://httpbin.org/anything",
                IntegrationMethod="ANY",
            )
            integration_id = integration_resp["IntegrationId"]
            assert integration_id
            assert integration_resp["IntegrationType"] == "HTTP_PROXY"

            get_resp = client.get_integration(
                ApiId=api_id,
                IntegrationId=integration_id,
            )
            assert get_resp["IntegrationId"] == integration_id
            assert get_resp["IntegrationType"] == "HTTP_PROXY"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_get_integrations_lists_all(self, aws_client):
        """GetIntegrations should list all integrations for an API."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-list-integrations-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            # Create two integrations
            resp1 = client.create_integration(
                ApiId=api_id,
                IntegrationType="AWS_PROXY",
                IntegrationUri="arn:aws:lambda:us-east-1:000000000000:function:func-a",
                PayloadFormatVersion="2.0",
            )
            resp2 = client.create_integration(
                ApiId=api_id,
                IntegrationType="AWS_PROXY",
                IntegrationUri="arn:aws:lambda:us-east-1:000000000000:function:func-b",
                PayloadFormatVersion="1.0",
            )

            integrations_resp = client.get_integrations(ApiId=api_id)
            ids = [i["IntegrationId"] for i in integrations_resp["Items"]]
            assert resp1["IntegrationId"] in ids
            assert resp2["IntegrationId"] in ids
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)


class TestApiGatewayV2Stages:
    """Tests for API Gateway V2 stage management."""

    def test_create_stage_and_get_stages(self, aws_client):
        """Create a stage and verify it appears in GetStages."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-stage-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            stage_resp = client.create_stage(
                ApiId=api_id,
                StageName="dev",
                Description="Development stage",
            )
            assert stage_resp["StageName"] == "dev"
            assert stage_resp["Description"] == "Development stage"

            stages_resp = client.get_stages(ApiId=api_id)
            stage_names = [s["StageName"] for s in stages_resp["Items"]]
            assert "dev" in stage_names
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_stage_with_auto_deploy(self, aws_client):
        """Create a stage with autoDeploy enabled."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-autodeploy-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            stage_resp = client.create_stage(
                ApiId=api_id,
                StageName="prod",
                AutoDeploy=True,
            )
            assert stage_resp["StageName"] == "prod"
            assert stage_resp.get("AutoDeploy") is True
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_multiple_stages(self, aws_client):
        """Create multiple stages on the same API."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-multi-stage-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            for stage_name in ["dev", "staging", "prod"]:
                client.create_stage(ApiId=api_id, StageName=stage_name)

            stages_resp = client.get_stages(ApiId=api_id)
            stage_names = {s["StageName"] for s in stages_resp["Items"]}
            assert {"dev", "staging", "prod"}.issubset(stage_names)
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)


class TestApiGatewayV2Deployments:
    """Tests for API Gateway V2 deployment management."""

    def test_create_deployment(self, aws_client):
        """Create a deployment for an API and verify it has a deployment ID."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-deployment-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            # Create a route so the API has something to deploy
            client.create_route(ApiId=api_id, RouteKey="GET /health")

            deploy_resp = client.create_deployment(
                ApiId=api_id,
                Description="Initial deployment",
            )
            deployment_id = deploy_resp["DeploymentId"]
            assert deployment_id
            assert deploy_resp.get("Description") == "Initial deployment"
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_get_deployments(self, aws_client):
        """GetDeployments should list all deployments for an API."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-get-deployments-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            client.create_route(ApiId=api_id, RouteKey="GET /ping")

            deploy1 = client.create_deployment(
                ApiId=api_id, Description="Deploy 1"
            )
            deploy2 = client.create_deployment(
                ApiId=api_id, Description="Deploy 2"
            )

            deployments_resp = client.get_deployments(ApiId=api_id)
            deploy_ids = [d["DeploymentId"] for d in deployments_resp["Items"]]
            assert deploy1["DeploymentId"] in deploy_ids
            assert deploy2["DeploymentId"] in deploy_ids
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)

    def test_create_stage_with_deployment(self, aws_client):
        """Create a stage linked to a specific deployment."""
        client = aws_client.apigatewayv2
        api_id = None
        try:
            api_resp = client.create_api(
                Name="test-stage-deploy-api",
                ProtocolType="HTTP",
            )
            api_id = api_resp["ApiId"]

            client.create_route(ApiId=api_id, RouteKey="GET /status")

            deploy_resp = client.create_deployment(ApiId=api_id)
            deployment_id = deploy_resp["DeploymentId"]

            stage_resp = client.create_stage(
                ApiId=api_id,
                StageName="v1",
                DeploymentId=deployment_id,
            )
            assert stage_resp["StageName"] == "v1"
            assert stage_resp.get("DeploymentId") == deployment_id
        finally:
            if api_id:
                client.delete_api(ApiId=api_id)
