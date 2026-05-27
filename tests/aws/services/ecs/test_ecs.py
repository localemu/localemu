"""Tests for the ECS service provider.

Covers cluster CRUD, task definition registration/deregistration,
and service create/update/delete operations. All operations go through
the Moto-backed API layer; Docker container execution is not tested here.
"""

import pytest
from botocore.exceptions import ClientError


class TestEcsCluster:
    """Tests for ECS cluster create, describe, list, and delete."""

    def test_create_and_describe_cluster(self, aws_client):
        """CreateCluster should return cluster details; DescribeClusters should find it."""
        ecs = aws_client.ecs
        cluster_name = "test-cluster-describe"

        try:
            create_resp = ecs.create_cluster(clusterName=cluster_name)
            cluster = create_resp["cluster"]
            assert cluster["clusterName"] == cluster_name
            assert cluster["status"] == "ACTIVE"
            cluster_arn = cluster["clusterArn"]

            # DescribeClusters by name
            desc_resp = ecs.describe_clusters(clusters=[cluster_name])
            assert len(desc_resp["clusters"]) == 1
            assert desc_resp["clusters"][0]["clusterArn"] == cluster_arn
            assert desc_resp["clusters"][0]["clusterName"] == cluster_name
        finally:
            try:
                ecs.delete_cluster(cluster=cluster_name)
            except Exception:
                pass

    def test_list_clusters(self, aws_client):
        """ListClusters should include a newly created cluster."""
        ecs = aws_client.ecs
        cluster_name = "test-cluster-list"

        try:
            ecs.create_cluster(clusterName=cluster_name)

            list_resp = ecs.list_clusters()
            cluster_arns = list_resp["clusterArns"]
            assert any(cluster_name in arn for arn in cluster_arns)
        finally:
            try:
                ecs.delete_cluster(cluster=cluster_name)
            except Exception:
                pass

    def test_delete_cluster(self, aws_client):
        """DeleteCluster should remove the cluster."""
        ecs = aws_client.ecs
        cluster_name = "test-cluster-delete"

        ecs.create_cluster(clusterName=cluster_name)

        # Delete it
        delete_resp = ecs.delete_cluster(cluster=cluster_name)
        assert delete_resp["cluster"]["clusterName"] == cluster_name

        # Verify it no longer appears as ACTIVE
        desc_resp = ecs.describe_clusters(clusters=[cluster_name])
        if desc_resp["clusters"]:
            assert desc_resp["clusters"][0]["status"] == "INACTIVE"
        # Or it might show up in failures
        # (Moto may place it in failures list after deletion)

    def test_describe_nonexistent_cluster(self, aws_client):
        """DescribeClusters for a nonexistent cluster should return it in failures."""
        ecs = aws_client.ecs

        desc_resp = ecs.describe_clusters(clusters=["nonexistent-cluster-xyz"])
        assert len(desc_resp["failures"]) > 0


class TestEcsTaskDefinition:
    """Tests for ECS task definition registration and deregistration."""

    def test_register_task_definition(self, aws_client):
        """RegisterTaskDefinition should return the registered definition."""
        ecs = aws_client.ecs

        try:
            resp = ecs.register_task_definition(
                family="test-task-family",
                containerDefinitions=[
                    {
                        "name": "web",
                        "image": "nginx:alpine",
                        "memory": 256,
                        "cpu": 128,
                        "essential": True,
                        "portMappings": [
                            {
                                "containerPort": 80,
                                "hostPort": 0,
                                "protocol": "tcp",
                            }
                        ],
                    }
                ],
            )
            task_def = resp["taskDefinition"]
            assert task_def["family"] == "test-task-family"
            assert task_def["status"] == "ACTIVE"
            assert len(task_def["containerDefinitions"]) == 1
            assert task_def["containerDefinitions"][0]["name"] == "web"
            assert task_def["containerDefinitions"][0]["image"] == "nginx:alpine"
            task_def_arn = task_def["taskDefinitionArn"]
            assert "test-task-family" in task_def_arn
        finally:
            try:
                ecs.deregister_task_definition(
                    taskDefinition="test-task-family:1"
                )
            except Exception:
                pass

    def test_register_task_definition_with_multiple_containers(self, aws_client):
        """RegisterTaskDefinition with multiple containers should register all of them."""
        ecs = aws_client.ecs

        try:
            resp = ecs.register_task_definition(
                family="test-multi-container",
                containerDefinitions=[
                    {
                        "name": "app",
                        "image": "python:3.11-slim",
                        "memory": 512,
                        "cpu": 256,
                        "essential": True,
                    },
                    {
                        "name": "sidecar",
                        "image": "redis:7-alpine",
                        "memory": 128,
                        "cpu": 64,
                        "essential": False,
                    },
                ],
            )
            task_def = resp["taskDefinition"]
            assert len(task_def["containerDefinitions"]) == 2
            container_names = [c["name"] for c in task_def["containerDefinitions"]]
            assert "app" in container_names
            assert "sidecar" in container_names
        finally:
            try:
                ecs.deregister_task_definition(
                    taskDefinition="test-multi-container:1"
                )
            except Exception:
                pass

    def test_deregister_task_definition(self, aws_client):
        """DeregisterTaskDefinition should mark the definition as INACTIVE."""
        ecs = aws_client.ecs

        ecs.register_task_definition(
            family="test-deregister",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "alpine:latest",
                    "memory": 128,
                    "cpu": 64,
                    "essential": True,
                }
            ],
        )

        dereg_resp = ecs.deregister_task_definition(
            taskDefinition="test-deregister:1"
        )
        assert dereg_resp["taskDefinition"]["status"] == "INACTIVE"


class TestEcsService:
    """Tests for ECS service create, update, and delete."""

    def test_create_service(self, aws_client):
        """CreateService should create a service with the specified desired count."""
        ecs = aws_client.ecs
        cluster_name = "test-svc-cluster"
        service_name = "test-service"

        try:
            ecs.create_cluster(clusterName=cluster_name)

            ecs.register_task_definition(
                family="svc-task",
                containerDefinitions=[
                    {
                        "name": "web",
                        "image": "nginx:alpine",
                        "memory": 256,
                        "cpu": 128,
                        "essential": True,
                    }
                ],
            )

            create_resp = ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition="svc-task:1",
                desiredCount=2,
            )
            service = create_resp["service"]
            assert service["serviceName"] == service_name
            assert service["desiredCount"] == 2
            assert service["status"] == "ACTIVE"
        finally:
            try:
                ecs.delete_service(
                    cluster=cluster_name,
                    service=service_name,
                    force=True,
                )
            except Exception:
                pass
            try:
                ecs.deregister_task_definition(taskDefinition="svc-task:1")
            except Exception:
                pass
            try:
                ecs.delete_cluster(cluster=cluster_name)
            except Exception:
                pass

    def test_update_service_scaling(self, aws_client):
        """UpdateService should change the desired count."""
        ecs = aws_client.ecs
        cluster_name = "test-update-svc-cluster"
        service_name = "test-update-service"

        try:
            ecs.create_cluster(clusterName=cluster_name)

            ecs.register_task_definition(
                family="update-svc-task",
                containerDefinitions=[
                    {
                        "name": "web",
                        "image": "nginx:alpine",
                        "memory": 256,
                        "cpu": 128,
                        "essential": True,
                    }
                ],
            )

            ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition="update-svc-task:1",
                desiredCount=1,
            )

            # Scale up
            update_resp = ecs.update_service(
                cluster=cluster_name,
                service=service_name,
                desiredCount=3,
            )
            assert update_resp["service"]["desiredCount"] == 3

            # Scale down
            update_resp = ecs.update_service(
                cluster=cluster_name,
                service=service_name,
                desiredCount=1,
            )
            assert update_resp["service"]["desiredCount"] == 1
        finally:
            try:
                ecs.delete_service(
                    cluster=cluster_name,
                    service=service_name,
                    force=True,
                )
            except Exception:
                pass
            try:
                ecs.deregister_task_definition(taskDefinition="update-svc-task:1")
            except Exception:
                pass
            try:
                ecs.delete_cluster(cluster=cluster_name)
            except Exception:
                pass

    def test_delete_service(self, aws_client):
        """DeleteService should remove the service."""
        ecs = aws_client.ecs
        cluster_name = "test-del-svc-cluster"
        service_name = "test-del-service"

        try:
            ecs.create_cluster(clusterName=cluster_name)

            ecs.register_task_definition(
                family="del-svc-task",
                containerDefinitions=[
                    {
                        "name": "web",
                        "image": "nginx:alpine",
                        "memory": 256,
                        "cpu": 128,
                        "essential": True,
                    }
                ],
            )

            ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition="del-svc-task:1",
                desiredCount=1,
            )

            # Delete the service
            del_resp = ecs.delete_service(
                cluster=cluster_name,
                service=service_name,
                force=True,
            )
            assert del_resp["service"]["serviceName"] == service_name

            # Verify the service is no longer ACTIVE
            list_resp = ecs.list_services(cluster=cluster_name)
            active_arns = list_resp.get("serviceArns", [])
            assert not any(service_name in arn for arn in active_arns)
        finally:
            try:
                ecs.deregister_task_definition(taskDefinition="del-svc-task:1")
            except Exception:
                pass
            try:
                ecs.delete_cluster(cluster=cluster_name)
            except Exception:
                pass
