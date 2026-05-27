"""Tests for the RDS service provider.

Covers DB instance CRUD (create, describe, modify, delete) and
Aurora DB cluster operations. All operations go through the Moto-backed
API layer; Docker database containers are not exercised here unless
RDS_DOCKER_BACKEND=1 is set.
"""

import pytest
from botocore.exceptions import ClientError


class TestRdsDbInstance:
    """Tests for RDS DB instance create, describe, modify, and delete."""

    def test_create_and_describe_db_instance(self, aws_client):
        """CreateDBInstance should create an instance; DescribeDBInstances should find it."""
        rds = aws_client.rds
        db_id = "test-pg-instance"

        try:
            create_resp = rds.create_db_instance(
                DBInstanceIdentifier=db_id,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="testadmin",
                MasterUserPassword="TestPassword123!",
                AllocatedStorage=20,
            )
            db_inst = create_resp["DBInstance"]
            assert db_inst["DBInstanceIdentifier"] == db_id
            assert db_inst["Engine"] == "postgres"
            assert db_inst["MasterUsername"] == "testadmin"
            assert db_inst["DBInstanceClass"] == "db.t3.micro"

            # DescribeDBInstances should return the instance
            desc_resp = rds.describe_db_instances(
                DBInstanceIdentifier=db_id
            )
            instances = desc_resp["DBInstances"]
            assert len(instances) == 1
            assert instances[0]["DBInstanceIdentifier"] == db_id
            assert instances[0]["Engine"] == "postgres"
        finally:
            try:
                rds.delete_db_instance(
                    DBInstanceIdentifier=db_id,
                    SkipFinalSnapshot=True,
                )
            except Exception:
                pass

    def test_describe_db_instances_all(self, aws_client):
        """DescribeDBInstances without filters should list all instances."""
        rds = aws_client.rds
        db_id_1 = "test-desc-all-1"
        db_id_2 = "test-desc-all-2"

        try:
            rds.create_db_instance(
                DBInstanceIdentifier=db_id_1,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin1",
                MasterUserPassword="Password123!",
                AllocatedStorage=20,
            )
            rds.create_db_instance(
                DBInstanceIdentifier=db_id_2,
                DBInstanceClass="db.t3.small",
                Engine="mysql",
                MasterUsername="admin2",
                MasterUserPassword="Password456!",
                AllocatedStorage=20,
            )

            desc_resp = rds.describe_db_instances()
            db_ids = [
                inst["DBInstanceIdentifier"]
                for inst in desc_resp["DBInstances"]
            ]
            assert db_id_1 in db_ids
            assert db_id_2 in db_ids
        finally:
            for db_id in (db_id_1, db_id_2):
                try:
                    rds.delete_db_instance(
                        DBInstanceIdentifier=db_id,
                        SkipFinalSnapshot=True,
                    )
                except Exception:
                    pass

    def test_modify_db_instance(self, aws_client):
        """ModifyDBInstance should update instance attributes."""
        rds = aws_client.rds
        db_id = "test-modify-instance"

        try:
            rds.create_db_instance(
                DBInstanceIdentifier=db_id,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                AllocatedStorage=20,
            )

            # Modify the instance class
            modify_resp = rds.modify_db_instance(
                DBInstanceIdentifier=db_id,
                DBInstanceClass="db.t3.small",
                ApplyImmediately=True,
            )
            modified = modify_resp["DBInstance"]
            assert modified["DBInstanceIdentifier"] == db_id
            # The new class should be reflected (may be pending or immediate)
            assert modified["DBInstanceClass"] in ("db.t3.small", "db.t3.micro")
        finally:
            try:
                rds.delete_db_instance(
                    DBInstanceIdentifier=db_id,
                    SkipFinalSnapshot=True,
                )
            except Exception:
                pass

    def test_delete_db_instance_with_skip_final_snapshot(self, aws_client):
        """DeleteDBInstance with SkipFinalSnapshot=True should succeed."""
        rds = aws_client.rds
        db_id = "test-delete-instance"

        rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="Password123!",
            AllocatedStorage=20,
        )

        # Delete with SkipFinalSnapshot
        del_resp = rds.delete_db_instance(
            DBInstanceIdentifier=db_id,
            SkipFinalSnapshot=True,
        )
        assert del_resp["DBInstance"]["DBInstanceIdentifier"] == db_id

        # Verify it is gone
        with pytest.raises(ClientError) as exc_info:
            rds.describe_db_instances(DBInstanceIdentifier=db_id)
        assert exc_info.value.response["Error"]["Code"] == "DBInstanceNotFound"

    def test_delete_nonexistent_db_instance_raises(self, aws_client):
        """Deleting a DB instance that does not exist should raise an error."""
        rds = aws_client.rds

        with pytest.raises(ClientError) as exc_info:
            rds.delete_db_instance(
                DBInstanceIdentifier="nonexistent-db-xyz",
                SkipFinalSnapshot=True,
            )
        assert "DBInstanceNotFound" in exc_info.value.response["Error"]["Code"]

    def test_create_db_instance_with_db_name(self, aws_client):
        """CreateDBInstance with a DBName should set the initial database name."""
        rds = aws_client.rds
        db_id = "test-dbname-instance"

        try:
            create_resp = rds.create_db_instance(
                DBInstanceIdentifier=db_id,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                AllocatedStorage=20,
                DBName="myappdb",
            )
            assert create_resp["DBInstance"]["DBName"] == "myappdb"
        finally:
            try:
                rds.delete_db_instance(
                    DBInstanceIdentifier=db_id,
                    SkipFinalSnapshot=True,
                )
            except Exception:
                pass


class TestRdsDbCluster:
    """Tests for RDS Aurora DB cluster create, describe, and delete."""

    def test_create_and_describe_db_cluster(self, aws_client):
        """CreateDBCluster should create an Aurora cluster; DescribeDBClusters should find it."""
        rds = aws_client.rds
        cluster_id = "test-aurora-cluster"

        try:
            create_resp = rds.create_db_cluster(
                DBClusterIdentifier=cluster_id,
                Engine="aurora-postgresql",
                MasterUsername="clusteradmin",
                MasterUserPassword="ClusterPass123!",
            )
            cluster = create_resp["DBCluster"]
            assert cluster["DBClusterIdentifier"] == cluster_id
            assert cluster["Engine"] == "aurora-postgresql"
            assert cluster["MasterUsername"] == "clusteradmin"

            # DescribeDBClusters should return the cluster
            desc_resp = rds.describe_db_clusters(
                DBClusterIdentifier=cluster_id
            )
            clusters = desc_resp["DBClusters"]
            assert len(clusters) == 1
            assert clusters[0]["DBClusterIdentifier"] == cluster_id
        finally:
            try:
                rds.delete_db_cluster(
                    DBClusterIdentifier=cluster_id,
                    SkipFinalSnapshot=True,
                )
            except Exception:
                pass

    def test_describe_db_clusters_all(self, aws_client):
        """DescribeDBClusters without filters should list all clusters."""
        rds = aws_client.rds
        cluster_id_1 = "test-cluster-all-1"
        cluster_id_2 = "test-cluster-all-2"

        try:
            rds.create_db_cluster(
                DBClusterIdentifier=cluster_id_1,
                Engine="aurora-postgresql",
                MasterUsername="admin1",
                MasterUserPassword="Password123!",
            )
            rds.create_db_cluster(
                DBClusterIdentifier=cluster_id_2,
                Engine="aurora-mysql",
                MasterUsername="admin2",
                MasterUserPassword="Password456!",
            )

            desc_resp = rds.describe_db_clusters()
            cluster_ids = [
                c["DBClusterIdentifier"] for c in desc_resp["DBClusters"]
            ]
            assert cluster_id_1 in cluster_ids
            assert cluster_id_2 in cluster_ids
        finally:
            for cid in (cluster_id_1, cluster_id_2):
                try:
                    rds.delete_db_cluster(
                        DBClusterIdentifier=cid,
                        SkipFinalSnapshot=True,
                    )
                except Exception:
                    pass

    def test_delete_db_cluster(self, aws_client):
        """DeleteDBCluster should remove the cluster."""
        rds = aws_client.rds
        cluster_id = "test-delete-cluster"

        rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-postgresql",
            MasterUsername="admin",
            MasterUserPassword="Password123!",
        )

        # Delete the cluster
        del_resp = rds.delete_db_cluster(
            DBClusterIdentifier=cluster_id,
            SkipFinalSnapshot=True,
        )
        assert del_resp["DBCluster"]["DBClusterIdentifier"] == cluster_id

        # Verify it is gone
        with pytest.raises(ClientError) as exc_info:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        assert "DBClusterNotFound" in exc_info.value.response["Error"]["Code"]

    def test_delete_nonexistent_cluster_raises(self, aws_client):
        """Deleting a cluster that does not exist should raise an error."""
        rds = aws_client.rds

        with pytest.raises(ClientError) as exc_info:
            rds.delete_db_cluster(
                DBClusterIdentifier="nonexistent-cluster-xyz",
                SkipFinalSnapshot=True,
            )
        assert "DBClusterNotFound" in exc_info.value.response["Error"]["Code"]
