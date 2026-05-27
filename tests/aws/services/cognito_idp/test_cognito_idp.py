"""Tests for Cognito Identity Provider (cognito-idp) service.

Covers user pool CRUD, user management, authentication flows,
and JWT token generation.
"""

import json

import pytest


class TestCognitoUserPools:
    """Test user pool and client CRUD operations."""

    def test_create_user_pool(self, aws_client):
        """CreateUserPool returns a valid pool with correct attributes."""
        client = aws_client.cognito_idp
        resp = client.create_user_pool(PoolName="test-pool-crud")
        pool = resp["UserPool"]
        pool_id = pool["Id"]

        try:
            assert pool["Name"] == "test-pool-crud"
            assert pool_id is not None

            # DescribeUserPool
            desc = client.describe_user_pool(UserPoolId=pool_id)
            assert desc["UserPool"]["Name"] == "test-pool-crud"
        finally:
            client.delete_user_pool(UserPoolId=pool_id)

    def test_list_user_pools(self, aws_client):
        """ListUserPools returns created pools."""
        client = aws_client.cognito_idp
        resp = client.create_user_pool(PoolName="test-pool-list")
        pool_id = resp["UserPool"]["Id"]

        try:
            pools = client.list_user_pools(MaxResults=50)
            pool_names = [p["Name"] for p in pools["UserPools"]]
            assert "test-pool-list" in pool_names
        finally:
            client.delete_user_pool(UserPoolId=pool_id)

    def test_create_user_pool_client(self, aws_client):
        """CreateUserPoolClient returns a valid client with secret."""
        client = aws_client.cognito_idp
        pool_resp = client.create_user_pool(PoolName="test-pool-client")
        pool_id = pool_resp["UserPool"]["Id"]

        try:
            client_resp = client.create_user_pool_client(
                UserPoolId=pool_id,
                ClientName="test-app-client",
                ExplicitAuthFlows=["USER_PASSWORD_AUTH"],
                GenerateSecret=True,
            )
            app_client = client_resp["UserPoolClient"]
            assert app_client["ClientName"] == "test-app-client"
            assert "ClientId" in app_client
            assert "ClientSecret" in app_client

            # DescribeUserPoolClient
            desc = client.describe_user_pool_client(
                UserPoolId=pool_id, ClientId=app_client["ClientId"]
            )
            assert desc["UserPoolClient"]["ClientName"] == "test-app-client"
        finally:
            client.delete_user_pool(UserPoolId=pool_id)


class TestCognitoUsers:
    """Test user management operations."""

    @pytest.fixture
    def pool_with_client(self, aws_client):
        """Create a user pool with an app client for auth testing."""
        client = aws_client.cognito_idp
        pool_resp = client.create_user_pool(
            PoolName="test-pool-users",
            Policies={
                "PasswordPolicy": {
                    "MinimumLength": 8,
                    "RequireUppercase": False,
                    "RequireLowercase": False,
                    "RequireNumbers": False,
                    "RequireSymbols": False,
                }
            },
            AutoVerifiedAttributes=["email"],
        )
        pool_id = pool_resp["UserPool"]["Id"]

        client_resp = client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName="test-auth-client",
            ExplicitAuthFlows=[
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
            ],
        )
        client_id = client_resp["UserPoolClient"]["ClientId"]

        yield {"pool_id": pool_id, "client_id": client_id, "client": client}

        client.delete_user_pool(UserPoolId=pool_id)

    def test_admin_create_user(self, pool_with_client):
        """AdminCreateUser creates a user with temporary password."""
        ctx = pool_with_client
        resp = ctx["client"].admin_create_user(
            UserPoolId=ctx["pool_id"],
            Username="testuser",
            TemporaryPassword="TempPass123!",
            UserAttributes=[
                {"Name": "email", "Value": "test@example.com"},
            ],
        )
        user = resp["User"]
        assert user["Username"] == "testuser"
        assert user["UserStatus"] == "FORCE_CHANGE_PASSWORD"

    def test_admin_get_user(self, pool_with_client):
        """AdminGetUser returns the correct user."""
        ctx = pool_with_client
        ctx["client"].admin_create_user(
            UserPoolId=ctx["pool_id"],
            Username="getuser",
            TemporaryPassword="TempPass123!",
        )
        resp = ctx["client"].admin_get_user(
            UserPoolId=ctx["pool_id"], Username="getuser"
        )
        assert resp["Username"] == "getuser"

    def test_list_users(self, pool_with_client):
        """ListUsers returns all users in the pool."""
        ctx = pool_with_client
        ctx["client"].admin_create_user(
            UserPoolId=ctx["pool_id"],
            Username="listuser1",
            TemporaryPassword="TempPass123!",
        )
        ctx["client"].admin_create_user(
            UserPoolId=ctx["pool_id"],
            Username="listuser2",
            TemporaryPassword="TempPass123!",
        )

        resp = ctx["client"].list_users(UserPoolId=ctx["pool_id"])
        usernames = [u["Username"] for u in resp["Users"]]
        assert "listuser1" in usernames
        assert "listuser2" in usernames

    def test_admin_delete_user(self, pool_with_client):
        """AdminDeleteUser removes the user."""
        ctx = pool_with_client
        ctx["client"].admin_create_user(
            UserPoolId=ctx["pool_id"],
            Username="deluser",
            TemporaryPassword="TempPass123!",
        )
        ctx["client"].admin_delete_user(
            UserPoolId=ctx["pool_id"], Username="deluser"
        )
        with pytest.raises(ctx["client"].exceptions.UserNotFoundException):
            ctx["client"].admin_get_user(
                UserPoolId=ctx["pool_id"], Username="deluser"
            )


class TestCognitoGroups:
    """Test group management."""

    def test_group_crud(self, aws_client):
        """Create, list, and delete groups."""
        client = aws_client.cognito_idp
        pool_resp = client.create_user_pool(PoolName="test-pool-groups")
        pool_id = pool_resp["UserPool"]["Id"]

        try:
            # Create group
            client.create_group(
                GroupName="admins",
                UserPoolId=pool_id,
                Description="Admin group",
            )

            # List groups
            resp = client.list_groups(UserPoolId=pool_id)
            group_names = [g["GroupName"] for g in resp["Groups"]]
            assert "admins" in group_names

            # Get group
            resp = client.get_group(GroupName="admins", UserPoolId=pool_id)
            assert resp["Group"]["GroupName"] == "admins"
            assert resp["Group"]["Description"] == "Admin group"

            # Delete group
            client.delete_group(GroupName="admins", UserPoolId=pool_id)
            resp = client.list_groups(UserPoolId=pool_id)
            assert len(resp["Groups"]) == 0
        finally:
            client.delete_user_pool(UserPoolId=pool_id)

    def test_add_user_to_group(self, aws_client):
        """AdminAddUserToGroup / AdminListGroupsForUser."""
        client = aws_client.cognito_idp
        pool_resp = client.create_user_pool(PoolName="test-pool-usergroup")
        pool_id = pool_resp["UserPool"]["Id"]

        try:
            client.admin_create_user(
                UserPoolId=pool_id,
                Username="groupuser",
                TemporaryPassword="TempPass123!",
            )
            client.create_group(GroupName="developers", UserPoolId=pool_id)
            client.admin_add_user_to_group(
                UserPoolId=pool_id,
                Username="groupuser",
                GroupName="developers",
            )

            resp = client.admin_list_groups_for_user(
                UserPoolId=pool_id, Username="groupuser"
            )
            group_names = [g["GroupName"] for g in resp["Groups"]]
            assert "developers" in group_names
        finally:
            client.delete_user_pool(UserPoolId=pool_id)
