"""Tests for the CloudTrail service provider.

Covers trail CRUD operations (backed by Moto) and the custom
LookupEvents implementation that queries the shared event store.
"""

import pytest
from botocore.exceptions import ClientError


class TestCloudTrailTrailCrud:
    """Tests for CloudTrail trail create, describe, start/stop logging, and delete."""

    def test_create_and_describe_trail(self, aws_client):
        """CreateTrail followed by DescribeTrails should return the trail."""
        cloudtrail = aws_client.cloudtrail
        s3 = aws_client.s3
        bucket_name = "cloudtrail-test-bucket"
        trail_name = "test-trail"

        try:
            # Create the S3 bucket that the trail references
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": "us-east-2"},
            )

            # Create the trail
            create_resp = cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
            )
            assert create_resp["Name"] == trail_name
            assert create_resp["S3BucketName"] == bucket_name

            # Describe trails should include the new trail
            describe_resp = cloudtrail.describe_trails()
            trail_names = [t["Name"] for t in describe_resp["trailList"]]
            assert trail_name in trail_names

            # Verify trail details
            matched = [t for t in describe_resp["trailList"] if t["Name"] == trail_name]
            assert len(matched) == 1
            assert matched[0]["S3BucketName"] == bucket_name
        finally:
            try:
                cloudtrail.delete_trail(Name=trail_name)
            except Exception:
                pass
            try:
                s3.delete_bucket(Bucket=bucket_name)
            except Exception:
                pass

    def test_start_and_stop_logging(self, aws_client):
        """StartLogging and StopLogging should succeed without error."""
        cloudtrail = aws_client.cloudtrail
        s3 = aws_client.s3
        bucket_name = "cloudtrail-logging-bucket"
        trail_name = "test-logging-trail"

        try:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": "us-east-2"},
            )
            cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
            )

            # StartLogging should succeed
            cloudtrail.start_logging(Name=trail_name)

            # Get trail status to verify logging is active
            status = cloudtrail.get_trail_status(Name=trail_name)
            assert status["IsLogging"] is True

            # StopLogging should succeed
            cloudtrail.stop_logging(Name=trail_name)

            status = cloudtrail.get_trail_status(Name=trail_name)
            assert status["IsLogging"] is False
        finally:
            try:
                cloudtrail.delete_trail(Name=trail_name)
            except Exception:
                pass
            try:
                s3.delete_bucket(Bucket=bucket_name)
            except Exception:
                pass

    def test_delete_trail(self, aws_client):
        """DeleteTrail should remove the trail from DescribeTrails results."""
        cloudtrail = aws_client.cloudtrail
        s3 = aws_client.s3
        bucket_name = "cloudtrail-delete-bucket"
        trail_name = "test-delete-trail"

        try:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": "us-east-2"},
            )
            cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
            )

            # Verify the trail exists
            trails = cloudtrail.describe_trails()["trailList"]
            assert any(t["Name"] == trail_name for t in trails)

            # Delete the trail
            cloudtrail.delete_trail(Name=trail_name)

            # Verify the trail no longer appears
            trails = cloudtrail.describe_trails()["trailList"]
            assert not any(t["Name"] == trail_name for t in trails)
        finally:
            try:
                s3.delete_bucket(Bucket=bucket_name)
            except Exception:
                pass

    def test_delete_nonexistent_trail_raises(self, aws_client):
        """Deleting a trail that does not exist should raise an error."""
        cloudtrail = aws_client.cloudtrail

        with pytest.raises(ClientError) as exc_info:
            cloudtrail.delete_trail(Name="nonexistent-trail-xyz")
        assert exc_info.value.response["Error"]["Code"] == "TrailNotFoundException"


class TestCloudTrailLookupEvents:
    """Tests for the custom LookupEvents implementation."""

    def test_lookup_events_returns_list(self, aws_client):
        """LookupEvents should return a list of events (possibly empty)."""
        cloudtrail = aws_client.cloudtrail

        # Make some API calls first so events get recorded
        aws_client.s3.list_buckets()

        response = cloudtrail.lookup_events(MaxResults=10)
        assert "Events" in response
        assert isinstance(response["Events"], list)

    def test_lookup_events_with_event_name_filter(self, aws_client):
        """LookupEvents with EventName filter should only return matching events."""
        cloudtrail = aws_client.cloudtrail

        # Generate a known event
        aws_client.s3.list_buckets()

        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    "AttributeKey": "EventName",
                    "AttributeValue": "ListBuckets",
                }
            ],
            MaxResults=50,
        )
        assert "Events" in response
        # All returned events (if any) should match the filter
        for event in response["Events"]:
            assert event.get("EventName") == "ListBuckets"

    def test_lookup_events_with_resource_type_filter(self, aws_client):
        """LookupEvents with ResourceType filter should return matching events."""
        cloudtrail = aws_client.cloudtrail

        # Create an S3 bucket to generate an event with a resource
        bucket_name = "cloudtrail-resource-filter-test"
        try:
            aws_client.s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": "us-east-2"},
            )

            response = cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "ResourceType",
                        "AttributeValue": "AWS::S3::Bucket",
                    }
                ],
                MaxResults=50,
            )
            assert "Events" in response
            assert isinstance(response["Events"], list)
        finally:
            try:
                aws_client.s3.delete_bucket(Bucket=bucket_name)
            except Exception:
                pass

    def test_lookup_events_max_results(self, aws_client):
        """LookupEvents should respect the MaxResults parameter."""
        cloudtrail = aws_client.cloudtrail

        # Generate multiple events
        for i in range(5):
            aws_client.s3.list_buckets()

        response = cloudtrail.lookup_events(MaxResults=2)
        assert "Events" in response
        assert len(response["Events"]) <= 2

    def test_lookup_events_pagination(self, aws_client):
        """LookupEvents should support pagination via NextToken."""
        cloudtrail = aws_client.cloudtrail

        # Generate events
        for i in range(5):
            aws_client.s3.list_buckets()

        # Request a small page
        first_page = cloudtrail.lookup_events(MaxResults=2)
        assert "Events" in first_page

        # If there is a NextToken, fetch the next page
        if "NextToken" in first_page and first_page["NextToken"]:
            second_page = cloudtrail.lookup_events(
                MaxResults=2,
                NextToken=first_page["NextToken"],
            )
            assert "Events" in second_page
