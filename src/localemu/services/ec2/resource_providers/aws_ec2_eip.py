from pathlib import Path
from typing import TypedDict

from botocore.exceptions import ClientError

from localemu.services.cloudformation.provider_utils import (
    get_schema_path,
    resource_tags_to_remove_or_update,
)
from localemu.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class Tag(TypedDict):
    Key: str
    Value: str


class EC2EIPProperties(TypedDict, total=False):
    Domain: str
    Tags: list[Tag]
    AllocationId: str
    PublicIp: str


class EC2EIPProvider(ResourceProvider[EC2EIPProperties]):
    """Manage a VPC Elastic IP allocated from the default EC2 pool."""

    TYPE = "AWS::EC2::EIP"
    SCHEMA = get_schema_path(Path(__file__))

    def create(self, request: ResourceRequest[EC2EIPProperties]) -> ProgressEvent[EC2EIPProperties]:
        """Allocate an address and expose both its public IP and allocation ID."""
        model = request.desired_state
        unsupported = model.keys() - {"Domain", "Tags"}
        if unsupported:
            raise ValueError(f"Unsupported Elastic IP properties: {', '.join(sorted(unsupported))}")

        params = {"Domain": model.get("Domain", "vpc")}
        if tags := model.get("Tags"):
            params["TagSpecifications"] = [{"ResourceType": "elastic-ip", "Tags": tags}]

        address = request.aws_client_factory.ec2.allocate_address(**params)
        model["AllocationId"] = address["AllocationId"]
        model["PublicIp"] = address["PublicIp"]
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def update(self, request: ResourceRequest[EC2EIPProperties]) -> ProgressEvent[EC2EIPProperties]:
        """Apply tag changes without replacing the address."""
        model = request.desired_state
        previous = request.previous_state
        changed = {
            key for key in model.keys() | previous.keys() if model.get(key) != previous.get(key)
        }
        if changed - {"Tags", "AllocationId", "PublicIp"}:
            raise ValueError("Only tag updates are supported for Elastic IPs")

        ec2 = request.aws_client_factory.ec2
        allocation_id = previous["AllocationId"]
        removed, updated = resource_tags_to_remove_or_update(
            previous.get("Tags", []), model.get("Tags", [])
        )
        if removed:
            ec2.delete_tags(Resources=[allocation_id], Tags=[{"Key": key} for key in removed])
        if updated:
            ec2.create_tags(
                Resources=[allocation_id],
                Tags=[{"Key": key, "Value": value} for key, value in updated.items()],
            )
        model["AllocationId"] = allocation_id
        model["PublicIp"] = previous["PublicIp"]
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(self, request: ResourceRequest[EC2EIPProperties]) -> ProgressEvent[EC2EIPProperties]:
        """Release the address, including on repeated deletion requests."""
        model = request.desired_state
        try:
            request.aws_client_factory.ec2.release_address(AllocationId=model["AllocationId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
                raise
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
