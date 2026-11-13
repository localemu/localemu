import pytest
from botocore.exceptions import ClientError

from localemu.testing.pytest import markers


@markers.aws.unknown
def test_vpc_eip_allocation_id(deploy_cfn_template, aws_client):
    """An EIP stack exposes a usable allocation ID and releases it on deletion."""
    template = """
Resources:
  ElasticIp:
    Type: AWS::EC2::EIP
    Properties:
      Domain: vpc
      Tags:
        - Key: Name
          Value: cfn-eip-test
Outputs:
  AllocationId:
    Value: !GetAtt ElasticIp.AllocationId
  PublicIp:
    Value: !Ref ElasticIp
"""
    stack = deploy_cfn_template(template=template)

    allocation_id = stack.outputs["AllocationId"]
    assert allocation_id.startswith("eipalloc-")
    [address] = aws_client.ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"]
    assert address["PublicIp"] == stack.outputs["PublicIp"]
    assert {"Key": "Name", "Value": "cfn-eip-test"} in address["Tags"]

    updated_stack = deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template=template.replace("Key: Name", "Key: Updated").replace(
            "Value: cfn-eip-test", "Value: cfn-eip-updated"
        ),
    )
    assert updated_stack.outputs["AllocationId"] == allocation_id
    [updated_address] = aws_client.ec2.describe_addresses(AllocationIds=[allocation_id])[
        "Addresses"
    ]
    tags = {tag["Key"]: tag["Value"] for tag in updated_address["Tags"]}
    assert "Name" not in tags
    assert tags["Updated"] == "cfn-eip-updated"

    stack.destroy()

    with pytest.raises(ClientError, match="InvalidAllocationID.NotFound"):
        aws_client.ec2.describe_addresses(AllocationIds=[allocation_id])
