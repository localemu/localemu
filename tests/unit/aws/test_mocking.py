import pytest

# ``localemu.aws.mocking`` pulls in ``rstr`` which only ships in the
# ``[dev]`` extra. Test environments installed via ``[test]`` (the
# common CI footprint) skip the whole module rather than failing
# collection of the entire ``tests/unit`` tree.
pytest.importorskip("rstr")

from localemu.aws.forwarder import create_aws_request_context
from localemu.aws.mocking import generate_request, generate_response, get_mocking_skeleton
from localemu.aws.protocol.serializer import create_serializer as create_response_serializer
from localemu.aws.protocol.validate import validate_request
from localemu.aws.spec import load_service
from localemu.utils.strings import long_uid


# currently, checking all operations just takes too long and is potentially flaky due to nondeterminism when
# generating strings. so we only test a few methods here.
@pytest.mark.parametrize(
    "service_name, operation_name",
    [
        ("dynamodb", "GetItem"),  # this input shape has a cycle
        ("ec2", "DescribeInstances"),
        ("lambda", "CreateFunction"),
        ("rds", "CreateDBCluster"),
    ],
)
def test_generate_request(service_name, operation_name):
    service = load_service(service_name)
    operation = service.operation_model(operation_name)
    request = generate_request(operation)

    assert request

    result = validate_request(operation, request)
    assert not result.has_errors()


@pytest.mark.parametrize(
    "service_name, operation_name",
    [
        ("dynamodb", "GetItem"),
        ("ec2", "DescribeInstances"),
        ("lambda", "CreateFunction"),
        ("rds", "CreateDBCluster"),
    ],
)
def test_generate_response(service_name, operation_name):
    service = load_service(service_name)
    operation = service.operation_model(operation_name)

    response = generate_response(operation)
    assert response

    # make sure we can serialize the response
    serializer = create_response_serializer(service)
    assert serializer.serialize_to_response(response, operation, {}, long_uid())


def test_get_mocking_skeleton():
    skeleton = get_mocking_skeleton("sqs")

    request = {"QueueName": "my-queue-name"}
    context = create_aws_request_context("sqs", "CreateQueue", "json", request)
    response = skeleton.invoke(context)
    # just a smoke test
    assert b"QueueUrl" in response.data
