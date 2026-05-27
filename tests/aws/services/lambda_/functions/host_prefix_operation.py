import json
import os
from urllib.parse import urlparse

import boto3
from botocore.config import Config

region = os.environ["AWS_REGION"]
account = boto3.client("sts").get_caller_identity()["Account"]
state_machine_arn_doesnotexist = (
    f"arn:aws:states:{region}:{account}:stateMachine:doesNotExistStateMachine"
)


def do_test(test_case):
    sfn_client = test_case["client"]
    try:
        sfn_client.start_sync_execution(
            stateMachineArn=state_machine_arn_doesnotexist,
            input=json.dumps({}),
            name="SyncExecution",
        )
        return {"status": "failure"}
    except sfn_client.exceptions.StateMachineDoesNotExist:
        # We are testing the error case here, so we expect this exception to be raised.
        # Testing the error case simplifies the test case because we don't need to set up a StepFunction.
        return {"status": "success"}
    except Exception as e:
        return {"status": "exception", "exception": str(e)}


def handler(event, context):
    # The environment variable AWS_ENDPOINT_URL is only available in LocalEmu
    aws_endpoint_url = os.environ.get("AWS_ENDPOINT_URL")

    host_prefix_client = boto3.client(
        "stepfunctions",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
    )
    localemu_adjusted_domain = None
    # The localemu domain only works in LocalEmu, None is ignored
    if aws_endpoint_url:
        port = urlparse(aws_endpoint_url).port
        localemu_adjusted_domain = f"http://localhost:{port}"
    host_prefix_client_localemu_domain = boto3.client(
        "stepfunctions",
        endpoint_url=localemu_adjusted_domain,
    )
    no_host_prefix_client = boto3.client(
        "stepfunctions",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
        config=Config(inject_host_prefix=False),
    )

    test_cases = [
        {"name": "host_prefix", "client": host_prefix_client},
        {"name": "host_prefix_localemu_domain", "client": host_prefix_client_localemu_domain},
        # Omitting the host prefix can only work in LocalEmu
        {
            "name": "no_host_prefix",
            "client": no_host_prefix_client if aws_endpoint_url else host_prefix_client,
        },
    ]

    test_results = {}
    for test_case in test_cases:
        test_name = test_case["name"]
        test_result = do_test(test_case)
        test_results[test_name] = test_result

    return test_results
