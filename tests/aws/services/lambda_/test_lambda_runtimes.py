"""Testing different Lambda runtimes focusing on specifics of particular runtimes (e.g., Nodejs ES6 modules).

See `test_lambda_common.py` for tests focusing on common functionality across all runtimes.
"""

import json
import os
import shutil
import textwrap

import pytest

from localemu.aws.api.lambda_ import Runtime
from localemu.packages import DownloadInstaller, Package, PackageInstaller
from localemu.testing.pytest import markers
from localemu.utils import testutil
from localemu.utils.archives import unzip
from localemu.utils.files import cp_r, load_file, mkdir, new_tmp_dir, save_file
from localemu.utils.functions import run_safe
from localemu.utils.strings import short_uid, to_str
from localemu.utils.sync import retry
from localemu.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events
from tests.aws.services.lambda_.test_lambda import (
    NODE_TEST_RUNTIMES,
    PYTHON_TEST_RUNTIMES,
    TEST_LAMBDA_CLOUDWATCH_LOGS,
    TEST_LAMBDA_NODEJS_ES6,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_VERSION,
    THIS_FOLDER,
    read_streams,
)


# TODO: consider using the multiruntime annotation directly?!
parametrize_python_runtimes = pytest.mark.parametrize("runtime", PYTHON_TEST_RUNTIMES)
parametrize_node_runtimes = pytest.mark.parametrize("runtime", NODE_TEST_RUNTIMES)


@pytest.fixture(autouse=True)
def add_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(snapshot.transform.key_value("CodeSha256", "<code-sha-256>"))


class TestNodeJSRuntimes:
    @markers.snapshot.skip_snapshot_verify(paths=["$..LoggingConfig"])
    @parametrize_node_runtimes
    @markers.aws.validated
    def test_invoke_nodejs_es6_lambda(self, create_lambda_function, snapshot, runtime, aws_client):
        """Test simple nodejs lambda invocation"""

        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS_ES6, get_content=True),
            runtime=runtime,
            handler="lambda_handler_es6.handler",
        )
        snapshot.match("creation-result", result)

        rs = aws_client.lambda_.invoke(
            FunctionName=function_name,
            Payload=json.dumps({"event_type": "test_lambda"}),
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invocation-result", rs)

        payload = rs["Payload"]
        response = json.loads(payload)
        assert "response from localemu lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=aws_client.logs)
            assert len(events) > 0

        retry(assert_events, retries=10)


class TestPythonRuntimes:
    @parametrize_python_runtimes
    @markers.aws.validated
    def test_handler_in_submodule(self, create_lambda_function, runtime, aws_client):
        """Test invocation of a lambda handler which resides in a submodule (= not root module)"""
        function_name = f"test-function-{short_uid()}"
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            runtime=runtime,
            file_name="localemu_package/def/main.py",
        )
        create_lambda_function(
            func_name=function_name,
            zip_file=zip_file,
            handler="localemu_package.def.main.handler",
            runtime=runtime,
        )

        # invoke function and assert result
        result = aws_client.lambda_.invoke(FunctionName=function_name, Payload=b"{}")
        result_data = json.load(result["Payload"])
        assert 200 == result["StatusCode"]
        assert json.loads("{}") == result_data["event"]

    @parametrize_python_runtimes
    @markers.aws.validated
    def test_python_runtime_correct_versions(self, create_lambda_function, runtime, aws_client):
        """Test different versions of python runtimes to report back the correct python version"""
        function_name = f"test_python_executor_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_VERSION,
            runtime=runtime,
        )
        result = aws_client.lambda_.invoke(
            FunctionName=function_name,
            Payload=b"{}",
        )
        result = json.load(result["Payload"])
        assert result["version"] == runtime


class TestGoProvidedRuntimes:
    """These tests are a subset of the common tests focusing on exercising Golang, which had a dedicated runtime.

    The Lambda sources are under ./common/<scenario>/runtime/
    The tests `test_uncaught_exception_invoke` and `test_manual_endpoint_injection` are copied from the common tests
    because the common tests only test each runtime once. Multiple tests per runtime are not supported and would make
    them even more complex. Usually, only a subset of the test scenarios is relevant to have extra test coverage.
    For example, Go used to have a dedicated runtime and therefore, we want to test the migration path.
    Calling LocalEmu and uncaught exception behavior can be language-specific and deserve dedicated tests while
    echo invoke is redundant (runtime is already tested and every other scenario covers this basic functionality).
    """

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: implement logging config
            "$..LoggingConfig",
            "$..CodeSha256",  # works locally but unfortunately still produces a different hash in CI
        ]
    )
    @markers.aws.validated
    @markers.multiruntime(scenario="uncaughtexception_extra", runtimes=["provided"])
    def test_uncaught_exception_invoke(self, multiruntime_lambda, snapshot, aws_client):
        # unfortunately the stack trace is quite unreliable and changes when AWS updates the runtime transparently
        # since the stack trace contains references to internal runtime code.
        snapshot.add_transformer(
            snapshot.transform.key_value("stackTrace", "<stack-trace>", reference_replacement=False)
        )
        create_function_result = multiruntime_lambda.create_function(MemorySize=1024)
        snapshot.match("create_function_result", create_function_result)

        # simple payload
        invocation_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
            Payload=b'{"error_msg": "some_error_msg"}',
        )
        assert "FunctionError" in invocation_result
        snapshot.match("error_result", invocation_result)

    @markers.aws.validated
    @markers.multiruntime(scenario="endpointinjection_extra", runtimes=["provided"])
    def test_manual_endpoint_injection(self, multiruntime_lambda, tmp_path, aws_client):
        """Test calling SQS from Lambda using manual AWS SDK client configuration via AWS_ENDPOINT_URL.
        This must work for all runtimes.
        The code might differ depending on the SDK version shipped with the Lambda runtime.
        This test is designed to be AWS-compatible using minimal code changes to configure the endpoint url for LS.
        """

        create_function_result = multiruntime_lambda.create_function(MemorySize=1024, Timeout=15)

        invocation_result = aws_client.lambda_.invoke(
            FunctionName=create_function_result["FunctionName"],
        )
        assert "FunctionError" not in invocation_result


class TestCloudwatchLogs:
    @pytest.fixture(autouse=True)
    def snapshot_transformers(self, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_report_logs())
        snapshot.add_transformer(
            snapshot.transform.key_value("eventId", reference_replacement=False)
        )
        snapshot.add_transformer(
            snapshot.transform.regex(r"::runtime:\w+", "::runtime:<runtime-id>")
        )
        snapshot.add_transformer(snapshot.transform.regex("\\.v\\d{2}", ".v<version>"))

    @markers.aws.validated
    # skip all snapshots - the logs are too different
    # TODO add INIT_START to make snapshotting of logs possible
    @markers.snapshot.skip_snapshot_verify()
    def test_multi_line_prints(self, aws_client, create_lambda_function, snapshot):
        function_name = f"test_lambda_{short_uid()}"
        log_group_name = f"/aws/lambda/{function_name}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_CLOUDWATCH_LOGS,
            runtime=Runtime.python3_13,
        )

        payload = {
            "body": textwrap.dedent("""
                multi
                line
                string
                another\rline
            """)
        }
        invoke_response = aws_client.lambda_.invoke(
            FunctionName=function_name, Payload=json.dumps(payload)
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                invoke_response["ResponseMetadata"]["RequestId"], "<request-id>"
            )
        )

        def fetch_logs():
            log_events_result = aws_client.logs.filter_log_events(logGroupName=log_group_name)
            assert any("REPORT" in e["message"] for e in log_events_result["events"])
            return log_events_result["events"]

        log_events = retry(fetch_logs, retries=10, sleep=2)
        snapshot.match("log-events", log_events)

        log_messages = [log["message"] for log in log_events]
        # some manual assertions until we can actually use the snapshot
        assert "multi\n" in log_messages
        assert "line\n" in log_messages
        assert "string\n" in log_messages
        assert "another\rline\n" in log_messages
