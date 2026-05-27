import os

import pytest
from _pytest.monkeypatch import MonkeyPatch

from localemu import config

os.environ["LOCALEMU_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "localemu.testing.pytest.fixtures",
    "localemu.testing.pytest.container",
    "localemu.testing.pytest.snapshot",
    "localemu.testing.pytest.filters",
    "localemu.testing.pytest.fixture_conflicts",
    "localemu.testing.pytest.marking",
    "localemu.testing.pytest.marker_report",
    "localemu.testing.pytest.in_memory_localemu",
    "localemu.testing.pytest.validation_tracking",
    "localemu.testing.pytest.path_filter",
    "localemu.testing.pytest.stepfunctions.fixtures",
    "localemu.testing.pytest.cloudformation.fixtures",
]


@pytest.fixture(scope="session")
def aws_session():
    """
    This fixture returns the Boto Session instance for testing.
    """
    from localemu.testing.aws.util import base_aws_session

    return base_aws_session()


@pytest.fixture(scope="session")
def secondary_aws_session():
    """
    This fixture returns the Boto Session instance for testing a secondary account.
    """
    from localemu.testing.aws.util import secondary_aws_session

    return secondary_aws_session()


@pytest.fixture(scope="session")
def aws_client_factory(aws_session):
    """
    This fixture returns a client factory for testing.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    from localemu.testing.aws.util import base_aws_client_factory

    return base_aws_client_factory(aws_session)


@pytest.fixture(scope="session")
def secondary_aws_client_factory(secondary_aws_session):
    """
    This fixture returns a client factory for testing a secondary account.

    Use this fixture if you need to use custom endpoint or Boto config.
    """
    from localemu.testing.aws.util import base_aws_client_factory

    return base_aws_client_factory(secondary_aws_session)


@pytest.fixture(scope="session")
def aws_client(aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing.

    The clients are configured with the primary testing credentials.
    """
    from localemu.testing.aws.util import base_testing_aws_client

    return base_testing_aws_client(aws_client_factory)


@pytest.fixture(scope="session")
def secondary_aws_client(secondary_aws_client_factory):
    """
    This fixture can be used to obtain Boto clients for testing a secondary account.

    The clients are configured with the secondary testing credentials.
    The region is not overridden.
    """
    from localemu.testing.aws.util import base_testing_aws_client

    return base_testing_aws_client(secondary_aws_client_factory)


@pytest.fixture(scope="session", autouse=True)
def enable_stack_trace_for_tests():
    """
    Ensure stack traces are enabled in HTTP responses during test sessions.

    This is useful for debugging purposes.
    """
    mpatch = MonkeyPatch()
    mpatch.setattr(config, "INCLUDE_STACK_TRACES_IN_HTTP_RESPONSE", True)
    yield mpatch
    mpatch.undo()
