import pytest


@pytest.fixture(autouse=True)
def _reset_ram_and_ec2_backends():
    """moto's BackendDicts are process-wide singletons - without a reset,
    a resource share created in one test leaks into the next test's
    visibility checks (e.g. "account B now sees nothing" would fail
    because of an unrelated ACTIVE share from an earlier test)."""
    from moto.ec2.models import ec2_backends
    from moto.ram.models import ram_backends

    ram_backends.reset()
    ec2_backends.reset()
    yield
    ram_backends.reset()
    ec2_backends.reset()
