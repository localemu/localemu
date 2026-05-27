from _pytest.config import Config

from localemu import config as localemu_config
from localemu import constants


def pytest_configure(config: Config):
    # FIXME: note that this should be the same as in tests/aws/conftest.py since both are currently run in
    #  the same CI test step, but only one localemu instance is started for both.
    config.option.start_localemu = True
    localemu_config.FORCE_SHUTDOWN = False
    localemu_config.GATEWAY_LISTEN = localemu_config.UniqueHostAndPortList(
        [localemu_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)]
    )
