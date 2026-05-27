import pytest
import requests

from localemu import config
from localemu.config import in_docker
from localemu.utils.bootstrap import LocalemuContainerServer
from localemu.utils.sync import poll_condition


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalemuContainerServer:
    def test_lifecycle(self):
        server = LocalemuContainerServer()
        server.container.config.ports.add(config.GATEWAY_LISTEN[0].port)

        assert not server.is_up()
        try:
            server.start()
            assert server.wait_is_up(60)

            health_response = requests.get("http://localhost:4566/_localemu/health")
            assert health_response.ok, f"expected health check to return OK: {health_response.text}"

            restart_response = requests.post(
                "http://localhost:4566/_localemu/health", json={"action": "restart"}
            )
            assert restart_response.ok, (
                f"expected restart command via health endpoint to return OK: {restart_response.text}"
            )

            def check_restart_successful():
                logs = server.container.get_logs()
                if logs.count("Ready.") < 2:
                    # second ready marker still missing
                    return False

                health_response_after_retry = requests.get(
                    "http://localhost:4566/_localemu/health"
                )
                if not health_response_after_retry.ok:
                    # health endpoint not yet ready again
                    return False

                # second restart marker found and health endpoint returned with 200!
                return True

            assert poll_condition(check_restart_successful, 45, 1), (
                "expected two Ready markers in the logs after triggering restart via health endpoint"
            )
        finally:
            server.shutdown()

        server.join(30)
        assert not server.is_up()
