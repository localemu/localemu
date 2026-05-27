import pytest
import requests

from localemu import config


@pytest.mark.usefixtures("openapi_validate")
class TestInitScriptsResource:
    def test_stages_have_completed(self):
        response = requests.get(config.internal_service_url() + "/_localemu/init")
        assert response.status_code == 200
        doc = response.json()

        assert doc["completed"] == {
            "BOOT": True,
            "START": True,
            "READY": True,
            "SHUTDOWN": False,
        }

    def test_query_nonexisting_stage(self):
        response = requests.get(config.internal_service_url() + "/_localemu/init/does_not_exist")
        assert response.status_code == 404

    @pytest.mark.parametrize(
        ("stage", "completed"),
        [("boot", True), ("start", True), ("ready", True), ("shutdown", False)],
    )
    def test_query_individual_stage_completed(self, stage, completed):
        response = requests.get(config.internal_service_url() + f"/_localemu/init/{stage}")
        assert response.status_code == 200
        assert response.json()["completed"] == completed


@pytest.mark.usefixtures("openapi_validate")
class TestHealthResource:
    def test_get(self):
        response = requests.get(config.internal_service_url() + "/_localemu/health")
        assert response.ok
        assert "services" in response.json()
        assert "edition" in response.json()

    def test_head(self):
        response = requests.head(config.internal_service_url() + "/_localemu/health")
        assert response.ok
        assert not response.text


@pytest.mark.usefixtures("openapi_validate")
class TestInfoEndpoint:
    def test_get(self):
        response = requests.get(config.internal_service_url() + "/_localemu/info")
        assert response.ok
        doc = response.json()

        from localemu.constants import VERSION

        # The /info endpoint exposes only build/runtime data — no machine fingerprint,
        # no session ID, no license-activation flag (LocalEmu has no licensing system
        # and no telemetry). See services/internal.py:get_info_data.
        assert doc["version"].startswith(str(VERSION))
        assert doc["edition"] == "community"
        assert "server_time_utc" in doc
        assert isinstance(doc["uptime"], int)
