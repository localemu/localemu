import contextlib
import ssl

import certifi
import pytest
from pytest_httpserver import HTTPServer
from requests.exceptions import SSLError

from localemu.http import Request
from localemu.http.client import SimpleRequestsClient
from localemu.utils.ssl import create_ssl_cert


@pytest.fixture(scope="session")
def ssl_cert_files():
    _, cert_file_name, key_file_name = create_ssl_cert()
    return cert_file_name, key_file_name


@pytest.fixture(scope="session")
def custom_httpserver_with_ssl(ssl_cert_files):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file_name, key_file_name = ssl_cert_files
    context.load_cert_chain(cert_file_name, key_file_name)
    return context


@pytest.fixture(scope="session")
def make_ssl_httpserver(custom_httpserver_with_ssl):
    # we don't want to override SSL for every httpserver fixture
    # see https://pytest-httpserver.readthedocs.io/en/latest/fixtures.html#make-httpserver
    server = HTTPServer(ssl_context=custom_httpserver_with_ssl)
    server.start()
    yield server
    server.clear()
    if server.is_running():
        server.stop()


@pytest.fixture
def ssl_httpserver(make_ssl_httpserver):
    server = make_ssl_httpserver
    yield server
    server.clear()


@pytest.mark.parametrize("verify", [True, False])
@pytest.mark.parametrize("cert_env", [None, "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_http_clients_respect_verify(verify, cert_env, ssl_httpserver, monkeypatch):
    # If we want to test that a certain environment variable, setting the CA bundle, is set, we
    # just set the same path as requests uses anyway (the issues is caused just by the variables being set).
    if cert_env:
        monkeypatch.setenv(cert_env, certifi.where())

    client = SimpleRequestsClient()
    # Whether ``verify`` is ``True`` (default CA bundle from certifi) or
    # ``False`` (no verification). The server presents a self-signed cert
    # which certifi does not trust, so the verify=True branches must raise
    # ``SSLError`` regardless of the env-var CA bundle setting. The
    # verify=False branches must always succeed, even when the env vars
    # ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` are set — that is the
    # ``_VerifyRespectingSession`` workaround for psf/requests#3829.
    client.session.verify = verify

    expected_response = {"Result": "This request has not been verified!"}
    ssl_httpserver.expect_request("/").respond_with_json(expected_response)
    request = Request(scheme="https")

    context_manager = pytest.raises(SSLError) if verify else contextlib.suppress()
    with context_manager:
        response = client.request(
            request, server=f"localhost:{ssl_httpserver.port}"
        ).json
        assert response == expected_response
