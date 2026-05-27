import logging
import os

from localemu import config
from localemu.utils.crypto import generate_ssl_cert

LOG = logging.getLogger(__name__)

_SERVER_CERT_PEM_FILE = "server.test.pem"


def install_predefined_cert_if_available():
    """Generate a self-signed SSL cert for local HTTPS support."""
    try:
        target_file = get_cert_pem_file_path()
        if not os.path.exists(target_file):
            create_ssl_cert()
            LOG.debug("Generated self-signed SSL certificate: %s", target_file)
    except Exception as e:
        LOG.warning("Failed to generate SSL certificate: %s", e)


def setup_ssl_cert() -> None:
    install_predefined_cert_if_available()


def get_cert_pem_file_path():
    return config.CUSTOM_SSL_CERT_PATH or os.path.join(config.dirs.cache, _SERVER_CERT_PEM_FILE)


def create_ssl_cert(serial_number=None):
    cert_pem_file = get_cert_pem_file_path()
    return generate_ssl_cert(cert_pem_file, serial_number=serial_number)
