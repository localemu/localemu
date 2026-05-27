import os

from localemu.version import __version__

VERSION = __version__

# HTTP headers used to forward proxy request URLs
HEADER_LOCALEMU_EDGE_URL = "x-localemu-edge"
HEADER_LOCALEMU_REQUEST_URL = "x-localemu-request-url"
# HTTP header optionally added to LocalEmu responses
HEADER_LOCALEMU_IDENTIFIER = "x-localemu"
# custom localemu authorization header only used in ext
HEADER_LOCALEMU_AUTHORIZATION = "x-localemu-authorization"
HEADER_LOCALEMU_TARGET = "x-localemu-target"
HEADER_AMZN_ERROR_TYPE = "X-Amzn-Errortype"

# backend service ports, for services that are behind a proxy (counting down from 4566)
DEFAULT_PORT_EDGE = 4566

# host name for localhost
LOCALHOST = "localhost"
LOCALHOST_IP = "127.0.0.1"
LOCALHOST_HOSTNAME = "localhost"

# User-agent string used in outgoing HTTP requests made by LocalEmu
USER_AGENT_STRING = f"localemu/{VERSION}"

# URL of localemu's artifacts repository on GitHub
ARTIFACTS_REPO = "https://github.com/localemu/localemu-artifacts"

# Artifacts endpoint
ASSETS_ENDPOINT = "https://assets.localemu.cloud"

# Hugging Face endpoint for localemu
HUGGING_FACE_ENDPOINT = "https://huggingface.co/localemu"

# Host to bind to when starting services INSIDE the LocalEmu Docker container.
# This is 0.0.0.0 because inside the container we need to accept connections
# from other containers/the docker bridge; the actual host-side exposure is
# controlled by the user's docker run / docker-compose port mapping (default
# binds only to 127.0.0.1 unless the user opts in). Do NOT use this value for
# binding services on the host directly — use GATEWAY_LISTEN / LOCALEMU_HOST
# Config instead.
BIND_HOST = "0.0.0.0"

# root code folder
MODULE_MAIN_PATH = os.path.dirname(os.path.realpath(__file__))
# TODO rename to "ROOT_FOLDER"!
LOCALEMU_ROOT_FOLDER = os.path.realpath(os.path.join(MODULE_MAIN_PATH, ".."))

# virtualenv folder
LOCALEMU_VENV_FOLDER: str = os.environ.get("VIRTUAL_ENV")
if not LOCALEMU_VENV_FOLDER:
    # fallback to the previous logic
    LOCALEMU_VENV_FOLDER = os.path.join(LOCALEMU_ROOT_FOLDER, ".venv")
    if not os.path.isdir(LOCALEMU_VENV_FOLDER):
        # assuming this package lives here: <python>/lib/pythonX.X/site-packages/localemu/
        LOCALEMU_VENV_FOLDER = os.path.realpath(
            os.path.join(LOCALEMU_ROOT_FOLDER, "..", "..", "..")
        )

# default volume directory containing shared data
DEFAULT_VOLUME_DIR = "/var/lib/localemu"

# API Gateway path to indicate a user request sent to the gateway
PATH_USER_REQUEST = "_user_request_"

# name of LocalEmu Docker image
DOCKER_IMAGE_NAME = "localemu/localemu"
DOCKER_IMAGE_NAME_PRO = "localemu/localemu"
DOCKER_IMAGE_NAME_FULL = "localemu/localemu"

# backdoor API path used to retrieve or update config variables
CONFIG_UPDATE_PATH = "/?_config_"

# API path for localemu internal resources
INTERNAL_RESOURCE_PATH = "/_localemu"

# environment variable name to tag local test runs
ENV_INTERNAL_TEST_RUN = "LOCALEMU_INTERNAL_TEST_RUN"

# environment variable name to tag collect metrics during a test run
ENV_INTERNAL_TEST_COLLECT_METRIC = "LOCALEMU_INTERNAL_TEST_COLLECT_METRIC"

# environment variable name to indicate that metrics should be stored within the container
ENV_INTERNAL_TEST_STORE_METRICS_IN_LOCALEMU = "LOCALEMU_INTERNAL_TEST_METRICS_IN_LOCALEMU"
ENV_INTERNAL_TEST_STORE_METRICS_PATH = "LOCALEMU_INTERNAL_TEST_STORE_METRICS_PATH"

# content types / encodings
HEADER_CONTENT_TYPE = "Content-Type"
TEXT_XML = "text/xml"
APPLICATION_AMZ_JSON_1_0 = "application/x-amz-json-1.0"
APPLICATION_AMZ_JSON_1_1 = "application/x-amz-json-1.1"
APPLICATION_AMZ_CBOR_1_1 = "application/x-amz-cbor-1.1"
APPLICATION_CBOR = "application/cbor"
APPLICATION_JSON = "application/json"
APPLICATION_XML = "application/xml"
APPLICATION_OCTET_STREAM = "application/octet-stream"
APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
HEADER_ACCEPT_ENCODING = "Accept-Encoding"

# strings to indicate truthy/falsy values
TRUE_STRINGS = ("1", "true", "True")
FALSE_STRINGS = ("0", "false", "False")
# strings with valid log levels for LS_LOG
LOG_LEVELS = ("trace-internal", "trace", "debug", "info", "warn", "error", "warning")

# environment variable to indicate this process should run the localemu infrastructure
LOCALEMU_INFRA_PROCESS = "LOCALEMU_INFRA_PROCESS"

# AWS region us-east-1
AWS_REGION_US_EAST_1 = "us-east-1"

# AWS region eu-west-1
AWS_REGION_EU_WEST_1 = "eu-west-1"

# environment variable to override max pool connections
try:
    MAX_POOL_CONNECTIONS = int(os.environ["MAX_POOL_CONNECTIONS"])
except Exception:
    MAX_POOL_CONNECTIONS = 150

# Fallback Account ID if not available in the client request
DEFAULT_AWS_ACCOUNT_ID = "000000000000"

# Credentials used for internal calls
INTERNAL_AWS_ACCESS_KEY_ID = "__internal_call__"
INTERNAL_AWS_SECRET_ACCESS_KEY = "__internal_call__"

# Sentinel access key id stamped onto requests that arrive with no credentials
# (see aws/handlers/auth.py::MissingAuthHeaderInjector). Under IAM enforcement
# this resolves to the *anonymous* principal: the request is evaluated against
# resource policies only (public access allowed, private denied), matching AWS.
ANONYMOUS_ACCESS_KEY_ID = "injectedaccesskey"

# trace log levels (excluding/including internal API calls), configurable via $LS_LOG
LS_LOG_TRACE = "trace"
LS_LOG_TRACE_INTERNAL = "trace-internal"
TRACE_LOG_LEVELS = [LS_LOG_TRACE, LS_LOG_TRACE_INTERNAL]

# list of official docker images
OFFICIAL_IMAGES = [
    "localemu/localemu",
]

# port for debug py
DEFAULT_DEVELOP_PORT = 5678

# Default bucket name of the s3 bucket used for local lambda development
# This name should be accepted by all IaC tools, so should respect s3 bucket naming conventions
DEFAULT_BUCKET_MARKER_LOCAL = "hot-reload"
LEGACY_DEFAULT_BUCKET_MARKER_LOCAL = "__local__"

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = "Ready."

# Regex for `Credential` field in the Authorization header in AWS signature version v4
# The format is as follows:
# Credential=<access-key-id>/<date>/<region-name>/<service-name>/aws4_request
# eg.
# Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
AUTH_CREDENTIAL_REGEX = r"Credential=(?P<access_key_id>[a-zA-Z0-9-_.]{1,})/(?P<date>\d{8})/(?P<region_name>[a-z0-9-]{1,})/(?P<service_name>[a-z0-9]{1,})/"

# Custom resource tag to override the generated resource ID.
TAG_KEY_CUSTOM_ID = "_custom_id_"
