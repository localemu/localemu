import os

from localemu.config import is_env_true
from localemu.constants import DEFAULT_AWS_ACCOUNT_ID

# Credentials used in the test suite
# These can be overridden if the tests are being run against AWS.
#
# Defaults are AWS's published example credentials, which the IAM
# enforcement layer recognises as the canonical demo root key (see
# ``localemu.services.iam_enforcement.identity._get_root_access_keys``
# and ``localemu.services.sts.provider``). Picking a structured
# access key here means tests run identically whether
# ``IAM_ENFORCEMENT`` is on (production-style) or off (unit-only):
# in the on case the key resolves to Root and bypasses policy
# evaluation; in the off case the value is irrelevant.
TEST_AWS_ACCOUNT_ID = os.getenv("TEST_AWS_ACCOUNT_ID") or DEFAULT_AWS_ACCOUNT_ID
# If a structured access key ID is used, it must correspond to the account ID
TEST_AWS_ACCESS_KEY_ID = os.getenv("TEST_AWS_ACCESS_KEY_ID") or "AKIAIOSFODNN7EXAMPLE"
TEST_AWS_SECRET_ACCESS_KEY = (
    os.getenv("TEST_AWS_SECRET_ACCESS_KEY")
    or "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
TEST_AWS_REGION_NAME = os.getenv("TEST_AWS_REGION_NAME") or "us-east-1"
TEST_AWS_ENDPOINT_URL = os.getenv("TEST_AWS_ENDPOINT_URL")

# Secondary test AWS profile - only used for testing against AWS
SECONDARY_TEST_AWS_PROFILE = os.getenv("SECONDARY_TEST_AWS_PROFILE")
# Additional credentials used in the test suite (when running cross-account tests)
SECONDARY_TEST_AWS_ACCOUNT_ID = os.getenv("SECONDARY_TEST_AWS_ACCOUNT_ID") or "000000000002"
SECONDARY_TEST_AWS_ACCESS_KEY_ID = os.getenv("SECONDARY_TEST_AWS_ACCESS_KEY_ID") or "000000000002"
SECONDARY_TEST_AWS_SECRET_ACCESS_KEY = os.getenv("SECONDARY_TEST_AWS_SECRET_ACCESS_KEY") or "test2"
SECONDARY_TEST_AWS_SESSION_TOKEN = os.getenv("SECONDARY_TEST_AWS_SESSION_TOKEN")
SECONDARY_TEST_AWS_REGION_NAME = os.getenv("SECONDARY_TEST_AWS_REGION_NAME") or "ap-southeast-1"

TEST_SKIP_LOCALEMU_START = is_env_true("TEST_SKIP_LOCALEMU_START")
TEST_FORCE_LOCALEMU_START = is_env_true("TEST_FORCE_LOCALEMU_START")
