"""Handler that simulates AWS API throttling for resilience testing."""

import logging
import random

from localemu import config
from localemu.aws.api import CommonServiceException, RequestContext
from localemu.aws.chain import HandlerChain

LOG = logging.getLogger(__name__)

# Mapping of service name -> (error_code, message, http_status)
# These mirror the actual error codes returned by each AWS service when throttled.
SERVICE_THROTTLE_ERRORS: dict[str, tuple[str, str, int]] = {
    "dynamodb": (
        "ProvisionedThroughputExceededException",
        "Rate of requests exceeds the allowed throughput.",
        400,
    ),
    "s3": (
        "SlowDown",
        "Please reduce your request rate.",
        503,
    ),
    "lambda": (
        "TooManyRequestsException",
        "Rate exceeded",
        429,
    ),
    "sqs": (
        "OverLimit",
        "Rate of requests exceeds the allowed throughput.",
        403,
    ),
    "sns": (
        "Throttled",
        "Rate exceeded",
        429,
    ),
    "kinesis": (
        "LimitExceededException",
        "Rate exceeded for shard.",
        400,
    ),
    "sts": (
        "Throttling",
        "Rate exceeded",
        400,
    ),
    "iam": (
        "Throttling",
        "Rate exceeded",
        429,
    ),
    "ec2": (
        "RequestLimitExceeded",
        "Request limit exceeded.",
        503,
    ),
    "cloudformation": (
        "Throttling",
        "Rate exceeded",
        400,
    ),
    "secretsmanager": (
        "ThrottlingException",
        "Rate exceeded",
        400,
    ),
    "ssm": (
        "ThrottlingException",
        "Rate exceeded",
        400,
    ),
    "events": (
        "ThrottlingException",
        "Rate exceeded",
        400,
    ),
    "stepfunctions": (
        "ThrottlingException",
        "Rate exceeded",
        400,
    ),
}

# Default throttle error for services not explicitly listed above.
_DEFAULT_THROTTLE_ERROR = ("Throttling", "Rate exceeded", 400)


def _get_throttle_rate(service_name: str) -> float:
    """Return the throttle rate for a given service.

    Checks for a per-service override env var (e.g. ``DYNAMODB_THROTTLE_RATE``)
    first, then falls back to the global ``THROTTLE_RATE``.
    """
    env_key = f"{service_name.upper()}_THROTTLE_RATE"
    override = config.os.environ.get(env_key, "").strip()
    if override:
        try:
            return float(override)
        except ValueError:
            LOG.warning("Invalid %s value %r, falling back to global rate", env_key, override)
    return config.THROTTLE_RATE


class ThrottlingHandler:
    """Gateway handler that probabilistically rejects requests with throttling errors.

    Controlled by the ``SIMULATE_THROTTLING`` and ``THROTTLE_RATE`` configuration
    variables.  Disabled by default.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response):
        if not config.SIMULATE_THROTTLING:
            return

        # Only throttle requests that have been fully parsed.
        if context.service is None or context.operation is None:
            return

        # Never throttle internal cross-service calls.
        if context.is_internal_call:
            return

        service_name = context.service.service_name
        rate = _get_throttle_rate(service_name)
        if rate <= 0:
            return

        if random.random() < rate:
            error_code, message, status_code = SERVICE_THROTTLE_ERRORS.get(
                service_name, _DEFAULT_THROTTLE_ERROR
            )
            LOG.info(
                "Throttling simulated for %s.%s (rate=%.2f)",
                service_name,
                context.operation.name,
                rate,
            )
            raise CommonServiceException(error_code, message, status_code=status_code)
