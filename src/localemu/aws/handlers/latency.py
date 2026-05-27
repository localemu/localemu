"""
Network latency simulation handler for LocalEmu.

Adds realistic per-service latency to responses when SIMULATE_LATENCY is set.
Supports two modes:
  - SIMULATE_LATENCY=1 (or "true"): per-service realistic latency profiles
  - SIMULATE_LATENCY=<number>: fixed delay in milliseconds for all services
"""

import logging
import random
import time
from dataclasses import dataclass

from localemu import config
from localemu.aws.api import RequestContext
from localemu.aws.chain import HandlerChain
from localemu.http import Response
from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LatencyProfile:
    """Defines a latency distribution for a service or operation."""

    mean_ms: float
    stddev_ms: float


# Per-service latency profiles keyed by (service_name, operation_name).
# Use "*" as the operation wildcard for a service-wide default.
_LATENCY_PROFILES: dict[tuple[str, str], LatencyProfile] = {
    # DynamoDB: single-digit latency for most operations
    ("dynamodb", "*"): LatencyProfile(mean_ms=8.0, stddev_ms=2.0),
    ("dynamodb", "Query"): LatencyProfile(mean_ms=10.0, stddev_ms=3.0),
    ("dynamodb", "Scan"): LatencyProfile(mean_ms=15.0, stddev_ms=5.0),
    # S3: higher latency, varies by operation
    ("s3", "*"): LatencyProfile(mean_ms=50.0, stddev_ms=15.0),
    ("s3", "GetObject"): LatencyProfile(mean_ms=30.0, stddev_ms=10.0),
    ("s3", "PutObject"): LatencyProfile(mean_ms=80.0, stddev_ms=20.0),
    # SQS: moderate latency
    ("sqs", "*"): LatencyProfile(mean_ms=20.0, stddev_ms=5.0),
    ("sqs", "SendMessage"): LatencyProfile(mean_ms=15.0, stddev_ms=4.0),
    ("sqs", "ReceiveMessage"): LatencyProfile(mean_ms=25.0, stddev_ms=6.0),
    # Lambda: invocation is the expensive one
    ("lambda", "*"): LatencyProfile(mean_ms=60.0, stddev_ms=15.0),
    ("lambda", "Invoke"): LatencyProfile(mean_ms=150.0, stddev_ms=40.0),
    # EC2: wide range depending on operation
    ("ec2", "*"): LatencyProfile(mean_ms=60.0, stddev_ms=20.0),
    ("ec2", "RunInstances"): LatencyProfile(mean_ms=200.0, stddev_ms=50.0),
    ("ec2", "DescribeInstances"): LatencyProfile(mean_ms=80.0, stddev_ms=20.0),
    # SNS
    ("sns", "*"): LatencyProfile(mean_ms=25.0, stddev_ms=6.0),
    # CloudFormation
    ("cloudformation", "*"): LatencyProfile(mean_ms=80.0, stddev_ms=25.0),
    # IAM: relatively fast
    ("iam", "*"): LatencyProfile(mean_ms=20.0, stddev_ms=5.0),
    # STS: fast
    ("sts", "*"): LatencyProfile(mean_ms=10.0, stddev_ms=3.0),
    # KMS
    ("kms", "*"): LatencyProfile(mean_ms=25.0, stddev_ms=8.0),
    # Kinesis
    ("kinesis", "*"): LatencyProfile(mean_ms=30.0, stddev_ms=10.0),
    # CloudWatch
    ("cloudwatch", "*"): LatencyProfile(mean_ms=35.0, stddev_ms=10.0),
}

# Global default for services without a specific profile
_DEFAULT_PROFILE = LatencyProfile(mean_ms=30.0, stddev_ms=12.0)


def _resolve_profile(service_name: str, operation_name: str) -> LatencyProfile:
    """Resolve the latency profile for a given service and operation."""
    # Try exact (service, operation) match first
    profile = _LATENCY_PROFILES.get((service_name, operation_name))
    if profile is not None:
        return profile
    # Fall back to service wildcard
    profile = _LATENCY_PROFILES.get((service_name, "*"))
    if profile is not None:
        return profile
    # Global default
    return _DEFAULT_PROFILE


def _compute_delay_ms(profile: LatencyProfile) -> float:
    """Compute a delay from a Gaussian distribution, clamped to a safe range."""
    delay = random.gauss(profile.mean_ms, profile.stddev_ms)
    # Clamp: at least 1ms, at most 5x the mean (prevent extreme outliers)
    return max(1.0, min(delay, profile.mean_ms * 5.0))


class LatencySimulationHandler:
    """
    Response handler that introduces artificial network latency.

    When ``mode`` is ``"1"`` or ``"true"``, per-service realistic latency profiles
    are applied.  When ``mode`` is a numeric string, that value is used as a fixed
    delay in milliseconds for every response.
    """

    def __init__(self, mode: str):
        self._fixed_ms: float | None = None
        normalised = mode.strip().lower()
        if normalised in ("1", "true", "yes"):
            self._fixed_ms = None  # per-service mode
            LOG.info("Latency simulation enabled (per-service realistic profiles)")
        else:
            try:
                self._fixed_ms = float(mode)
                LOG.info("Latency simulation enabled (fixed %.1f ms)", self._fixed_ms)
            except ValueError:
                LOG.warning(
                    "SIMULATE_LATENCY value %r is not recognised; "
                    "falling back to per-service mode",
                    mode,
                )
                self._fixed_ms = None

    def __call__(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        # Skip internal (service-to-service) calls -- they should not be slowed down
        if context.is_internal_call:
            return

        if self._fixed_ms is not None:
            delay_ms = self._fixed_ms
        else:
            service_name = ""
            operation_name = ""
            if context.service:
                service_name = context.service.service_name
            if context.operation:
                operation_name = context.operation.name
            profile = _resolve_profile(service_name, operation_name)
            delay_ms = _compute_delay_ms(profile)

        delay_s = delay_ms / 1000.0
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug(
                "Simulating %.1f ms latency for %s.%s",
                delay_ms,
                getattr(context.service, "service_name", "unknown"),
                getattr(context.operation, "name", "unknown"),
            )
        time.sleep(delay_s)


@hooks.on_infra_start(
    should_load=lambda: bool(config.SIMULATE_LATENCY)
    and config.SIMULATE_LATENCY not in ("0", "false", "no")
)
def register_latency_handler():
    from localemu.aws.handlers import run_custom_response_handlers

    handler = LatencySimulationHandler(config.SIMULATE_LATENCY)
    run_custom_response_handlers.handlers.insert(0, handler)
