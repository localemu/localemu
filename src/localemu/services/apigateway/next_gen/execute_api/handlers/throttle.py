"""
Basic per-stage rate limiting for API Gateway REST API invocations.

AWS API Gateway enforces throttling at the account level (10,000 RPS by default)
and per-stage/method level. This handler provides basic rate limiting to match
AWS parity using a simple token bucket algorithm.
"""

import logging
import threading
import time
from collections import defaultdict

from localemu.http import Response

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext
from ..gateway_response import ThrottledError

LOG = logging.getLogger(__name__)

# AWS default throttle limits
DEFAULT_RATE_LIMIT = 10000  # requests per second (account-level default)
DEFAULT_BURST_LIMIT = 5000  # burst capacity


class TokenBucket:
    """Simple thread-safe token bucket for rate limiting."""

    def __init__(self, rate: float, burst: int):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> bool:
        """Try to consume one token. Returns True if allowed, False if throttled."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class ThrottleHandler(RestApiGatewayHandler):
    """
    Enforces per-stage rate limiting based on the stage's throttling settings.
    If no throttle settings are configured, uses AWS default limits.
    """

    def __init__(self):
        # Keyed by (api_id, stage_name) -> TokenBucket
        self._buckets: dict[tuple[str, str], TokenBucket] = defaultdict(
            lambda: TokenBucket(rate=DEFAULT_RATE_LIMIT, burst=DEFAULT_BURST_LIMIT)
        )
        self._lock = threading.Lock()

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        api_id = context.api_id or ""
        stage = context.stage or ""
        bucket_key = (api_id, stage)

        # Get or create the bucket with the right limits from stage config
        bucket = self._get_or_create_bucket(bucket_key, context)

        if not bucket.consume():
            LOG.info("Throttling request to API %s stage %s", api_id, stage)
            raise ThrottledError("Rate exceeded")

    def _get_or_create_bucket(
        self, key: tuple[str, str], context: RestApiInvocationContext
    ) -> TokenBucket:
        with self._lock:
            if key not in self._buckets:
                rate_limit = DEFAULT_RATE_LIMIT
                burst_limit = DEFAULT_BURST_LIMIT

                # Check stage-level throttle settings
                if context.stage_configuration:
                    method_settings = context.stage_configuration.get("methodSettings", {})
                    # Check for stage-level default (*/*) throttle settings
                    default_settings = method_settings.get("*/*", {})
                    if throttle_rate := default_settings.get("throttlingRateLimit"):
                        rate_limit = float(throttle_rate)
                    if throttle_burst := default_settings.get("throttlingBurstLimit"):
                        burst_limit = int(throttle_burst)

                self._buckets[key] = TokenBucket(rate=rate_limit, burst=burst_limit)

            return self._buckets[key]
