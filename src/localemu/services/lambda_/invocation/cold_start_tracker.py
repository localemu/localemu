"""
Thread-safe tracker for Lambda cold start simulation.

Tracks per-function-version warm/cold state to simulate AWS Lambda cold starts.
A function is considered "cold" if it has never been invoked or has been idle
longer than the configured timeout (default 300s, matching AWS behavior).

Enable via: LAMBDA_COLD_START_DELAY=<seconds>  (e.g. 3)
Configure idle timeout: LAMBDA_COLD_START_IDLE_TIMEOUT=<seconds>  (default 300)
"""

import threading
import time

from localemu import config


class ColdStartTracker:
    """
    Tracks warm/cold state for Lambda function versions.

    Thread-safe: multiple concurrent invocations for the same function will only
    see one cold start — the first caller wins and marks the function warm
    immediately, so subsequent concurrent requests proceed without delay.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # qualified_arn -> last invocation monotonic timestamp
        self._last_invocation: dict[str, float] = {}

    def should_cold_start(self, qualified_arn: str) -> bool:
        """
        Check whether the given function version should experience a cold start.

        Returns True if the function has never been invoked or has been idle
        longer than LAMBDA_COLD_START_IDLE_TIMEOUT seconds.

        Side effect: immediately marks the function as warm so that concurrent
        invocations do not all experience a cold start delay.
        """
        now = time.monotonic()
        timeout = config.LAMBDA_COLD_START_IDLE_TIMEOUT

        with self._lock:
            last = self._last_invocation.get(qualified_arn)
            # Mark warm immediately (before the caller sleeps) so concurrent
            # invocations see this function as warm.
            self._last_invocation[qualified_arn] = now

            if last is None:
                return True
            if (now - last) > timeout:
                return True
            return False

    def mark_warm(self, qualified_arn: str) -> None:
        """Explicitly mark a function version as warm (e.g. provisioned concurrency)."""
        with self._lock:
            self._last_invocation[qualified_arn] = time.monotonic()

    def mark_cold(self, qualified_arn: str) -> None:
        """Remove tracking for a function version (e.g. on delete/cleanup)."""
        with self._lock:
            self._last_invocation.pop(qualified_arn, None)

    def reset(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._last_invocation.clear()
