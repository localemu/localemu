"""Phase 1 — preflight checks.

Verifies that:

* LocalEmu is reachable (we hit its ``sts`` endpoint locally).
* The user-supplied AWS credentials authenticate against real AWS.
* The authenticated account matches the ``--aws-account-id`` flag — this
  is the single most common foot-gun (deploying a sandbox to the wrong
  account) so we fail loudly rather than silently allowing it.

A failure here aborts the export before any files are written.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

LOG = logging.getLogger(__name__)


class PreflightError(RuntimeError):
    """Raised when a preflight check fails. Aborts the export."""


@dataclass(frozen=True)
class AwsCredentials:
    """Resolved credentials for the target real-AWS account."""

    profile: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None

    def boto3_session_kwargs(self, region: str) -> dict[str, str]:
        """Return kwargs suitable for :class:`boto3.session.Session`."""
        kwargs: dict[str, str] = {"region_name": region}
        if self.profile:
            kwargs["profile_name"] = self.profile
        if self.access_key_id:
            kwargs["aws_access_key_id"] = self.access_key_id
        if self.secret_access_key:
            kwargs["aws_secret_access_key"] = self.secret_access_key
        if self.session_token:
            kwargs["aws_session_token"] = self.session_token
        return kwargs

    def env_for_subprocess(self, region: str) -> dict[str, str]:
        """Return env vars for ``terraform``/``aws`` subprocess invocations.

        Profile-based credentials are passed through ``AWS_PROFILE``; static
        creds are passed through the standard ``AWS_ACCESS_KEY_ID`` /
        ``AWS_SECRET_ACCESS_KEY`` / ``AWS_SESSION_TOKEN`` triplet. The
        existing environment is preserved (terraform needs ``PATH``, ``HOME``
        for plugin cache, etc.) and any pre-existing AWS env vars are
        cleared first so we do not silently fall through to ambient
        credentials when the caller asked for explicit ones.
        """
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        env["AWS_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region
        if self.profile:
            env["AWS_PROFILE"] = self.profile
        if self.access_key_id:
            env["AWS_ACCESS_KEY_ID"] = self.access_key_id
        if self.secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = self.secret_access_key
        if self.session_token:
            env["AWS_SESSION_TOKEN"] = self.session_token
        return env


def check_localemu_reachable(endpoint: str = "http://localhost:4566") -> None:
    """Verify LocalEmu is up by hitting its STS endpoint.

    Raises:
        PreflightError: if LocalEmu is unreachable.
    """
    import urllib.error
    import urllib.request

    # The LocalEmu health endpoint is the canonical reachability probe.
    # The legacy ``/_localstack/health`` path is no longer served by this
    # build, so probing it produced spurious 404s that aborted preflight
    # against a perfectly healthy LocalEmu.
    health_url = endpoint.rstrip("/") + "/_localemu/health"
    try:
        req = urllib.request.Request(health_url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status >= 500:
                raise PreflightError(
                    f"LocalEmu at {endpoint} returned HTTP {resp.status}; "
                    "is it running?"
                )
    except urllib.error.URLError as exc:
        raise PreflightError(
            f"Cannot reach LocalEmu at {endpoint}: {exc}. "
            "Start LocalEmu with `localemu start` before running export."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise PreflightError(
            f"Unexpected error contacting LocalEmu at {endpoint}: {exc}"
        ) from exc


def verify_aws_account(
    creds: AwsCredentials,
    expected_account_id: str,
    region: str,
) -> str:
    """Call ``sts:GetCallerIdentity`` and confirm the account matches.

    Returns:
        The verified account id string.

    Raises:
        PreflightError: if credentials are invalid or the account does not
            match ``expected_account_id``.
    """
    try:
        import boto3  # type: ignore
        import botocore.exceptions  # type: ignore
    except Exception as exc:  # pragma: no cover - boto3 is a hard dep
        raise PreflightError(f"boto3 unavailable: {exc}") from exc

    try:
        session = boto3.session.Session(**creds.boto3_session_kwargs(region))
        sts = session.client("sts")
        identity = sts.get_caller_identity()
    except botocore.exceptions.NoCredentialsError as exc:
        raise PreflightError(
            "No AWS credentials found. Pass --aws-profile or "
            "--aws-access-key-id / --aws-secret-access-key, or configure "
            "the standard AWS credential chain."
        ) from exc
    except botocore.exceptions.ClientError as exc:
        raise PreflightError(
            f"AWS sts:GetCallerIdentity failed: {exc}. "
            "Check that the supplied credentials are valid for the target account."
        ) from exc
    except Exception as exc:
        raise PreflightError(f"AWS credential verification failed: {exc}") from exc

    actual = str(identity.get("Account") or "")
    if actual != expected_account_id:
        raise PreflightError(
            f"Account mismatch: --aws-account-id={expected_account_id!r} but "
            f"the supplied credentials authenticate as account {actual!r}. "
            "Refusing to export to the wrong account."
        )
    LOG.info("Preflight: authenticated as account %s in %s", actual, region)
    return actual
