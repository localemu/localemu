"""awsemu - Thin wrapper around the AWS CLI for use with LocalEmu.

Instead of:
  aws --endpoint-url=http://localhost:4566 s3 ls
Just use:
  awsemu s3 ls
"""

import os
import sys


# AWS-published canonical example credentials. AKIAIOSFODNN7EXAMPLE is in
# ROOT_ACCESS_KEYS by default, so this works under IAM_ENFORCEMENT=1.
_LOCALEMU_DEFAULT_AK = "AKIAIOSFODNN7EXAMPLE"
_LOCALEMU_DEFAULT_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Pre-IAM-enforcement docs told users to set AWS_ACCESS_KEY_ID=test. That
# value is NOT a root access key, so it produces AccessDenied under
# IAM_ENFORCEMENT=1. Treat a literal "test" in the shell env as the
# foot-gun it is and replace it.
_LEGACY_FOOTGUN_VALUES = {"test", ""}


def _normalize_localemu_credentials() -> None:
    """Ensure AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY work against LocalEmu.

    Behavior:
      - Unset env var → set to the LocalEmu canonical example value.
      - Env var literally equals "test" → replace with the canonical value
        AND print a one-line stderr notice so the user knows their shell
        had stale credentials. Pre-IAM-enforcement docs hardcoded "test"
        everywhere; this fixes that foot-gun.
      - Any other env value → respect it verbatim. This preserves
        intentional impersonation flows (e.g. AKIA_DEV_KEY for IAM
        policy-evaluation testing).
    """
    for var, default in (
        ("AWS_ACCESS_KEY_ID", _LOCALEMU_DEFAULT_AK),
        ("AWS_SECRET_ACCESS_KEY", _LOCALEMU_DEFAULT_SK),
    ):
        current = os.environ.get(var)
        if current is None:
            os.environ[var] = default
        elif current in _LEGACY_FOOTGUN_VALUES:
            print(
                f"awsemu: replacing {var}={current!r} from your shell with "
                f"LocalEmu's canonical example value; "
                f"export {var}={default} to silence this notice, "
                f"or set ROOT_ACCESS_KEYS={current} if you genuinely need "
                f"{current!r} to be a valid root key.",
                file=sys.stderr,
            )
            os.environ[var] = default


def main():
    # Default endpoint
    endpoint = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")

    _normalize_localemu_credentials()
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

    # Suppress SSL warnings
    os.environ.setdefault("PYTHONWARNINGS", "ignore:Unverified HTTPS request")

    # Services that don't need an endpoint
    no_endpoint = {"help", "configure"}

    # Get the service name (first non-flag argument)
    service = None
    for arg in sys.argv[1:]:
        if not arg.startswith("-"):
            service = arg
            break

    # Build the command
    cmd = ["aws"]

    # Add endpoint URL unless it's a help/configure command or already specified
    if service not in no_endpoint and "--endpoint-url" not in " ".join(sys.argv):
        cmd.append(f"--endpoint-url={endpoint}")

    # Add all original arguments
    cmd.extend(sys.argv[1:])

    # Intercept: awsemu ssm start-session --target <instance-id>
    if len(sys.argv) >= 4 and sys.argv[1] == "ssm" and sys.argv[2] == "start-session":
        target = None
        for i, arg in enumerate(sys.argv):
            if arg == "--target" and i + 1 < len(sys.argv):
                target = sys.argv[i + 1]
                break
        if target:
            container_name = f"localemu-ec2-{target}"
            # Prefer bash when present, fall back to sh. Alpine (the
            # default LocalEmu AMI) ships no bash; ubuntu / amazon-linux
            # do. One wrapper handles both.
            os.execvp("docker", [
                "docker", "exec", "-it", container_name,
                "/bin/sh", "-c",
                "if command -v bash >/dev/null 2>&1; "
                "then exec bash -i; else exec sh -i; fi",
            ])

    # Replace this process with the aws CLI
    os.execvp("aws", cmd)


if __name__ == "__main__":
    main()
