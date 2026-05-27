"""Gating for the real-AWS export acceptance tests.

These tests seed LocalEmu, run ``localemu export``, deploy the output to
a real AWS sandbox account, assert the resulting AWS state matches, and
destroy. They are skipped unless BOTH environment variables are set:

* ``LOCALEMU_EXPORT_E2E_AWS=1``
* ``AWS_SANDBOX_PROFILE=<profile name>``
* ``AWS_SANDBOX_ACCOUNT_ID=<12-digit account id>``

The ``AWS_SANDBOX_REGION`` var is optional (defaults to ``us-east-1``).

These tests intentionally have a cost: they create, apply, and destroy
real AWS resources. Do not run them in shared CI without a dedicated
sandbox account.
"""

from __future__ import annotations

import os

import pytest


def _enabled() -> bool:
    return bool(
        os.environ.get("LOCALEMU_EXPORT_E2E_AWS")
        and os.environ.get("AWS_SANDBOX_PROFILE")
        and os.environ.get("AWS_SANDBOX_ACCOUNT_ID")
    )


# Apply the skip to every test collected from this folder.
collect_ignore_glob: list[str] = []
if not _enabled():
    collect_ignore_glob.append("test_*.py")


@pytest.fixture(scope="session")
def sandbox_profile() -> str:
    return os.environ["AWS_SANDBOX_PROFILE"]


@pytest.fixture(scope="session")
def sandbox_account_id() -> str:
    return os.environ["AWS_SANDBOX_ACCOUNT_ID"]


@pytest.fixture(scope="session")
def sandbox_region() -> str:
    return os.environ.get("AWS_SANDBOX_REGION", "us-east-1")
