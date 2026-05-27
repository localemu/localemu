"""Shared fixtures for CloudTrail native API regression tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _reset_native_state():
    """Every test starts with empty in-memory stores.

    The native module stores state at module level (no per-account keying
    internally — we key by ARN), so tests must reset it explicitly.
    """
    from localemu.services.cloudtrail import native

    native._reset_all_state()
    yield
    native._reset_all_state()


@pytest.fixture
def ctx():
    """A minimal RequestContext-shaped stand-in.

    The native handlers only read ``partition``, ``region``, and
    ``account_id`` from the context, so a MagicMock with those attrs is
    sufficient and avoids importing the full gateway stack.
    """
    m = MagicMock()
    m.partition = "aws"
    m.region = "us-east-1"
    m.account_id = "000000000000"
    return m
