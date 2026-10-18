"""Unit tests for the pre-flight RAM gate.

Deliberately simple: a static, one-time comparison of the machine's
TOTAL physical RAM against the model's declared tier (16/32/64GB) - no
live/available-memory probing, no safety margin.
"""
from __future__ import annotations

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.bedrock_runtime import memory_gate


def test_passes_when_machine_meets_the_tier(monkeypatch):
    monkeypatch.setattr(memory_gate, "total_memory_gb", lambda: 16.0)
    memory_gate.check_memory("some.model", 16)  # must not raise


def test_passes_when_machine_exceeds_the_tier(monkeypatch):
    monkeypatch.setattr(memory_gate, "total_memory_gb", lambda: 64.0)
    memory_gate.check_memory("some.model", 16)  # must not raise


def test_raises_when_machine_is_below_the_tier(monkeypatch):
    monkeypatch.setattr(memory_gate, "total_memory_gb", lambda: 16.0)
    with pytest.raises(CommonServiceException) as exc_info:
        memory_gate.check_memory("meta.llama3-1-70b-instruct-v1:0", 64)
    assert exc_info.value.code == "ServiceQuotaExceededException"
    assert "meta.llama3-1-70b-instruct-v1:0" in exc_info.value.message
    assert "64GB-tier" in exc_info.value.message
    assert "16.0GB" in exc_info.value.message


def test_no_margin_is_applied(monkeypatch):
    """Exactly at the tier boundary must pass - no hidden multiplier."""
    monkeypatch.setattr(memory_gate, "total_memory_gb", lambda: 32.0)
    memory_gate.check_memory("x", 32)  # must not raise


def test_just_under_the_tier_fails(monkeypatch):
    monkeypatch.setattr(memory_gate, "total_memory_gb", lambda: 31.9)
    with pytest.raises(CommonServiceException):
        memory_gate.check_memory("x", 32)
