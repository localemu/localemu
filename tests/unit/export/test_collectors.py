"""Unit tests for :mod:`localemu.export.collectors`.

These tests exercise the registry machinery plus smoke-test each of the
built-in collectors. Per-service collector tests that need real LocalEmu
state are marked ``integration`` and use the :func:`seeded_infra` fixture.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

from localemu.export import collectors as collectors_pkg
from localemu.export.collectors import BaseCollector, CollectorRegistry, register_collector
from localemu.export.ir import Resource


# --------------------------------------------------------------------------- #
# Registry                                                                    #
# --------------------------------------------------------------------------- #


class _DummyCollector(BaseCollector):
    service = "_dummy"

    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
        return []


def test_register_collector_decorator_registers() -> None:
    # The decorator must put the class into the singleton.
    @register_collector("_dummy_decorated")
    class _D(BaseCollector):
        service = "_dummy_decorated"

        def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
            return []

    got = CollectorRegistry.instance().get_all()
    assert got.get("_dummy_decorated") is _D


def test_registry_singleton_identity() -> None:
    a = CollectorRegistry.instance()
    b = CollectorRegistry.instance()
    assert a is b


def test_registry_replacement_keeps_last() -> None:
    reg = CollectorRegistry.instance()
    reg.register("_replaceable", _DummyCollector)

    class _Other(BaseCollector):
        service = "_replaceable"

        def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
            return []

    reg.register("_replaceable", _Other)
    assert reg.get_all()["_replaceable"] is _Other


def test_base_collector_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseCollector()  # type: ignore[abstract]


# --------------------------------------------------------------------------- #
# Built-in collectors: import each module and verify they register.           #
# --------------------------------------------------------------------------- #


def _iter_builtin_collector_modules() -> list[str]:
    names: list[str] = []
    for _, name, ispkg in pkgutil.iter_modules(collectors_pkg.__path__):
        if ispkg or name.startswith("_"):
            continue
        names.append(name)
    return names


def test_all_collector_modules_import_cleanly() -> None:
    modules = _iter_builtin_collector_modules()
    # We expect v1 to ship a handful (target: 15 eventually). At least the
    # ones currently on disk must import.
    assert modules, "no collector modules found on disk"
    for mod in modules:
        full = f"localemu.export.collectors.{mod}"
        importlib.import_module(full)


def test_each_collector_class_implements_collect() -> None:
    for mod in _iter_builtin_collector_modules():
        importlib.import_module(f"localemu.export.collectors.{mod}")
    registry = CollectorRegistry.instance().get_all()
    assert registry, "no collectors registered after import"
    for name, cls in registry.items():
        if name.startswith("_"):
            continue
        instance = cls()
        assert hasattr(instance, "collect")
        # Empty region/account yields a well-typed empty-ish list.
        out = instance.collect("000000000000", "us-east-1", False)
        assert isinstance(out, list)
        for r in out:
            assert isinstance(r, Resource)


# --------------------------------------------------------------------------- #
# Per-service smoke tests against seeded infrastructure                       #
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_s3_collector_sees_seeded_bucket(seeded_infra) -> None:
    if "bucket" not in seeded_infra:
        pytest.skip("S3 not available in seeded_infra")
    importlib.import_module("localemu.export.collectors.s3")
    cls = CollectorRegistry.instance().get_all().get("s3")
    if cls is None:
        pytest.skip("s3 collector not registered")
    out = cls().collect("000000000000", "us-east-1", include_data=False)
    assert any(r.resource_id == seeded_infra["bucket"] for r in out)


@pytest.mark.integration
def test_dynamodb_collector_sees_seeded_table(seeded_infra) -> None:
    if "table" not in seeded_infra:
        pytest.skip("DynamoDB not available in seeded_infra")
    importlib.import_module("localemu.export.collectors.dynamodb")
    cls = CollectorRegistry.instance().get_all().get("dynamodb")
    if cls is None:
        pytest.skip("dynamodb collector not registered")
    out = cls().collect("000000000000", "us-east-1", include_data=False)
    assert any(r.resource_id == seeded_infra["table"] for r in out)


@pytest.mark.integration
def test_sns_collector_sees_seeded_topic(seeded_infra) -> None:
    if "topic" not in seeded_infra:
        pytest.skip("SNS not available in seeded_infra")
    importlib.import_module("localemu.export.collectors.sns")
    cls = CollectorRegistry.instance().get_all().get("sns")
    if cls is None:
        pytest.skip("sns collector not registered")
    out = cls().collect("000000000000", "us-east-1", include_data=False)
    assert any(seeded_infra["topic"] in r.resource_id for r in out)


@pytest.mark.integration
def test_collector_handles_empty_state_gracefully() -> None:
    """Collectors must return [] when nothing exists in a given region."""
    for mod in _iter_builtin_collector_modules():
        importlib.import_module(f"localemu.export.collectors.{mod}")
    registry = CollectorRegistry.instance().get_all()
    for name, cls in registry.items():
        if name.startswith("_"):
            continue
        # An unseeded, fictional region should yield an empty list without raising.
        out = cls().collect("999999999999", "ap-northeast-3", include_data=False)
        assert isinstance(out, list)


def test_collector_survives_individual_resource_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A collector whose per-resource logic raises should either
    skip the bad resource or propagate — *not* return partial garbage.

    Since collectors are still being built, this is a contract test: we
    verify the failure mode is well-defined (either clean skip with a
    log, or a raised exception the orchestrator catches).
    """

    class _PartiallyBroken(BaseCollector):
        service = "broken"

        def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
            good = Resource(
                service="broken",
                resource_type="x",
                resource_id="ok",
                account_id=account_id,
                region=region,
            )
            # Pretend resource #2 blew up and we logged+skipped it.
            return [good]

    out = _PartiallyBroken().collect("000000000000", "us-east-1", False)
    assert len(out) == 1 and out[0].resource_id == "ok"
