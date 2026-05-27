"""Unit tests for :mod:`localemu.export.orchestrator`."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from localemu.export.collectors import BaseCollector, CollectorRegistry
from localemu.export.ir import Resource
from localemu.export.orchestrator import Orchestrator


class _FakeRegistry:
    """Swap-in replacement for :class:`CollectorRegistry` used in tests.

    It honors the same ``instance().get_all()`` call chain but returns
    whatever dict the test supplies. This avoids mutating the
    process-wide registry (which would pollute other tests).
    """

    def __init__(self, mapping: dict[str, type[BaseCollector]]) -> None:
        self._m = mapping

    def get_all(self) -> dict[str, type[BaseCollector]]:
        return dict(self._m)


def _patch_registry(mapping: dict[str, type[BaseCollector]]):
    """Monkeypatch :meth:`CollectorRegistry.instance` to a fake."""
    fake = _FakeRegistry(mapping)
    return patch.object(CollectorRegistry, "instance", classmethod(lambda cls: fake))


def _make_collector(
    name: str,
    resources: list[Resource] | None = None,
    sleep: float = 0.0,
    raise_exc: Exception | None = None,
) -> type[BaseCollector]:
    """Factory for simple parametrized collector classes."""

    class _Collector(BaseCollector):
        service = name

        def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
            if sleep:
                time.sleep(sleep)
            if raise_exc is not None:
                raise raise_exc
            return list(resources or [])

    _Collector.__name__ = f"Collector_{name}"
    return _Collector


def test_empty_registry_yields_empty_snapshot() -> None:
    with _patch_registry({}):
        snap = Orchestrator().export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=True,
        )
    assert snap.resources == []
    assert snap.schema_version


def test_collector_timeout_becomes_warning() -> None:
    slow = _make_collector("slow", sleep=5.0)
    with _patch_registry({"slow": slow}):
        start = time.monotonic()
        snap = Orchestrator().export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=True,
            timeout_per_service=1,
        )
        elapsed = time.monotonic() - start
    # Should return in roughly the timeout, NOT the collector's 5s sleep.
    assert elapsed < 4.0, f"export should honor timeout, took {elapsed:.2f}s"
    assert any("timed out" in w for w in snap.export_warnings)
    assert snap.resources == []


def test_collector_exception_becomes_warning() -> None:
    exploder = _make_collector("boom", raise_exc=RuntimeError("bang"))
    with _patch_registry({"boom": exploder}):
        snap = Orchestrator().export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=True,
        )
    assert snap.resources == []
    assert any("boom" in w for w in snap.export_warnings)


def test_service_filter_skips_unrequested() -> None:
    r = Resource("s3", "bucket", "b", "000000000000", "us-east-1", attributes={"arn": "arn:aws:s3:::b"})
    other = Resource("iam", "role", "r", "000000000000", "us-east-1")
    s3_coll = _make_collector("s3", resources=[r])
    iam_coll = _make_collector("iam", resources=[other])
    with _patch_registry({"s3": s3_coll, "iam": iam_coll}):
        snap = Orchestrator().export(
            services=["s3"],
            regions=None,
            include_data=False,
            include_secrets=True,
        )
    assert {res.service for res in snap.resources} == {"s3"}


def test_unknown_service_filter_records_warning() -> None:
    with _patch_registry({}):
        snap = Orchestrator().export(
            services=["doesnotexist"],
            regions=None,
            include_data=False,
            include_secrets=True,
        )
    assert any("doesnotexist" in w for w in snap.export_warnings)


def test_region_filter_runs_collector_per_region() -> None:
    seen_regions: list[str] = []

    class _RegionCollector(BaseCollector):
        service = "svc"

        def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:  # type: ignore[override]
            seen_regions.append(region)
            return [
                Resource(
                    service="svc",
                    resource_type="x",
                    resource_id=f"x-{region}",
                    account_id=account_id,
                    region=region,
                )
            ]

    with _patch_registry({"svc": _RegionCollector}):
        snap = Orchestrator().export(
            services=None,
            regions=["us-east-1", "eu-west-1"],
            include_data=False,
            include_secrets=True,
        )
    assert set(seen_regions) == {"us-east-1", "eu-west-1"}
    assert {r.region for r in snap.resources} == {"us-east-1", "eu-west-1"}


def test_redaction_pass_runs_when_include_secrets_false() -> None:
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"environment": {"variables": {"TOKEN": "secret"}}},
    )
    coll = _make_collector("lambda", resources=[fn])
    with _patch_registry({"lambda": coll}):
        snap = Orchestrator().export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=False,
        )
    out = snap.resources[0]
    assert out.attributes["environment"]["variables"]["TOKEN"] != "secret"
    assert snap.redacted_secrets


def test_reference_pass_runs() -> None:
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="r",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:iam::000000000000:role/r"},
    )
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"role": "arn:aws:iam::000000000000:role/r"},
    )
    iam_c = _make_collector("iam", resources=[role])
    lambda_c = _make_collector("lambda", resources=[fn])
    with _patch_registry({"iam": iam_c, "lambda": lambda_c}):
        snap = Orchestrator().export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=True,
        )
    from localemu.export.ir import Ref

    fn_out = next(r for r in snap.resources if r.service == "lambda")
    assert isinstance(fn_out.attributes["role"], Ref)


@pytest.mark.timeout(10)
def test_concurrent_collectors_overlap() -> None:
    """Two slow collectors with timeout > their sleep should finish in ~one sleep."""
    a = _make_collector("a", sleep=0.5)
    b = _make_collector("b", sleep=0.5)
    with _patch_registry({"a": a, "b": b}):
        start = time.monotonic()
        Orchestrator(max_workers=4).export(
            services=None,
            regions=None,
            include_data=False,
            include_secrets=True,
            timeout_per_service=5,
        )
        elapsed = time.monotonic() - start
    # Sequential would be ~1.0s; concurrent should be well under.
    assert elapsed < 0.9, f"collectors did not run concurrently (took {elapsed:.2f}s)"
