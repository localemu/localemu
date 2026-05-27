"""Regression tests for the CloudWatch metrics SQLite database.

The original bug: ``CloudwatchDatabase.__init__`` created the DB file
once on first use and early-returned if it existed. If the parent
directory was pruned between that first call and subsequent
``PutMetricData`` calls (persistence cleanup, state reset, fresh
volume mount), the next write failed with SQLite's misleading
``unable to open database file`` error — caller got a 500.

The fix: every ``add_metric_data`` call is preceded by a cheap
``_ensure_ready()`` that mkdirs the directory and runs CREATE TABLE
IF NOT EXISTS. Cheap when healthy, self-heals when not.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime

import pytest

from localemu.services.cloudwatch.cloudwatch_database_helper import CloudwatchDatabase


@pytest.fixture
def cw_db(tmp_path, monkeypatch):
    """A CloudwatchDatabase instance whose files live in a test-owned tmp
    dir, so each test starts from a clean slate."""
    root = tmp_path / "cw-metrics"
    # Override the class-level paths before constructing.
    monkeypatch.setattr(CloudwatchDatabase, "CLOUDWATCH_DATA_ROOT", str(root))
    monkeypatch.setattr(CloudwatchDatabase, "METRICS_DB", str(root / "metrics.db"))
    monkeypatch.setattr(CloudwatchDatabase, "METRICS_DB_READ_ONLY",
                         f"file:{root / 'metrics.db'}?mode=ro")
    db = CloudwatchDatabase()
    yield db


def _metric():
    return [{
        "MetricName": "TestMetric",
        "Value":      1.5,
        "Unit":       "None",
        "Dimensions": [{"Name": "d1", "Value": "v1"}],
        "StorageResolution": 60,
    }]


class TestHappyPath:
    def test_add_metric_data_works_first_time(self, cw_db):
        cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())
        # No assertion needed — it either raises or doesn't.

    def test_add_metric_data_works_repeatedly(self, cw_db):
        for _ in range(5):
            cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())


class TestResilience:
    def test_recovers_when_parent_dir_was_removed(self, cw_db):
        """Regression: directory pruned between init and first write
        used to crash with 'unable to open database file'."""
        # First write — everything healthy.
        cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())

        # Nuke the entire metrics dir (simulating a state reset or a
        # persistence cleanup sweep between requests).
        shutil.rmtree(cw_db.CLOUDWATCH_DATA_ROOT)
        assert not os.path.exists(cw_db.CLOUDWATCH_DATA_ROOT)

        # Next write must self-heal: recreate the dir, recreate the DB,
        # and succeed rather than exploding.
        cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())

        # Directory is back.
        assert os.path.exists(cw_db.CLOUDWATCH_DATA_ROOT)
        assert os.path.exists(cw_db.METRICS_DB)

    def test_recovers_when_only_db_file_was_removed(self, cw_db):
        """The dir survives but someone deleted metrics.db — still fine."""
        cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())
        os.remove(cw_db.METRICS_DB)

        cw_db.add_metric_data("000000000000", "us-east-1", "Test", _metric())
        assert os.path.exists(cw_db.METRICS_DB)

    def test_ensure_ready_is_idempotent(self, cw_db):
        """Guard against regression to the ``CREATE TABLE`` without
        ``IF NOT EXISTS`` form — it would crash on the second call."""
        cw_db._ensure_ready()
        cw_db._ensure_ready()
        cw_db._ensure_ready()
