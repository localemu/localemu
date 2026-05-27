"""Regression test for the S3 lifecycle background scanner.

The scanner used to crash with ``AttributeError: 'FakeBucket' object has
no attribute 'lifecycle_rules'`` when the in-memory bucket registry
contained any object that did not surface a ``lifecycle_rules``
attribute. moto's pristine ``FakeBucket`` instances are the obvious
trigger in tests, but the same class hierarchy is reachable from real
flows that import a bucket before lifecycle is touched.

The fix is to read the attribute defensively via ``getattr(..., None)``
and continue when it's missing. This test pins that behaviour.
"""

from __future__ import annotations

import datetime
from types import SimpleNamespace
from unittest import mock


def _make_store(buckets):
    """Build the minimal nested mapping the scanner walks."""
    store = SimpleNamespace(buckets=buckets)
    return {"000000000000": {"us-east-1": store}}


def test_scanner_skips_buckets_with_no_lifecycle_rules_attr():
    """A bucket missing the lifecycle_rules attr should not crash the sweep."""
    from localemu.services.s3 import lifecycle as life

    # Two buckets: one without the attribute at all (the bug case), one with an
    # empty list of rules (the boring case). Neither should raise; both should
    # be skipped silently.
    bucket_attrless = object()  # truly no attribute
    bucket_empty = SimpleNamespace(lifecycle_rules=[])

    stores = _make_store({"a": bucket_attrless, "b": bucket_empty})

    with mock.patch.object(life, "s3_stores", stores):
        # Should return cleanly, not raise.
        life._scan_all_buckets(storage_backend=mock.Mock())


def test_scanner_processes_buckets_with_enabled_expiration_rules():
    """Sanity-check: a bucket with one Enabled+Expiration rule reaches the
    expirer. This proves the new ``getattr`` path doesn't accidentally drop
    legitimate rules."""
    from localemu.services.s3 import lifecycle as life

    bucket = SimpleNamespace(lifecycle_rules=[
        {"ID": "expire-30d", "Status": "Enabled",
         "Expiration": {"Days": 30}, "Filter": {"Prefix": ""}},
    ])
    stores = _make_store({"with-rules": bucket})

    with mock.patch.object(life, "s3_stores", stores), \
         mock.patch.object(life, "_expire_bucket_objects", return_value=3) as expirer:
        life._scan_all_buckets(storage_backend=mock.Mock())

    expirer.assert_called_once()
    # Confirm the call received the enabled rule we set up.
    _, kwargs = expirer.call_args[0], expirer.call_args[1]  # noqa: F841
    args = expirer.call_args[0]
    enabled_rules = args[2]
    assert len(enabled_rules) == 1
    assert enabled_rules[0]["ID"] == "expire-30d"


def test_scanner_skips_buckets_with_only_disabled_rules():
    """Disabled rules should be skipped without calling the expirer."""
    from localemu.services.s3 import lifecycle as life

    bucket = SimpleNamespace(lifecycle_rules=[
        {"ID": "off", "Status": "Disabled",
         "Expiration": {"Days": 30}, "Filter": {"Prefix": ""}},
    ])
    stores = _make_store({"disabled": bucket})

    with mock.patch.object(life, "s3_stores", stores), \
         mock.patch.object(life, "_expire_bucket_objects") as expirer:
        life._scan_all_buckets(storage_backend=mock.Mock())

    expirer.assert_not_called()
