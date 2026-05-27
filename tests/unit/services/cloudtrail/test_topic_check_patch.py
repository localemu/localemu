"""Regression test for the ``check_topic_exists`` patch (B2).

Sibling of ``test_bucket_check_patch.py``. Moto's
``Trail.check_topic_exists`` consults moto's own SNS backend. LocalEmu's
SNS is NOT moto-backed (it's our own provider with its own store), so a
topic that exists per ``aws sns list-topics`` was invisible to moto's
CloudTrail — ``CreateTrail`` with ``--sns-topic-name <real-topic>``
failed with ``InsufficientSnsTopicPolicyException`` even though the
topic clearly existed.

The fix rewires the check to consult LocalEmu's ``sns_stores`` first,
falling back to moto only if the topic isn't in LocalEmu's store.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_sns_store():
    """Clear LocalEmu's SNS store before and after each test."""
    from localemu.services.sns.models import sns_stores
    snapshot = dict(sns_stores)
    sns_stores.clear()
    yield
    sns_stores.clear()
    sns_stores.update(snapshot)


def _patched_trail(
    topic_name: str | None,
    account_id: str = "000000000000",
    region: str = "us-east-1",
):
    """Build a minimal Trail-shaped object the patched check can run
    against. We don't need the full moto machinery — just the attributes
    the check uses: ``account_id``, ``region_name``, ``partition`` and
    ``sns_topic_name`` (which ``topic_arn`` is derived from)."""
    from moto.cloudtrail.models import Trail

    t = Trail.__new__(Trail)
    t.account_id = account_id
    t.region_name = region
    t.partition = "aws"
    t.sns_topic_name = topic_name
    return t


class TestPatchInstallation:
    def test_patch_is_installed_at_service_creation(self):
        """``create_cloudtrail_service`` installs the patch on Trail."""
        from moto.cloudtrail.models import Trail
        from localemu.services.cloudtrail.provider import create_cloudtrail_service

        create_cloudtrail_service()
        assert getattr(Trail.check_topic_exists, "_le_patched", False) is True

    def test_patch_is_idempotent(self):
        """Calling the installer twice must not wrap twice."""
        from moto.cloudtrail.models import Trail
        from localemu.services.cloudtrail.provider import _patch_moto_topic_check

        _patch_moto_topic_check()
        first = Trail.check_topic_exists
        _patch_moto_topic_check()
        assert Trail.check_topic_exists is first


class TestTopicCheck:
    def test_no_topic_configured_is_a_noop(self):
        """A trail without ``sns_topic_name`` must pass without error."""
        from localemu.services.cloudtrail.provider import _patch_moto_topic_check

        _patch_moto_topic_check()
        trail = _patched_trail(topic_name=None)
        trail.check_topic_exists()  # must not raise

    def test_accepts_topic_in_localemu_store(self):
        """A topic present in sns_stores must pass the check."""
        from localemu.services.cloudtrail.provider import _patch_moto_topic_check
        from localemu.services.sns.models import sns_stores

        _patch_moto_topic_check()

        account_id, region, topic_name = "000000000000", "us-east-1", "my-topic"
        topic_arn = f"arn:aws:sns:{region}:{account_id}:{topic_name}"
        store = sns_stores[account_id][region]
        store.topics[topic_arn] = {
            "arn": topic_arn,
            "name": topic_name,
            "attributes": {},
            "data_protection_policy": None,
            "subscriptions": [],
        }

        trail = _patched_trail(
            topic_name=topic_name, account_id=account_id, region=region
        )
        trail.check_topic_exists()  # must not raise

    def test_rejects_unknown_topic(self):
        """A topic missing from both LocalEmu and moto must still error."""
        from moto.cloudtrail.models import InsufficientSnsTopicPolicyException
        from localemu.services.cloudtrail.provider import _patch_moto_topic_check

        _patch_moto_topic_check()

        trail = _patched_trail(topic_name="le-never-existed")
        with pytest.raises(InsufficientSnsTopicPolicyException):
            trail.check_topic_exists()
