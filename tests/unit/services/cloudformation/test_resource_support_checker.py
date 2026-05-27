"""CFN change-set resource-support checker.

The checker is what stands between a user template that references a
type LocalEmu can't deploy (e.g. ``AWS::Glue::Crawler``, which has no
provider plugin) and a silent "change set committed, no resource
created" surprise. The supported set MUST be the registered
``CloudFormationResourceProviderPlugin`` names plus the engine-built-in
pseudo-types, NOT the entire CFN catalog.
"""

from __future__ import annotations

import pytest

from localemu.aws.api.cloudformation import ChangeSetType
from localemu.services.cloudformation.engine.v2.change_set_resource_support_checker import (
    ChangeSetResourceSupportChecker,
    _implemented_resource_types,
)


class _FakeType:
    def __init__(self, value: str):
        self.value = value


class _FakeNodeResource:
    def __init__(self, resource_type: str):
        self.type_ = _FakeType(resource_type)

    def get_children(self):
        # The visitor walks children after visiting the resource node;
        # we have none, so return an empty list.
        return []


@pytest.fixture(autouse=True)
def _clear_cache():
    _implemented_resource_types.cache_clear()
    yield
    _implemented_resource_types.cache_clear()


class TestImplementedResourceTypes:
    def test_set_is_non_empty(self):
        impl = _implemented_resource_types()
        assert len(impl) > 0, "no resource providers discovered — registry is broken"

    def test_set_contains_known_implemented_types(self):
        impl = _implemented_resource_types()
        # Sanity check on a handful of well-known providers shipped in
        # the repo. If any of these stop being supported the test
        # should fail loudly — they're load-bearing for nearly every
        # real-world template.
        for known in (
            "AWS::S3::Bucket",
            "AWS::IAM::Role",
            "AWS::Lambda::Function",
            "AWS::DynamoDB::Table",
        ):
            assert known in impl, known

    def test_set_contains_engine_builtin_pseudo_types(self):
        impl = _implemented_resource_types()
        for builtin in (
            "AWS::CloudFormation::Stack",
            "AWS::CloudFormation::CustomResource",
            "AWS::CloudFormation::WaitCondition",
            "AWS::CloudFormation::WaitConditionHandle",
        ):
            assert builtin in impl, builtin

    def test_set_does_not_include_unimplemented_aws_resources(self):
        """Negative coverage: the AWS catalog is much larger than what
        we implement. Confirm one type we definitely don't support so
        the dump-of-everything regression can't re-land."""
        impl = _implemented_resource_types()
        assert "AWS::Glue::Crawler" not in impl, (
            "Glue Crawler has no provider plugin — flagging it as supported "
            "means change-sets that reference it deploy silently to nothing."
        )


@pytest.fixture
def _enforce_unsupported(monkeypatch):
    """Flip the default-true ``CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES``
    off so the checker actually emits failure messages — otherwise every
    unsupported type is silently allowed and the checker is a no-op."""
    from localemu import config

    monkeypatch.setattr(config, "CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES", False)


@pytest.mark.usefixtures("_enforce_unsupported")
class TestChangeSetResourceSupportChecker:
    def _check(self, *resource_types: str) -> list[str]:
        checker = ChangeSetResourceSupportChecker(ChangeSetType.CREATE)
        for rt in resource_types:
            checker.visit_node_resource(_FakeNodeResource(rt))
        return checker.failure_messages

    def test_supported_types_emit_no_failure(self):
        assert self._check("AWS::S3::Bucket", "AWS::IAM::Role") == []

    def test_unsupported_type_emits_friendly_message(self):
        failures = self._check("AWS::Glue::Crawler")
        assert len(failures) == 1
        assert "AWS::Glue::Crawler" in failures[0]
        assert "github.com/localemu/localemu/issues" in failures[0]

    def test_custom_resources_resolve_to_custom_resource_type(self):
        """``Custom::MyThing`` is dispatched via
        ``AWS::CloudFormation::CustomResource``; the checker must mirror
        that mapping or every custom-resource template fails the check."""
        assert self._check("Custom::MyThing") == []

    def test_failure_message_is_deduped_per_resource_type(self):
        """Visiting the same unsupported type twice must surface only
        one failure message, not a duplicate per appearance."""
        failures = self._check("AWS::Glue::Crawler", "AWS::Glue::Crawler")
        assert len(failures) == 1

    def test_legacy_cfn_resources_module_is_gone(self):
        """Negative coverage: the old generated dump must stay deleted —
        re-introducing it tempts a future change to wire the broad set
        back in."""
        import importlib.util

        assert (
            importlib.util.find_spec(
                "localemu.services.cloudformation.resources"
            )
            is None
        ), (
            "localemu.services.cloudformation.resources is gone for a "
            "reason — do not regenerate it. The provider plugin list is "
            "the authoritative supported-types set."
        )
