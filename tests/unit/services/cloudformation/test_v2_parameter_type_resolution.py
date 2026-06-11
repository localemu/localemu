"""Regression tests for ``visit_node_parameter`` in the v2 change-set engine.

Earlier code only called ``_resolve_parameter_type`` on the ``after`` side
of the delta. When a downstream ``_cached_apply`` later resolved a
``Fn::Ref`` to the ``before`` state of a ``CommaDelimitedList`` (or
``List<...>``) parameter, it received the **raw comma-string**
(``"foo,bar"``) instead of a list (``["foo", "bar"]``). The subsequent
``Fn::Join`` resolver then crashed with::

    RuntimeError: Invalid arguments list definition for Fn::Join:
                  '['|', 'foo,bar']'

These tests pin that both deltas now flow through the same coercion.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from localemu.services.cloudformation.engine.v2.change_set_model import (
    Nothing,
    NodeParameter,
)
from localemu.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_preproc() -> ChangeSetModelPreproc:
    """Build a minimal ``ChangeSetModelPreproc`` for direct method invocation.

    The visitor's only dependency that matters for the parameter-type
    coercion path is its own ``visit`` method; we stub that below in each
    test rather than constructing a full ``ChangeSet``.
    """
    fake_change_set = MagicMock()
    fake_change_set.stack.resolved_resources = {}
    return ChangeSetModelPreproc(change_set=fake_change_set)


def _node_parameter(name: str) -> NodeParameter:
    """A minimally-populated ``NodeParameter``.

    The internal children (type / dynamic / default value) are placeholders;
    the visitor's ``visit`` method is stubbed in each test to return the
    delta we want for each child, so the children themselves are never
    inspected.
    """
    return NodeParameter(
        scope=MagicMock(),
        name=name,
        type_=MagicMock(),
        dynamic_value=MagicMock(),
        default_value=MagicMock(),
    )


def _stub_visits(
    preproc: ChangeSetModelPreproc,
    dynamic_delta: PreprocEntityDelta,
    default_delta: PreprocEntityDelta,
    type_delta: PreprocEntityDelta,
) -> None:
    """Stub ``preproc.visit`` so the three NodeParameter children produce the
    deltas we want without traversing the real change-set graph.

    ``visit_node_parameter`` calls ``self.visit`` three times, in this
    order: dynamic_value, default_value, type_.
    """
    preproc.visit = MagicMock(side_effect=[dynamic_delta, default_delta, type_delta])


# ---------------------------------------------------------------------------
# CommaDelimitedList: BEFORE must be parsed to a list, not left as a string
# ---------------------------------------------------------------------------


def test_comma_delimited_list_parses_before_as_list():
    """The bug: ``before`` of a CommaDelimitedList came back as ``'foo,bar'``."""
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        # dynamic value: before and after both the user-supplied string
        dynamic_delta=PreprocEntityDelta(before="foo,bar", after="foo,bar"),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="CommaDelimitedList", after="CommaDelimitedList"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert result.before == ["foo", "bar"], (
        "before must be the parsed list, not the raw comma-string; otherwise "
        "Fn::Ref + Fn::Join downstream crashes"
    )
    assert result.after == ["foo", "bar"]


def test_comma_delimited_list_strips_whitespace_in_before():
    """Match the contract already enforced for ``after``."""
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before=" foo , bar ", after=" foo , bar "),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="CommaDelimitedList", after="CommaDelimitedList"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert result.before == ["foo", "bar"]
    assert result.after == ["foo", "bar"]


def test_list_of_strings_parses_before():
    """``List<String>`` should follow the same coercion as CommaDelimitedList."""
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before="foo,bar", after="foo,bar"),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="List<String>", after="List<String>"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert result.before == ["foo", "bar"]
    assert result.after == ["foo", "bar"]


def test_list_of_subnet_ids_parses_before():
    """``List<AWS::EC2::Subnet::Id>`` (the test_subnet_id_parameter_type case)."""
    preproc = _new_preproc()
    raw = "subnet-aaa,subnet-bbb"
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before=raw, after=raw),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(
            before="List<AWS::EC2::Subnet::Id>",
            after="List<AWS::EC2::Subnet::Id>",
        ),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert result.before == ["subnet-aaa", "subnet-bbb"]
    assert result.after == ["subnet-aaa", "subnet-bbb"]


# ---------------------------------------------------------------------------
# Number / scalar types: before/after must keep matching real-CFN behaviour
# ---------------------------------------------------------------------------


def test_number_type_parses_before_to_number():
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before="42", after="42"),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="Number", after="Number"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamCount"))

    assert result.before == 42
    assert result.after == 42


def test_string_type_leaves_before_alone():
    """A plain String parameter must NOT have its before-value mangled."""
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before="some-value", after="some-value"),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="String", after="String"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamStr"))

    assert result.before == "some-value"
    assert result.after == "some-value"


# ---------------------------------------------------------------------------
# Nothing-side handling: must not crash, must propagate Nothing untouched
# ---------------------------------------------------------------------------


def test_nothing_before_stays_nothing():
    """A pure-CREATE change-set has no before; resolver must not crash."""
    from localemu.services.cloudformation.engine.v2.change_set_model import (
        is_nothing,
    )

    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before=Nothing, after="foo,bar"),
        default_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        type_delta=PreprocEntityDelta(before="CommaDelimitedList", after="CommaDelimitedList"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert is_nothing(result.before)
    assert result.after == ["foo", "bar"]


def test_default_value_fallback_parsed_when_dynamic_is_nothing():
    """When the user omits the param and the template has a default, the
    default still flows through ``_resolve_parameter_type``."""
    preproc = _new_preproc()
    _stub_visits(
        preproc,
        dynamic_delta=PreprocEntityDelta(before=Nothing, after=Nothing),
        default_delta=PreprocEntityDelta(before="x,y", after="x,y"),
        type_delta=PreprocEntityDelta(before="CommaDelimitedList", after="CommaDelimitedList"),
    )

    result = preproc.visit_node_parameter(_node_parameter("ParamsList"))

    assert result.before == ["x", "y"]
    assert result.after == ["x", "y"]
