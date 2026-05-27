"""apply_input_template — placeholder substitution + JSON detection."""

from __future__ import annotations

from localemu.services.pipes.transform import apply_input_template


class TestPathPlaceholders:
    def test_none_template_returns_event_unchanged(self):
        event = {"a": 1}
        assert apply_input_template(None, event) is event

    def test_empty_template_returns_event_unchanged(self):
        event = {"a": 1}
        assert apply_input_template("", event) is event

    def test_simple_jsonpath_substitution_returns_dict(self):
        result = apply_input_template(
            '{"id": <$.body.id>, "kind": "<$.body.kind>"}',
            {"body": {"id": 42, "kind": "thing"}},
        )
        assert result == {"id": 42, "kind": "thing"}

    def test_missing_jsonpath_defaults_to_empty(self):
        result = apply_input_template(
            '{"id": <$.body.id>, "missing": "<$.body.missing>"}',
            {"body": {"id": 1}},
        )
        assert result == {"id": 1, "missing": ""}


class TestPipesSpecificAliases:
    def test_aws_pipes_event_json_inlines_serialised_event(self):
        result = apply_input_template(
            "<aws.pipes.event.json>",
            {"k": "v"},
        )
        assert result == {"k": "v"}

    def test_string_template_keeps_string_shape(self):
        result = apply_input_template("hello <$.name>", {"name": "world"})
        assert result == "hello world"
