"""Apply a Pipes ``InputTemplate`` to a single event.

Delegates the actual placeholder substitution to the EventBridge
helpers (``services/events/target.py``) so the two engines stay
behaviourally identical for the shared subset of placeholders
(``<$.path.expressions>``). Pipes-specific aliases like
``<aws.pipes.event>`` are pre-expanded before the underlying helper
runs.
"""

from __future__ import annotations

import json
from typing import Any

from localemu.services.events.target import (
    TRANSFORMER_PLACEHOLDER_PATTERN,
    get_template_replacements,
    replace_template_placeholders,
)


def apply_input_template(template: str | None, event: Any) -> Any:
    """Render *template* against *event* and return the transformed payload.

    ``template`` of ``None`` / empty string is a no-op — the event flows
    through untouched, which is the AWS default when ``InputTemplate``
    isn't set on the pipe.

    The result is JSON-decoded when the template's outer shape was JSON
    (object or array literal) so downstream targets receive a structured
    payload rather than a serialised string.
    """
    if not template:
        return event

    # Build the placeholder map. Every ``$.foo.bar`` reference becomes
    # an InputPathsMap entry; the events helper then resolves it via
    # jsonpath against the event.
    placeholders = TRANSFORMER_PLACEHOLDER_PATTERN.findall(template)
    paths_map = {
        p: p for p in placeholders if p.startswith("$.")
    }

    # Pipes-specific aliases. These resolve directly without a jsonpath
    # lookup so we substitute them in before handing off.
    populated = template
    if "<aws.pipes.event>" in populated or "<aws.pipes.event.json>" in populated:
        event_json = (
            json.dumps(event) if not isinstance(event, str) else event
        )
        populated = populated.replace("<aws.pipes.event.json>", event_json)
        populated = populated.replace(
            "<aws.pipes.event>",
            event_json if populated.strip().startswith("{") else event_json.strip('"'),
        )

    replacements = get_template_replacements({"InputPathsMap": paths_map}, event)
    stripped = populated.strip()
    if stripped.startswith(("{", "[")):
        # JSON template — delegate to the events helper, which knows how
        # to handle nested-in-string vs raw placement and re-parses the
        # JSON when it succeeds.
        rendered = replace_template_placeholders(populated, replacements)
        if isinstance(rendered, str):
            try:
                return json.loads(rendered.strip())
            except json.JSONDecodeError:
                return rendered
        return rendered

    # Plain-string template — substitute placeholders verbatim, no outer-
    # quote stripping. The events helper assumes a quoted string for
    # string templates, which doesn't match the Pipes convention.
    def _sub(match):
        key = match.group(1)
        value = replacements.get(key, "")
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    return TRANSFORMER_PLACEHOLDER_PATTERN.sub(_sub, populated)
