"""HashiCorp Configuration Language (HCL) serializer.

This module converts a Python ``dict`` of Terraform resources into
pretty-printed HCL text. It is intentionally *Terraform-only*: HCL has
its own quoting rules, heredoc support, reference syntax
(``aws_iam_role.foo.arn`` — a bare identifier) and interpolation syntax
(``${...}`` inside strings). Sharing this logic with a JSON writer would
produce subtle bugs.

Two pseudo-types are understood on top of plain Python scalars / lists /
dicts:

* :class:`~localemu.export.ir.Ref`
    Materialized to the bare Terraform address
    ``<tf_type>.<safe_name>.<attribute>`` at the top level of an
    assignment. When embedded inside a string it is wrapped with
    ``${...}`` so Terraform interpolates it.

* :class:`HclRaw`
    A value that is already valid HCL source (e.g. ``jsonencode({...})``
    or a ``filebase64sha256(...)`` call). It is emitted verbatim.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from localemu.export.ir import Ref

# Valid Terraform identifier: starts with letter/underscore, then
# alphanumerics / underscores / hyphens. We normalize to the stricter
# ``[a-z_][a-z_0-9]*`` for generated resource names upstream.
_TF_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]*$")


@dataclass(frozen=True)
class HclRaw:
    """A value that must be emitted verbatim (no quoting, no escaping).

    Use this for HCL function calls (``jsonencode({...})``,
    ``filebase64sha256("lambda/foo.zip")``) produced by the per-service
    builders.
    """

    source: str


# Signature of the resolver that converts a ``Ref`` into the Terraform
# address it should render as. Supplied by the writer because only the
# writer knows the final (sanitized, collision-resolved) logical names.
RefResolver = Callable[[Ref], str]


class HclSerializer:
    """Serialize a resources dict plus provider dict to HCL text."""

    def __init__(self, ref_resolver: RefResolver | None = None) -> None:
        """Create a serializer.

        Args:
            ref_resolver: Callable mapping a :class:`Ref` to its
                Terraform address (e.g. ``aws_iam_role.my_role.arn``).
                If ``None``, a default resolver is used that builds the
                address from the ``Ref``'s own fields — adequate for unit
                tests but not for real exports (the writer overrides it).
        """
        self._resolve_ref = ref_resolver or self._default_ref_resolver

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def serialize(
        self,
        resources: dict[str, dict[str, Any]],
        providers: dict[str, Any] | None = None,
    ) -> str:
        """Serialize ``resources`` (and optionally ``providers``) to HCL.

        Args:
            resources: Mapping of ``tf_type`` → mapping of logical name →
                attribute dict. Example::

                    {"aws_s3_bucket": {"my_bucket": {"bucket": "x"}}}

            providers: Optional mapping of ``provider_name`` → attribute
                dict. Usually emitted into ``providers.tf`` separately,
                so most callers pass ``None`` here.

        Returns:
            HCL text with trailing newline.
        """
        out: list[str] = []

        if providers:
            for name, attrs in providers.items():
                out.append(self._emit_block("provider", [name], attrs, 0))
                out.append("")

        for tf_type, instances in resources.items():
            for logical_name, attrs in instances.items():
                out.append(self._emit_block("resource", [tf_type, logical_name], attrs, 0))
                out.append("")

        text = "\n".join(out).rstrip() + "\n"
        return text

    # ------------------------------------------------------------------
    # Block / value emission
    # ------------------------------------------------------------------

    def _emit_block(
        self,
        kind: str,
        labels: list[str],
        attrs: dict[str, Any],
        level: int,
    ) -> str:
        """Emit a top-level HCL block (``resource "x" "y" { ... }``)."""
        indent = self._indent(level)
        label_parts = " ".join(f'"{lbl}"' for lbl in labels)
        header = f"{indent}{kind} {label_parts} {{" if labels else f"{indent}{kind} {{"
        lines = [header]
        lines.extend(self._emit_body(attrs, level + 1))
        lines.append(f"{indent}}}")
        return "\n".join(lines)

    def _emit_body(self, attrs: dict[str, Any], level: int) -> list[str]:
        """Emit the key/value lines inside a block body.

        Lists of dicts are emitted as *nested blocks* (HCL idiom) rather
        than list-of-map assignments — this matches how the AWS provider
        schema is authored and produces readable output.
        """
        indent = self._indent(level)
        lines: list[str] = []
        for key, value in attrs.items():
            if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                # Repeated nested block, e.g. DynamoDB ``attribute`` blocks.
                for item in value:
                    lines.append(f"{indent}{key} {{")
                    lines.extend(self._emit_body(item, level + 1))
                    lines.append(f"{indent}}}")
            elif isinstance(value, dict) and self._dict_is_block(value):
                lines.append(f"{indent}{key} {{")
                lines.extend(self._emit_body(value, level + 1))
                lines.append(f"{indent}}}")
            else:
                lines.append(f"{indent}{key} = {self._emit_value(value, level)}")
        return lines

    @staticmethod
    def _dict_is_block(value: dict[str, Any]) -> bool:
        """Decide whether to render a dict as an HCL block vs. a map.

        HCL distinguishes nested blocks (``ttl { attribute_name = "x" }``)
        from map assignments (``tags = { Env = "dev" }``). Heuristic:
        empty dicts and dicts with non-identifier keys are maps; the
        caller opts into map rendering by using a :class:`HclRaw` key is
        not supported — instead, pass ``{}`` / use a map literal.

        We treat any dict whose keys are all valid identifiers *and*
        which contains no top-level non-identifier strings as a block.
        This matches how Terraform schema is written. The small set of
        cases where a user actually wants a map (``tags``, ``environment
        .variables``) is handled by builders emitting a ``dict`` with
        non-identifier keys or wrapping values in :class:`HclRaw`.
        """
        if not value:
            return False
        # Tags and env variable dicts commonly have PascalCase / mixed-case
        # keys that *are* valid identifiers. To avoid mis-detecting them
        # as blocks, builders should wrap them using a sentinel — but for
        # the common idiomatic cases we want block rendering. We pick
        # blocks when *all* values are scalars/refs and the dict is small
        # enough; otherwise map.
        # Simpler rule: always render dicts as maps. Builders that need
        # blocks use lists-of-dicts (handled above).
        return False

    def _emit_value(self, value: Any, level: int) -> str:
        """Render a single right-hand-side value."""
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return json.dumps(value)  # handles float formatting + inf/nan safely
        if isinstance(value, HclRaw):
            return self._indent_continuation(value.source, level)
        if isinstance(value, Ref):
            return self._resolve_ref(value)
        # ``JsonEncoded`` is defined in ``tf_specs`` to avoid pulling a
        # writer-specific import into this module at load time. We do a
        # duck-type check on ``.value`` so the serializer stays format
        # agnostic while still rendering the wrapper correctly.
        if type(value).__name__ == "JsonEncoded" and hasattr(value, "value"):
            inner = self._emit_value(value.value, level)
            return f"jsonencode({inner})"
        if isinstance(value, str):
            return self._quote_string(value, level)
        if isinstance(value, list):
            return self._emit_list(value, level)
        if isinstance(value, dict):
            return self._emit_map(value, level)
        # Fallback: JSON-encode unknown types as a string.
        return self._quote_string(json.dumps(value), level)

    def _emit_list(self, items: list[Any], level: int) -> str:
        """Emit an HCL list — inline if short, multiline otherwise."""
        if not items:
            return "[]"
        rendered = [self._emit_value(v, level + 1) for v in items]
        inline = "[" + ", ".join(rendered) + "]"
        # Inline when short and no embedded newlines.
        if len(inline) <= 80 and "\n" not in inline:
            return inline
        indent = self._indent(level + 1)
        close = self._indent(level)
        body = ",\n".join(f"{indent}{r}" for r in rendered)
        return f"[\n{body},\n{close}]"

    def _emit_map(self, items: dict[str, Any], level: int) -> str:
        """Emit an HCL map (``{ key = value, ... }``)."""
        if not items:
            return "{}"
        indent = self._indent(level + 1)
        close = self._indent(level)
        lines = []
        for k, v in items.items():
            key = k if _TF_IDENT_RE.match(k) else f'"{self._escape_string(k)}"'
            lines.append(f"{indent}{key} = {self._emit_value(v, level + 1)}")
        return "{\n" + "\n".join(lines) + f"\n{close}}}"

    # ------------------------------------------------------------------
    # String handling
    # ------------------------------------------------------------------

    def _quote_string(self, value: str, level: int) -> str:
        """Quote a Python string as an HCL string literal.

        Embedded :class:`Ref` values are impossible here (a ``Ref`` is
        not a ``str``), but *interpolations* can be introduced by
        builders that compose templates; those arrive as literal
        ``${...}`` inside the Python string and we must not escape them.

        Long multiline values are rendered as heredocs for readability.
        """
        # Heredoc for multi-line strings longer than a single newline.
        if "\n" in value and len(value) > 60:
            return self._emit_heredoc(value, level)
        return f'"{self._escape_string(value)}"'

    @staticmethod
    def _escape_string(value: str) -> str:
        """Escape a string for inclusion in a double-quoted HCL literal.

        HCL interpolates ``${...}`` and ``%{...}`` inside strings. We
        preserve any ``${...}`` that is already well-formed (builders
        use this to embed resource references inside template strings)
        and escape stray ``$`` characters by doubling them (``$$``),
        which Terraform treats as a literal ``$``.
        """
        out: list[str] = []
        i = 0
        n = len(value)
        while i < n:
            ch = value[i]
            if ch == "\\":
                out.append("\\\\")
            elif ch == '"':
                out.append('\\"')
            elif ch == "\n":
                out.append("\\n")
            elif ch == "\t":
                out.append("\\t")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "$" and i + 1 < n and value[i + 1] == "{":
                # Preserve interpolation: scan to matching closing brace.
                depth = 0
                j = i + 1
                while j < n:
                    if value[j] == "{":
                        depth += 1
                    elif value[j] == "}":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                out.append(value[i:j])
                i = j
                continue
            # NOTE: ``$`` only needs escaping when followed by ``{`` (HCL
            # interpolation). Bare ``$`` (e.g. ``$default`` stage name,
            # ``$request.method`` route-selection expression) must be
            # passed through verbatim — earlier blanket ``$``->``$$``
            # escaping caused AWS to reject these as literal ``$$...``.
            elif ch == "%" and i + 1 < n and value[i + 1] == "{":
                out.append("%%")
            else:
                out.append(ch)
            i += 1
        return "".join(out)

    def _emit_heredoc(self, value: str, level: int) -> str:
        """Emit a long string as an indented heredoc (``<<-EOT ... EOT``)."""
        indent = self._indent(level + 1)
        close = self._indent(level)
        # Strip trailing newline so the closing marker sits on its own line.
        body = value.rstrip("\n")
        lines = [f"{indent}{line}" for line in body.split("\n")]
        return "<<-EOT\n" + "\n".join(lines) + f"\n{close}EOT"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _indent(level: int) -> str:
        """Return ``level`` * 2 spaces of indentation."""
        return "  " * level

    def _indent_continuation(self, source: str, level: int) -> str:
        """Indent a multi-line :class:`HclRaw` source to the current level."""
        if "\n" not in source:
            return source
        indent = self._indent(level + 1)
        head, *rest = source.split("\n")
        return head + "\n" + "\n".join(indent + line if line else line for line in rest)

    @staticmethod
    def _default_ref_resolver(ref: Ref) -> str:
        """Fallback resolver: build an address from the ``Ref`` fields.

        Used only when no resolver is injected (unit tests). Real exports
        use :class:`~localemu.export.formats.terraform.TerraformWriter`'s
        resolver, which knows about name sanitization and collisions.
        """
        # Naive sanitization — the real writer does this properly.
        safe = re.sub(r"[^a-z0-9_]+", "_", ref.resource_id.lower()).strip("_") or "r"
        if safe[0].isdigit():
            safe = "_" + safe
        return f"aws_{ref.service}_{ref.resource_type}.{safe}.{ref.attribute}"
