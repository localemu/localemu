from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from localemu.services.stepfunctions.asl.utils.encoding import to_json_str

JSONataExpression = str
VariableReference = str
VariableDeclarations = str


# TODO: move the extraction logic to a formal ANTLR-base parser, as done with legacy
#       Intrinsic Functions in package localemu.services.stepfunctions.asl.antlr
#       with grammars ASLIntrinsicLexer and ASLIntrinsicParser, later used by upstream
#       logics such as in:
#       localemu.services.stepfunctions.asl.parse.intrinsic.preprocessor.Preprocessor
_PATTERN_VARIABLE_REFERENCE = re.compile(
    # 1) Non-capturing branch for JSONata regex literal
    #    /.../ (slash delimited), allowing escaped slashes \/
    r"(?:\/(?:\\.|[^\\/])*\/[a-zA-Z]*)"
    r"|"
    # 2) Non-capturing branch for JSONata string literal:
    #    "..." (double quotes) or '...' (single quotes),
    #    allowing escapes
    r"(?:\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\')"
    r"|"
    # 3) Capturing branch for $identifier[.prop...]
    #    Requires at least one identifier character after $, so bare $ (the
    #    JSONata context variable used in filter predicates like [$ = 1]) is
    #    never captured.  $$ is captured but filtered out downstream.
    r"(\$[A-Za-z0-9_$]+(?:\.[A-Za-z0-9_][A-Za-z0-9_$]*)*)"
)

_ILLEGAL_VARIABLE_REFERENCES: Final[set[str]] = {"$", "$$"}
_VARIABLE_REFERENCE_ASSIGNMENT_OPERATOR: Final[str] = ":="
_VARIABLE_REFERENCE_ASSIGNMENT_STOP_SYMBOL: Final[str] = ";"
_EXPRESSION_OPEN_SYMBOL: Final[str] = "("
_EXPRESSION_CLOSE_SYMBOL: Final[str] = ")"


class JSONataException(Exception):
    error: Final[str]
    details: str | None

    def __init__(self, error: str, details: str | None):
        self.error = error
        self.details = details


def eval_jsonata_expression(jsonata_expression: JSONataExpression) -> Any:
    raise NotImplementedError(
        "JSONata evaluation is not available: Java/JPype support has been removed."
    )


class IllegalJSONataVariableReference(ValueError):
    variable_reference: Final[VariableReference]

    def __init__(self, variable_reference: VariableReference):
        self.variable_reference = variable_reference


def extract_jsonata_variable_references(
    jsonata_expression: JSONataExpression,
) -> set[VariableReference]:
    if not jsonata_expression:
        return set()
    # Extract all recognised patterns.
    all_references: list[Any] = _PATTERN_VARIABLE_REFERENCE.findall(jsonata_expression)
    # Filter non-empty patterns (this includes consumed blocks such as jsonata
    # regular expressions, delimited between non-escaped slashes).
    variable_references: set[VariableReference] = {
        reference for reference in all_references if reference and isinstance(reference, str)
    }
    for variable_reference in variable_references:
        if variable_reference in _ILLEGAL_VARIABLE_REFERENCES:
            raise IllegalJSONataVariableReference(variable_reference=variable_reference)
    return variable_references


def encode_jsonata_variable_declarations(
    bindings: dict[VariableReference, Any],
) -> VariableDeclarations:
    declarations_parts: list[str] = []
    for variable_reference, value in bindings.items():
        if isinstance(value, str):
            value_str_lit = f'"{value}"'
        else:
            value_str_lit = to_json_str(value, separators=(",", ":"))
        declarations_parts.extend(
            [
                variable_reference,
                _VARIABLE_REFERENCE_ASSIGNMENT_OPERATOR,
                value_str_lit,
                _VARIABLE_REFERENCE_ASSIGNMENT_STOP_SYMBOL,
            ]
        )
    return "".join(declarations_parts)


def compose_jsonata_expression(
    final_jsonata_expression: JSONataExpression,
    variable_declarations_list: list[VariableDeclarations],
) -> JSONataExpression:
    variable_declarations = "".join(variable_declarations_list)
    expression = "".join(
        [
            _EXPRESSION_OPEN_SYMBOL,
            variable_declarations,
            final_jsonata_expression,
            _EXPRESSION_CLOSE_SYMBOL,
        ]
    )
    return expression
