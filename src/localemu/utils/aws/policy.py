"""Helpers for parsing AWS IAM/resource policy documents safely.

AWS IAM policy grammar lets the top-level ``Statement`` field be either a
single statement object **or** a list of statement objects. Code that does
``for stmt in policy["Statement"]`` on the single-dict form ends up
iterating over the dict's *keys* (the strings ``"Effect"``, ``"Principal"``
...) and any subsequent ``stmt.get(...)`` raises ``AttributeError``. The
bug surfaces in production any time a real-world policy uses the
single-statement form, which is common because the AWS console emits both
forms and CloudFormation/CDK round-trip either.

This module concentrates the normalisation in one place so every site that
walks a policy gets the same dict/list handling and the same malformed-
input behaviour (deny by default, with debug logging).
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

LOG = logging.getLogger(__name__)


def iter_policy_statements(policy: Any) -> Iterator[dict]:
    """Yield each statement dict from a parsed AWS policy document.

    Handles both AWS-valid shapes of the ``Statement`` field:

    * Single dict (``{"Statement": {"Effect": "Allow", ...}}``) -> yields
      that one dict.
    * List of dicts (``{"Statement": [{...}, {...}]}``) -> yields each
      element.

    Anything else (missing ``Statement``, non-dict/non-list value, or list
    elements that are not dicts) is treated as malformed: a debug log line
    is emitted and the element is skipped. Callers iterating to collect
    Allow / Deny decisions see no statements in that case, which is the
    safe default (no permissions can be derived from a malformed policy).

    Args:
        policy: A parsed policy document (``dict`` from ``json.loads``) or
            anything else; non-dict ``policy`` simply yields nothing.

    Yields:
        Each statement dict, in input order.
    """
    if not isinstance(policy, dict):
        if policy is not None:
            LOG.debug(
                "iter_policy_statements: non-dict policy (type=%s); yielding nothing",
                type(policy).__name__,
            )
        return

    statements = policy.get("Statement")
    if statements is None:
        return

    if isinstance(statements, dict):
        yield statements
        return

    if not isinstance(statements, list):
        LOG.debug(
            "iter_policy_statements: malformed Statement (type=%s); yielding nothing",
            type(statements).__name__,
        )
        return

    for st in statements:
        if isinstance(st, dict):
            yield st
        else:
            LOG.debug(
                "iter_policy_statements: skipping non-dict statement (type=%s)",
                type(st).__name__,
            )


def normalize_policy_statements(policy: Any) -> list[dict]:
    """Return all statements from a policy as a list of dicts.

    Convenience wrapper over :func:`iter_policy_statements` for callers
    that need the materialised list (e.g. list comprehensions, ``next``
    over a generator expression, or mutation via index).
    """
    return list(iter_policy_statements(policy))
