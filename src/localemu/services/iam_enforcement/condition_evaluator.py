"""AWS IAM condition evaluation engine.

Evaluates Condition blocks in IAM policy statements against request context values.
Supports all standard condition operators, IfExists variants, and set operators
(ForAllValues, ForAnyValue).

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
"""

import fnmatch
import ipaddress
import logging
from datetime import datetime

from .resource_matcher import arn_matches, _substitute_policy_variables

LOG = logging.getLogger(__name__)


def _parse_date(value: str) -> datetime:
    """Parse an ISO 8601 date string."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse date: {value}")


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check if an IP address is in a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except ValueError:
        return False


# Condition operators: (context_value, condition_value) -> bool
_OPERATORS: dict[str, callable] = {
    # String conditions
    "StringEquals": lambda a, b: str(a) == str(b),
    "StringNotEquals": lambda a, b: str(a) != str(b),
    "StringEqualsIgnoreCase": lambda a, b: str(a).lower() == str(b).lower(),
    "StringNotEqualsIgnoreCase": lambda a, b: str(a).lower() != str(b).lower(),
    "StringLike": lambda a, b: fnmatch.fnmatch(str(a), str(b)),
    "StringNotLike": lambda a, b: not fnmatch.fnmatch(str(a), str(b)),
    # Numeric conditions
    "NumericEquals": lambda a, b: float(a) == float(b),
    "NumericNotEquals": lambda a, b: float(a) != float(b),
    "NumericLessThan": lambda a, b: float(a) < float(b),
    "NumericLessThanEquals": lambda a, b: float(a) <= float(b),
    "NumericGreaterThan": lambda a, b: float(a) > float(b),
    "NumericGreaterThanEquals": lambda a, b: float(a) >= float(b),
    # Date conditions
    "DateEquals": lambda a, b: _parse_date(a) == _parse_date(b),
    "DateNotEquals": lambda a, b: _parse_date(a) != _parse_date(b),
    "DateLessThan": lambda a, b: _parse_date(a) < _parse_date(b),
    "DateLessThanEquals": lambda a, b: _parse_date(a) <= _parse_date(b),
    "DateGreaterThan": lambda a, b: _parse_date(a) > _parse_date(b),
    "DateGreaterThanEquals": lambda a, b: _parse_date(a) >= _parse_date(b),
    # Boolean
    "Bool": lambda a, b: str(a).lower() == str(b).lower(),
    # IP address
    "IpAddress": lambda a, b: _ip_in_cidr(str(a), str(b)),
    "NotIpAddress": lambda a, b: not _ip_in_cidr(str(a), str(b)),
    # ARN conditions
    "ArnEquals": lambda a, b: str(a) == str(b),
    "ArnNotEquals": lambda a, b: str(a) != str(b),
    "ArnLike": lambda a, b: arn_matches(str(b), str(a)),
    "ArnNotLike": lambda a, b: not arn_matches(str(b), str(a)),
    # Null check: key is "null" (absent) only when the value is truly None.
    # Empty string "" counts as present (not null) per AWS docs.
    "Null": lambda a, b: (a is None) == (str(b).lower() == "true"),
}


def matches_conditions(statement: dict, context: dict) -> bool:
    """Evaluate all conditions in a policy statement.

    Args:
        statement: Policy statement with optional Condition block
        context: Request context with condition key values

    Returns:
        True if all conditions are satisfied (AND logic across operators,
        OR logic across values within a single condition key)
    """
    conditions = statement.get("Condition")
    if not conditions:
        return True

    for operator, condition_block in conditions.items():
        # Handle IfExists variant
        if_exists = operator.endswith("IfExists")
        base_operator = operator.replace("IfExists", "") if if_exists else operator

        # Handle ForAllValues / ForAnyValue set operators
        set_op = None
        if base_operator.startswith("ForAllValues:"):
            set_op = "all"
            base_operator = base_operator[len("ForAllValues:"):]
        elif base_operator.startswith("ForAnyValue:"):
            set_op = "any"
            base_operator = base_operator[len("ForAnyValue:"):]

        compare_fn = _OPERATORS.get(base_operator)
        if not compare_fn:
            LOG.warning("Unknown IAM condition operator: %s", operator)
            return False  # Unknown operator - deny (safe default)

        for condition_key, condition_values in condition_block.items():
            if isinstance(condition_values, str):
                condition_values = [condition_values]

            # Substitute IAM policy variables (e.g. ${aws:username}) in condition values
            condition_values = [
                _substitute_policy_variables(str(v), context) for v in condition_values
            ]

            context_value = context.get(condition_key)

            # Treat empty list as absent (AWS treats empty multi-value keys as absent)
            if isinstance(context_value, list) and len(context_value) == 0:
                context_value = None

            # IfExists: skip if key not present in context
            if context_value is None:
                if if_exists:
                    continue
                if base_operator == "Null":
                    if not compare_fn(None, condition_values[0]):
                        return False
                    continue
                return False  # Key required but not present

            # Set operations (ForAllValues / ForAnyValue)
            if set_op:
                ctx_values = context_value if isinstance(context_value, list) else [context_value]
                if set_op == "all":
                    # Every context value must match at least one condition value
                    for cv in ctx_values:
                        if not any(_safe_compare(compare_fn, cv, cond_v) for cond_v in condition_values):
                            return False
                elif set_op == "any":
                    # At least one context value must match at least one condition value
                    if not any(
                        _safe_compare(compare_fn, cv, cond_v)
                        for cv in ctx_values
                        for cond_v in condition_values
                    ):
                        return False
            else:
                # Standard: at least one condition value must match (OR within a key)
                if not any(
                    _safe_compare(compare_fn, context_value, v) for v in condition_values
                ):
                    return False

    return True


def _safe_compare(fn: callable, a, b) -> bool:
    """Run a comparison function, returning False on any error."""
    try:
        return fn(a, b)
    except (ValueError, TypeError):
        return False
