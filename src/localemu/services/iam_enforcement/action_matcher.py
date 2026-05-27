"""AWS IAM action matching with wildcard support.

Actions follow the format `service:ActionName`. Policy statements can use
wildcards: `s3:*`, `s3:Get*`, `dynamodb:BatchGet*`.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
"""

import fnmatch
import logging

LOG = logging.getLogger(__name__)


def _escape_brackets(pattern: str) -> str:
    """Escape square brackets so fnmatch treats them as literals.

    IAM wildcards only support * and ?, not character classes like [abc].
    fnmatch interprets [ as a character class bracket, so we must escape them.
    """
    return pattern.replace("[", "[[]").replace("]", "[]]")


def matches_action(statement: dict, action: str) -> bool:
    """Check if an action matches a statement's Action or NotAction list.

    Args:
        statement: Policy statement dict with Action or NotAction
        action: The API action (e.g., "s3:PutObject")

    Returns:
        True if the action matches the statement's action list
    """
    actions = statement.get("Action", [])
    not_actions = statement.get("NotAction", [])

    if isinstance(actions, str):
        actions = [actions]
    if isinstance(not_actions, str):
        not_actions = [not_actions]

    # A well-formed statement uses exactly one of Action or NotAction. AWS
    # rejects the both-present combination at CreatePolicy with
    # MalformedPolicyDocument; if we see it here the policy was constructed
    # outside that validator. Treat as non-matching so a malformed Allow does
    # not accidentally grant and a malformed Deny does not accidentally block.
    if actions and not_actions:
        LOG.warning(
            "Malformed policy statement: both Action and NotAction present "
            "(Sid=%r). Statement will not match any action.",
            statement.get("Sid"),
        )
        return False

    # Symmetric: neither Action nor NotAction — AWS also rejects this at
    # policy creation. Be defensive and fail closed.
    if not actions and not not_actions:
        return False

    # NotAction: matches everything EXCEPT the listed actions
    if not_actions:
        return not any(
            fnmatch.fnmatch(action.lower(), _escape_brackets(pattern.lower()))
            for pattern in not_actions
        )

    # Action: matches if any pattern matches
    return any(
        fnmatch.fnmatch(action.lower(), _escape_brackets(pattern.lower()))
        for pattern in actions
    )
