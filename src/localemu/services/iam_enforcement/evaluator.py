"""IAM Policy Evaluation Engine.

Implements the AWS IAM policy evaluation algorithm as documented at:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

Evaluation order:
1. Explicit Deny in any policy -> DENY
2. Resource-based policy Allow (same account) -> ALLOW
3. Identity-based policy Allow -> required
4. Permission boundary Allow -> required (if set)
5. Session policy Allow -> required (if assumed role)
6. Default -> DENY
"""

import logging
from enum import Enum

from .action_matcher import matches_action
from .condition_evaluator import matches_conditions
from .identity import CallerIdentity, get_identity_policies, get_permission_boundary, get_session_policies
from .resource_matcher import matches_resource

LOG = logging.getLogger(__name__)


class Decision(Enum):
    ALLOW = "ALLOW"
    IMPLICIT_DENY = "IMPLICIT_DENY"
    EXPLICIT_DENY = "EXPLICIT_DENY"


class PolicyEvaluator:
    """Evaluates IAM policies following the AWS evaluation algorithm."""

    def evaluate(
        self,
        caller: CallerIdentity,
        action: str,
        resource: str,
        conditions: dict,
        resource_policy: dict | None = None,
    ) -> Decision:
        """Evaluate whether a caller is allowed to perform an action on a resource.

        Args:
            caller: The resolved caller identity
            action: The API action (e.g., "s3:PutObject")
            resource: The resource ARN
            conditions: Request context for condition evaluation
            resource_policy: Optional resource-based policy (e.g., S3 bucket policy)

        Returns:
            Decision.ALLOW or Decision.EXPLICIT_DENY or Decision.IMPLICIT_DENY
        """
        # Root account bypasses all checks
        if caller.principal_type == "Root":
            return Decision.ALLOW

        # Merge caller tags into conditions
        merged_conditions = {**conditions, **caller.tags}

        # Gather policies
        identity_policies = get_identity_policies(caller)
        permission_boundary = get_permission_boundary(caller)

        # Step 1: Check ALL policies for explicit Deny
        all_policies = list(identity_policies)
        if resource_policy:
            all_policies.append(resource_policy)
        if permission_boundary:
            all_policies.append(permission_boundary)

        for policy in all_policies:
            for statement in policy.get("Statement", []):
                if statement.get("Effect") != "Deny":
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                # For resource policies, also check Principal
                if policy is resource_policy and not _matches_principal(statement, caller):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                LOG.debug(
                    "IAM: explicit deny for %s on %s (action=%s)",
                    caller.arn, resource, action,
                )
                return Decision.EXPLICIT_DENY

        # Step 2: Check resource-based policy for Allow.
        #
        # For SAME-account calls, a resource-policy Allow is sufficient per
        # the AWS policy evaluation reference:
        #   "If either the identity-based policy or the resource-based policy
        #    within the same account allows the request and the other doesn't,
        #    the request is still allowed."
        #   — reference_policies_evaluation-logic_policy-eval-basics.html
        #
        # For CROSS-account (caller account != resource owner account), AWS
        # requires Allow in BOTH policies. LocalEmu defaults to a single
        # account (000000000000) and cross-account setups are rare; we short-
        # circuit on resource-policy Allow uniformly. If cross-account
        # scenarios become common, this step should be gated on account
        # comparison and the identity-policy branch below must also run.
        #
        # The `_matches_principal` call here enforces the resource-policy
        # grammar: statements missing Principal do NOT auto-grant.
        if resource_policy:
            for statement in resource_policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                if not _matches_principal(statement, caller):
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                LOG.debug(
                    "IAM: allowed by resource policy for %s on %s",
                    caller.arn, resource,
                )
                return Decision.ALLOW

        # Step 3: Check identity-based policies for Allow
        identity_allow = False
        for policy in identity_policies:
            for statement in policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                identity_allow = True
                break
            if identity_allow:
                break

        if not identity_allow:
            LOG.debug(
                "IAM: implicit deny (no identity policy allows) for %s on %s (action=%s)",
                caller.arn, resource, action,
            )
            return Decision.IMPLICIT_DENY

        # Step 4: Check permission boundary (if present)
        if permission_boundary:
            boundary_allow = False
            for statement in permission_boundary.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                boundary_allow = True
                break
            if not boundary_allow:
                LOG.debug(
                    "IAM: denied by permission boundary for %s on %s",
                    caller.arn, resource,
                )
                return Decision.IMPLICIT_DENY

        # Step 5: Check session policies (for assumed roles)
        if caller.principal_type == "AssumedRole":
            session_policies = get_session_policies(caller)
            if session_policies:
                session_allow = False
                for policy in session_policies:
                    for statement in policy.get("Statement", []):
                        if statement.get("Effect") != "Allow":
                            continue
                        if not matches_action(statement, action):
                            continue
                        if not matches_resource(statement, resource, merged_conditions):
                            continue
                        if not matches_conditions(statement, merged_conditions):
                            continue
                        session_allow = True
                        break
                    if session_allow:
                        break
                if not session_allow:
                    LOG.debug(
                        "IAM: denied by session policy for %s on %s",
                        caller.arn, resource,
                    )
                    return Decision.IMPLICIT_DENY

        return Decision.ALLOW


def _matches_principal(statement: dict, caller: CallerIdentity) -> bool:
    """Check if a caller matches a statement's Principal.

    Only called for resource-based policy statements (the evaluator skips this
    step for identity policies). On resource-based policies:
      - Principal is REQUIRED. A statement missing both Principal and
        NotPrincipal doesn't match any caller (AWS rejects at policy-creation
        time; we fail closed at evaluation time.)
      - Having both Principal AND NotPrincipal is also malformed; fail closed.

    Principal can be:
    - "*" (everyone)
    - {"AWS": "arn:aws:iam::123456789012:root"}
    - {"AWS": ["arn:aws:iam::123456789012:user/alice"]}
    - {"Service": "lambda.amazonaws.com"}
    - {"Federated": "arn:aws:iam::123456789012:saml-provider/..."}
    - {"CanonicalUser": "..."}
    """
    principal = statement.get("Principal")
    not_principal = statement.get("NotPrincipal")

    if principal and not_principal:
        LOG.warning(
            "Malformed resource policy statement: both Principal and "
            "NotPrincipal present (Sid=%r). Statement will not match.",
            statement.get("Sid"),
        )
        return False

    if not_principal:
        return not _principal_matches(not_principal, caller)

    if not principal:
        # Missing Principal on a resource-based policy does NOT implicitly
        # match all callers (unlike identity policies, where the Principal
        # element is disallowed and the statement applies to the attached
        # identity). A resource-policy statement must name its grantees.
        return False

    return _principal_matches(principal, caller)


def _principal_matches(principal, caller: CallerIdentity) -> bool:
    """Check if a principal specification matches a caller."""
    if principal == "*":
        return True

    if isinstance(principal, str):
        return _arn_or_account_matches(principal, caller)

    if isinstance(principal, dict):
        # Check AWS principals
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if _arn_or_account_matches(p, caller):
                return True

        # Check Service principals (for service-to-service)
        service_principals = principal.get("Service", [])
        if isinstance(service_principals, str):
            service_principals = [service_principals]
        # A bucket / KMS / SNS / SQS resource policy granting
        # ``Principal: {Service: lambda.amazonaws.com}`` matches a caller
        # whose role's trust policy authorizes ``lambda.amazonaws.com``
        # to assume it (see identity._trust_policy_services). This is
        # the AWS pattern for Lambda execution roles, EventBridge,
        # ECS task roles, and friends.
        acting = getattr(caller, "acting_services", []) or []
        if acting:
            for sp in service_principals:
                if sp in acting:
                    return True

        # Check Federated principals
        federated_principals = principal.get("Federated", [])
        if isinstance(federated_principals, str):
            federated_principals = [federated_principals]
        for fp in federated_principals:
            # Federated principal matches if the caller's ARN indicates
            # federation from that provider, or if provider matches
            if fp == "*":
                return True
            if caller.principal_type == "AssumedRole" and fp in (caller.arn or ""):
                return True

        # CanonicalUser is S3-specific; match by account ID
        canonical_user = principal.get("CanonicalUser", [])
        if isinstance(canonical_user, str):
            canonical_user = [canonical_user]
        for cu in canonical_user:
            if cu == caller.account_id:
                return True

    return False


def _arn_or_account_matches(principal_value: str, caller: CallerIdentity) -> bool:
    """Match a principal value (ARN or account ID) against a caller."""
    if principal_value == "*":
        return True

    # Account ID match
    if principal_value == caller.account_id:
        return True

    # ARN match
    if principal_value == caller.arn:
        return True

    # Root principal matches all users in the account
    if principal_value.endswith(":root"):
        account = principal_value.split(":")[4] if ":" in principal_value else ""
        if account == caller.account_id:
            return True

    return False
