"""IAM Policy Evaluation Engine.

Implements the AWS IAM policy evaluation algorithm as documented at:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

Evaluation order:
0. Organizations SCP Deny (anywhere in the account's OU ancestry) -> DENY
1. Explicit Deny in any policy -> DENY
2. Resource-based policy Allow (same account) -> ALLOW
3. Identity-based policy Allow -> required
4. Permission boundary Allow -> required (if set)
5. Session policy Allow -> required (if assumed role)
6. Default -> DENY
"""

import json
import logging
from enum import Enum

from localemu.utils.aws.policy import iter_policy_statements

from .action_matcher import matches_action
from .condition_evaluator import matches_conditions
from .identity import CallerIdentity, get_identity_policies, get_permission_boundary, get_session_policies
from .resource_matcher import matches_resource

LOG = logging.getLogger(__name__)


def _scp_denies(account_id: str, action: str, resource: str, conditions: dict) -> bool:
    """True if a Service Control Policy attached anywhere in this account's
    Organizations ancestry (the account itself, its OU(s), or the root)
    explicitly denies this action.

    SCPs only ever restrict, never grant - an Allow statement in an SCP is
    not consulted here, only Deny. This covers the common, AWS-documented
    pattern ("deny this action account-wide unless the caller matches a
    condition") without implementing the rarer Allow-list-intersection
    semantics (an SCP that only explicitly allows a subset of actions
    implicitly denying the rest) - no attached SCP replacing the default
    FullAWSAccess policy is assumed to intend that stricter behaviour here.
    """
    try:
        from moto.organizations import organizations_backends

        for backend in dict(organizations_backends).values():
            ob = backend.get("aws") if isinstance(backend, dict) else backend
            if getattr(ob, "org", None) is None:
                continue
            account = next((a for a in ob.accounts if a.id == account_id), None)
            if account is None:
                continue

            attached = list(account.attached_policies)
            node_id = account.parent_id
            seen_ids = set()
            while node_id and node_id not in seen_ids:
                seen_ids.add(node_id)
                node = next((o for o in ob.ou if o.id == node_id), None)
                if node is None:
                    break
                attached.extend(node.attached_policies)
                node_id = getattr(node, "parent_id", None)

            for policy in attached:
                if getattr(policy, "type", "") != "SERVICE_CONTROL_POLICY":
                    continue
                try:
                    doc = json.loads(policy.content)
                except Exception:
                    continue
                for statement in iter_policy_statements(doc):
                    if statement.get("Effect") != "Deny":
                        continue
                    if not matches_action(statement, action):
                        continue
                    if not matches_resource(statement, resource, conditions):
                        continue
                    if not matches_conditions(statement, conditions):
                        continue
                    return True
            return False  # this account belongs to this org; no need to check others
    except Exception:
        LOG.debug("SCP evaluation failed for account %s", account_id, exc_info=True)
    return False


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
        endpoint_policy: dict | None = None,
    ) -> Decision:
        """Evaluate whether a caller is allowed to perform an action on a resource.

        Args:
            caller: The resolved caller identity
            action: The API action (e.g., "s3:PutObject")
            resource: The resource ARN
            conditions: Request context for condition evaluation
            resource_policy: Optional resource-based policy (e.g., S3 bucket policy)
            endpoint_policy: The policy attached to the VPC endpoint the request
                arrived through, if any. Per AWS's documented evaluation logic
                for VPC endpoints, this is an independent AND-gate: an explicit
                Deny here denies regardless of identity/resource policy, and an
                Allow here is REQUIRED in addition to (never instead of) the
                identity/resource-policy Allow - it never grants access on its
                own. Pass None (the default) for requests that did not arrive
                through a VPC endpoint, which reproduces pre-existing behavior
                exactly.

        Returns:
            Decision.ALLOW or Decision.EXPLICIT_DENY or Decision.IMPLICIT_DENY
        """
        def _record(decision: Decision, reason: str, source: str | None = None, statement: dict | None = None) -> Decision:
            from localemu.services.iam_enforcement.decision_log import record_decision

            try:
                record_decision(
                    decision=decision.value,
                    principal_arn=caller.arn,
                    account_id=caller.account_id,
                    action=action,
                    resource=resource,
                    reason=reason,
                    source=source,
                    statement=statement,
                )
            except Exception:
                LOG.debug("Failed to record IAM decision log entry", exc_info=True)
            return decision

        # Root account bypasses all checks
        if caller.principal_type == "Root":
            return _record(Decision.ALLOW, "root account bypasses all checks")

        # Merge caller tags into conditions
        merged_conditions = {**conditions, **caller.tags}

        # Step 0: Organizations SCP Deny - restricts every identity in the
        # account (including ones with a broad identity-policy Allow),
        # checked before anything that could grant access.
        if _scp_denies(caller.account_id, action, resource, merged_conditions):
            LOG.debug(
                "IAM: SCP deny for %s on %s (action=%s) source=scp",
                caller.arn, resource, action,
            )
            return _record(Decision.EXPLICIT_DENY, "Organizations SCP deny", source="scp")

        # Gather policies
        identity_policies = get_identity_policies(caller)
        permission_boundary = get_permission_boundary(caller)

        # Step 1: Check ALL policies for explicit Deny - identity, resource,
        # boundary, AND the VPC endpoint policy. An endpoint policy is a
        # resource-shaped policy (it carries Principal), so it gets the same
        # Principal check as resource_policy; skipping that check here was
        # the gap that let an endpoint policy's explicit Deny fall through
        # unenforced to the implicit-deny path below, where the KMS-grant
        # override (in enforcer.py) could incorrectly turn it into an ALLOW.
        all_policies = list(identity_policies)
        if resource_policy:
            all_policies.append(resource_policy)
        if permission_boundary:
            all_policies.append(permission_boundary)
        if endpoint_policy:
            all_policies.append(endpoint_policy)

        for policy in all_policies:
            for statement in iter_policy_statements(policy):
                if statement.get("Effect") != "Deny":
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                # For resource-shaped policies, also check Principal
                if policy in (resource_policy, endpoint_policy) and not _matches_principal(statement, caller):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                if policy is resource_policy:
                    deny_source = "resource"
                elif policy is endpoint_policy:
                    deny_source = "endpoint"
                else:
                    deny_source = "identity"
                LOG.debug(
                    "IAM: explicit deny for %s on %s (action=%s) source=%s statement=%s",
                    caller.arn, resource, action, deny_source, _fmt_statement(statement),
                )
                return _record(
                    Decision.EXPLICIT_DENY, "explicit Deny statement matched",
                    source=deny_source, statement=statement,
                )

        # Step 1.5: VPC endpoint policy Allow is an independent AND-gate, not
        # an alternate OR-path like the resource-policy step below. It must
        # be checked before Step 2 can short-circuit to ALLOW on a resource-
        # policy match, since "resource policy says yes" must not bypass
        # "the endpoint this request arrived through says no". moto defaults
        # every VPC endpoint to an Allow-all policy, so this is a no-op for
        # every endpoint that hasn't had a custom policy attached.
        if endpoint_policy is not None:
            endpoint_allow = False
            for statement in iter_policy_statements(endpoint_policy):
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
                endpoint_allow = True
                break
            if not endpoint_allow:
                LOG.debug(
                    "IAM: denied by VPC endpoint policy for %s on %s (action=%s)",
                    caller.arn, resource, action,
                )
                return _record(
                    Decision.IMPLICIT_DENY, "VPC endpoint policy does not allow", source="endpoint",
                )

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
        #
        # KMS exception: unlike every other resource policy, a KMS key
        # policy statement that grants only the ACCOUNT ROOT is documented
        # by AWS as "enables IAM policies in the account to grant access" -
        # it does NOT, by itself, grant the action the way a specific
        # principal (or a bucket/queue/topic policy's root grant) does.
        # Every key gets this default root statement, so without this,
        # ANY key policy would make the OR-logic above grant kms:* to every
        # principal in the account regardless of their own IAM policy.
        require_specific_principal = action.startswith("kms:")
        if resource_policy:
            for statement in iter_policy_statements(resource_policy):
                if statement.get("Effect") != "Allow":
                    continue
                if not _matches_principal(statement, caller, require_specific_principal):
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                LOG.debug(
                    "IAM: allowed by resource policy for %s on %s (action=%s) statement=%s",
                    caller.arn, resource, action, _fmt_statement(statement),
                )
                return _record(
                    Decision.ALLOW, "resource-policy Allow statement matched",
                    source="resource", statement=statement,
                )

        # Step 3: Check identity-based policies for Allow
        identity_allow = False
        matched_statement = None
        for policy in identity_policies:
            for statement in iter_policy_statements(policy):
                if statement.get("Effect") != "Allow":
                    continue
                if not matches_action(statement, action):
                    continue
                if not matches_resource(statement, resource, merged_conditions):
                    continue
                if not matches_conditions(statement, merged_conditions):
                    continue
                identity_allow = True
                matched_statement = statement
                break
            if identity_allow:
                break

        if not identity_allow:
            LOG.debug(
                "IAM: implicit deny (no identity policy allows) for %s on %s (action=%s)",
                caller.arn, resource, action,
            )
            return _record(Decision.IMPLICIT_DENY, "no identity policy statement allows this action")

        LOG.debug(
            "IAM: identity policy allows %s on %s (action=%s), pending boundary/session "
            "checks, statement=%s",
            caller.arn, resource, action, _fmt_statement(matched_statement),
        )

        # Step 4: Check permission boundary (if present)
        if permission_boundary:
            boundary_allow = False
            for statement in iter_policy_statements(permission_boundary):
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
                return _record(Decision.IMPLICIT_DENY, "permission boundary does not allow", source="boundary")

        # Step 5: Check session policies (for assumed roles)
        if caller.principal_type in ("AssumedRole", "FederatedUser"):
            session_policies = get_session_policies(caller)
            if session_policies:
                session_allow = False
                for policy in session_policies:
                    for statement in iter_policy_statements(policy):
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
                    return _record(Decision.IMPLICIT_DENY, "session policy does not allow", source="session")

        LOG.debug("IAM: final decision ALLOW for %s on %s (action=%s)", caller.arn, resource, action)
        return _record(
            Decision.ALLOW, "identity policy Allow (boundary/session checks passed)",
            source="identity", statement=matched_statement,
        )


def _fmt_statement(statement: dict | None) -> str:
    """Compact JSON for the per-request decision log - the DEBUG-gated
    logging showed the reason, caller, action and resource, but not the
    actual policy statement that decided it."""
    if statement is None:
        return "?"
    try:
        return json.dumps(statement, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(statement)


def _matches_principal(statement: dict, caller: CallerIdentity, require_specific: bool = False) -> bool:
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

    ``require_specific``: see ``_arn_or_account_matches``.
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
        return not _principal_matches(not_principal, caller, require_specific)

    if not principal:
        # Missing Principal on a resource-based policy does NOT implicitly
        # match all callers (unlike identity policies, where the Principal
        # element is disallowed and the statement applies to the attached
        # identity). A resource-policy statement must name its grantees.
        return False

    return _principal_matches(principal, caller, require_specific)


def _principal_matches(principal, caller: CallerIdentity, require_specific: bool = False) -> bool:
    """Check if a principal specification matches a caller."""
    if principal == "*":
        return not require_specific

    if isinstance(principal, str):
        return _arn_or_account_matches(principal, caller, require_specific)

    if isinstance(principal, dict):
        # Check AWS principals
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if _arn_or_account_matches(p, caller, require_specific):
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


def _arn_or_account_matches(
    principal_value: str, caller: CallerIdentity, require_specific: bool = False
) -> bool:
    """Match a principal value (ARN or account ID) against a caller.

    ``require_specific``, when set, rejects the "whole account" forms
    (``"*"``, a bare account id, or the ``:root`` ARN) and only matches an
    exact ARN - see ``matches_resource_policy_principal_strictly`` for why.
    """
    # ARN match - always allowed, even when require_specific
    if principal_value == caller.arn:
        return True

    if require_specific:
        return False

    if principal_value == "*":
        return True

    # Account ID match
    if principal_value == caller.account_id:
        return True

    # Root principal matches all users in the account
    if principal_value.endswith(":root"):
        account = principal_value.split(":")[4] if ":" in principal_value else ""
        if account == caller.account_id:
            return True

    return False
