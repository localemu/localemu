import abc
import fnmatch
import json
import logging

from moto.iam import iam_backends
from moto.iam.models import IAMBackend

from localemu.aws.api import RequestContext
from localemu.aws.api.iam import (
    ActionNameType,
    EvaluationResult,
    PolicyEvaluationDecisionType,
    ResourceNameType,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
)

LOG = logging.getLogger(__name__)


def _ensure_list(value) -> list:
    """Normalize a string-or-list field to always be a list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _matches_pattern(value: str, patterns: list[str]) -> bool:
    """Check if *value* matches any of the IAM-style patterns (supporting wildcards via fnmatch)."""
    value_lower = value.lower()
    for pattern in patterns:
        if fnmatch.fnmatch(value_lower, pattern.lower()):
            return True
    return False


class IAMPolicySimulator(abc.ABC):
    @abc.abstractmethod
    def simulate_principal_policy(
        self, context: RequestContext, request: SimulatePrincipalPolicyRequest
    ) -> SimulatePolicyResponse:
        """
        Simulate principal policy
        :param request: SimulatePrincipalPolicyRequest
        :param context: RequestContext
        :return: SimulatePrincipalResponse
        """
        pass


class BasicIAMPolicySimulator(IAMPolicySimulator):
    def simulate_principal_policy(
        self,
        context: RequestContext,
        request: SimulatePrincipalPolicyRequest,
    ) -> SimulatePolicyResponse:
        backend = self.get_iam_backend(context)
        policies = self.get_policies_from_principal(backend, request.get("PolicySourceArn"))

        def _get_statements_from_policy_list(_policies: list) -> list[dict]:
            statements = []
            for policy_item in _policies:
                # Handle None policy documents
                if policy_item is None:
                    continue
                # Handle both dict and string policy documents
                if isinstance(policy_item, dict):
                    policy_dict = policy_item
                elif isinstance(policy_item, str):
                    try:
                        policy_dict = json.loads(policy_item)
                    except (json.JSONDecodeError, TypeError):
                        LOG.warning("Failed to parse policy document: %s", policy_item)
                        continue
                else:
                    LOG.warning("Unexpected policy document type: %s", type(policy_item))
                    continue

                stmt = policy_dict.get("Statement")
                if stmt is None:
                    continue
                if isinstance(stmt, list):
                    statements.extend(stmt)
                else:
                    statements.append(stmt)
            return statements

        policy_statements = _get_statements_from_policy_list(policies)

        evaluations = [
            self.build_evaluation_result(action_name, resource_arn, policy_statements)
            for action_name in request.get("ActionNames")
            for resource_arn in request.get("ResourceArns")
        ]

        response = SimulatePolicyResponse()
        response["IsTruncated"] = False
        response["EvaluationResults"] = evaluations

        return response

    @staticmethod
    def build_evaluation_result(
        action_name: ActionNameType, resource_name: ResourceNameType, policy_statements: list[dict]
    ) -> EvaluationResult:
        eval_res = EvaluationResult()
        eval_res["EvalActionName"] = action_name
        eval_res["EvalResourceName"] = resource_name

        # Implement proper IAM evaluation logic:
        # 1. Default deny
        # 2. Check all statements for explicit deny first
        # 3. Then check for allows
        has_allow = False
        has_explicit_deny = False

        for statement in policy_statements:
            effect = statement.get("Effect", "")
            actions = statement.get("Action")
            not_actions = statement.get("NotAction")
            resources = statement.get("Resource")
            not_resources = statement.get("NotResource")

            # Determine if action matches
            action_matched = False
            if actions is not None:
                action_matched = _matches_pattern(action_name, _ensure_list(actions))
            elif not_actions is not None:
                # NotAction: matches if the action is NOT in the list
                action_matched = not _matches_pattern(action_name, _ensure_list(not_actions))

            if not action_matched:
                continue

            # Determine if resource matches
            resource_matched = False
            if resources is not None:
                resource_list = _ensure_list(resources)
                resource_matched = _matches_pattern(resource_name, resource_list)
            elif not_resources is not None:
                # NotResource: matches if the resource is NOT in the list
                resource_matched = not _matches_pattern(resource_name, _ensure_list(not_resources))

            if not resource_matched:
                continue

            # Both action and resource matched
            if effect == "Deny":
                has_explicit_deny = True
                break  # Explicit deny takes precedence, no need to continue
            elif effect == "Allow":
                has_allow = True

        if has_explicit_deny:
            eval_res["EvalDecision"] = PolicyEvaluationDecisionType.explicitDeny
        elif has_allow:
            eval_res["EvalDecision"] = PolicyEvaluationDecisionType.allowed
            eval_res["MatchedStatements"] = []  # TODO: add support for statement compilation.
        else:
            eval_res["EvalDecision"] = PolicyEvaluationDecisionType.implicitDeny

        return eval_res

    @staticmethod
    def get_iam_backend(context: RequestContext) -> IAMBackend:
        return iam_backends[context.account_id][context.partition]

    @staticmethod
    def get_policies_from_principal(backend: IAMBackend, principal_arn: str) -> list:
        policies = []
        if ":role" in principal_arn:
            role_name = principal_arn.split("/")[-1]

            # Do NOT include assume_role_policy_document - it's a trust policy, not an identity policy
            policy_names = backend.list_role_policies(role_name=role_name)
            policies.extend(
                [
                    backend.get_role_policy(role_name=role_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_role_policies(role_name=role_name)
            policies.extend([policy.document for policy in attached_policies])

        if ":group" in principal_arn:
            group_name = principal_arn.split("/")[-1]
            policy_names = backend.list_group_policies(group_name=group_name)
            policies.extend(
                [
                    backend.get_group_policy(group_name=group_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_group_policies(group_name=group_name)
            policies.extend([policy.document for policy in attached_policies])

        if ":user" in principal_arn:
            user_name = principal_arn.split("/")[-1]
            policy_names = backend.list_user_policies(user_name=user_name)
            policies.extend(
                [
                    backend.get_user_policy(user_name=user_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_user_policies(user_name=user_name)
            policies.extend([policy.document for policy in attached_policies])

        return policies
