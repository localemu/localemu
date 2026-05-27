import json
import logging
import re
import secrets
import string
import threading
import uuid
from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import quote

from moto.iam.models import (
    IAMBackend,
    filter_items_with_path_prefix,
    iam_backends,
)
from moto.iam.models import Role as MotoRole
from moto.iam.models import User as MotoUser
from moto.iam.utils import generate_access_key_id_from_account_id

from localemu.aws.api import CommonServiceException, RequestContext, handler
from localemu.aws.api.iam import (
    AttachedPermissionsBoundary,
    CreateRoleRequest,
    CreateRoleResponse,
    CreateServiceLinkedRoleResponse,
    CreateServiceSpecificCredentialResponse,
    CreateUserResponse,
    DeleteConflictException,
    DeleteServiceLinkedRoleResponse,
    DeletionTaskIdType,
    DeletionTaskStatusType,
    GetServiceLinkedRoleDeletionStatusResponse,
    GetUserResponse,
    IamApi,
    InvalidInputException,
    ListInstanceProfileTagsResponse,
    ListRolesResponse,
    ListServiceSpecificCredentialsResponse,
    MalformedPolicyDocumentException,
    NoSuchEntityException,
    ResetServiceSpecificCredentialResponse,
    Role,
    ServiceSpecificCredential,
    ServiceSpecificCredentialMetadata,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
    User,
    allUsers,
    arnType,
    credentialAgeDays,
    customSuffixType,
    existingUserNameType,
    groupNameType,
    instanceProfileNameType,
    markerType,
    maxItemsType,
    pathPrefixType,
    pathType,
    roleDescriptionType,
    roleNameType,
    serviceName,
    serviceSpecificCredentialId,
    statusType,
    tagKeyListType,
    tagListType,
    userNameType,
)
from localemu.aws.connect import connect_to
from localemu.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localemu.services.iam.iam_patches import apply_iam_patches
from localemu.services.iam.resources.policy_simulator import (
    BasicIAMPolicySimulator,
    IAMPolicySimulator,
)
from localemu.services.iam.resources.service_linked_roles import SERVICE_LINKED_ROLES
from localemu.services.moto import call_moto
from localemu.state import StateVisitor
from localemu.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)

SERVICE_LINKED_ROLE_PATH_PREFIX = "/aws-service-role"

POLICY_ARN_REGEX = re.compile(r"arn:(?:aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b):iam::(?:\d{12}|aws):policy/.+")

CREDENTIAL_ID_REGEX = re.compile(r"^\w+$")

# L-03: IAM username validation per AWS spec: alphanumeric plus +=,.@_-
USERNAME_REGEX = re.compile(r"^[\w+=,.@-]{1,128}$")

T = TypeVar("T")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class ValidationListError(ValidationError):
    def __init__(self, validation_errors: list[str]):
        message = f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {'; '.join(validation_errors)}"
        super().__init__(message)


def get_iam_backend(context: RequestContext) -> IAMBackend:
    return iam_backends[context.account_id][context.partition]


class IamProvider(IamApi):
    policy_simulator: IAMPolicySimulator

    def __init__(self):
        apply_iam_patches()
        self.policy_simulator = BasicIAMPolicySimulator()
        # Lock for thread-safe mutation of service_specific_credentials
        self._credential_lock = threading.Lock()
        # Lock for thread-safe Moto backend dictionary iterations
        self._backend_lock = threading.RLock()

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(iam_backends)

    @handler("CreateRole", expand=False)
    def create_role(
        self, context: RequestContext, request: CreateRoleRequest
    ) -> CreateRoleResponse:
        try:
            json.loads(request["AssumeRolePolicyDocument"])
        except json.JSONDecodeError:
            raise MalformedPolicyDocumentException("This policy contains invalid Json")
        result = call_moto(context)

        if not request.get("MaxSessionDuration") and result["Role"].get("MaxSessionDuration"):
            result["Role"].pop("MaxSessionDuration")

        if "RoleLastUsed" in result["Role"] and not result["Role"]["RoleLastUsed"]:
            # not part of the AWS response if it's empty
            # FIXME: RoleLastUsed did not seem well supported when this check was added
            result["Role"].pop("RoleLastUsed")

        return result

    @handler("SimulatePrincipalPolicy", expand=False)
    def simulate_principal_policy(
        self,
        context: RequestContext,
        request: SimulatePrincipalPolicyRequest,
        **kwargs,
    ) -> SimulatePolicyResponse:
        return self.policy_simulator.simulate_principal_policy(context, request)

    def delete_policy(self, context: RequestContext, policy_arn: arnType, **kwargs) -> None:
        backend = get_iam_backend(context)
        policy = backend.managed_policies.get(policy_arn)
        if not policy:
            raise NoSuchEntityException(f"Policy {policy_arn} was not found.")
        # Check attachment count before deletion
        if policy.attachment_count > 0:
            raise DeleteConflictException(
                "Cannot delete a policy attached to entities."
            )
        # Check for non-default policy versions
        if hasattr(policy, "versions") and len(policy.versions) > 1:
            raise DeleteConflictException(
                "Cannot delete a policy that has non-default versions. "
                "Delete the non-default versions first."
            )
        backend.managed_policies.pop(policy_arn, None)

    def detach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        backend = get_iam_backend(context)
        try:
            role = backend.get_role(role_name)
            policy = role.managed_policies[policy_arn]
            policy.detach_from(role)
        except KeyError:
            raise NoSuchEntityException(f"Policy {policy_arn} was not found.")

    @staticmethod
    def moto_role_to_role_type(moto_role: MotoRole) -> Role:
        role = Role()
        role["Path"] = moto_role.path
        role["RoleName"] = moto_role.name
        role["RoleId"] = moto_role.id
        role["Arn"] = moto_role.arn
        role["CreateDate"] = moto_role.create_date
        if moto_role.assume_role_policy_document:
            role["AssumeRolePolicyDocument"] = moto_role.assume_role_policy_document
        if moto_role.description:
            role["Description"] = moto_role.description
        if moto_role.max_session_duration:
            role["MaxSessionDuration"] = moto_role.max_session_duration
        if moto_role.permissions_boundary:
            role["PermissionsBoundary"] = moto_role.permissions_boundary
        if moto_role.tags:
            role["Tags"] = moto_role.tags
        # role["RoleLastUsed"]: # TODO: add support
        return role

    def list_roles(
        self,
        context: RequestContext,
        path_prefix: pathPrefixType = None,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListRolesResponse:
        backend = get_iam_backend(context)
        # Protect Moto backend dictionary iteration with lock
        with self._backend_lock:
            moto_roles = list(backend.roles.values())
        if path_prefix:
            moto_roles = filter_items_with_path_prefix(path_prefix, moto_roles)
        moto_roles = sorted(moto_roles, key=lambda role: role.id)

        # Implement proper pagination with marker and max_items
        start_index = 0
        if marker:
            for i, role in enumerate(moto_roles):
                if role.id == marker:
                    start_index = i + 1
                    break

        limit = max_items if max_items else len(moto_roles)
        paginated_roles = moto_roles[start_index : start_index + limit]
        is_truncated = (start_index + limit) < len(moto_roles)

        response_roles = []
        for moto_role in paginated_roles:
            response_role = self.moto_role_to_role_type(moto_role)
            # Permission boundary and Tags should not be a part of the response
            response_role.pop("PermissionsBoundary", None)
            response_role.pop("Tags", None)
            response_roles.append(response_role)
            # L-04: Always URL-encode the trust policy document for consistency
            response_role["AssumeRolePolicyDocument"] = quote(
                json.dumps(moto_role.assume_role_policy_document or {})
            )

        result = ListRolesResponse(Roles=response_roles, IsTruncated=is_truncated)
        if is_truncated:
            result["Marker"] = moto_roles[start_index + limit].id
        return result

    def update_group(
        self,
        context: RequestContext,
        group_name: groupNameType,
        new_path: pathType = None,
        new_group_name: groupNameType = None,
        **kwargs,
    ) -> None:
        new_group_name = new_group_name or group_name
        backend = get_iam_backend(context)
        group = backend.get_group(group_name)
        # Only update path if new_path is explicitly provided
        if new_path is not None:
            group.path = new_path
        group.name = new_group_name
        backend.groups[new_group_name] = backend.groups.pop(group_name)

    def list_instance_profile_tags(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        marker: markerType = None,
        max_items: maxItemsType = None,
        **kwargs,
    ) -> ListInstanceProfileTagsResponse:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        response = ListInstanceProfileTagsResponse()
        response["Tags"] = profile.tags
        return response

    def tag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tags: tagListType,
        **kwargs,
    ) -> None:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        new_keys = [tag["Key"] for tag in tags]
        updated_tags = [tag for tag in profile.tags if tag["Key"] not in new_keys]
        updated_tags.extend(tags)
        profile.tags = updated_tags

    def untag_instance_profile(
        self,
        context: RequestContext,
        instance_profile_name: instanceProfileNameType,
        tag_keys: tagKeyListType,
        **kwargs,
    ) -> None:
        backend = get_iam_backend(context)
        profile = backend.get_instance_profile(instance_profile_name)
        profile.tags = [tag for tag in profile.tags if tag["Key"] not in tag_keys]

    def create_service_linked_role(
        self,
        context: RequestContext,
        aws_service_name: groupNameType,
        description: roleDescriptionType = None,
        custom_suffix: customSuffixType = None,
        **kwargs,
    ) -> CreateServiceLinkedRoleResponse:
        policy_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": aws_service_name},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )
        service_role_data = SERVICE_LINKED_ROLES.get(aws_service_name)

        path = f"{SERVICE_LINKED_ROLE_PATH_PREFIX}/{aws_service_name}/"
        if service_role_data:
            if custom_suffix and not service_role_data["suffix_allowed"]:
                raise InvalidInputException(f"Custom suffix is not allowed for {aws_service_name}")
            role_name = service_role_data.get("role_name")
            attached_policies = service_role_data["attached_policies"]
        else:
            # Use title-case on the first segment for proper service name formatting
            # capitalize() lowercases the rest of the string, title() preserves it better
            service_prefix = aws_service_name.split(".")[0]
            role_name = f"AWSServiceRoleFor{service_prefix[0].upper()}{service_prefix[1:]}"
            attached_policies = []
        if custom_suffix:
            role_name = f"{role_name}_{custom_suffix}"
        backend = get_iam_backend(context)

        # check for role duplicates
        for role in backend.roles.values():
            if role.name == role_name:
                raise InvalidInputException(
                    f"Service role name {role_name} has been taken in this account, please try a different suffix."
                )

        role = backend.create_role(
            role_name=role_name,
            assume_role_policy_document=policy_doc,
            path=path,
            permissions_boundary="",
            description=description,
            tags={},
            max_session_duration=3600,
            linked_service=aws_service_name,
        )
        # attach policies
        for policy in attached_policies:
            try:
                backend.attach_role_policy(policy, role_name)
            except Exception as e:
                LOG.warning(
                    "Policy %s for service linked role %s does not exist: %s",
                    policy,
                    aws_service_name,
                    e,
                )

        res_role = self.moto_role_to_role_type(role)
        return CreateServiceLinkedRoleResponse(Role=res_role)

    def delete_service_linked_role(
        self, context: RequestContext, role_name: roleNameType, **kwargs
    ) -> DeleteServiceLinkedRoleResponse:
        backend = get_iam_backend(context)
        role = backend.get_role(role_name=role_name)
        role.managed_policies.clear()
        backend.delete_role(role_name)
        return DeleteServiceLinkedRoleResponse(
            DeletionTaskId=f"task{role.path}{role.name}/{uuid.uuid4()}"
        )

    def get_service_linked_role_deletion_status(
        self, context: RequestContext, deletion_task_id: DeletionTaskIdType, **kwargs
    ) -> GetServiceLinkedRoleDeletionStatusResponse:
        # L-02: Extract role name from task id and check if the role still exists
        # Task ID format: "task{path}{role_name}/{uuid}"
        backend = get_iam_backend(context)
        # Try to extract role name from the deletion task id
        try:
            # Task format: task/aws-service-role/{service}/{role_name}/{uuid}
            parts = deletion_task_id.split("/")
            if len(parts) >= 2:
                # The role name is the second-to-last segment before the UUID
                potential_role_name = parts[-2] if len(parts) >= 2 else None
                if potential_role_name and potential_role_name in backend.roles:
                    return GetServiceLinkedRoleDeletionStatusResponse(
                        Status=DeletionTaskStatusType.IN_PROGRESS
                    )
        except (IndexError, AttributeError):
            pass
        return GetServiceLinkedRoleDeletionStatusResponse(Status=DeletionTaskStatusType.SUCCEEDED)

    def put_user_permissions_boundary(
        self,
        context: RequestContext,
        user_name: userNameType,
        permissions_boundary: arnType,
        **kwargs,
    ) -> None:
        if user := get_iam_backend(context).users.get(user_name):
            user.permissions_boundary = permissions_boundary
        else:
            raise NoSuchEntityException()

    def delete_user_permissions_boundary(
        self, context: RequestContext, user_name: userNameType, **kwargs
    ) -> None:
        if user := get_iam_backend(context).users.get(user_name):
            if hasattr(user, "permissions_boundary"):
                delattr(user, "permissions_boundary")
        else:
            raise NoSuchEntityException()

    def create_user(
        self,
        context: RequestContext,
        user_name: userNameType,
        path: pathType = None,
        permissions_boundary: arnType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> CreateUserResponse:
        # L-03: Validate username format per AWS IAM spec
        if not USERNAME_REGEX.match(user_name):
            raise ValidationError(
                f"The specified value for userName is invalid. "
                f"It must contain only alphanumeric characters and/or the following: +=,.@_-"
            )
        response = call_moto(context=context)
        user = get_iam_backend(context).get_user(user_name)
        if permissions_boundary:
            user.permissions_boundary = permissions_boundary
            response["User"]["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=permissions_boundary,
                PermissionsBoundaryType="Policy",
            )
        return response

    # Cache STS clients keyed by (region, access_key_id) to avoid re-creating on every call
    _sts_client_cache: dict[tuple, Any] = {}
    _sts_cache_lock = threading.Lock()

    def _get_sts_client(self, region: str, access_key_id: str):
        """Return a cached STS client for the given region and access key."""
        cache_key = (region, access_key_id)
        with self._sts_cache_lock:
            client = self._sts_client_cache.get(cache_key)
            if client is None:
                client = connect_to(
                    region_name=region,
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                ).sts
                self._sts_client_cache[cache_key] = client
            return client

    def get_user(
        self, context: RequestContext, user_name: existingUserNameType = None, **kwargs
    ) -> GetUserResponse:
        response = call_moto(context=context)
        moto_user_name = response["User"]["UserName"]
        moto_user = get_iam_backend(context).users.get(moto_user_name)
        # if the user does not exist or is no user
        if not moto_user and not user_name:
            access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
            # Use cached STS client
            sts_client = self._get_sts_client(context.region, access_key_id)
            caller_identity = sts_client.get_caller_identity()
            caller_arn = caller_identity["Arn"]
            if caller_arn.endswith(":root"):
                return GetUserResponse(
                    User=User(
                        UserId=context.account_id,
                        Arn=caller_arn,
                        CreateDate=datetime.now(),
                        PasswordLastUsed=datetime.now(),
                    )
                )
            else:
                raise CommonServiceException(
                    "ValidationError",
                    "Must specify userName when calling with non-User credentials",
                )

        if hasattr(moto_user, "permissions_boundary") and moto_user.permissions_boundary:
            response["User"]["PermissionsBoundary"] = AttachedPermissionsBoundary(
                PermissionsBoundaryArn=moto_user.permissions_boundary,
                PermissionsBoundaryType="Policy",
            )

        return response

    def delete_user(
        self, context: RequestContext, user_name: existingUserNameType, **kwargs
    ) -> None:
        backend = get_iam_backend(context)
        moto_user = backend.users.get(user_name)
        if not moto_user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
        # Check ALL dependencies before deletion, not just service_specific_credentials
        if moto_user.service_specific_credentials:
            raise DeleteConflictException(
                "Cannot delete entity, must remove service specific credentials first."
            )
        if moto_user.managed_policies:
            raise DeleteConflictException(
                "Cannot delete entity, must detach all policies first."
            )
        if moto_user.policies:
            raise DeleteConflictException(
                "Cannot delete entity, must delete all inline policies first."
            )
        if moto_user.access_keys:
            raise DeleteConflictException(
                "Cannot delete entity, must delete all access keys first."
            )
        if hasattr(moto_user, "signing_certificates") and moto_user.signing_certificates:
            raise DeleteConflictException(
                "Cannot delete entity, must delete all signing certificates first."
            )
        if hasattr(moto_user, "mfa_devices") and moto_user.mfa_devices:
            raise DeleteConflictException(
                "Cannot delete entity, must remove all MFA devices first."
            )
        return call_moto(context=context)

    def attach_role_policy(
        self, context: RequestContext, role_name: roleNameType, policy_arn: arnType, **kwargs
    ) -> None:
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError("Invalid ARN:  Could not be parsed!")
        return call_moto(context=context)

    def attach_user_policy(
        self, context: RequestContext, user_name: userNameType, policy_arn: arnType, **kwargs
    ) -> None:
        if not POLICY_ARN_REGEX.match(policy_arn):
            raise ValidationError("Invalid ARN:  Could not be parsed!")
        return call_moto(context=context)

    # ------------------------------ Service specific credentials ------------------------------ #

    def _get_user_or_raise_error(self, user_name: str, context: RequestContext) -> MotoUser:
        """
        Return the moto user from the store, or raise the proper exception if no user can be found.

        :param user_name: Username to find
        :param context: Request context
        :return: A moto user object
        """
        moto_user = get_iam_backend(context).users.get(user_name)
        if not moto_user:
            raise NoSuchEntityException(f"The user with name {user_name} cannot be found.")
        return moto_user

    def _validate_service_name(self, service_name: str) -> None:
        """
        Validate if the service provided is supported.

        :param service_name: Service name to check
        """
        if service_name not in ["codecommit.amazonaws.com", "cassandra.amazonaws.com"]:
            raise NoSuchEntityException(
                f"No such service {service_name} is supported for Service Specific Credentials"
            )

    def _validate_credential_id(self, credential_id: str) -> None:
        """
        Validate if the credential id is correctly formed.

        :param credential_id: Credential ID to check
        """
        if not CREDENTIAL_ID_REGEX.match(credential_id):
            raise ValidationListError(
                [
                    "Value at 'serviceSpecificCredentialId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w]+"
                ]
            )

    def _generate_service_password(self):
        """
        Generate a new service password for a service specific credential.

        :return: 60 letter password ending in `=`
        """
        password_charset = string.ascii_letters + string.digits + "+/"
        # L-01: Use secrets for cryptographically secure password generation
        # password always ends in = for some reason - but it is not base64
        return "".join(secrets.choice(password_charset) for _ in range(59)) + "="

    def _generate_credential_id(self, context: RequestContext):
        """
        Generate a credential ID.
        Credentials have a similar structure as access key ids, and also contain the account id encoded in them.
        Example: `ACCAQAAAAAAAPBAFQJI5W` for account `000000000000`

        :param context: Request context (to extract account id)
        :return: New credential id.
        """
        return generate_access_key_id_from_account_id(
            context.account_id, prefix="ACCA", total_length=21
        )

    def _new_service_specific_credential(
        self, user_name: str, service_name: str, context: RequestContext
    ) -> ServiceSpecificCredential:
        """
        Create a new service specific credential for the given username and service.

        :param user_name: Username the credential will be assigned to.
        :param service_name: Service the credential will be used for.
        :param context: Request context, used to extract the account id.
        :return: New ServiceSpecificCredential
        """
        password = self._generate_service_password()
        credential_id = self._generate_credential_id(context)
        return ServiceSpecificCredential(
            CreateDate=datetime.now(),
            ServiceName=service_name,
            ServiceUserName=f"{user_name}-at-{context.account_id}",
            ServicePassword=password,
            ServiceSpecificCredentialId=credential_id,
            UserName=user_name,
            Status=statusType.Active,
        )

    def _find_credential_in_user_by_id(
        self, user_name: str, credential_id: str, context: RequestContext
    ) -> ServiceSpecificCredential:
        """
        Find a credential by a given username and id.
        Raises errors if the user or credential is not found.

        :param user_name: Username of the user the credential is assigned to.
        :param credential_id: Credential ID to check
        :param context: Request context (used to determine account and region)
        :return: Service specific credential
        """
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_credential_id(credential_id)
        matching_credentials = [
            cred
            for cred in moto_user.service_specific_credentials
            if cred["ServiceSpecificCredentialId"] == credential_id
        ]
        if not matching_credentials:
            raise NoSuchEntityException(f"No such credential {credential_id} exists")
        return matching_credentials[0]

    def _validate_status(self, status: str):
        """
        Validate if the status has an accepted value.
        Raises a ValidationError if the status is invalid.

        :param status: Status to check
        """
        try:
            statusType(status)
        except ValueError:
            raise ValidationListError(
                [
                    "Value at 'status' failed to satisfy constraint: Member must satisfy enum value set"
                ]
            )

    def build_dict_with_only_defined_keys(
        self, data: dict[str, Any], typed_dict_type: type[T]
    ) -> T:
        """
        Builds a dict with only the defined keys from a given typed dict.
        Filtering is only present on the first level.

        :param data: Dict to filter.
        :param typed_dict_type: TypedDict subtype containing the attributes allowed to be present in the return value
        :return: shallow copy of the data only containing the keys defined on typed_dict_type
        """
        # L-10: Use __annotations__ directly instead of inspect.get_annotations
        # which has edge cases with inheritance and evaluation
        key_set = typed_dict_type.__annotations__.keys()
        return {k: v for k, v in data.items() if k in key_set}

    def create_service_specific_credential(
        self,
        context: RequestContext,
        user_name: userNameType,
        service_name: serviceName,
        credential_age_days: credentialAgeDays | None = None,
        **kwargs,
    ) -> CreateServiceSpecificCredentialResponse:
        # TODO add support for credential_age_days
        moto_user = self._get_user_or_raise_error(user_name, context)
        self._validate_service_name(service_name)
        credential = self._new_service_specific_credential(user_name, service_name, context)
        # Thread-safe mutation of service_specific_credentials
        with self._credential_lock:
            moto_user.service_specific_credentials.append(credential)
        return CreateServiceSpecificCredentialResponse(ServiceSpecificCredential=credential)

    def list_service_specific_credentials(
        self,
        context: RequestContext,
        user_name: userNameType | None = None,
        service_name: serviceName | None = None,
        all_users: allUsers | None = None,
        marker: markerType | None = None,
        max_items: maxItemsType | None = None,
        **kwargs,
    ) -> ListServiceSpecificCredentialsResponse:
        # TODO add support for all_users, marker, max_items
        moto_user = self._get_user_or_raise_error(user_name, context)
        # Service_name is optional - only validate and filter if provided
        if service_name:
            self._validate_service_name(service_name)
            result = [
                self.build_dict_with_only_defined_keys(creds, ServiceSpecificCredentialMetadata)
                for creds in moto_user.service_specific_credentials
                if creds["ServiceName"] == service_name
            ]
        else:
            result = [
                self.build_dict_with_only_defined_keys(creds, ServiceSpecificCredentialMetadata)
                for creds in moto_user.service_specific_credentials
            ]
        return ListServiceSpecificCredentialsResponse(ServiceSpecificCredentials=result)

    def update_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        status: statusType,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        self._validate_status(status)

        credential = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        credential["Status"] = status

    def reset_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> ResetServiceSpecificCredentialResponse:
        credential = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        credential["ServicePassword"] = self._generate_service_password()
        return ResetServiceSpecificCredentialResponse(ServiceSpecificCredential=credential)

    def delete_service_specific_credential(
        self,
        context: RequestContext,
        service_specific_credential_id: serviceSpecificCredentialId,
        user_name: userNameType = None,
        **kwargs,
    ) -> None:
        moto_user = self._get_user_or_raise_error(user_name, context)
        credentials = self._find_credential_in_user_by_id(
            user_name, service_specific_credential_id, context
        )
        # Thread-safe mutation of service_specific_credentials
        with self._credential_lock:
            try:
                moto_user.service_specific_credentials.remove(credentials)
            except ValueError:
                raise NoSuchEntityException(
                    f"No such credential {service_specific_credential_id} exists"
                )
