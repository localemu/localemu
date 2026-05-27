from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict
from collections.abc import Iterable, Iterator

from localemu.aws.api import handler, RequestContext, ServiceException, ServiceRequest
MaxResults = int
_boolean = bool
_double = float
_integer = int
_integerMin5Max100 = int
_string = str
class AuthenticationStrategy(StrEnum):
    SIMPLE = "SIMPLE"
    LDAP = "LDAP"
    CONFIG_MANAGED = "CONFIG_MANAGED"

class BrokerState(StrEnum):
    CREATION_IN_PROGRESS = "CREATION_IN_PROGRESS"
    CREATION_FAILED = "CREATION_FAILED"
    DELETION_IN_PROGRESS = "DELETION_IN_PROGRESS"
    RUNNING = "RUNNING"
    REBOOT_IN_PROGRESS = "REBOOT_IN_PROGRESS"
    CRITICAL_ACTION_REQUIRED = "CRITICAL_ACTION_REQUIRED"
    REPLICA = "REPLICA"

class BrokerStorageType(StrEnum):
    EBS = "EBS"
    EFS = "EFS"

class ChangeType(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"

class DataReplicationMode(StrEnum):
    NONE = "NONE"
    CRDR = "CRDR"

class DayOfWeek(StrEnum):
    MONDAY = "MONDAY"
    TUESDAY = "TUESDAY"
    WEDNESDAY = "WEDNESDAY"
    THURSDAY = "THURSDAY"
    FRIDAY = "FRIDAY"
    SATURDAY = "SATURDAY"
    SUNDAY = "SUNDAY"

class DeploymentMode(StrEnum):
    SINGLE_INSTANCE = "SINGLE_INSTANCE"
    ACTIVE_STANDBY_MULTI_AZ = "ACTIVE_STANDBY_MULTI_AZ"
    CLUSTER_MULTI_AZ = "CLUSTER_MULTI_AZ"

class EngineType(StrEnum):
    ACTIVEMQ = "ACTIVEMQ"
    RABBITMQ = "RABBITMQ"

class PromoteMode(StrEnum):
    SWITCHOVER = "SWITCHOVER"
    FAILOVER = "FAILOVER"

class SanitizationWarningReason(StrEnum):
    DISALLOWED_ELEMENT_REMOVED = "DISALLOWED_ELEMENT_REMOVED"
    DISALLOWED_ATTRIBUTE_REMOVED = "DISALLOWED_ATTRIBUTE_REMOVED"
    INVALID_ATTRIBUTE_VALUE_REMOVED = "INVALID_ATTRIBUTE_VALUE_REMOVED"

class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400
    ErrorAttribute: _string | None

class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409
    ErrorAttribute: _string | None

class ForbiddenException(ServiceException):
    code: str = "ForbiddenException"
    sender_fault: bool = False
    status_code: int = 403
    ErrorAttribute: _string | None

class InternalServerErrorException(ServiceException):
    code: str = "InternalServerErrorException"
    sender_fault: bool = False
    status_code: int = 500
    ErrorAttribute: _string | None

class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404
    ErrorAttribute: _string | None

class UnauthorizedException(ServiceException):
    code: str = "UnauthorizedException"
    sender_fault: bool = False
    status_code: int = 401
    ErrorAttribute: _string | None

class ActionRequired(TypedDict, total=False):
    ActionRequiredCode: _string | None
    ActionRequiredInfo: _string | None

class AvailabilityZone(TypedDict, total=False):
    Name: _string | None

class EngineVersion(TypedDict, total=False):
    Name: _string | None

_listOfEngineVersion = list[EngineVersion]
class BrokerEngineType(TypedDict, total=False):
    EngineType: EngineType | None
    EngineVersions: _listOfEngineVersion | None

_listOfBrokerEngineType = list[BrokerEngineType]
class BrokerEngineTypeOutput(TypedDict, total=False):
    BrokerEngineTypes: _listOfBrokerEngineType | None
    MaxResults: _integerMin5Max100
    NextToken: _string | None

_listOf__string = list[_string]
class BrokerInstance(TypedDict, total=False):
    ConsoleURL: _string | None
    Endpoints: _listOf__string | None
    IpAddress: _string | None

_listOfDeploymentMode = list[DeploymentMode]
_listOfAvailabilityZone = list[AvailabilityZone]
class BrokerInstanceOption(TypedDict, total=False):
    AvailabilityZones: _listOfAvailabilityZone | None
    EngineType: EngineType | None
    HostInstanceType: _string | None
    StorageType: BrokerStorageType | None
    SupportedDeploymentModes: _listOfDeploymentMode | None
    SupportedEngineVersions: _listOf__string | None

_listOfBrokerInstanceOption = list[BrokerInstanceOption]
class BrokerInstanceOptionsOutput(TypedDict, total=False):
    BrokerInstanceOptions: _listOfBrokerInstanceOption | None
    MaxResults: _integerMin5Max100
    NextToken: _string | None

_timestampIso8601 = datetime
class BrokerSummary(TypedDict, total=False):
    BrokerArn: _string | None
    BrokerId: _string | None
    BrokerName: _string | None
    BrokerState: BrokerState | None
    Created: _timestampIso8601 | None
    DeploymentMode: DeploymentMode
    EngineType: EngineType
    HostInstanceType: _string | None

_mapOf__string = dict[_string, _string]
class ConfigurationRevision(TypedDict, total=False):
    Created: _timestampIso8601
    Description: _string | None
    Revision: _integer

class Configuration(TypedDict, total=False):
    Arn: _string
    AuthenticationStrategy: AuthenticationStrategy
    Created: _timestampIso8601
    Description: _string
    EngineType: EngineType
    EngineVersion: _string
    Id: _string
    LatestRevision: ConfigurationRevision
    Name: _string
    Tags: _mapOf__string | None

class ConfigurationId(TypedDict, total=False):
    Id: _string
    Revision: _integer | None

_listOfConfigurationId = list[ConfigurationId]
class Configurations(TypedDict, total=False):
    Current: ConfigurationId | None
    History: _listOfConfigurationId | None
    Pending: ConfigurationId | None

class User(TypedDict, total=False):
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Password: _string
    Username: _string
    ReplicationUser: _boolean | None

_listOfUser = list[User]
class WeeklyStartTime(TypedDict, total=False):
    DayOfWeek: DayOfWeek
    TimeOfDay: _string
    TimeZone: _string | None

class Logs(TypedDict, total=False):
    Audit: _boolean | None
    General: _boolean | None

class LdapServerMetadataInput(TypedDict, total=False):
    Hosts: _listOf__string
    RoleBase: _string
    RoleName: _string | None
    RoleSearchMatching: _string
    RoleSearchSubtree: _boolean | None
    ServiceAccountPassword: _string
    ServiceAccountUsername: _string
    UserBase: _string
    UserRoleName: _string | None
    UserSearchMatching: _string
    UserSearchSubtree: _boolean | None

class EncryptionOptions(TypedDict, total=False):
    KmsKeyId: _string | None
    UseAwsOwnedKey: _boolean

class CreateBrokerInput(TypedDict, total=False):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerName: _string
    Configuration: ConfigurationId | None
    CreatorRequestId: _string | None
    DeploymentMode: DeploymentMode
    DataReplicationMode: DataReplicationMode | None
    DataReplicationPrimaryBrokerArn: _string | None
    EncryptionOptions: EncryptionOptions | None
    EngineType: EngineType
    EngineVersion: _string | None
    HostInstanceType: _string
    LdapServerMetadata: LdapServerMetadataInput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    PubliclyAccessible: _boolean
    SecurityGroups: _listOf__string | None
    StorageType: BrokerStorageType | None
    SubnetIds: _listOf__string | None
    Tags: _mapOf__string | None
    Users: _listOfUser | None

class CreateBrokerOutput(TypedDict, total=False):
    BrokerArn: _string | None
    BrokerId: _string | None

class CreateBrokerRequest(ServiceRequest):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerName: _string
    Configuration: ConfigurationId | None
    CreatorRequestId: _string | None
    DeploymentMode: DeploymentMode
    EncryptionOptions: EncryptionOptions | None
    EngineType: EngineType
    EngineVersion: _string | None
    HostInstanceType: _string
    LdapServerMetadata: LdapServerMetadataInput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    PubliclyAccessible: _boolean
    SecurityGroups: _listOf__string | None
    StorageType: BrokerStorageType | None
    SubnetIds: _listOf__string | None
    Tags: _mapOf__string | None
    Users: _listOfUser | None
    DataReplicationMode: DataReplicationMode | None
    DataReplicationPrimaryBrokerArn: _string | None

class CreateBrokerResponse(TypedDict, total=False):
    BrokerArn: _string | None
    BrokerId: _string | None

class CreateConfigurationInput(TypedDict, total=False):
    AuthenticationStrategy: AuthenticationStrategy | None
    EngineType: EngineType
    EngineVersion: _string | None
    Name: _string
    Tags: _mapOf__string | None

class CreateConfigurationOutput(TypedDict, total=False):
    Arn: _string
    AuthenticationStrategy: AuthenticationStrategy
    Created: _timestampIso8601
    Id: _string
    LatestRevision: ConfigurationRevision | None
    Name: _string

class CreateConfigurationRequest(ServiceRequest):
    AuthenticationStrategy: AuthenticationStrategy | None
    EngineType: EngineType
    EngineVersion: _string | None
    Name: _string
    Tags: _mapOf__string | None

class CreateConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    AuthenticationStrategy: AuthenticationStrategy | None
    Created: _timestampIso8601 | None
    Id: _string | None
    LatestRevision: ConfigurationRevision | None
    Name: _string | None

class CreateTagsRequest(ServiceRequest):
    ResourceArn: _string
    Tags: _mapOf__string | None

class CreateUserInput(TypedDict, total=False):
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Password: _string
    ReplicationUser: _boolean | None

class CreateUserRequest(ServiceRequest):
    BrokerId: _string
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Password: _string
    Username: _string
    ReplicationUser: _boolean | None

class CreateUserResponse(TypedDict, total=False):
    pass

class DataReplicationCounterpart(TypedDict, total=False):
    BrokerId: _string
    Region: _string

class DataReplicationMetadataOutput(TypedDict, total=False):
    DataReplicationCounterpart: DataReplicationCounterpart | None
    DataReplicationRole: _string

class DeleteBrokerOutput(TypedDict, total=False):
    BrokerId: _string | None

class DeleteBrokerRequest(ServiceRequest):
    BrokerId: _string

class DeleteBrokerResponse(TypedDict, total=False):
    BrokerId: _string | None

class DeleteConfigurationOutput(TypedDict, total=False):
    ConfigurationId: _string | None

class DeleteConfigurationRequest(ServiceRequest):
    ConfigurationId: _string

class DeleteConfigurationResponse(TypedDict, total=False):
    ConfigurationId: _string | None

class DeleteTagsRequest(ServiceRequest):
    ResourceArn: _string
    TagKeys: _listOf__string

class DeleteUserRequest(ServiceRequest):
    BrokerId: _string
    Username: _string

class DeleteUserResponse(TypedDict, total=False):
    pass

class DescribeBrokerEngineTypesRequest(ServiceRequest):
    EngineType: _string | None
    MaxResults: MaxResults | None
    NextToken: _string | None

class DescribeBrokerEngineTypesResponse(TypedDict, total=False):
    BrokerEngineTypes: _listOfBrokerEngineType | None
    MaxResults: _integerMin5Max100 | None
    NextToken: _string | None

class DescribeBrokerInstanceOptionsRequest(ServiceRequest):
    EngineType: _string | None
    HostInstanceType: _string | None
    MaxResults: MaxResults | None
    NextToken: _string | None
    StorageType: _string | None

class DescribeBrokerInstanceOptionsResponse(TypedDict, total=False):
    BrokerInstanceOptions: _listOfBrokerInstanceOption | None
    MaxResults: _integerMin5Max100 | None
    NextToken: _string | None

class UserSummary(TypedDict, total=False):
    PendingChange: ChangeType | None
    Username: _string

_listOfUserSummary = list[UserSummary]
class LdapServerMetadataOutput(TypedDict, total=False):
    Hosts: _listOf__string
    RoleBase: _string
    RoleName: _string | None
    RoleSearchMatching: _string
    RoleSearchSubtree: _boolean | None
    ServiceAccountUsername: _string
    UserBase: _string
    UserRoleName: _string | None
    UserSearchMatching: _string
    UserSearchSubtree: _boolean | None

class PendingLogs(TypedDict, total=False):
    Audit: _boolean | None
    General: _boolean | None

class LogsSummary(TypedDict, total=False):
    Audit: _boolean | None
    AuditLogGroup: _string | None
    General: _boolean
    GeneralLogGroup: _string
    Pending: PendingLogs | None

_listOfBrokerInstance = list[BrokerInstance]
_listOfActionRequired = list[ActionRequired]
class DescribeBrokerOutput(TypedDict, total=False):
    ActionsRequired: _listOfActionRequired | None
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean
    BrokerArn: _string | None
    BrokerId: _string | None
    BrokerInstances: _listOfBrokerInstance | None
    BrokerName: _string | None
    BrokerState: BrokerState | None
    Configurations: Configurations | None
    Created: _timestampIso8601 | None
    DeploymentMode: DeploymentMode
    DataReplicationMetadata: DataReplicationMetadataOutput | None
    DataReplicationMode: DataReplicationMode | None
    EncryptionOptions: EncryptionOptions | None
    EngineType: EngineType
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataOutput | None
    Logs: LogsSummary | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    PendingAuthenticationStrategy: AuthenticationStrategy | None
    PendingDataReplicationMetadata: DataReplicationMetadataOutput | None
    PendingDataReplicationMode: DataReplicationMode | None
    PendingEngineVersion: _string | None
    PendingHostInstanceType: _string | None
    PendingLdapServerMetadata: LdapServerMetadataOutput | None
    PendingSecurityGroups: _listOf__string | None
    PubliclyAccessible: _boolean
    SecurityGroups: _listOf__string | None
    StorageType: BrokerStorageType | None
    SubnetIds: _listOf__string | None
    Tags: _mapOf__string | None
    Users: _listOfUserSummary | None

class DescribeBrokerRequest(ServiceRequest):
    BrokerId: _string

class DescribeBrokerResponse(TypedDict, total=False):
    ActionsRequired: _listOfActionRequired | None
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerArn: _string | None
    BrokerId: _string | None
    BrokerInstances: _listOfBrokerInstance | None
    BrokerName: _string | None
    BrokerState: BrokerState | None
    Configurations: Configurations | None
    Created: _timestampIso8601 | None
    DeploymentMode: DeploymentMode | None
    EncryptionOptions: EncryptionOptions | None
    EngineType: EngineType | None
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataOutput | None
    Logs: LogsSummary | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    PendingAuthenticationStrategy: AuthenticationStrategy | None
    PendingEngineVersion: _string | None
    PendingHostInstanceType: _string | None
    PendingLdapServerMetadata: LdapServerMetadataOutput | None
    PendingSecurityGroups: _listOf__string | None
    PubliclyAccessible: _boolean | None
    SecurityGroups: _listOf__string | None
    StorageType: BrokerStorageType | None
    SubnetIds: _listOf__string | None
    Tags: _mapOf__string | None
    Users: _listOfUserSummary | None
    DataReplicationMetadata: DataReplicationMetadataOutput | None
    DataReplicationMode: DataReplicationMode | None
    PendingDataReplicationMetadata: DataReplicationMetadataOutput | None
    PendingDataReplicationMode: DataReplicationMode | None

class DescribeConfigurationRequest(ServiceRequest):
    ConfigurationId: _string

class DescribeConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    AuthenticationStrategy: AuthenticationStrategy | None
    Created: _timestampIso8601 | None
    Description: _string | None
    EngineType: EngineType | None
    EngineVersion: _string | None
    Id: _string | None
    LatestRevision: ConfigurationRevision | None
    Name: _string | None
    Tags: _mapOf__string | None

class DescribeConfigurationRevisionOutput(TypedDict, total=False):
    ConfigurationId: _string
    Created: _timestampIso8601
    Data: _string
    Description: _string | None

class DescribeConfigurationRevisionRequest(ServiceRequest):
    ConfigurationId: _string
    ConfigurationRevision: _string

class DescribeConfigurationRevisionResponse(TypedDict, total=False):
    ConfigurationId: _string | None
    Created: _timestampIso8601 | None
    Data: _string | None
    Description: _string | None

class UserPendingChanges(TypedDict, total=False):
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    PendingChange: ChangeType

class DescribeUserOutput(TypedDict, total=False):
    BrokerId: _string
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Pending: UserPendingChanges | None
    ReplicationUser: _boolean | None
    Username: _string

class DescribeUserRequest(ServiceRequest):
    BrokerId: _string
    Username: _string

class DescribeUserResponse(TypedDict, total=False):
    BrokerId: _string | None
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Pending: UserPendingChanges | None
    Username: _string | None
    ReplicationUser: _boolean | None

class Error(TypedDict, total=False):
    ErrorAttribute: _string | None
    Message: _string | None

_listOfBrokerSummary = list[BrokerSummary]
class ListBrokersOutput(TypedDict, total=False):
    BrokerSummaries: _listOfBrokerSummary | None
    NextToken: _string | None

class ListBrokersRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListBrokersResponse(TypedDict, total=False):
    BrokerSummaries: _listOfBrokerSummary | None
    NextToken: _string | None

_listOfConfigurationRevision = list[ConfigurationRevision]
class ListConfigurationRevisionsOutput(TypedDict, total=False):
    ConfigurationId: _string | None
    MaxResults: _integer | None
    NextToken: _string | None
    Revisions: _listOfConfigurationRevision | None

class ListConfigurationRevisionsRequest(ServiceRequest):
    ConfigurationId: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListConfigurationRevisionsResponse(TypedDict, total=False):
    ConfigurationId: _string | None
    MaxResults: _integer | None
    NextToken: _string | None
    Revisions: _listOfConfigurationRevision | None

_listOfConfiguration = list[Configuration]
class ListConfigurationsOutput(TypedDict, total=False):
    Configurations: _listOfConfiguration | None
    MaxResults: _integer | None
    NextToken: _string | None

class ListConfigurationsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListConfigurationsResponse(TypedDict, total=False):
    Configurations: _listOfConfiguration | None
    MaxResults: _integer | None
    NextToken: _string | None

class ListTagsRequest(ServiceRequest):
    ResourceArn: _string

class ListTagsResponse(TypedDict, total=False):
    Tags: _mapOf__string | None

class ListUsersOutput(TypedDict, total=False):
    BrokerId: _string
    MaxResults: _integerMin5Max100
    NextToken: _string | None
    Users: _listOfUserSummary

class ListUsersRequest(ServiceRequest):
    BrokerId: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListUsersResponse(TypedDict, total=False):
    BrokerId: _string | None
    MaxResults: _integerMin5Max100 | None
    NextToken: _string | None
    Users: _listOfUserSummary | None

class PromoteInput(TypedDict, total=False):
    Mode: PromoteMode

class PromoteOutput(TypedDict, total=False):
    BrokerId: _string | None

class PromoteRequest(ServiceRequest):
    BrokerId: _string
    Mode: PromoteMode

class PromoteResponse(TypedDict, total=False):
    BrokerId: _string | None

class RebootBrokerRequest(ServiceRequest):
    BrokerId: _string

class RebootBrokerResponse(TypedDict, total=False):
    pass

class SanitizationWarning(TypedDict, total=False):
    AttributeName: _string | None
    ElementName: _string | None
    Reason: SanitizationWarningReason

class Tags(TypedDict, total=False):
    Tags: _mapOf__string | None

class UpdateBrokerInput(TypedDict, total=False):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    Configuration: ConfigurationId | None
    DataReplicationMode: DataReplicationMode | None
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataInput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    SecurityGroups: _listOf__string | None

class UpdateBrokerOutput(TypedDict, total=False):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerId: _string
    Configuration: ConfigurationId | None
    DataReplicationMetadata: DataReplicationMetadataOutput | None
    DataReplicationMode: DataReplicationMode | None
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataOutput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    PendingDataReplicationMetadata: DataReplicationMetadataOutput | None
    PendingDataReplicationMode: DataReplicationMode | None
    SecurityGroups: _listOf__string | None

class UpdateBrokerRequest(ServiceRequest):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerId: _string
    Configuration: ConfigurationId | None
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataInput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    SecurityGroups: _listOf__string | None
    DataReplicationMode: DataReplicationMode | None

class UpdateBrokerResponse(TypedDict, total=False):
    AuthenticationStrategy: AuthenticationStrategy | None
    AutoMinorVersionUpgrade: _boolean | None
    BrokerId: _string | None
    Configuration: ConfigurationId | None
    EngineVersion: _string | None
    HostInstanceType: _string | None
    LdapServerMetadata: LdapServerMetadataOutput | None
    Logs: Logs | None
    MaintenanceWindowStartTime: WeeklyStartTime | None
    SecurityGroups: _listOf__string | None
    DataReplicationMetadata: DataReplicationMetadataOutput | None
    DataReplicationMode: DataReplicationMode | None
    PendingDataReplicationMetadata: DataReplicationMetadataOutput | None
    PendingDataReplicationMode: DataReplicationMode | None

class UpdateConfigurationInput(TypedDict, total=False):
    Data: _string
    Description: _string | None

_listOfSanitizationWarning = list[SanitizationWarning]
class UpdateConfigurationOutput(TypedDict, total=False):
    Arn: _string
    Created: _timestampIso8601
    Id: _string
    LatestRevision: ConfigurationRevision | None
    Name: _string
    Warnings: _listOfSanitizationWarning | None

class UpdateConfigurationRequest(ServiceRequest):
    ConfigurationId: _string
    Data: _string
    Description: _string | None

class UpdateConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    Created: _timestampIso8601 | None
    Id: _string | None
    LatestRevision: ConfigurationRevision | None
    Name: _string | None
    Warnings: _listOfSanitizationWarning | None

class UpdateUserInput(TypedDict, total=False):
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Password: _string | None
    ReplicationUser: _boolean | None

class UpdateUserRequest(ServiceRequest):
    BrokerId: _string
    ConsoleAccess: _boolean | None
    Groups: _listOf__string | None
    Password: _string | None
    Username: _string
    ReplicationUser: _boolean | None

class UpdateUserResponse(TypedDict, total=False):
    pass

_long = int
_timestampUnix = datetime
class MqApi:

    service: str = "mq"
    version: str = "2017-11-27"

    @handler("CreateBroker")
    def create_broker(self, context: RequestContext, host_instance_type: _string, broker_name: _string, deployment_mode: DeploymentMode, engine_type: EngineType, publicly_accessible: _boolean, authentication_strategy: AuthenticationStrategy | None = None, auto_minor_version_upgrade: _boolean | None = None, configuration: ConfigurationId | None = None, creator_request_id: _string | None = None, encryption_options: EncryptionOptions | None = None, engine_version: _string | None = None, ldap_server_metadata: LdapServerMetadataInput | None = None, logs: Logs | None = None, maintenance_window_start_time: WeeklyStartTime | None = None, security_groups: _listOf__string | None = None, storage_type: BrokerStorageType | None = None, subnet_ids: _listOf__string | None = None, tags: _mapOf__string | None = None, users: _listOfUser | None = None, data_replication_mode: DataReplicationMode | None = None, data_replication_primary_broker_arn: _string | None = None, **kwargs) -> CreateBrokerResponse:
        raise NotImplementedError

    @handler("CreateConfiguration")
    def create_configuration(self, context: RequestContext, engine_type: EngineType, name: _string, authentication_strategy: AuthenticationStrategy | None = None, engine_version: _string | None = None, tags: _mapOf__string | None = None, **kwargs) -> CreateConfigurationResponse:
        raise NotImplementedError

    @handler("CreateTags")
    def create_tags(self, context: RequestContext, resource_arn: _string, tags: _mapOf__string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("CreateUser")
    def create_user(self, context: RequestContext, username: _string, broker_id: _string, password: _string, console_access: _boolean | None = None, groups: _listOf__string | None = None, replication_user: _boolean | None = None, **kwargs) -> CreateUserResponse:
        raise NotImplementedError

    @handler("DeleteBroker")
    def delete_broker(self, context: RequestContext, broker_id: _string, **kwargs) -> DeleteBrokerResponse:
        raise NotImplementedError

    @handler("DeleteConfiguration")
    def delete_configuration(self, context: RequestContext, configuration_id: _string, **kwargs) -> DeleteConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(self, context: RequestContext, tag_keys: _listOf__string, resource_arn: _string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteUser")
    def delete_user(self, context: RequestContext, username: _string, broker_id: _string, **kwargs) -> DeleteUserResponse:
        raise NotImplementedError

    @handler("DescribeBroker")
    def describe_broker(self, context: RequestContext, broker_id: _string, **kwargs) -> DescribeBrokerResponse:
        raise NotImplementedError

    @handler("DescribeBrokerEngineTypes")
    def describe_broker_engine_types(self, context: RequestContext, engine_type: _string | None = None, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> DescribeBrokerEngineTypesResponse:
        raise NotImplementedError

    @handler("DescribeBrokerInstanceOptions")
    def describe_broker_instance_options(self, context: RequestContext, engine_type: _string | None = None, host_instance_type: _string | None = None, max_results: MaxResults | None = None, next_token: _string | None = None, storage_type: _string | None = None, **kwargs) -> DescribeBrokerInstanceOptionsResponse:
        raise NotImplementedError

    @handler("DescribeConfiguration")
    def describe_configuration(self, context: RequestContext, configuration_id: _string, **kwargs) -> DescribeConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRevision")
    def describe_configuration_revision(self, context: RequestContext, configuration_revision: _string, configuration_id: _string, **kwargs) -> DescribeConfigurationRevisionResponse:
        raise NotImplementedError

    @handler("DescribeUser")
    def describe_user(self, context: RequestContext, username: _string, broker_id: _string, **kwargs) -> DescribeUserResponse:
        raise NotImplementedError

    @handler("ListBrokers")
    def list_brokers(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListBrokersResponse:
        raise NotImplementedError

    @handler("ListConfigurationRevisions")
    def list_configuration_revisions(self, context: RequestContext, configuration_id: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListConfigurationRevisionsResponse:
        raise NotImplementedError

    @handler("ListConfigurations")
    def list_configurations(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListConfigurationsResponse:
        raise NotImplementedError

    @handler("ListTags")
    def list_tags(self, context: RequestContext, resource_arn: _string, **kwargs) -> ListTagsResponse:
        raise NotImplementedError

    @handler("ListUsers")
    def list_users(self, context: RequestContext, broker_id: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListUsersResponse:
        raise NotImplementedError

    @handler("Promote")
    def promote(self, context: RequestContext, broker_id: _string, mode: PromoteMode, **kwargs) -> PromoteResponse:
        raise NotImplementedError

    @handler("RebootBroker")
    def reboot_broker(self, context: RequestContext, broker_id: _string, **kwargs) -> RebootBrokerResponse:
        raise NotImplementedError

    @handler("UpdateBroker")
    def update_broker(self, context: RequestContext, broker_id: _string, authentication_strategy: AuthenticationStrategy | None = None, auto_minor_version_upgrade: _boolean | None = None, configuration: ConfigurationId | None = None, engine_version: _string | None = None, host_instance_type: _string | None = None, ldap_server_metadata: LdapServerMetadataInput | None = None, logs: Logs | None = None, maintenance_window_start_time: WeeklyStartTime | None = None, security_groups: _listOf__string | None = None, data_replication_mode: DataReplicationMode | None = None, **kwargs) -> UpdateBrokerResponse:
        raise NotImplementedError

    @handler("UpdateConfiguration")
    def update_configuration(self, context: RequestContext, configuration_id: _string, data: _string, description: _string | None = None, **kwargs) -> UpdateConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateUser")
    def update_user(self, context: RequestContext, username: _string, broker_id: _string, console_access: _boolean | None = None, groups: _listOf__string | None = None, password: _string | None = None, replication_user: _boolean | None = None, **kwargs) -> UpdateUserResponse:
        raise NotImplementedError
