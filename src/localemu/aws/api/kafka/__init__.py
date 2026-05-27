from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict
from collections.abc import Iterable, Iterator

from localemu.aws.api import handler, RequestContext, ServiceException, ServiceRequest
MaxResults = int
_boolean = bool
_double = float
_integer = int
_integerMin1Max15 = int
_integerMin1Max16384 = int
_integerMin1 = int
_string = str
_stringMax1024 = str
_stringMax249 = str
_stringMax256 = str
_stringMin1Max128 = str
_stringMin1Max64 = str
_stringMin5Max32 = str
_stringMin1Max128Pattern09AZaZ09AZaZ0 = str
class BrokerAZDistribution(StrEnum):
    DEFAULT = "DEFAULT"

class RebalancingStatus(StrEnum):
    PAUSED = "PAUSED"
    ACTIVE = "ACTIVE"

class ClientBroker(StrEnum):
    TLS = "TLS"
    TLS_PLAINTEXT = "TLS_PLAINTEXT"
    PLAINTEXT = "PLAINTEXT"

class ClusterState(StrEnum):
    ACTIVE = "ACTIVE"
    CREATING = "CREATING"
    DELETING = "DELETING"
    FAILED = "FAILED"
    HEALING = "HEALING"
    MAINTENANCE = "MAINTENANCE"
    REBOOTING_BROKER = "REBOOTING_BROKER"
    UPDATING = "UPDATING"

class ClusterType(StrEnum):
    PROVISIONED = "PROVISIONED"
    SERVERLESS = "SERVERLESS"

class ConfigurationState(StrEnum):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETE_FAILED = "DELETE_FAILED"

class CustomerActionStatus(StrEnum):
    CRITICAL_ACTION_REQUIRED = "CRITICAL_ACTION_REQUIRED"
    ACTION_RECOMMENDED = "ACTION_RECOMMENDED"
    NONE = "NONE"

class EnhancedMonitoring(StrEnum):
    DEFAULT = "DEFAULT"
    PER_BROKER = "PER_BROKER"
    PER_TOPIC_PER_BROKER = "PER_TOPIC_PER_BROKER"
    PER_TOPIC_PER_PARTITION = "PER_TOPIC_PER_PARTITION"

class KafkaVersionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"

class NetworkType(StrEnum):
    IPV4 = "IPV4"
    DUAL = "DUAL"

class NodeType(StrEnum):
    BROKER = "BROKER"

class ReplicationStartingPositionType(StrEnum):
    LATEST = "LATEST"
    EARLIEST = "EARLIEST"

class ReplicationTopicNameConfigurationType(StrEnum):
    PREFIXED_WITH_SOURCE_CLUSTER_ALIAS = "PREFIXED_WITH_SOURCE_CLUSTER_ALIAS"
    IDENTICAL = "IDENTICAL"

class ReplicatorState(StrEnum):
    RUNNING = "RUNNING"
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    FAILED = "FAILED"

class StorageMode(StrEnum):
    LOCAL = "LOCAL"
    TIERED = "TIERED"

class TargetCompressionType(StrEnum):
    NONE = "NONE"
    GZIP = "GZIP"
    SNAPPY = "SNAPPY"
    LZ4 = "LZ4"
    ZSTD = "ZSTD"

class UserIdentityType(StrEnum):
    AWSACCOUNT = "AWSACCOUNT"
    AWSSERVICE = "AWSSERVICE"

class TopicState(StrEnum):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    DELETING = "DELETING"
    ACTIVE = "ACTIVE"

class VpcConnectionState(StrEnum):
    CREATING = "CREATING"
    AVAILABLE = "AVAILABLE"
    INACTIVE = "INACTIVE"
    DEACTIVATING = "DEACTIVATING"
    DELETING = "DELETING"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    REJECTING = "REJECTING"

class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400
    InvalidParameter: _string | None

class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class ForbiddenException(ServiceException):
    code: str = "ForbiddenException"
    sender_fault: bool = False
    status_code: int = 403
    InvalidParameter: _string | None

class TopicExistsException(ServiceException):
    code: str = "TopicExistsException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class ClusterConnectivityException(ServiceException):
    code: str = "ClusterConnectivityException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class KafkaTimeoutException(ServiceException):
    code: str = "KafkaTimeoutException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class UnknownTopicOrPartitionException(ServiceException):
    code: str = "UnknownTopicOrPartitionException"
    sender_fault: bool = False
    status_code: int = 404
    InvalidParameter: _string | None

class ControllerMovedException(ServiceException):
    code: str = "ControllerMovedException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class NotControllerException(ServiceException):
    code: str = "NotControllerException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class ReassignmentInProgressException(ServiceException):
    code: str = "ReassignmentInProgressException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class GroupSubscribedToTopicException(ServiceException):
    code: str = "GroupSubscribedToTopicException"
    sender_fault: bool = False
    status_code: int = 409
    InvalidParameter: _string | None

class KafkaRequestException(ServiceException):
    code: str = "KafkaRequestException"
    sender_fault: bool = False
    status_code: int = 400
    InvalidParameter: _string | None

class InternalServerErrorException(ServiceException):
    code: str = "InternalServerErrorException"
    sender_fault: bool = False
    status_code: int = 500
    InvalidParameter: _string | None

class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404
    InvalidParameter: _string | None

class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 503
    InvalidParameter: _string | None

class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429
    InvalidParameter: _string | None

class UnauthorizedException(ServiceException):
    code: str = "UnauthorizedException"
    sender_fault: bool = False
    status_code: int = 401
    InvalidParameter: _string | None

class AmazonMskCluster(TypedDict, total=False):
    MskClusterArn: _string

_listOf__string = list[_string]
class BatchAssociateScramSecretRequest(ServiceRequest):
    ClusterArn: _string
    SecretArnList: _listOf__string

class UnprocessedScramSecret(TypedDict, total=False):
    ErrorCode: _string | None
    ErrorMessage: _string | None
    SecretArn: _string | None

_listOfUnprocessedScramSecret = list[UnprocessedScramSecret]
class BatchAssociateScramSecretResponse(TypedDict, total=False):
    ClusterArn: _string | None
    UnprocessedScramSecrets: _listOfUnprocessedScramSecret | None

_listOf__double = list[_double]
class BrokerCountUpdateInfo(TypedDict, total=False):
    CreatedBrokerIds: _listOf__double | None
    DeletedBrokerIds: _listOf__double | None

class ProvisionedThroughput(TypedDict, total=False):
    Enabled: _boolean | None
    VolumeThroughput: _integer | None

class BrokerEBSVolumeInfo(TypedDict, total=False):
    KafkaBrokerNodeId: _string
    ProvisionedThroughput: ProvisionedThroughput | None
    VolumeSizeGB: _integer | None

class S3(TypedDict, total=False):
    Bucket: _string | None
    Enabled: _boolean
    Prefix: _string | None

class Firehose(TypedDict, total=False):
    DeliveryStream: _string | None
    Enabled: _boolean

class CloudWatchLogs(TypedDict, total=False):
    Enabled: _boolean
    LogGroup: _string | None

class BrokerLogs(TypedDict, total=False):
    CloudWatchLogs: CloudWatchLogs | None
    Firehose: Firehose | None
    S3: S3 | None

class Rebalancing(TypedDict, total=False):
    Status: RebalancingStatus | None

class VpcConnectivityTls(TypedDict, total=False):
    Enabled: _boolean | None

class VpcConnectivityIam(TypedDict, total=False):
    Enabled: _boolean | None

class VpcConnectivityScram(TypedDict, total=False):
    Enabled: _boolean | None

class VpcConnectivitySasl(TypedDict, total=False):
    Scram: VpcConnectivityScram | None
    Iam: VpcConnectivityIam | None

class VpcConnectivityClientAuthentication(TypedDict, total=False):
    Sasl: VpcConnectivitySasl | None
    Tls: VpcConnectivityTls | None

class VpcConnectivity(TypedDict, total=False):
    ClientAuthentication: VpcConnectivityClientAuthentication | None

class PublicAccess(TypedDict, total=False):
    Type: _string | None

class ConnectivityInfo(TypedDict, total=False):
    PublicAccess: PublicAccess | None
    VpcConnectivity: VpcConnectivity | None
    NetworkType: NetworkType | None

class EBSStorageInfo(TypedDict, total=False):
    ProvisionedThroughput: ProvisionedThroughput | None
    VolumeSize: _integerMin1Max16384 | None

class StorageInfo(TypedDict, total=False):
    EbsStorageInfo: EBSStorageInfo | None

class BrokerNodeGroupInfo(TypedDict, total=False):
    BrokerAZDistribution: BrokerAZDistribution | None
    ClientSubnets: _listOf__string
    InstanceType: _stringMin5Max32
    SecurityGroups: _listOf__string | None
    StorageInfo: StorageInfo | None
    ConnectivityInfo: ConnectivityInfo | None
    ZoneIds: _listOf__string | None

_long = int
class BrokerSoftwareInfo(TypedDict, total=False):
    ConfigurationArn: _string | None
    ConfigurationRevision: _long | None
    KafkaVersion: _string | None

class BrokerNodeInfo(TypedDict, total=False):
    AttachedENIId: _string | None
    BrokerId: _double | None
    ClientSubnet: _string | None
    ClientVpcIpAddress: _string | None
    CurrentBrokerSoftwareInfo: BrokerSoftwareInfo | None
    Endpoints: _listOf__string | None

class Unauthenticated(TypedDict, total=False):
    Enabled: _boolean | None

class Tls(TypedDict, total=False):
    CertificateAuthorityArnList: _listOf__string | None
    Enabled: _boolean | None

class Iam(TypedDict, total=False):
    Enabled: _boolean | None

class Scram(TypedDict, total=False):
    Enabled: _boolean | None

class Sasl(TypedDict, total=False):
    Scram: Scram | None
    Iam: Iam | None

class ClientAuthentication(TypedDict, total=False):
    Sasl: Sasl | None
    Tls: Tls | None
    Unauthenticated: Unauthenticated | None

class ServerlessSasl(TypedDict, total=False):
    Iam: Iam | None

class ServerlessClientAuthentication(TypedDict, total=False):
    Sasl: ServerlessSasl | None

_mapOf__string = dict[_string, _string]
class StateInfo(TypedDict, total=False):
    Code: _string | None
    Message: _string | None

class LoggingInfo(TypedDict, total=False):
    BrokerLogs: BrokerLogs

class NodeExporter(TypedDict, total=False):
    EnabledInBroker: _boolean

class JmxExporter(TypedDict, total=False):
    EnabledInBroker: _boolean

class Prometheus(TypedDict, total=False):
    JmxExporter: JmxExporter | None
    NodeExporter: NodeExporter | None

class OpenMonitoring(TypedDict, total=False):
    Prometheus: Prometheus

class EncryptionInTransit(TypedDict, total=False):
    ClientBroker: ClientBroker | None
    InCluster: _boolean | None

class EncryptionAtRest(TypedDict, total=False):
    DataVolumeKMSKeyId: _string

class EncryptionInfo(TypedDict, total=False):
    EncryptionAtRest: EncryptionAtRest | None
    EncryptionInTransit: EncryptionInTransit | None

_timestampIso8601 = datetime
class ClusterInfo(TypedDict, total=False):
    ActiveOperationArn: _string | None
    BrokerNodeGroupInfo: BrokerNodeGroupInfo | None
    Rebalancing: Rebalancing | None
    ClientAuthentication: ClientAuthentication | None
    ClusterArn: _string | None
    ClusterName: _string | None
    CreationTime: _timestampIso8601 | None
    CurrentBrokerSoftwareInfo: BrokerSoftwareInfo | None
    CurrentVersion: _string | None
    EncryptionInfo: EncryptionInfo | None
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoring | None
    LoggingInfo: LoggingInfo | None
    NumberOfBrokerNodes: _integer | None
    State: ClusterState | None
    StateInfo: StateInfo | None
    Tags: _mapOf__string | None
    ZookeeperConnectString: _string | None
    ZookeeperConnectStringTls: _string | None
    StorageMode: StorageMode | None
    CustomerActionStatus: CustomerActionStatus | None

class ServerlessConnectivityInfo(TypedDict, total=False):
    NetworkType: NetworkType | None

class VpcConfig(TypedDict, total=False):
    SubnetIds: _listOf__string
    SecurityGroupIds: _listOf__string | None

_listOfVpcConfig = list[VpcConfig]
class Serverless(TypedDict, total=False):
    VpcConfigs: _listOfVpcConfig
    ClientAuthentication: ServerlessClientAuthentication | None
    ConnectivityInfo: ServerlessConnectivityInfo | None

class NodeExporterInfo(TypedDict, total=False):
    EnabledInBroker: _boolean

class JmxExporterInfo(TypedDict, total=False):
    EnabledInBroker: _boolean

class PrometheusInfo(TypedDict, total=False):
    JmxExporter: JmxExporterInfo | None
    NodeExporter: NodeExporterInfo | None

class OpenMonitoringInfo(TypedDict, total=False):
    Prometheus: PrometheusInfo

class Provisioned(TypedDict, total=False):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    Rebalancing: Rebalancing | None
    CurrentBrokerSoftwareInfo: BrokerSoftwareInfo | None
    ClientAuthentication: ClientAuthentication | None
    EncryptionInfo: EncryptionInfo | None
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoringInfo | None
    LoggingInfo: LoggingInfo | None
    NumberOfBrokerNodes: _integerMin1Max15
    ZookeeperConnectString: _string | None
    ZookeeperConnectStringTls: _string | None
    StorageMode: StorageMode | None
    CustomerActionStatus: CustomerActionStatus | None

class Cluster(TypedDict, total=False):
    ActiveOperationArn: _string | None
    ClusterType: ClusterType | None
    ClusterArn: _string | None
    ClusterName: _string | None
    CreationTime: _timestampIso8601 | None
    CurrentVersion: _string | None
    State: ClusterState | None
    StateInfo: StateInfo | None
    Tags: _mapOf__string | None
    Provisioned: Provisioned | None
    Serverless: Serverless | None

class UserIdentity(TypedDict, total=False):
    Type: UserIdentityType | None
    PrincipalId: _string | None

class VpcConnectionInfo(TypedDict, total=False):
    VpcConnectionArn: _string | None
    Owner: _string | None
    UserIdentity: UserIdentity | None
    CreationTime: _timestampIso8601 | None

class ConfigurationInfo(TypedDict, total=False):
    Arn: _string
    Revision: _long

_listOfBrokerEBSVolumeInfo = list[BrokerEBSVolumeInfo]
class MutableClusterInfo(TypedDict, total=False):
    BrokerEBSVolumeInfo: _listOfBrokerEBSVolumeInfo | None
    ConfigurationInfo: ConfigurationInfo | None
    NumberOfBrokerNodes: _integer | None
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoring | None
    KafkaVersion: _string | None
    LoggingInfo: LoggingInfo | None
    InstanceType: _stringMin5Max32 | None
    ClientAuthentication: ClientAuthentication | None
    EncryptionInfo: EncryptionInfo | None
    ConnectivityInfo: ConnectivityInfo | None
    StorageMode: StorageMode | None
    BrokerCountUpdateInfo: BrokerCountUpdateInfo | None
    Rebalancing: Rebalancing | None

class ClusterOperationStepInfo(TypedDict, total=False):
    StepStatus: _string | None

class ClusterOperationStep(TypedDict, total=False):
    StepInfo: ClusterOperationStepInfo | None
    StepName: _string | None

_listOfClusterOperationStep = list[ClusterOperationStep]
class ErrorInfo(TypedDict, total=False):
    ErrorCode: _string | None
    ErrorString: _string | None

class ClusterOperationInfo(TypedDict, total=False):
    ClientRequestId: _string | None
    ClusterArn: _string | None
    CreationTime: _timestampIso8601 | None
    EndTime: _timestampIso8601 | None
    ErrorInfo: ErrorInfo | None
    OperationArn: _string | None
    OperationState: _string | None
    OperationSteps: _listOfClusterOperationStep | None
    OperationType: _string | None
    SourceClusterInfo: MutableClusterInfo | None
    TargetClusterInfo: MutableClusterInfo | None
    VpcConnectionInfo: VpcConnectionInfo | None

class ProvisionedRequest(TypedDict, total=False):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    Rebalancing: Rebalancing | None
    ClientAuthentication: ClientAuthentication | None
    ConfigurationInfo: ConfigurationInfo | None
    EncryptionInfo: EncryptionInfo | None
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoringInfo | None
    KafkaVersion: _stringMin1Max128
    LoggingInfo: LoggingInfo | None
    NumberOfBrokerNodes: _integerMin1Max15
    StorageMode: StorageMode | None

class ServerlessRequest(TypedDict, total=False):
    VpcConfigs: _listOfVpcConfig
    ClientAuthentication: ServerlessClientAuthentication | None

class ClientVpcConnection(TypedDict, total=False):
    Authentication: _string | None
    CreationTime: _timestampIso8601 | None
    State: VpcConnectionState | None
    VpcConnectionArn: _string
    Owner: _string | None

class VpcConnection(TypedDict, total=False):
    VpcConnectionArn: _string
    TargetClusterArn: _string
    CreationTime: _timestampIso8601 | None
    Authentication: _string | None
    VpcId: _string | None
    State: VpcConnectionState | None

class CompatibleKafkaVersion(TypedDict, total=False):
    SourceVersion: _string | None
    TargetVersions: _listOf__string | None

class ConfigurationRevision(TypedDict, total=False):
    CreationTime: _timestampIso8601
    Description: _string | None
    Revision: _long

class Configuration(TypedDict, total=False):
    Arn: _string
    CreationTime: _timestampIso8601
    Description: _string
    KafkaVersions: _listOf__string
    LatestRevision: ConfigurationRevision
    Name: _string
    State: ConfigurationState

_listOf__stringMax256 = list[_stringMax256]
class ConsumerGroupReplication(TypedDict, total=False):
    ConsumerGroupsToExclude: _listOf__stringMax256 | None
    ConsumerGroupsToReplicate: _listOf__stringMax256
    DetectAndCopyNewConsumerGroups: _boolean | None
    SynchroniseConsumerGroupOffsets: _boolean | None

class ConsumerGroupReplicationUpdate(TypedDict, total=False):
    ConsumerGroupsToExclude: _listOf__stringMax256
    ConsumerGroupsToReplicate: _listOf__stringMax256
    DetectAndCopyNewConsumerGroups: _boolean
    SynchroniseConsumerGroupOffsets: _boolean

class CreateClusterV2Request(ServiceRequest):
    ClusterName: _stringMin1Max64
    Tags: _mapOf__string | None
    Provisioned: ProvisionedRequest | None
    Serverless: ServerlessRequest | None

class CreateClusterRequest(ServiceRequest):
    BrokerNodeGroupInfo: BrokerNodeGroupInfo
    Rebalancing: Rebalancing | None
    ClientAuthentication: ClientAuthentication | None
    ClusterName: _stringMin1Max64
    ConfigurationInfo: ConfigurationInfo | None
    EncryptionInfo: EncryptionInfo | None
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoringInfo | None
    KafkaVersion: _stringMin1Max128
    LoggingInfo: LoggingInfo | None
    NumberOfBrokerNodes: _integerMin1Max15
    Tags: _mapOf__string | None
    StorageMode: StorageMode | None

class CreateClusterResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterName: _string | None
    State: ClusterState | None

class CreateClusterV2Response(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterName: _string | None
    State: ClusterState | None
    ClusterType: ClusterType | None

_blob = bytes
class CreateConfigurationRequest(ServiceRequest):
    Description: _string | None
    KafkaVersions: _listOf__string | None
    Name: _string
    ServerProperties: _blob

class CreateConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    CreationTime: _timestampIso8601 | None
    LatestRevision: ConfigurationRevision | None
    Name: _string | None
    State: ConfigurationState | None

_listOf__stringMax249 = list[_stringMax249]
class ReplicationTopicNameConfiguration(TypedDict, total=False):
    Type: ReplicationTopicNameConfigurationType | None

class ReplicationStartingPosition(TypedDict, total=False):
    Type: ReplicationStartingPositionType | None

class TopicReplication(TypedDict, total=False):
    CopyAccessControlListsForTopics: _boolean | None
    CopyTopicConfigurations: _boolean | None
    DetectAndCopyNewTopics: _boolean | None
    StartingPosition: ReplicationStartingPosition | None
    TopicNameConfiguration: ReplicationTopicNameConfiguration | None
    TopicsToExclude: _listOf__stringMax249 | None
    TopicsToReplicate: _listOf__stringMax249

class ReplicationInfo(TypedDict, total=False):
    ConsumerGroupReplication: ConsumerGroupReplication
    SourceKafkaClusterArn: _string
    TargetCompressionType: TargetCompressionType
    TargetKafkaClusterArn: _string
    TopicReplication: TopicReplication

_listOfReplicationInfo = list[ReplicationInfo]
class KafkaClusterClientVpcConfig(TypedDict, total=False):
    SecurityGroupIds: _listOf__string | None
    SubnetIds: _listOf__string

class KafkaCluster(TypedDict, total=False):
    AmazonMskCluster: AmazonMskCluster
    VpcConfig: KafkaClusterClientVpcConfig

_listOfKafkaCluster = list[KafkaCluster]
class CreateReplicatorRequest(ServiceRequest):
    Description: _stringMax1024 | None
    KafkaClusters: _listOfKafkaCluster
    ReplicationInfoList: _listOfReplicationInfo
    ReplicatorName: _stringMin1Max128Pattern09AZaZ09AZaZ0
    ServiceExecutionRoleArn: _string
    Tags: _mapOf__string | None

class CreateReplicatorResponse(TypedDict, total=False):
    ReplicatorArn: _string | None
    ReplicatorName: _string | None
    ReplicatorState: ReplicatorState | None

class CreateVpcConnectionRequest(ServiceRequest):
    TargetClusterArn: _string
    Authentication: _string
    VpcId: _string
    ClientSubnets: _listOf__string
    SecurityGroups: _listOf__string
    Tags: _mapOf__string | None

class CreateVpcConnectionResponse(TypedDict, total=False):
    VpcConnectionArn: _string | None
    State: VpcConnectionState | None
    Authentication: _string | None
    VpcId: _string | None
    ClientSubnets: _listOf__string | None
    SecurityGroups: _listOf__string | None
    CreationTime: _timestampIso8601 | None
    Tags: _mapOf__string | None

class CreateTopicRequest(ServiceRequest):
    ClusterArn: _string
    TopicName: _string
    PartitionCount: _integerMin1
    ReplicationFactor: _integerMin1
    Configs: _string | None

class CreateTopicResponse(TypedDict, total=False):
    TopicArn: _string | None
    TopicName: _string | None
    Status: TopicState | None

class DeleteTopicRequest(ServiceRequest):
    ClusterArn: _string
    TopicName: _string

class DeleteTopicResponse(TypedDict, total=False):
    TopicArn: _string | None
    TopicName: _string | None
    Status: TopicState | None

class UpdateTopicRequest(ServiceRequest):
    ClusterArn: _string
    TopicName: _string
    Configs: _string | None
    PartitionCount: _integer | None

class UpdateTopicResponse(TypedDict, total=False):
    TopicArn: _string | None
    TopicName: _string | None
    Status: TopicState | None

class VpcConnectionInfoServerless(TypedDict, total=False):
    CreationTime: _timestampIso8601 | None
    Owner: _string | None
    UserIdentity: UserIdentity | None
    VpcConnectionArn: _string | None

class ClusterOperationV2Serverless(TypedDict, total=False):
    SourceClusterInfo: ServerlessConnectivityInfo | None
    TargetClusterInfo: ServerlessConnectivityInfo | None
    VpcConnectionInfo: VpcConnectionInfoServerless | None

class ClusterOperationV2Provisioned(TypedDict, total=False):
    OperationSteps: _listOfClusterOperationStep | None
    SourceClusterInfo: MutableClusterInfo | None
    TargetClusterInfo: MutableClusterInfo | None
    VpcConnectionInfo: VpcConnectionInfo | None

class ClusterOperationV2(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterType: ClusterType | None
    StartTime: _timestampIso8601 | None
    EndTime: _timestampIso8601 | None
    ErrorInfo: ErrorInfo | None
    OperationArn: _string | None
    OperationState: _string | None
    OperationType: _string | None
    Provisioned: ClusterOperationV2Provisioned | None
    Serverless: ClusterOperationV2Serverless | None

class ClusterOperationV2Summary(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterType: ClusterType | None
    StartTime: _timestampIso8601 | None
    EndTime: _timestampIso8601 | None
    OperationArn: _string | None
    OperationState: _string | None
    OperationType: _string | None

class ControllerNodeInfo(TypedDict, total=False):
    Endpoints: _listOf__string | None

class DeleteClusterRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string | None

class DeleteClusterResponse(TypedDict, total=False):
    ClusterArn: _string | None
    State: ClusterState | None

class DeleteClusterPolicyRequest(ServiceRequest):
    ClusterArn: _string

class DeleteClusterPolicyResponse(TypedDict, total=False):
    pass

class DeleteConfigurationRequest(ServiceRequest):
    Arn: _string

class DeleteConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    State: ConfigurationState | None

class DeleteReplicatorRequest(ServiceRequest):
    CurrentVersion: _string | None
    ReplicatorArn: _string

class DeleteReplicatorResponse(TypedDict, total=False):
    ReplicatorArn: _string | None
    ReplicatorState: ReplicatorState | None

class DeleteVpcConnectionRequest(ServiceRequest):
    Arn: _string

class DeleteVpcConnectionResponse(TypedDict, total=False):
    VpcConnectionArn: _string | None
    State: VpcConnectionState | None

class DescribeClusterOperationRequest(ServiceRequest):
    ClusterOperationArn: _string

class DescribeClusterOperationV2Request(ServiceRequest):
    ClusterOperationArn: _string

class DescribeClusterOperationResponse(TypedDict, total=False):
    ClusterOperationInfo: ClusterOperationInfo | None

class DescribeClusterOperationV2Response(TypedDict, total=False):
    ClusterOperationInfo: ClusterOperationV2 | None

class DescribeClusterRequest(ServiceRequest):
    ClusterArn: _string

class DescribeClusterV2Request(ServiceRequest):
    ClusterArn: _string

class DescribeClusterResponse(TypedDict, total=False):
    ClusterInfo: ClusterInfo | None

class DescribeClusterV2Response(TypedDict, total=False):
    ClusterInfo: Cluster | None

class DescribeConfigurationRequest(ServiceRequest):
    Arn: _string

class DescribeConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    CreationTime: _timestampIso8601 | None
    Description: _string | None
    KafkaVersions: _listOf__string | None
    LatestRevision: ConfigurationRevision | None
    Name: _string | None
    State: ConfigurationState | None

class DescribeConfigurationRevisionRequest(ServiceRequest):
    Arn: _string
    Revision: _long

class DescribeConfigurationRevisionResponse(TypedDict, total=False):
    Arn: _string | None
    CreationTime: _timestampIso8601 | None
    Description: _string | None
    Revision: _long | None
    ServerProperties: _blob | None

class DescribeTopicRequest(ServiceRequest):
    ClusterArn: _string
    TopicName: _string

class DescribeTopicPartitionsRequest(ServiceRequest):
    ClusterArn: _string
    TopicName: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class DescribeTopicResponse(TypedDict, total=False):
    TopicArn: _string | None
    TopicName: _string | None
    ReplicationFactor: _integer | None
    PartitionCount: _integer | None
    Configs: _string | None
    Status: TopicState | None

_listOf__integer = list[_integer]
class TopicPartitionInfo(TypedDict, total=False):
    Partition: _integer | None
    Leader: _integer | None
    Replicas: _listOf__integer | None
    Isr: _listOf__integer | None

_listOfTopicPartitionInfo = list[TopicPartitionInfo]
class DescribeTopicPartitionsResponse(TypedDict, total=False):
    Partitions: _listOfTopicPartitionInfo | None
    NextToken: _string | None

class DescribeVpcConnectionRequest(ServiceRequest):
    Arn: _string

class DescribeReplicatorRequest(ServiceRequest):
    ReplicatorArn: _string

class ReplicationStateInfo(TypedDict, total=False):
    Code: _string | None
    Message: _string | None

class ReplicationInfoDescription(TypedDict, total=False):
    ConsumerGroupReplication: ConsumerGroupReplication | None
    SourceKafkaClusterAlias: _string | None
    TargetCompressionType: TargetCompressionType | None
    TargetKafkaClusterAlias: _string | None
    TopicReplication: TopicReplication | None

_listOfReplicationInfoDescription = list[ReplicationInfoDescription]
class KafkaClusterDescription(TypedDict, total=False):
    AmazonMskCluster: AmazonMskCluster | None
    KafkaClusterAlias: _string | None
    VpcConfig: KafkaClusterClientVpcConfig | None

_listOfKafkaClusterDescription = list[KafkaClusterDescription]
class DescribeReplicatorResponse(TypedDict, total=False):
    CreationTime: _timestampIso8601 | None
    CurrentVersion: _string | None
    IsReplicatorReference: _boolean | None
    KafkaClusters: _listOfKafkaClusterDescription | None
    ReplicationInfoList: _listOfReplicationInfoDescription | None
    ReplicatorArn: _string | None
    ReplicatorDescription: _string | None
    ReplicatorName: _string | None
    ReplicatorResourceArn: _string | None
    ReplicatorState: ReplicatorState | None
    ServiceExecutionRoleArn: _string | None
    StateInfo: ReplicationStateInfo | None
    Tags: _mapOf__string | None

class DescribeVpcConnectionResponse(TypedDict, total=False):
    VpcConnectionArn: _string | None
    TargetClusterArn: _string | None
    State: VpcConnectionState | None
    Authentication: _string | None
    VpcId: _string | None
    Subnets: _listOf__string | None
    SecurityGroups: _listOf__string | None
    CreationTime: _timestampIso8601 | None
    Tags: _mapOf__string | None

class BatchDisassociateScramSecretRequest(ServiceRequest):
    ClusterArn: _string
    SecretArnList: _listOf__string

class BatchDisassociateScramSecretResponse(TypedDict, total=False):
    ClusterArn: _string | None
    UnprocessedScramSecrets: _listOfUnprocessedScramSecret | None

class Error(TypedDict, total=False):
    InvalidParameter: _string | None
    Message: _string | None

class GetBootstrapBrokersRequest(ServiceRequest):
    ClusterArn: _string

class GetBootstrapBrokersResponse(TypedDict, total=False):
    BootstrapBrokerString: _string | None
    BootstrapBrokerStringTls: _string | None
    BootstrapBrokerStringSaslScram: _string | None
    BootstrapBrokerStringSaslIam: _string | None
    BootstrapBrokerStringPublicTls: _string | None
    BootstrapBrokerStringPublicSaslScram: _string | None
    BootstrapBrokerStringPublicSaslIam: _string | None
    BootstrapBrokerStringVpcConnectivityTls: _string | None
    BootstrapBrokerStringVpcConnectivitySaslScram: _string | None
    BootstrapBrokerStringVpcConnectivitySaslIam: _string | None
    BootstrapBrokerStringIpv6: _string | None
    BootstrapBrokerStringTlsIpv6: _string | None
    BootstrapBrokerStringSaslScramIpv6: _string | None
    BootstrapBrokerStringSaslIamIpv6: _string | None

class GetCompatibleKafkaVersionsRequest(ServiceRequest):
    ClusterArn: _string | None

_listOfCompatibleKafkaVersion = list[CompatibleKafkaVersion]
class GetCompatibleKafkaVersionsResponse(TypedDict, total=False):
    CompatibleKafkaVersions: _listOfCompatibleKafkaVersion | None

class GetClusterPolicyRequest(ServiceRequest):
    ClusterArn: _string

class GetClusterPolicyResponse(TypedDict, total=False):
    CurrentVersion: _string | None
    Policy: _string | None

class KafkaClusterSummary(TypedDict, total=False):
    AmazonMskCluster: AmazonMskCluster | None
    KafkaClusterAlias: _string | None

class KafkaVersion(TypedDict, total=False):
    Version: _string | None
    Status: KafkaVersionStatus | None

class ListClusterOperationsRequest(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListClusterOperationsV2Request(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfClusterOperationInfo = list[ClusterOperationInfo]
class ListClusterOperationsResponse(TypedDict, total=False):
    ClusterOperationInfoList: _listOfClusterOperationInfo | None
    NextToken: _string | None

_listOfClusterOperationV2Summary = list[ClusterOperationV2Summary]
class ListClusterOperationsV2Response(TypedDict, total=False):
    ClusterOperationInfoList: _listOfClusterOperationV2Summary | None
    NextToken: _string | None

class ListClustersRequest(ServiceRequest):
    ClusterNameFilter: _string | None
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListClustersV2Request(ServiceRequest):
    ClusterNameFilter: _string | None
    ClusterTypeFilter: _string | None
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfClusterInfo = list[ClusterInfo]
class ListClustersResponse(TypedDict, total=False):
    ClusterInfoList: _listOfClusterInfo | None
    NextToken: _string | None

_listOfCluster = list[Cluster]
class ListClustersV2Response(TypedDict, total=False):
    ClusterInfoList: _listOfCluster | None
    NextToken: _string | None

class ListConfigurationRevisionsRequest(ServiceRequest):
    Arn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfConfigurationRevision = list[ConfigurationRevision]
class ListConfigurationRevisionsResponse(TypedDict, total=False):
    NextToken: _string | None
    Revisions: _listOfConfigurationRevision | None

class ListConfigurationsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfConfiguration = list[Configuration]
class ListConfigurationsResponse(TypedDict, total=False):
    Configurations: _listOfConfiguration | None
    NextToken: _string | None

class ListKafkaVersionsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfKafkaVersion = list[KafkaVersion]
class ListKafkaVersionsResponse(TypedDict, total=False):
    KafkaVersions: _listOfKafkaVersion | None
    NextToken: _string | None

class ListNodesRequest(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class ZookeeperNodeInfo(TypedDict, total=False):
    AttachedENIId: _string | None
    ClientVpcIpAddress: _string | None
    Endpoints: _listOf__string | None
    ZookeeperId: _double | None
    ZookeeperVersion: _string | None

class NodeInfo(TypedDict, total=False):
    AddedToClusterTime: _string | None
    BrokerNodeInfo: BrokerNodeInfo | None
    ControllerNodeInfo: ControllerNodeInfo | None
    InstanceType: _string | None
    NodeARN: _string | None
    NodeType: NodeType | None
    ZookeeperNodeInfo: ZookeeperNodeInfo | None

_listOfNodeInfo = list[NodeInfo]
class ListNodesResponse(TypedDict, total=False):
    NextToken: _string | None
    NodeInfoList: _listOfNodeInfo | None

class ListReplicatorsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None
    ReplicatorNameFilter: _string | None

class ReplicationInfoSummary(TypedDict, total=False):
    SourceKafkaClusterAlias: _string | None
    TargetKafkaClusterAlias: _string | None

_listOfReplicationInfoSummary = list[ReplicationInfoSummary]
_listOfKafkaClusterSummary = list[KafkaClusterSummary]
class ReplicatorSummary(TypedDict, total=False):
    CreationTime: _timestampIso8601 | None
    CurrentVersion: _string | None
    IsReplicatorReference: _boolean | None
    KafkaClustersSummary: _listOfKafkaClusterSummary | None
    ReplicationInfoSummaryList: _listOfReplicationInfoSummary | None
    ReplicatorArn: _string | None
    ReplicatorName: _string | None
    ReplicatorResourceArn: _string | None
    ReplicatorState: ReplicatorState | None

_listOfReplicatorSummary = list[ReplicatorSummary]
class ListReplicatorsResponse(TypedDict, total=False):
    NextToken: _string | None
    Replicators: _listOfReplicatorSummary | None

class ListScramSecretsRequest(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

class ListScramSecretsResponse(TypedDict, total=False):
    NextToken: _string | None
    SecretArnList: _listOf__string | None

class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: _string

class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: _mapOf__string | None

class ListClientVpcConnectionsRequest(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfClientVpcConnection = list[ClientVpcConnection]
class ListClientVpcConnectionsResponse(TypedDict, total=False):
    ClientVpcConnections: _listOfClientVpcConnection | None
    NextToken: _string | None

class ListTopicsRequest(ServiceRequest):
    ClusterArn: _string
    MaxResults: MaxResults | None
    NextToken: _string | None
    TopicNameFilter: _string | None

class TopicInfo(TypedDict, total=False):
    TopicArn: _string | None
    TopicName: _string | None
    ReplicationFactor: _integer | None
    PartitionCount: _integer | None
    OutOfSyncReplicaCount: _integer | None

_listOfTopicInfo = list[TopicInfo]
class ListTopicsResponse(TypedDict, total=False):
    Topics: _listOfTopicInfo | None
    NextToken: _string | None

class ListVpcConnectionsRequest(ServiceRequest):
    MaxResults: MaxResults | None
    NextToken: _string | None

_listOfVpcConnection = list[VpcConnection]
class ListVpcConnectionsResponse(TypedDict, total=False):
    VpcConnections: _listOfVpcConnection | None
    NextToken: _string | None

class RejectClientVpcConnectionRequest(ServiceRequest):
    ClusterArn: _string
    VpcConnectionArn: _string

class RejectClientVpcConnectionResponse(TypedDict, total=False):
    pass

class PutClusterPolicyRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string | None
    Policy: _string

class PutClusterPolicyResponse(TypedDict, total=False):
    CurrentVersion: _string | None

class RebootBrokerRequest(ServiceRequest):
    BrokerIds: _listOf__string
    ClusterArn: _string

class RebootBrokerResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class TagResourceRequest(ServiceRequest):
    ResourceArn: _string
    Tags: _mapOf__string

class TopicReplicationUpdate(TypedDict, total=False):
    CopyAccessControlListsForTopics: _boolean
    CopyTopicConfigurations: _boolean
    DetectAndCopyNewTopics: _boolean
    TopicsToExclude: _listOf__stringMax249
    TopicsToReplicate: _listOf__stringMax249

class UntagResourceRequest(ServiceRequest):
    ResourceArn: _string
    TagKeys: _listOf__string

class UpdateBrokerCountRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    TargetNumberOfBrokerNodes: _integerMin1Max15

class UpdateBrokerCountResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateBrokerTypeRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    TargetInstanceType: _string

class UpdateBrokerTypeResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateBrokerStorageRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    TargetBrokerEBSVolumeInfo: _listOfBrokerEBSVolumeInfo

class UpdateBrokerStorageResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateClusterConfigurationRequest(ServiceRequest):
    ClusterArn: _string
    ConfigurationInfo: ConfigurationInfo
    CurrentVersion: _string

class UpdateClusterConfigurationResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateClusterKafkaVersionRequest(ServiceRequest):
    ClusterArn: _string
    ConfigurationInfo: ConfigurationInfo | None
    CurrentVersion: _string
    TargetKafkaVersion: _string

class UpdateClusterKafkaVersionResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateMonitoringRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    EnhancedMonitoring: EnhancedMonitoring | None
    OpenMonitoring: OpenMonitoringInfo | None
    LoggingInfo: LoggingInfo | None

class UpdateMonitoringResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateRebalancingRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    Rebalancing: Rebalancing

class UpdateRebalancingResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateReplicationInfoRequest(ServiceRequest):
    ConsumerGroupReplication: ConsumerGroupReplicationUpdate | None
    CurrentVersion: _string
    ReplicatorArn: _string
    SourceKafkaClusterArn: _string
    TargetKafkaClusterArn: _string
    TopicReplication: TopicReplicationUpdate | None

class UpdateReplicationInfoResponse(TypedDict, total=False):
    ReplicatorArn: _string | None
    ReplicatorState: ReplicatorState | None

class UpdateSecurityRequest(ServiceRequest):
    ClientAuthentication: ClientAuthentication | None
    ClusterArn: _string
    CurrentVersion: _string
    EncryptionInfo: EncryptionInfo | None

class UpdateSecurityResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateStorageRequest(ServiceRequest):
    ClusterArn: _string
    CurrentVersion: _string
    ProvisionedThroughput: ProvisionedThroughput | None
    StorageMode: StorageMode | None
    VolumeSizeGB: _integer | None

class UpdateStorageResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

class UpdateConfigurationRequest(ServiceRequest):
    Arn: _string
    Description: _string | None
    ServerProperties: _blob

class UpdateConfigurationResponse(TypedDict, total=False):
    Arn: _string | None
    LatestRevision: ConfigurationRevision | None

class UpdateConnectivityRequest(ServiceRequest):
    ClusterArn: _string
    ConnectivityInfo: ConnectivityInfo
    CurrentVersion: _string

class UpdateConnectivityResponse(TypedDict, total=False):
    ClusterArn: _string | None
    ClusterOperationArn: _string | None

_timestampUnix = datetime
class KafkaApi:

    service: str = "kafka"
    version: str = "2018-11-14"

    @handler("BatchAssociateScramSecret")
    def batch_associate_scram_secret(self, context: RequestContext, cluster_arn: _string, secret_arn_list: _listOf__string, **kwargs) -> BatchAssociateScramSecretResponse:
        raise NotImplementedError

    @handler("CreateCluster")
    def create_cluster(self, context: RequestContext, broker_node_group_info: BrokerNodeGroupInfo, kafka_version: _stringMin1Max128, number_of_broker_nodes: _integerMin1Max15, cluster_name: _stringMin1Max64, rebalancing: Rebalancing | None = None, client_authentication: ClientAuthentication | None = None, configuration_info: ConfigurationInfo | None = None, encryption_info: EncryptionInfo | None = None, enhanced_monitoring: EnhancedMonitoring | None = None, open_monitoring: OpenMonitoringInfo | None = None, logging_info: LoggingInfo | None = None, tags: _mapOf__string | None = None, storage_mode: StorageMode | None = None, **kwargs) -> CreateClusterResponse:
        raise NotImplementedError

    @handler("CreateClusterV2")
    def create_cluster_v2(self, context: RequestContext, cluster_name: _stringMin1Max64, tags: _mapOf__string | None = None, provisioned: ProvisionedRequest | None = None, serverless: ServerlessRequest | None = None, **kwargs) -> CreateClusterV2Response:
        raise NotImplementedError

    @handler("CreateConfiguration")
    def create_configuration(self, context: RequestContext, server_properties: _blob, name: _string, description: _string | None = None, kafka_versions: _listOf__string | None = None, **kwargs) -> CreateConfigurationResponse:
        raise NotImplementedError

    @handler("CreateReplicator")
    def create_replicator(self, context: RequestContext, service_execution_role_arn: _string, replicator_name: _stringMin1Max128Pattern09AZaZ09AZaZ0, replication_info_list: _listOfReplicationInfo, kafka_clusters: _listOfKafkaCluster, description: _stringMax1024 | None = None, tags: _mapOf__string | None = None, **kwargs) -> CreateReplicatorResponse:
        raise NotImplementedError

    @handler("CreateTopic")
    def create_topic(self, context: RequestContext, cluster_arn: _string, topic_name: _string, partition_count: _integerMin1, replication_factor: _integerMin1, configs: _string | None = None, **kwargs) -> CreateTopicResponse:
        raise NotImplementedError

    @handler("CreateVpcConnection")
    def create_vpc_connection(self, context: RequestContext, target_cluster_arn: _string, authentication: _string, vpc_id: _string, client_subnets: _listOf__string, security_groups: _listOf__string, tags: _mapOf__string | None = None, **kwargs) -> CreateVpcConnectionResponse:
        raise NotImplementedError

    @handler("DeleteCluster")
    def delete_cluster(self, context: RequestContext, cluster_arn: _string, current_version: _string | None = None, **kwargs) -> DeleteClusterResponse:
        raise NotImplementedError

    @handler("DeleteClusterPolicy")
    def delete_cluster_policy(self, context: RequestContext, cluster_arn: _string, **kwargs) -> DeleteClusterPolicyResponse:
        raise NotImplementedError

    @handler("DeleteConfiguration")
    def delete_configuration(self, context: RequestContext, arn: _string, **kwargs) -> DeleteConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteReplicator")
    def delete_replicator(self, context: RequestContext, replicator_arn: _string, current_version: _string | None = None, **kwargs) -> DeleteReplicatorResponse:
        raise NotImplementedError

    @handler("DeleteTopic")
    def delete_topic(self, context: RequestContext, cluster_arn: _string, topic_name: _string, **kwargs) -> DeleteTopicResponse:
        raise NotImplementedError

    @handler("DeleteVpcConnection")
    def delete_vpc_connection(self, context: RequestContext, arn: _string, **kwargs) -> DeleteVpcConnectionResponse:
        raise NotImplementedError

    @handler("DescribeCluster")
    def describe_cluster(self, context: RequestContext, cluster_arn: _string, **kwargs) -> DescribeClusterResponse:
        raise NotImplementedError

    @handler("DescribeClusterV2")
    def describe_cluster_v2(self, context: RequestContext, cluster_arn: _string, **kwargs) -> DescribeClusterV2Response:
        raise NotImplementedError

    @handler("DescribeClusterOperation")
    def describe_cluster_operation(self, context: RequestContext, cluster_operation_arn: _string, **kwargs) -> DescribeClusterOperationResponse:
        raise NotImplementedError

    @handler("DescribeClusterOperationV2")
    def describe_cluster_operation_v2(self, context: RequestContext, cluster_operation_arn: _string, **kwargs) -> DescribeClusterOperationV2Response:
        raise NotImplementedError

    @handler("DescribeConfiguration")
    def describe_configuration(self, context: RequestContext, arn: _string, **kwargs) -> DescribeConfigurationResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRevision")
    def describe_configuration_revision(self, context: RequestContext, revision: _long, arn: _string, **kwargs) -> DescribeConfigurationRevisionResponse:
        raise NotImplementedError

    @handler("DescribeReplicator")
    def describe_replicator(self, context: RequestContext, replicator_arn: _string, **kwargs) -> DescribeReplicatorResponse:
        raise NotImplementedError

    @handler("DescribeTopic")
    def describe_topic(self, context: RequestContext, cluster_arn: _string, topic_name: _string, **kwargs) -> DescribeTopicResponse:
        raise NotImplementedError

    @handler("DescribeTopicPartitions")
    def describe_topic_partitions(self, context: RequestContext, cluster_arn: _string, topic_name: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> DescribeTopicPartitionsResponse:
        raise NotImplementedError

    @handler("DescribeVpcConnection")
    def describe_vpc_connection(self, context: RequestContext, arn: _string, **kwargs) -> DescribeVpcConnectionResponse:
        raise NotImplementedError

    @handler("BatchDisassociateScramSecret")
    def batch_disassociate_scram_secret(self, context: RequestContext, cluster_arn: _string, secret_arn_list: _listOf__string, **kwargs) -> BatchDisassociateScramSecretResponse:
        raise NotImplementedError

    @handler("GetBootstrapBrokers")
    def get_bootstrap_brokers(self, context: RequestContext, cluster_arn: _string, **kwargs) -> GetBootstrapBrokersResponse:
        raise NotImplementedError

    @handler("GetCompatibleKafkaVersions")
    def get_compatible_kafka_versions(self, context: RequestContext, cluster_arn: _string | None = None, **kwargs) -> GetCompatibleKafkaVersionsResponse:
        raise NotImplementedError

    @handler("GetClusterPolicy")
    def get_cluster_policy(self, context: RequestContext, cluster_arn: _string, **kwargs) -> GetClusterPolicyResponse:
        raise NotImplementedError

    @handler("ListClusterOperations")
    def list_cluster_operations(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListClusterOperationsResponse:
        raise NotImplementedError

    @handler("ListClusterOperationsV2")
    def list_cluster_operations_v2(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListClusterOperationsV2Response:
        raise NotImplementedError

    @handler("ListClusters")
    def list_clusters(self, context: RequestContext, cluster_name_filter: _string | None = None, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListClustersResponse:
        raise NotImplementedError

    @handler("ListClustersV2")
    def list_clusters_v2(self, context: RequestContext, cluster_name_filter: _string | None = None, cluster_type_filter: _string | None = None, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListClustersV2Response:
        raise NotImplementedError

    @handler("ListConfigurationRevisions")
    def list_configuration_revisions(self, context: RequestContext, arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListConfigurationRevisionsResponse:
        raise NotImplementedError

    @handler("ListConfigurations")
    def list_configurations(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListConfigurationsResponse:
        raise NotImplementedError

    @handler("ListKafkaVersions")
    def list_kafka_versions(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListKafkaVersionsResponse:
        raise NotImplementedError

    @handler("ListNodes")
    def list_nodes(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListNodesResponse:
        raise NotImplementedError

    @handler("ListReplicators")
    def list_replicators(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, replicator_name_filter: _string | None = None, **kwargs) -> ListReplicatorsResponse:
        raise NotImplementedError

    @handler("ListScramSecrets")
    def list_scram_secrets(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListScramSecretsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(self, context: RequestContext, resource_arn: _string, **kwargs) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListClientVpcConnections")
    def list_client_vpc_connections(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListClientVpcConnectionsResponse:
        raise NotImplementedError

    @handler("ListTopics")
    def list_topics(self, context: RequestContext, cluster_arn: _string, max_results: MaxResults | None = None, next_token: _string | None = None, topic_name_filter: _string | None = None, **kwargs) -> ListTopicsResponse:
        raise NotImplementedError

    @handler("ListVpcConnections")
    def list_vpc_connections(self, context: RequestContext, max_results: MaxResults | None = None, next_token: _string | None = None, **kwargs) -> ListVpcConnectionsResponse:
        raise NotImplementedError

    @handler("RejectClientVpcConnection")
    def reject_client_vpc_connection(self, context: RequestContext, vpc_connection_arn: _string, cluster_arn: _string, **kwargs) -> RejectClientVpcConnectionResponse:
        raise NotImplementedError

    @handler("PutClusterPolicy")
    def put_cluster_policy(self, context: RequestContext, cluster_arn: _string, policy: _string, current_version: _string | None = None, **kwargs) -> PutClusterPolicyResponse:
        raise NotImplementedError

    @handler("RebootBroker")
    def reboot_broker(self, context: RequestContext, cluster_arn: _string, broker_ids: _listOf__string, **kwargs) -> RebootBrokerResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource_arn: _string, tags: _mapOf__string, **kwargs) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(self, context: RequestContext, tag_keys: _listOf__string, resource_arn: _string, **kwargs) -> None:
        raise NotImplementedError

    @handler("UpdateBrokerCount")
    def update_broker_count(self, context: RequestContext, cluster_arn: _string, current_version: _string, target_number_of_broker_nodes: _integerMin1Max15, **kwargs) -> UpdateBrokerCountResponse:
        raise NotImplementedError

    @handler("UpdateBrokerType")
    def update_broker_type(self, context: RequestContext, cluster_arn: _string, current_version: _string, target_instance_type: _string, **kwargs) -> UpdateBrokerTypeResponse:
        raise NotImplementedError

    @handler("UpdateBrokerStorage")
    def update_broker_storage(self, context: RequestContext, cluster_arn: _string, target_broker_ebs_volume_info: _listOfBrokerEBSVolumeInfo, current_version: _string, **kwargs) -> UpdateBrokerStorageResponse:
        raise NotImplementedError

    @handler("UpdateConfiguration")
    def update_configuration(self, context: RequestContext, arn: _string, server_properties: _blob, description: _string | None = None, **kwargs) -> UpdateConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateConnectivity")
    def update_connectivity(self, context: RequestContext, cluster_arn: _string, connectivity_info: ConnectivityInfo, current_version: _string, **kwargs) -> UpdateConnectivityResponse:
        raise NotImplementedError

    @handler("UpdateClusterConfiguration")
    def update_cluster_configuration(self, context: RequestContext, cluster_arn: _string, current_version: _string, configuration_info: ConfigurationInfo, **kwargs) -> UpdateClusterConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateClusterKafkaVersion")
    def update_cluster_kafka_version(self, context: RequestContext, cluster_arn: _string, target_kafka_version: _string, current_version: _string, configuration_info: ConfigurationInfo | None = None, **kwargs) -> UpdateClusterKafkaVersionResponse:
        raise NotImplementedError

    @handler("UpdateMonitoring")
    def update_monitoring(self, context: RequestContext, cluster_arn: _string, current_version: _string, enhanced_monitoring: EnhancedMonitoring | None = None, open_monitoring: OpenMonitoringInfo | None = None, logging_info: LoggingInfo | None = None, **kwargs) -> UpdateMonitoringResponse:
        raise NotImplementedError

    @handler("UpdateRebalancing")
    def update_rebalancing(self, context: RequestContext, cluster_arn: _string, current_version: _string, rebalancing: Rebalancing, **kwargs) -> UpdateRebalancingResponse:
        raise NotImplementedError

    @handler("UpdateReplicationInfo")
    def update_replication_info(self, context: RequestContext, replicator_arn: _string, source_kafka_cluster_arn: _string, current_version: _string, target_kafka_cluster_arn: _string, consumer_group_replication: ConsumerGroupReplicationUpdate | None = None, topic_replication: TopicReplicationUpdate | None = None, **kwargs) -> UpdateReplicationInfoResponse:
        raise NotImplementedError

    @handler("UpdateSecurity")
    def update_security(self, context: RequestContext, cluster_arn: _string, current_version: _string, client_authentication: ClientAuthentication | None = None, encryption_info: EncryptionInfo | None = None, **kwargs) -> UpdateSecurityResponse:
        raise NotImplementedError

    @handler("UpdateStorage")
    def update_storage(self, context: RequestContext, cluster_arn: _string, current_version: _string, provisioned_throughput: ProvisionedThroughput | None = None, storage_mode: StorageMode | None = None, volume_size_gb: _integer | None = None, **kwargs) -> UpdateStorageResponse:
        raise NotImplementedError

    @handler("UpdateTopic")
    def update_topic(self, context: RequestContext, cluster_arn: _string, topic_name: _string, configs: _string | None = None, partition_count: _integer | None = None, **kwargs) -> UpdateTopicResponse:
        raise NotImplementedError
