from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict
from collections.abc import Iterable, Iterator

from localemu.aws.api import handler, RequestContext, ServiceException, ServiceRequest
AdditionalContactEmailAddress = str
AdminEmail = str
AmazonResourceName = str
ArchiveArn = str
AttachmentContentDescription = str
AttachmentContentId = str
AttachmentContentType = str
AttachmentFileName = str
AttributesData = str
BlacklistItemName = str
BlacklistingDescription = str
BounceSubType = str
CampaignId = str
CaseId = str
Charset = str
ComplaintFeedbackType = str
ComplaintSubType = str
ConfigurationSetName = str
ContactListName = str
CustomRedirectDomain = str
DefaultDimensionValue = str
DeliverabilityTestSubject = str
Description = str
DiagnosticCode = str
DimensionName = str
DisplayName = str
DnsToken = str
Domain = str
EmailAddress = str
EmailSubject = str
EmailTemplateData = str
EmailTemplateHtml = str
EmailTemplateName = str
EmailTemplateSubject = str
EmailTemplateText = str
Enabled = bool
EnabledWrapper = bool
EndpointId = str
EndpointName = str
ErrorMessage = str
Esp = str
EventDestinationName = str
ExportedRecordsCount = int
FailedRecordsCount = int
FailedRecordsS3Url = str
FailureRedirectionURL = str
FeedbackId = str
GeneralEnforcementStatus = str
HostedZone = str
Identity = str
ImageUrl = str
InsightsEmailAddress = str
Ip = str
Isp = str
IspName = str
JobId = str
ListRecommendationFilterValue = str
ListTenantResourcesFilterValue = str
MailFromDomainName = str
Max24HourSend = float
MaxItems = int
MaxSendRate = float
MessageContent = str
MessageData = str
MessageHeaderName = str
MessageHeaderValue = str
MessageInsightsExportMaxResults = int
MessageTagName = str
MessageTagValue = str
MetricDimensionValue = str
NextToken = str
NextTokenV2 = str
OutboundMessageId = str
PageSizeV2 = int
Percentage = float
Percentage100Wrapper = int
Policy = str
PolicyName = str
PoolName = str
PrimaryNameServer = str
PrivateKey = str
ProcessedRecordsCount = int
QueryErrorMessage = str
QueryIdentifier = str
RblName = str
RecommendationDescription = str
Region = str
RenderedEmailTemplate = str
ReportId = str
ReportName = str
ReputationEntityFilterValue = str
ReputationEntityReference = str
S3Url = str
Selector = str
SendingPoolName = str
SentLast24Hours = float
StatusCause = str
Subject = str
SuccessRedirectionURL = str
TagKey = str
TagValue = str
TemplateContent = str
TenantId = str
TenantName = str
TopicName = str
UnsubscribeAll = bool
UseCaseDescription = str
UseDefaultIfPreferenceUnavailable = bool
WebsiteURL = str
class AttachmentContentDisposition(StrEnum):
    ATTACHMENT = "ATTACHMENT"
    INLINE = "INLINE"

class AttachmentContentTransferEncoding(StrEnum):
    BASE64 = "BASE64"
    QUOTED_PRINTABLE = "QUOTED_PRINTABLE"
    SEVEN_BIT = "SEVEN_BIT"

class BehaviorOnMxFailure(StrEnum):
    USE_DEFAULT_VALUE = "USE_DEFAULT_VALUE"
    REJECT_MESSAGE = "REJECT_MESSAGE"

class BounceType(StrEnum):
    UNDETERMINED = "UNDETERMINED"
    TRANSIENT = "TRANSIENT"
    PERMANENT = "PERMANENT"

class BulkEmailStatus(StrEnum):
    SUCCESS = "SUCCESS"
    MESSAGE_REJECTED = "MESSAGE_REJECTED"
    MAIL_FROM_DOMAIN_NOT_VERIFIED = "MAIL_FROM_DOMAIN_NOT_VERIFIED"
    CONFIGURATION_SET_NOT_FOUND = "CONFIGURATION_SET_NOT_FOUND"
    TEMPLATE_NOT_FOUND = "TEMPLATE_NOT_FOUND"
    ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
    ACCOUNT_THROTTLED = "ACCOUNT_THROTTLED"
    ACCOUNT_DAILY_QUOTA_EXCEEDED = "ACCOUNT_DAILY_QUOTA_EXCEEDED"
    INVALID_SENDING_POOL_NAME = "INVALID_SENDING_POOL_NAME"
    ACCOUNT_SENDING_PAUSED = "ACCOUNT_SENDING_PAUSED"
    CONFIGURATION_SET_SENDING_PAUSED = "CONFIGURATION_SET_SENDING_PAUSED"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    TRANSIENT_FAILURE = "TRANSIENT_FAILURE"
    FAILED = "FAILED"

class ContactLanguage(StrEnum):
    EN = "EN"
    JA = "JA"

class ContactListImportAction(StrEnum):
    DELETE = "DELETE"
    PUT = "PUT"

class DataFormat(StrEnum):
    CSV = "CSV"
    JSON = "JSON"

class DeliverabilityDashboardAccountStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PENDING_EXPIRATION = "PENDING_EXPIRATION"
    DISABLED = "DISABLED"

class DeliverabilityTestStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"

class DeliveryEventType(StrEnum):
    SEND = "SEND"
    DELIVERY = "DELIVERY"
    TRANSIENT_BOUNCE = "TRANSIENT_BOUNCE"
    PERMANENT_BOUNCE = "PERMANENT_BOUNCE"
    UNDETERMINED_BOUNCE = "UNDETERMINED_BOUNCE"
    COMPLAINT = "COMPLAINT"

class DimensionValueSource(StrEnum):
    MESSAGE_TAG = "MESSAGE_TAG"
    EMAIL_HEADER = "EMAIL_HEADER"
    LINK_TAG = "LINK_TAG"

class DkimSigningAttributesOrigin(StrEnum):
    AWS_SES = "AWS_SES"
    EXTERNAL = "EXTERNAL"
    AWS_SES_AF_SOUTH_1 = "AWS_SES_AF_SOUTH_1"
    AWS_SES_EU_NORTH_1 = "AWS_SES_EU_NORTH_1"
    AWS_SES_AP_SOUTH_1 = "AWS_SES_AP_SOUTH_1"
    AWS_SES_EU_WEST_3 = "AWS_SES_EU_WEST_3"
    AWS_SES_EU_WEST_2 = "AWS_SES_EU_WEST_2"
    AWS_SES_EU_SOUTH_1 = "AWS_SES_EU_SOUTH_1"
    AWS_SES_EU_WEST_1 = "AWS_SES_EU_WEST_1"
    AWS_SES_AP_NORTHEAST_3 = "AWS_SES_AP_NORTHEAST_3"
    AWS_SES_AP_NORTHEAST_2 = "AWS_SES_AP_NORTHEAST_2"
    AWS_SES_ME_SOUTH_1 = "AWS_SES_ME_SOUTH_1"
    AWS_SES_AP_NORTHEAST_1 = "AWS_SES_AP_NORTHEAST_1"
    AWS_SES_IL_CENTRAL_1 = "AWS_SES_IL_CENTRAL_1"
    AWS_SES_SA_EAST_1 = "AWS_SES_SA_EAST_1"
    AWS_SES_CA_CENTRAL_1 = "AWS_SES_CA_CENTRAL_1"
    AWS_SES_AP_SOUTHEAST_1 = "AWS_SES_AP_SOUTHEAST_1"
    AWS_SES_AP_SOUTHEAST_2 = "AWS_SES_AP_SOUTHEAST_2"
    AWS_SES_AP_SOUTHEAST_3 = "AWS_SES_AP_SOUTHEAST_3"
    AWS_SES_EU_CENTRAL_1 = "AWS_SES_EU_CENTRAL_1"
    AWS_SES_US_EAST_1 = "AWS_SES_US_EAST_1"
    AWS_SES_US_EAST_2 = "AWS_SES_US_EAST_2"
    AWS_SES_US_WEST_1 = "AWS_SES_US_WEST_1"
    AWS_SES_US_WEST_2 = "AWS_SES_US_WEST_2"
    AWS_SES_ME_CENTRAL_1 = "AWS_SES_ME_CENTRAL_1"
    AWS_SES_AP_SOUTH_2 = "AWS_SES_AP_SOUTH_2"
    AWS_SES_EU_CENTRAL_2 = "AWS_SES_EU_CENTRAL_2"
    AWS_SES_AP_SOUTHEAST_5 = "AWS_SES_AP_SOUTHEAST_5"
    AWS_SES_CA_WEST_1 = "AWS_SES_CA_WEST_1"

class DkimSigningKeyLength(StrEnum):
    RSA_1024_BIT = "RSA_1024_BIT"
    RSA_2048_BIT = "RSA_2048_BIT"

class DkimStatus(StrEnum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TEMPORARY_FAILURE = "TEMPORARY_FAILURE"
    NOT_STARTED = "NOT_STARTED"

class EmailAddressInsightsConfidenceVerdict(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class EngagementEventType(StrEnum):
    OPEN = "OPEN"
    CLICK = "CLICK"

class EventType(StrEnum):
    SEND = "SEND"
    REJECT = "REJECT"
    BOUNCE = "BOUNCE"
    COMPLAINT = "COMPLAINT"
    DELIVERY = "DELIVERY"
    OPEN = "OPEN"
    CLICK = "CLICK"
    RENDERING_FAILURE = "RENDERING_FAILURE"
    DELIVERY_DELAY = "DELIVERY_DELAY"
    SUBSCRIPTION = "SUBSCRIPTION"

class ExportSourceType(StrEnum):
    METRICS_DATA = "METRICS_DATA"
    MESSAGE_INSIGHTS = "MESSAGE_INSIGHTS"

class FeatureStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"

class HttpsPolicy(StrEnum):
    REQUIRE = "REQUIRE"
    REQUIRE_OPEN_ONLY = "REQUIRE_OPEN_ONLY"
    OPTIONAL = "OPTIONAL"

class IdentityType(StrEnum):
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    DOMAIN = "DOMAIN"
    MANAGED_DOMAIN = "MANAGED_DOMAIN"

class ImportDestinationType(StrEnum):
    SUPPRESSION_LIST = "SUPPRESSION_LIST"
    CONTACT_LIST = "CONTACT_LIST"

class JobStatus(StrEnum):
    CREATED = "CREATED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ListRecommendationsFilterKey(StrEnum):
    TYPE = "TYPE"
    IMPACT = "IMPACT"
    STATUS = "STATUS"
    RESOURCE_ARN = "RESOURCE_ARN"

class ListTenantResourcesFilterKey(StrEnum):
    RESOURCE_TYPE = "RESOURCE_TYPE"

class MailFromDomainStatus(StrEnum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TEMPORARY_FAILURE = "TEMPORARY_FAILURE"

class MailType(StrEnum):
    MARKETING = "MARKETING"
    TRANSACTIONAL = "TRANSACTIONAL"

class Metric(StrEnum):
    SEND = "SEND"
    COMPLAINT = "COMPLAINT"
    PERMANENT_BOUNCE = "PERMANENT_BOUNCE"
    TRANSIENT_BOUNCE = "TRANSIENT_BOUNCE"
    OPEN = "OPEN"
    CLICK = "CLICK"
    DELIVERY = "DELIVERY"
    DELIVERY_OPEN = "DELIVERY_OPEN"
    DELIVERY_CLICK = "DELIVERY_CLICK"
    DELIVERY_COMPLAINT = "DELIVERY_COMPLAINT"

class MetricAggregation(StrEnum):
    RATE = "RATE"
    VOLUME = "VOLUME"

class MetricDimensionName(StrEnum):
    EMAIL_IDENTITY = "EMAIL_IDENTITY"
    CONFIGURATION_SET = "CONFIGURATION_SET"
    ISP = "ISP"

class MetricNamespace(StrEnum):
    VDM = "VDM"

class QueryErrorCode(StrEnum):
    INTERNAL_FAILURE = "INTERNAL_FAILURE"
    ACCESS_DENIED = "ACCESS_DENIED"

class RecommendationImpact(StrEnum):
    LOW = "LOW"
    HIGH = "HIGH"

class RecommendationStatus(StrEnum):
    OPEN = "OPEN"
    FIXED = "FIXED"

class RecommendationType(StrEnum):
    DKIM = "DKIM"
    DMARC = "DMARC"
    SPF = "SPF"
    BIMI = "BIMI"
    COMPLAINT = "COMPLAINT"
    BOUNCE = "BOUNCE"
    FEEDBACK_3P = "FEEDBACK_3P"
    IP_LISTING = "IP_LISTING"

class ReputationEntityFilterKey(StrEnum):
    ENTITY_TYPE = "ENTITY_TYPE"
    REPUTATION_IMPACT = "REPUTATION_IMPACT"
    SENDING_STATUS = "SENDING_STATUS"
    ENTITY_REFERENCE_PREFIX = "ENTITY_REFERENCE_PREFIX"

class ReputationEntityType(StrEnum):
    RESOURCE = "RESOURCE"

class ResourceType(StrEnum):
    EMAIL_IDENTITY = "EMAIL_IDENTITY"
    CONFIGURATION_SET = "CONFIGURATION_SET"
    EMAIL_TEMPLATE = "EMAIL_TEMPLATE"

class ReviewStatus(StrEnum):
    PENDING = "PENDING"
    FAILED = "FAILED"
    GRANTED = "GRANTED"
    DENIED = "DENIED"

class ScalingMode(StrEnum):
    STANDARD = "STANDARD"
    MANAGED = "MANAGED"

class SendingStatus(StrEnum):
    ENABLED = "ENABLED"
    REINSTATED = "REINSTATED"
    DISABLED = "DISABLED"

class Status(StrEnum):
    CREATING = "CREATING"
    READY = "READY"
    FAILED = "FAILED"
    DELETING = "DELETING"

class SubscriptionStatus(StrEnum):
    OPT_IN = "OPT_IN"
    OPT_OUT = "OPT_OUT"

class SuppressionConfidenceVerdictThreshold(StrEnum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    MANAGED = "MANAGED"

class SuppressionListImportAction(StrEnum):
    DELETE = "DELETE"
    PUT = "PUT"

class SuppressionListReason(StrEnum):
    BOUNCE = "BOUNCE"
    COMPLAINT = "COMPLAINT"

class TlsPolicy(StrEnum):
    REQUIRE = "REQUIRE"
    OPTIONAL = "OPTIONAL"

class VerificationError(StrEnum):
    SERVICE_ERROR = "SERVICE_ERROR"
    DNS_SERVER_ERROR = "DNS_SERVER_ERROR"
    HOST_NOT_FOUND = "HOST_NOT_FOUND"
    TYPE_NOT_FOUND = "TYPE_NOT_FOUND"
    INVALID_VALUE = "INVALID_VALUE"
    REPLICATION_ACCESS_DENIED = "REPLICATION_ACCESS_DENIED"
    REPLICATION_PRIMARY_NOT_FOUND = "REPLICATION_PRIMARY_NOT_FOUND"
    REPLICATION_PRIMARY_BYO_DKIM_NOT_SUPPORTED = "REPLICATION_PRIMARY_BYO_DKIM_NOT_SUPPORTED"
    REPLICATION_REPLICA_AS_PRIMARY_NOT_SUPPORTED = "REPLICATION_REPLICA_AS_PRIMARY_NOT_SUPPORTED"
    REPLICATION_PRIMARY_INVALID_REGION = "REPLICATION_PRIMARY_INVALID_REGION"

class VerificationStatus(StrEnum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TEMPORARY_FAILURE = "TEMPORARY_FAILURE"
    NOT_STARTED = "NOT_STARTED"

class WarmupStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class AccountSuspendedException(ServiceException):
    code: str = "AccountSuspendedException"
    sender_fault: bool = False
    status_code: int = 400

class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExistsException"
    sender_fault: bool = False
    status_code: int = 400

class BadRequestException(ServiceException):
    code: str = "BadRequestException"
    sender_fault: bool = False
    status_code: int = 400

class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 500

class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 409

class InternalServiceErrorException(ServiceException):
    code: str = "InternalServiceErrorException"
    sender_fault: bool = False
    status_code: int = 500

class InvalidNextTokenException(ServiceException):
    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400

class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400

class MailFromDomainNotVerifiedException(ServiceException):
    code: str = "MailFromDomainNotVerifiedException"
    sender_fault: bool = False
    status_code: int = 400

class MessageRejected(ServiceException):
    code: str = "MessageRejected"
    sender_fault: bool = False
    status_code: int = 400

class NotFoundException(ServiceException):
    code: str = "NotFoundException"
    sender_fault: bool = False
    status_code: int = 404

class SendingPausedException(ServiceException):
    code: str = "SendingPausedException"
    sender_fault: bool = False
    status_code: int = 400

class TooManyRequestsException(ServiceException):
    code: str = "TooManyRequestsException"
    sender_fault: bool = False
    status_code: int = 429

class ReviewDetails(TypedDict, total=False):
    Status: ReviewStatus | None
    CaseId: CaseId | None

AdditionalContactEmailAddresses = list[AdditionalContactEmailAddress]
class AccountDetails(TypedDict, total=False):
    MailType: MailType | None
    WebsiteURL: WebsiteURL | None
    ContactLanguage: ContactLanguage | None
    UseCaseDescription: UseCaseDescription | None
    AdditionalContactEmailAddresses: AdditionalContactEmailAddresses | None
    ReviewDetails: ReviewDetails | None

class ArchivingOptions(TypedDict, total=False):
    ArchiveArn: ArchiveArn | None

RawAttachmentData = bytes
class Attachment(TypedDict, total=False):
    RawContent: RawAttachmentData
    ContentDisposition: AttachmentContentDisposition | None
    FileName: AttachmentFileName
    ContentDescription: AttachmentContentDescription | None
    ContentId: AttachmentContentId | None
    ContentTransferEncoding: AttachmentContentTransferEncoding | None
    ContentType: AttachmentContentType | None

AttachmentList = list[Attachment]
Timestamp = datetime
Dimensions = dict[MetricDimensionName, MetricDimensionValue]
class BatchGetMetricDataQuery(TypedDict, total=False):
    Id: QueryIdentifier
    Namespace: MetricNamespace
    Metric: Metric
    Dimensions: Dimensions | None
    StartDate: Timestamp
    EndDate: Timestamp

BatchGetMetricDataQueries = list[BatchGetMetricDataQuery]
class BatchGetMetricDataRequest(ServiceRequest):
    Queries: BatchGetMetricDataQueries

class MetricDataError(TypedDict, total=False):
    Id: QueryIdentifier | None
    Code: QueryErrorCode | None
    Message: QueryErrorMessage | None

MetricDataErrorList = list[MetricDataError]
Counter = int
MetricValueList = list[Counter]
TimestampList = list[Timestamp]
class MetricDataResult(TypedDict, total=False):
    Id: QueryIdentifier | None
    Timestamps: TimestampList | None
    Values: MetricValueList | None

MetricDataResultList = list[MetricDataResult]
class BatchGetMetricDataResponse(TypedDict, total=False):
    Results: MetricDataResultList | None
    Errors: MetricDataErrorList | None

class BlacklistEntry(TypedDict, total=False):
    RblName: RblName | None
    ListingTime: Timestamp | None
    Description: BlacklistingDescription | None

BlacklistEntries = list[BlacklistEntry]
BlacklistItemNames = list[BlacklistItemName]
BlacklistReport = dict[BlacklistItemName, BlacklistEntries]
class Content(TypedDict, total=False):
    Data: MessageData
    Charset: Charset | None

class Body(TypedDict, total=False):
    Text: Content | None
    Html: Content | None

class Bounce(TypedDict, total=False):
    BounceType: BounceType | None
    BounceSubType: BounceSubType | None
    DiagnosticCode: DiagnosticCode | None

class MessageHeader(TypedDict, total=False):
    Name: MessageHeaderName
    Value: MessageHeaderValue

MessageHeaderList = list[MessageHeader]
class EmailTemplateContent(TypedDict, total=False):
    Subject: EmailTemplateSubject | None
    Text: EmailTemplateText | None
    Html: EmailTemplateHtml | None

class Template(TypedDict, total=False):
    TemplateName: EmailTemplateName | None
    TemplateArn: AmazonResourceName | None
    TemplateContent: EmailTemplateContent | None
    TemplateData: EmailTemplateData | None
    Headers: MessageHeaderList | None
    Attachments: AttachmentList | None

class BulkEmailContent(TypedDict, total=False):
    Template: Template | None

class ReplacementTemplate(TypedDict, total=False):
    ReplacementTemplateData: EmailTemplateData | None

class ReplacementEmailContent(TypedDict, total=False):
    ReplacementTemplate: ReplacementTemplate | None

class MessageTag(TypedDict, total=False):
    Name: MessageTagName
    Value: MessageTagValue

MessageTagList = list[MessageTag]
EmailAddressList = list[EmailAddress]
class Destination(TypedDict, total=False):
    ToAddresses: EmailAddressList | None
    CcAddresses: EmailAddressList | None
    BccAddresses: EmailAddressList | None

class BulkEmailEntry(TypedDict, total=False):
    Destination: Destination
    ReplacementTags: MessageTagList | None
    ReplacementEmailContent: ReplacementEmailContent | None
    ReplacementHeaders: MessageHeaderList | None

BulkEmailEntryList = list[BulkEmailEntry]
class BulkEmailEntryResult(TypedDict, total=False):
    Status: BulkEmailStatus | None
    Error: ErrorMessage | None
    MessageId: OutboundMessageId | None

BulkEmailEntryResultList = list[BulkEmailEntryResult]
class CancelExportJobRequest(ServiceRequest):
    JobId: JobId

class CancelExportJobResponse(TypedDict, total=False):
    pass

class CloudWatchDimensionConfiguration(TypedDict, total=False):
    DimensionName: DimensionName
    DimensionValueSource: DimensionValueSource
    DefaultDimensionValue: DefaultDimensionValue

CloudWatchDimensionConfigurations = list[CloudWatchDimensionConfiguration]
class CloudWatchDestination(TypedDict, total=False):
    DimensionConfigurations: CloudWatchDimensionConfigurations

class Complaint(TypedDict, total=False):
    ComplaintSubType: ComplaintSubType | None
    ComplaintFeedbackType: ComplaintFeedbackType | None

ConfigurationSetNameList = list[ConfigurationSetName]
class TopicPreference(TypedDict, total=False):
    TopicName: TopicName
    SubscriptionStatus: SubscriptionStatus

TopicPreferenceList = list[TopicPreference]
class Contact(TypedDict, total=False):
    EmailAddress: EmailAddress | None
    TopicPreferences: TopicPreferenceList | None
    TopicDefaultPreferences: TopicPreferenceList | None
    UnsubscribeAll: UnsubscribeAll | None
    LastUpdatedTimestamp: Timestamp | None

class ContactList(TypedDict, total=False):
    ContactListName: ContactListName | None
    LastUpdatedTimestamp: Timestamp | None

class ContactListDestination(TypedDict, total=False):
    ContactListName: ContactListName
    ContactListImportAction: ContactListImportAction

class PinpointDestination(TypedDict, total=False):
    ApplicationArn: AmazonResourceName | None

class EventBridgeDestination(TypedDict, total=False):
    EventBusArn: AmazonResourceName

class SnsDestination(TypedDict, total=False):
    TopicArn: AmazonResourceName

class KinesisFirehoseDestination(TypedDict, total=False):
    IamRoleArn: AmazonResourceName
    DeliveryStreamArn: AmazonResourceName

EventTypes = list[EventType]
class EventDestinationDefinition(TypedDict, total=False):
    Enabled: Enabled | None
    MatchingEventTypes: EventTypes | None
    KinesisFirehoseDestination: KinesisFirehoseDestination | None
    CloudWatchDestination: CloudWatchDestination | None
    SnsDestination: SnsDestination | None
    EventBridgeDestination: EventBridgeDestination | None
    PinpointDestination: PinpointDestination | None

class CreateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName
    EventDestination: EventDestinationDefinition

class CreateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass

class GuardianOptions(TypedDict, total=False):
    OptimizedSharedDelivery: FeatureStatus | None

class DashboardOptions(TypedDict, total=False):
    EngagementMetrics: FeatureStatus | None

class VdmOptions(TypedDict, total=False):
    DashboardOptions: DashboardOptions | None
    GuardianOptions: GuardianOptions | None

class SuppressionConfidenceThreshold(TypedDict, total=False):
    ConfidenceVerdictThreshold: SuppressionConfidenceVerdictThreshold

class SuppressionConditionThreshold(TypedDict, total=False):
    ConditionThresholdEnabled: FeatureStatus
    OverallConfidenceThreshold: SuppressionConfidenceThreshold | None

class SuppressionValidationOptions(TypedDict, total=False):
    ConditionThreshold: SuppressionConditionThreshold

SuppressionListReasons = list[SuppressionListReason]
class SuppressionOptions(TypedDict, total=False):
    SuppressedReasons: SuppressionListReasons | None
    ValidationOptions: SuppressionValidationOptions | None

class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue

TagList = list[Tag]
class SendingOptions(TypedDict, total=False):
    SendingEnabled: Enabled | None

LastFreshStart = datetime
class ReputationOptions(TypedDict, total=False):
    ReputationMetricsEnabled: Enabled | None
    LastFreshStart: LastFreshStart | None

MaxDeliverySeconds = int
class DeliveryOptions(TypedDict, total=False):
    TlsPolicy: TlsPolicy | None
    SendingPoolName: PoolName | None
    MaxDeliverySeconds: MaxDeliverySeconds | None

class TrackingOptions(TypedDict, total=False):
    CustomRedirectDomain: CustomRedirectDomain
    HttpsPolicy: HttpsPolicy | None

class CreateConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: TrackingOptions | None
    DeliveryOptions: DeliveryOptions | None
    ReputationOptions: ReputationOptions | None
    SendingOptions: SendingOptions | None
    Tags: TagList | None
    SuppressionOptions: SuppressionOptions | None
    VdmOptions: VdmOptions | None
    ArchivingOptions: ArchivingOptions | None

class CreateConfigurationSetResponse(TypedDict, total=False):
    pass

class Topic(TypedDict, total=False):
    TopicName: TopicName
    DisplayName: DisplayName
    Description: Description | None
    DefaultSubscriptionStatus: SubscriptionStatus

Topics = list[Topic]
class CreateContactListRequest(ServiceRequest):
    ContactListName: ContactListName
    Topics: Topics | None
    Description: Description | None
    Tags: TagList | None

class CreateContactListResponse(TypedDict, total=False):
    pass

class CreateContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress
    TopicPreferences: TopicPreferenceList | None
    UnsubscribeAll: UnsubscribeAll | None
    AttributesData: AttributesData | None

class CreateContactResponse(TypedDict, total=False):
    pass

class CreateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    FromEmailAddress: EmailAddress
    TemplateSubject: EmailTemplateSubject
    TemplateContent: TemplateContent
    Tags: TagList | None
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL

class CreateCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass

class CreateDedicatedIpPoolRequest(ServiceRequest):
    PoolName: PoolName
    Tags: TagList | None
    ScalingMode: ScalingMode | None

class CreateDedicatedIpPoolResponse(TypedDict, total=False):
    pass

RawMessageData = bytes
class RawMessage(TypedDict, total=False):
    Data: RawMessageData

class Message(TypedDict, total=False):
    Subject: Content
    Body: Body
    Headers: MessageHeaderList | None
    Attachments: AttachmentList | None

class EmailContent(TypedDict, total=False):
    Simple: Message | None
    Raw: RawMessage | None
    Template: Template | None

class CreateDeliverabilityTestReportRequest(ServiceRequest):
    ReportName: ReportName | None
    FromEmailAddress: EmailAddress
    Content: EmailContent
    Tags: TagList | None

class CreateDeliverabilityTestReportResponse(TypedDict, total=False):
    ReportId: ReportId
    DeliverabilityTestStatus: DeliverabilityTestStatus

class CreateEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName
    Policy: Policy

class CreateEmailIdentityPolicyResponse(TypedDict, total=False):
    pass

class DkimSigningAttributes(TypedDict, total=False):
    DomainSigningSelector: Selector | None
    DomainSigningPrivateKey: PrivateKey | None
    NextSigningKeyLength: DkimSigningKeyLength | None
    DomainSigningAttributesOrigin: DkimSigningAttributesOrigin | None

class CreateEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity
    Tags: TagList | None
    DkimSigningAttributes: DkimSigningAttributes | None
    ConfigurationSetName: ConfigurationSetName | None

DnsTokenList = list[DnsToken]
class DkimAttributes(TypedDict, total=False):
    SigningEnabled: Enabled | None
    Status: DkimStatus | None
    Tokens: DnsTokenList | None
    SigningHostedZone: HostedZone | None
    SigningAttributesOrigin: DkimSigningAttributesOrigin | None
    NextSigningKeyLength: DkimSigningKeyLength | None
    CurrentSigningKeyLength: DkimSigningKeyLength | None
    LastKeyGenerationTimestamp: Timestamp | None

class CreateEmailIdentityResponse(TypedDict, total=False):
    IdentityType: IdentityType | None
    VerifiedForSendingStatus: Enabled | None
    DkimAttributes: DkimAttributes | None

class CreateEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent
    Tags: TagList | None

class CreateEmailTemplateResponse(TypedDict, total=False):
    pass

class ExportDestination(TypedDict, total=False):
    DataFormat: DataFormat
    S3Url: S3Url | None

LastEngagementEventList = list[EngagementEventType]
LastDeliveryEventList = list[DeliveryEventType]
IspFilterList = list[Isp]
EmailSubjectFilterList = list[EmailSubject]
EmailAddressFilterList = list[InsightsEmailAddress]
class MessageInsightsFilters(TypedDict, total=False):
    FromEmailAddress: EmailAddressFilterList | None
    Destination: EmailAddressFilterList | None
    Subject: EmailSubjectFilterList | None
    Isp: IspFilterList | None
    LastDeliveryEvent: LastDeliveryEventList | None
    LastEngagementEvent: LastEngagementEventList | None

class MessageInsightsDataSource(TypedDict, total=False):
    StartDate: Timestamp
    EndDate: Timestamp
    Include: MessageInsightsFilters | None
    Exclude: MessageInsightsFilters | None
    MaxResults: MessageInsightsExportMaxResults | None

class ExportMetric(TypedDict, total=False):
    Name: Metric | None
    Aggregation: MetricAggregation | None

ExportMetrics = list[ExportMetric]
ExportDimensionValue = list[MetricDimensionValue]
ExportDimensions = dict[MetricDimensionName, ExportDimensionValue]
class MetricsDataSource(TypedDict, total=False):
    Dimensions: ExportDimensions
    Namespace: MetricNamespace
    Metrics: ExportMetrics
    StartDate: Timestamp
    EndDate: Timestamp

class ExportDataSource(TypedDict, total=False):
    MetricsDataSource: MetricsDataSource | None
    MessageInsightsDataSource: MessageInsightsDataSource | None

class CreateExportJobRequest(ServiceRequest):
    ExportDataSource: ExportDataSource
    ExportDestination: ExportDestination

class CreateExportJobResponse(TypedDict, total=False):
    JobId: JobId | None

class ImportDataSource(TypedDict, total=False):
    S3Url: S3Url
    DataFormat: DataFormat

class SuppressionListDestination(TypedDict, total=False):
    SuppressionListImportAction: SuppressionListImportAction

class ImportDestination(TypedDict, total=False):
    SuppressionListDestination: SuppressionListDestination | None
    ContactListDestination: ContactListDestination | None

class CreateImportJobRequest(ServiceRequest):
    ImportDestination: ImportDestination
    ImportDataSource: ImportDataSource

class CreateImportJobResponse(TypedDict, total=False):
    JobId: JobId | None

class RouteDetails(TypedDict, total=False):
    Region: Region

RoutesDetails = list[RouteDetails]
class Details(TypedDict, total=False):
    RoutesDetails: RoutesDetails

class CreateMultiRegionEndpointRequest(ServiceRequest):
    EndpointName: EndpointName
    Details: Details
    Tags: TagList | None

class CreateMultiRegionEndpointResponse(TypedDict, total=False):
    Status: Status | None
    EndpointId: EndpointId | None

class CreateTenantRequest(ServiceRequest):
    TenantName: TenantName
    Tags: TagList | None

class CreateTenantResourceAssociationRequest(ServiceRequest):
    TenantName: TenantName
    ResourceArn: AmazonResourceName

class CreateTenantResourceAssociationResponse(TypedDict, total=False):
    pass

class CreateTenantResponse(TypedDict, total=False):
    TenantName: TenantName | None
    TenantId: TenantId | None
    TenantArn: AmazonResourceName | None
    CreatedTimestamp: Timestamp | None
    Tags: TagList | None
    SendingStatus: SendingStatus | None

class CustomVerificationEmailTemplateMetadata(TypedDict, total=False):
    TemplateName: EmailTemplateName | None
    FromEmailAddress: EmailAddress | None
    TemplateSubject: EmailTemplateSubject | None
    SuccessRedirectionURL: SuccessRedirectionURL | None
    FailureRedirectionURL: FailureRedirectionURL | None

CustomVerificationEmailTemplatesList = list[CustomVerificationEmailTemplateMetadata]
Volume = int
class DomainIspPlacement(TypedDict, total=False):
    IspName: IspName | None
    InboxRawCount: Volume | None
    SpamRawCount: Volume | None
    InboxPercentage: Percentage | None
    SpamPercentage: Percentage | None

DomainIspPlacements = list[DomainIspPlacement]
class VolumeStatistics(TypedDict, total=False):
    InboxRawCount: Volume | None
    SpamRawCount: Volume | None
    ProjectedInbox: Volume | None
    ProjectedSpam: Volume | None

class DailyVolume(TypedDict, total=False):
    StartDate: Timestamp | None
    VolumeStatistics: VolumeStatistics | None
    DomainIspPlacements: DomainIspPlacements | None

DailyVolumes = list[DailyVolume]
class DashboardAttributes(TypedDict, total=False):
    EngagementMetrics: FeatureStatus | None

class DedicatedIp(TypedDict, total=False):
    Ip: Ip
    WarmupStatus: WarmupStatus
    WarmupPercentage: Percentage100Wrapper
    PoolName: PoolName | None

DedicatedIpList = list[DedicatedIp]
class DedicatedIpPool(TypedDict, total=False):
    PoolName: PoolName
    ScalingMode: ScalingMode

class DeleteConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName

class DeleteConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass

class DeleteConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName

class DeleteConfigurationSetResponse(TypedDict, total=False):
    pass

class DeleteContactListRequest(ServiceRequest):
    ContactListName: ContactListName

class DeleteContactListResponse(TypedDict, total=False):
    pass

class DeleteContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress

class DeleteContactResponse(TypedDict, total=False):
    pass

class DeleteCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName

class DeleteCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass

class DeleteDedicatedIpPoolRequest(ServiceRequest):
    PoolName: PoolName

class DeleteDedicatedIpPoolResponse(TypedDict, total=False):
    pass

class DeleteEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName

class DeleteEmailIdentityPolicyResponse(TypedDict, total=False):
    pass

class DeleteEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity

class DeleteEmailIdentityResponse(TypedDict, total=False):
    pass

class DeleteEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName

class DeleteEmailTemplateResponse(TypedDict, total=False):
    pass

class DeleteMultiRegionEndpointRequest(ServiceRequest):
    EndpointName: EndpointName

class DeleteMultiRegionEndpointResponse(TypedDict, total=False):
    Status: Status | None

class DeleteSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress

class DeleteSuppressedDestinationResponse(TypedDict, total=False):
    pass

class DeleteTenantRequest(ServiceRequest):
    TenantName: TenantName

class DeleteTenantResourceAssociationRequest(ServiceRequest):
    TenantName: TenantName
    ResourceArn: AmazonResourceName

class DeleteTenantResourceAssociationResponse(TypedDict, total=False):
    pass

class DeleteTenantResponse(TypedDict, total=False):
    pass

class DeliverabilityTestReport(TypedDict, total=False):
    ReportId: ReportId | None
    ReportName: ReportName | None
    Subject: DeliverabilityTestSubject | None
    FromEmailAddress: EmailAddress | None
    CreateDate: Timestamp | None
    DeliverabilityTestStatus: DeliverabilityTestStatus | None

DeliverabilityTestReports = list[DeliverabilityTestReport]
Esps = list[Esp]
IpList = list[Ip]
class DomainDeliverabilityCampaign(TypedDict, total=False):
    CampaignId: CampaignId | None
    ImageUrl: ImageUrl | None
    Subject: Subject | None
    FromAddress: Identity | None
    SendingIps: IpList | None
    FirstSeenDateTime: Timestamp | None
    LastSeenDateTime: Timestamp | None
    InboxCount: Volume | None
    SpamCount: Volume | None
    ReadRate: Percentage | None
    DeleteRate: Percentage | None
    ReadDeleteRate: Percentage | None
    ProjectedVolume: Volume | None
    Esps: Esps | None

DomainDeliverabilityCampaignList = list[DomainDeliverabilityCampaign]
IspNameList = list[IspName]
class InboxPlacementTrackingOption(TypedDict, total=False):
    Global: Enabled | None
    TrackedIsps: IspNameList | None

class DomainDeliverabilityTrackingOption(TypedDict, total=False):
    Domain: Domain | None
    SubscriptionStartDate: Timestamp | None
    InboxPlacementTrackingOption: InboxPlacementTrackingOption | None

DomainDeliverabilityTrackingOptions = list[DomainDeliverabilityTrackingOption]
class EmailAddressInsightsVerdict(TypedDict, total=False):
    ConfidenceVerdict: EmailAddressInsightsConfidenceVerdict | None

class EmailAddressInsightsMailboxEvaluations(TypedDict, total=False):
    HasValidSyntax: EmailAddressInsightsVerdict | None
    HasValidDnsRecords: EmailAddressInsightsVerdict | None
    MailboxExists: EmailAddressInsightsVerdict | None
    IsRoleAddress: EmailAddressInsightsVerdict | None
    IsDisposable: EmailAddressInsightsVerdict | None
    IsRandomInput: EmailAddressInsightsVerdict | None

class EventDetails(TypedDict, total=False):
    Bounce: Bounce | None
    Complaint: Complaint | None

class InsightsEvent(TypedDict, total=False):
    Timestamp: Timestamp | None
    Type: EventType | None
    Details: EventDetails | None

InsightsEvents = list[InsightsEvent]
class EmailInsights(TypedDict, total=False):
    Destination: InsightsEmailAddress | None
    Isp: Isp | None
    Events: InsightsEvents | None

EmailInsightsList = list[EmailInsights]
class EmailTemplateMetadata(TypedDict, total=False):
    TemplateName: EmailTemplateName | None
    CreatedTimestamp: Timestamp | None

EmailTemplateMetadataList = list[EmailTemplateMetadata]
class EventDestination(TypedDict, total=False):
    Name: EventDestinationName
    Enabled: Enabled | None
    MatchingEventTypes: EventTypes
    KinesisFirehoseDestination: KinesisFirehoseDestination | None
    CloudWatchDestination: CloudWatchDestination | None
    SnsDestination: SnsDestination | None
    EventBridgeDestination: EventBridgeDestination | None
    PinpointDestination: PinpointDestination | None

EventDestinations = list[EventDestination]
class ExportJobSummary(TypedDict, total=False):
    JobId: JobId | None
    ExportSourceType: ExportSourceType | None
    JobStatus: JobStatus | None
    CreatedTimestamp: Timestamp | None
    CompletedTimestamp: Timestamp | None

ExportJobSummaryList = list[ExportJobSummary]
class ExportStatistics(TypedDict, total=False):
    ProcessedRecordsCount: ProcessedRecordsCount | None
    ExportedRecordsCount: ExportedRecordsCount | None

class FailureInfo(TypedDict, total=False):
    FailedRecordsS3Url: FailedRecordsS3Url | None
    ErrorMessage: ErrorMessage | None

class GetAccountRequest(ServiceRequest):
    pass

class GuardianAttributes(TypedDict, total=False):
    OptimizedSharedDelivery: FeatureStatus | None

class VdmAttributes(TypedDict, total=False):
    VdmEnabled: FeatureStatus
    DashboardAttributes: DashboardAttributes | None
    GuardianAttributes: GuardianAttributes | None

class SuppressionValidationAttributes(TypedDict, total=False):
    ConditionThreshold: SuppressionConditionThreshold

class SuppressionAttributes(TypedDict, total=False):
    SuppressedReasons: SuppressionListReasons | None
    ValidationAttributes: SuppressionValidationAttributes | None

class SendQuota(TypedDict, total=False):
    Max24HourSend: Max24HourSend | None
    MaxSendRate: MaxSendRate | None
    SentLast24Hours: SentLast24Hours | None

class GetAccountResponse(TypedDict, total=False):
    DedicatedIpAutoWarmupEnabled: Enabled | None
    EnforcementStatus: GeneralEnforcementStatus | None
    ProductionAccessEnabled: Enabled | None
    SendQuota: SendQuota | None
    SendingEnabled: Enabled | None
    SuppressionAttributes: SuppressionAttributes | None
    Details: AccountDetails | None
    VdmAttributes: VdmAttributes | None

class GetBlacklistReportsRequest(ServiceRequest):
    BlacklistItemNames: BlacklistItemNames

class GetBlacklistReportsResponse(TypedDict, total=False):
    BlacklistReport: BlacklistReport

class GetConfigurationSetEventDestinationsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName

class GetConfigurationSetEventDestinationsResponse(TypedDict, total=False):
    EventDestinations: EventDestinations | None

class GetConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName

class GetConfigurationSetResponse(TypedDict, total=False):
    ConfigurationSetName: ConfigurationSetName | None
    TrackingOptions: TrackingOptions | None
    DeliveryOptions: DeliveryOptions | None
    ReputationOptions: ReputationOptions | None
    SendingOptions: SendingOptions | None
    Tags: TagList | None
    SuppressionOptions: SuppressionOptions | None
    VdmOptions: VdmOptions | None
    ArchivingOptions: ArchivingOptions | None

class GetContactListRequest(ServiceRequest):
    ContactListName: ContactListName

class GetContactListResponse(TypedDict, total=False):
    ContactListName: ContactListName | None
    Topics: Topics | None
    Description: Description | None
    CreatedTimestamp: Timestamp | None
    LastUpdatedTimestamp: Timestamp | None
    Tags: TagList | None

class GetContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress

class GetContactResponse(TypedDict, total=False):
    ContactListName: ContactListName | None
    EmailAddress: EmailAddress | None
    TopicPreferences: TopicPreferenceList | None
    TopicDefaultPreferences: TopicPreferenceList | None
    UnsubscribeAll: UnsubscribeAll | None
    AttributesData: AttributesData | None
    CreatedTimestamp: Timestamp | None
    LastUpdatedTimestamp: Timestamp | None

class GetCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName

class GetCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    TemplateName: EmailTemplateName | None
    FromEmailAddress: EmailAddress | None
    TemplateSubject: EmailTemplateSubject | None
    TemplateContent: TemplateContent | None
    Tags: TagList | None
    SuccessRedirectionURL: SuccessRedirectionURL | None
    FailureRedirectionURL: FailureRedirectionURL | None

class GetDedicatedIpPoolRequest(ServiceRequest):
    PoolName: PoolName

class GetDedicatedIpPoolResponse(TypedDict, total=False):
    DedicatedIpPool: DedicatedIpPool | None

class GetDedicatedIpRequest(ServiceRequest):
    Ip: Ip

class GetDedicatedIpResponse(TypedDict, total=False):
    DedicatedIp: DedicatedIp | None

class GetDedicatedIpsRequest(ServiceRequest):
    PoolName: PoolName | None
    NextToken: NextToken | None
    PageSize: MaxItems | None

class GetDedicatedIpsResponse(TypedDict, total=False):
    DedicatedIps: DedicatedIpList | None
    NextToken: NextToken | None

class GetDeliverabilityDashboardOptionsRequest(ServiceRequest):
    pass

class GetDeliverabilityDashboardOptionsResponse(TypedDict, total=False):
    DashboardEnabled: Enabled
    SubscriptionExpiryDate: Timestamp | None
    AccountStatus: DeliverabilityDashboardAccountStatus | None
    ActiveSubscribedDomains: DomainDeliverabilityTrackingOptions | None
    PendingExpirationSubscribedDomains: DomainDeliverabilityTrackingOptions | None

class GetDeliverabilityTestReportRequest(ServiceRequest):
    ReportId: ReportId

class PlacementStatistics(TypedDict, total=False):
    InboxPercentage: Percentage | None
    SpamPercentage: Percentage | None
    MissingPercentage: Percentage | None
    SpfPercentage: Percentage | None
    DkimPercentage: Percentage | None

class IspPlacement(TypedDict, total=False):
    IspName: IspName | None
    PlacementStatistics: PlacementStatistics | None

IspPlacements = list[IspPlacement]
class GetDeliverabilityTestReportResponse(TypedDict, total=False):
    DeliverabilityTestReport: DeliverabilityTestReport
    OverallPlacement: PlacementStatistics
    IspPlacements: IspPlacements
    Message: MessageContent | None
    Tags: TagList | None

class GetDomainDeliverabilityCampaignRequest(ServiceRequest):
    CampaignId: CampaignId

class GetDomainDeliverabilityCampaignResponse(TypedDict, total=False):
    DomainDeliverabilityCampaign: DomainDeliverabilityCampaign

class GetDomainStatisticsReportRequest(ServiceRequest):
    Domain: Identity
    StartDate: Timestamp
    EndDate: Timestamp

class OverallVolume(TypedDict, total=False):
    VolumeStatistics: VolumeStatistics | None
    ReadRatePercent: Percentage | None
    DomainIspPlacements: DomainIspPlacements | None

class GetDomainStatisticsReportResponse(TypedDict, total=False):
    OverallVolume: OverallVolume
    DailyVolumes: DailyVolumes

class GetEmailAddressInsightsRequest(ServiceRequest):
    EmailAddress: EmailAddress

class MailboxValidation(TypedDict, total=False):
    IsValid: EmailAddressInsightsVerdict | None
    Evaluations: EmailAddressInsightsMailboxEvaluations | None

class GetEmailAddressInsightsResponse(TypedDict, total=False):
    MailboxValidation: MailboxValidation | None

class GetEmailIdentityPoliciesRequest(ServiceRequest):
    EmailIdentity: Identity

PolicyMap = dict[PolicyName, Policy]
class GetEmailIdentityPoliciesResponse(TypedDict, total=False):
    Policies: PolicyMap | None

class GetEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity

SerialNumber = int
class SOARecord(TypedDict, total=False):
    PrimaryNameServer: PrimaryNameServer | None
    AdminEmail: AdminEmail | None
    SerialNumber: SerialNumber | None

class VerificationInfo(TypedDict, total=False):
    LastCheckedTimestamp: Timestamp | None
    LastSuccessTimestamp: Timestamp | None
    ErrorType: VerificationError | None
    SOARecord: SOARecord | None

class MailFromAttributes(TypedDict, total=False):
    MailFromDomain: MailFromDomainName
    MailFromDomainStatus: MailFromDomainStatus
    BehaviorOnMxFailure: BehaviorOnMxFailure

class GetEmailIdentityResponse(TypedDict, total=False):
    IdentityType: IdentityType | None
    FeedbackForwardingStatus: Enabled | None
    VerifiedForSendingStatus: Enabled | None
    DkimAttributes: DkimAttributes | None
    MailFromAttributes: MailFromAttributes | None
    Policies: PolicyMap | None
    Tags: TagList | None
    ConfigurationSetName: ConfigurationSetName | None
    VerificationStatus: VerificationStatus | None
    VerificationInfo: VerificationInfo | None

class GetEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName

class GetEmailTemplateResponse(TypedDict, total=False):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent
    Tags: TagList | None

class GetExportJobRequest(ServiceRequest):
    JobId: JobId

class GetExportJobResponse(TypedDict, total=False):
    JobId: JobId | None
    ExportSourceType: ExportSourceType | None
    JobStatus: JobStatus | None
    ExportDestination: ExportDestination | None
    ExportDataSource: ExportDataSource | None
    CreatedTimestamp: Timestamp | None
    CompletedTimestamp: Timestamp | None
    FailureInfo: FailureInfo | None
    Statistics: ExportStatistics | None

class GetImportJobRequest(ServiceRequest):
    JobId: JobId

class GetImportJobResponse(TypedDict, total=False):
    JobId: JobId | None
    ImportDestination: ImportDestination | None
    ImportDataSource: ImportDataSource | None
    FailureInfo: FailureInfo | None
    JobStatus: JobStatus | None
    CreatedTimestamp: Timestamp | None
    CompletedTimestamp: Timestamp | None
    ProcessedRecordsCount: ProcessedRecordsCount | None
    FailedRecordsCount: FailedRecordsCount | None

class GetMessageInsightsRequest(ServiceRequest):
    MessageId: OutboundMessageId

class GetMessageInsightsResponse(TypedDict, total=False):
    MessageId: OutboundMessageId | None
    FromEmailAddress: InsightsEmailAddress | None
    Subject: EmailSubject | None
    EmailTags: MessageTagList | None
    Insights: EmailInsightsList | None

class GetMultiRegionEndpointRequest(ServiceRequest):
    EndpointName: EndpointName

class Route(TypedDict, total=False):
    Region: Region

Routes = list[Route]
class GetMultiRegionEndpointResponse(TypedDict, total=False):
    EndpointName: EndpointName | None
    EndpointId: EndpointId | None
    Routes: Routes | None
    Status: Status | None
    CreatedTimestamp: Timestamp | None
    LastUpdatedTimestamp: Timestamp | None

class GetReputationEntityRequest(ServiceRequest):
    ReputationEntityReference: ReputationEntityReference
    ReputationEntityType: ReputationEntityType

class StatusRecord(TypedDict, total=False):
    Status: SendingStatus | None
    Cause: StatusCause | None
    LastUpdatedTimestamp: Timestamp | None

class ReputationEntity(TypedDict, total=False):
    ReputationEntityReference: ReputationEntityReference | None
    ReputationEntityType: ReputationEntityType | None
    ReputationManagementPolicy: AmazonResourceName | None
    CustomerManagedStatus: StatusRecord | None
    AwsSesManagedStatus: StatusRecord | None
    SendingStatusAggregate: SendingStatus | None
    ReputationImpact: RecommendationImpact | None

class GetReputationEntityResponse(TypedDict, total=False):
    ReputationEntity: ReputationEntity | None

class GetSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress

class SuppressedDestinationAttributes(TypedDict, total=False):
    MessageId: OutboundMessageId | None
    FeedbackId: FeedbackId | None

class SuppressedDestination(TypedDict, total=False):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason
    LastUpdateTime: Timestamp
    Attributes: SuppressedDestinationAttributes | None

class GetSuppressedDestinationResponse(TypedDict, total=False):
    SuppressedDestination: SuppressedDestination

class GetTenantRequest(ServiceRequest):
    TenantName: TenantName

class Tenant(TypedDict, total=False):
    TenantName: TenantName | None
    TenantId: TenantId | None
    TenantArn: AmazonResourceName | None
    CreatedTimestamp: Timestamp | None
    Tags: TagList | None
    SendingStatus: SendingStatus | None

class GetTenantResponse(TypedDict, total=False):
    Tenant: Tenant | None

class IdentityInfo(TypedDict, total=False):
    IdentityType: IdentityType | None
    IdentityName: Identity | None
    SendingEnabled: Enabled | None
    VerificationStatus: VerificationStatus | None

IdentityInfoList = list[IdentityInfo]
class ImportJobSummary(TypedDict, total=False):
    JobId: JobId | None
    ImportDestination: ImportDestination | None
    JobStatus: JobStatus | None
    CreatedTimestamp: Timestamp | None
    ProcessedRecordsCount: ProcessedRecordsCount | None
    FailedRecordsCount: FailedRecordsCount | None

ImportJobSummaryList = list[ImportJobSummary]
class ListConfigurationSetsRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListConfigurationSetsResponse(TypedDict, total=False):
    ConfigurationSets: ConfigurationSetNameList | None
    NextToken: NextToken | None

class ListContactListsRequest(ServiceRequest):
    PageSize: MaxItems | None
    NextToken: NextToken | None

ListOfContactLists = list[ContactList]
class ListContactListsResponse(TypedDict, total=False):
    ContactLists: ListOfContactLists | None
    NextToken: NextToken | None

class TopicFilter(TypedDict, total=False):
    TopicName: TopicName | None
    UseDefaultIfPreferenceUnavailable: UseDefaultIfPreferenceUnavailable | None

class ListContactsFilter(TypedDict, total=False):
    FilteredStatus: SubscriptionStatus | None
    TopicFilter: TopicFilter | None

class ListContactsRequest(ServiceRequest):
    ContactListName: ContactListName
    Filter: ListContactsFilter | None
    PageSize: MaxItems | None
    NextToken: NextToken | None

ListOfContacts = list[Contact]
class ListContactsResponse(TypedDict, total=False):
    Contacts: ListOfContacts | None
    NextToken: NextToken | None

class ListCustomVerificationEmailTemplatesRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListCustomVerificationEmailTemplatesResponse(TypedDict, total=False):
    CustomVerificationEmailTemplates: CustomVerificationEmailTemplatesList | None
    NextToken: NextToken | None

class ListDedicatedIpPoolsRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

ListOfDedicatedIpPools = list[PoolName]
class ListDedicatedIpPoolsResponse(TypedDict, total=False):
    DedicatedIpPools: ListOfDedicatedIpPools | None
    NextToken: NextToken | None

class ListDeliverabilityTestReportsRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListDeliverabilityTestReportsResponse(TypedDict, total=False):
    DeliverabilityTestReports: DeliverabilityTestReports
    NextToken: NextToken | None

class ListDomainDeliverabilityCampaignsRequest(ServiceRequest):
    StartDate: Timestamp
    EndDate: Timestamp
    SubscribedDomain: Domain
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListDomainDeliverabilityCampaignsResponse(TypedDict, total=False):
    DomainDeliverabilityCampaigns: DomainDeliverabilityCampaignList
    NextToken: NextToken | None

class ListEmailIdentitiesRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListEmailIdentitiesResponse(TypedDict, total=False):
    EmailIdentities: IdentityInfoList | None
    NextToken: NextToken | None

class ListEmailTemplatesRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListEmailTemplatesResponse(TypedDict, total=False):
    TemplatesMetadata: EmailTemplateMetadataList | None
    NextToken: NextToken | None

class ListExportJobsRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None
    ExportSourceType: ExportSourceType | None
    JobStatus: JobStatus | None

class ListExportJobsResponse(TypedDict, total=False):
    ExportJobs: ExportJobSummaryList | None
    NextToken: NextToken | None

class ListImportJobsRequest(ServiceRequest):
    ImportDestinationType: ImportDestinationType | None
    NextToken: NextToken | None
    PageSize: MaxItems | None

class ListImportJobsResponse(TypedDict, total=False):
    ImportJobs: ImportJobSummaryList | None
    NextToken: NextToken | None

class ListManagementOptions(TypedDict, total=False):
    ContactListName: ContactListName
    TopicName: TopicName | None

class ListMultiRegionEndpointsRequest(ServiceRequest):
    NextToken: NextTokenV2 | None
    PageSize: PageSizeV2 | None

Regions = list[Region]
class MultiRegionEndpoint(TypedDict, total=False):
    EndpointName: EndpointName | None
    Status: Status | None
    EndpointId: EndpointId | None
    Regions: Regions | None
    CreatedTimestamp: Timestamp | None
    LastUpdatedTimestamp: Timestamp | None

MultiRegionEndpoints = list[MultiRegionEndpoint]
class ListMultiRegionEndpointsResponse(TypedDict, total=False):
    MultiRegionEndpoints: MultiRegionEndpoints | None
    NextToken: NextTokenV2 | None

ListRecommendationsFilter = dict[ListRecommendationsFilterKey, ListRecommendationFilterValue]
class ListRecommendationsRequest(ServiceRequest):
    Filter: ListRecommendationsFilter | None
    NextToken: NextToken | None
    PageSize: MaxItems | None

class Recommendation(TypedDict, total=False):
    ResourceArn: AmazonResourceName | None
    Type: RecommendationType | None
    Description: RecommendationDescription | None
    Status: RecommendationStatus | None
    CreatedTimestamp: Timestamp | None
    LastUpdatedTimestamp: Timestamp | None
    Impact: RecommendationImpact | None

RecommendationsList = list[Recommendation]
class ListRecommendationsResponse(TypedDict, total=False):
    Recommendations: RecommendationsList | None
    NextToken: NextToken | None

ReputationEntityFilter = dict[ReputationEntityFilterKey, ReputationEntityFilterValue]
class ListReputationEntitiesRequest(ServiceRequest):
    Filter: ReputationEntityFilter | None
    NextToken: NextToken | None
    PageSize: MaxItems | None

ReputationEntitiesList = list[ReputationEntity]
class ListReputationEntitiesResponse(TypedDict, total=False):
    ReputationEntities: ReputationEntitiesList | None
    NextToken: NextToken | None

class ListResourceTenantsRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    PageSize: MaxItems | None
    NextToken: NextToken | None

class ResourceTenantMetadata(TypedDict, total=False):
    TenantName: TenantName | None
    TenantId: TenantId | None
    ResourceArn: AmazonResourceName | None
    AssociatedTimestamp: Timestamp | None

ResourceTenantMetadataList = list[ResourceTenantMetadata]
class ListResourceTenantsResponse(TypedDict, total=False):
    ResourceTenants: ResourceTenantMetadataList | None
    NextToken: NextToken | None

class ListSuppressedDestinationsRequest(ServiceRequest):
    Reasons: SuppressionListReasons | None
    StartDate: Timestamp | None
    EndDate: Timestamp | None
    NextToken: NextToken | None
    PageSize: MaxItems | None

class SuppressedDestinationSummary(TypedDict, total=False):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason
    LastUpdateTime: Timestamp

SuppressedDestinationSummaries = list[SuppressedDestinationSummary]
class ListSuppressedDestinationsResponse(TypedDict, total=False):
    SuppressedDestinationSummaries: SuppressedDestinationSummaries | None
    NextToken: NextToken | None

class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName

class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList

ListTenantResourcesFilter = dict[ListTenantResourcesFilterKey, ListTenantResourcesFilterValue]
class ListTenantResourcesRequest(ServiceRequest):
    TenantName: TenantName
    Filter: ListTenantResourcesFilter | None
    PageSize: MaxItems | None
    NextToken: NextToken | None

class TenantResource(TypedDict, total=False):
    ResourceType: ResourceType | None
    ResourceArn: AmazonResourceName | None

TenantResourceList = list[TenantResource]
class ListTenantResourcesResponse(TypedDict, total=False):
    TenantResources: TenantResourceList | None
    NextToken: NextToken | None

class ListTenantsRequest(ServiceRequest):
    NextToken: NextToken | None
    PageSize: MaxItems | None

class TenantInfo(TypedDict, total=False):
    TenantName: TenantName | None
    TenantId: TenantId | None
    TenantArn: AmazonResourceName | None
    CreatedTimestamp: Timestamp | None

TenantInfoList = list[TenantInfo]
class ListTenantsResponse(TypedDict, total=False):
    Tenants: TenantInfoList | None
    NextToken: NextToken | None

class PutAccountDedicatedIpWarmupAttributesRequest(ServiceRequest):
    AutoWarmupEnabled: Enabled | None

class PutAccountDedicatedIpWarmupAttributesResponse(TypedDict, total=False):
    pass

class PutAccountDetailsRequest(ServiceRequest):
    MailType: MailType
    WebsiteURL: WebsiteURL
    ContactLanguage: ContactLanguage | None
    UseCaseDescription: UseCaseDescription | None
    AdditionalContactEmailAddresses: AdditionalContactEmailAddresses | None
    ProductionAccessEnabled: EnabledWrapper | None

class PutAccountDetailsResponse(TypedDict, total=False):
    pass

class PutAccountSendingAttributesRequest(ServiceRequest):
    SendingEnabled: Enabled | None

class PutAccountSendingAttributesResponse(TypedDict, total=False):
    pass

class PutAccountSuppressionAttributesRequest(ServiceRequest):
    SuppressedReasons: SuppressionListReasons | None
    ValidationAttributes: SuppressionValidationAttributes | None

class PutAccountSuppressionAttributesResponse(TypedDict, total=False):
    pass

class PutAccountVdmAttributesRequest(ServiceRequest):
    VdmAttributes: VdmAttributes

class PutAccountVdmAttributesResponse(TypedDict, total=False):
    pass

class PutConfigurationSetArchivingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    ArchiveArn: ArchiveArn | None

class PutConfigurationSetArchivingOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetDeliveryOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TlsPolicy: TlsPolicy | None
    SendingPoolName: SendingPoolName | None
    MaxDeliverySeconds: MaxDeliverySeconds | None

class PutConfigurationSetDeliveryOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetReputationOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    ReputationMetricsEnabled: Enabled | None

class PutConfigurationSetReputationOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetSendingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    SendingEnabled: Enabled | None

class PutConfigurationSetSendingOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetSuppressionOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    SuppressedReasons: SuppressionListReasons | None
    ValidationOptions: SuppressionValidationOptions | None

class PutConfigurationSetSuppressionOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetTrackingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    CustomRedirectDomain: CustomRedirectDomain | None
    HttpsPolicy: HttpsPolicy | None

class PutConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    pass

class PutConfigurationSetVdmOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    VdmOptions: VdmOptions | None

class PutConfigurationSetVdmOptionsResponse(TypedDict, total=False):
    pass

class PutDedicatedIpInPoolRequest(ServiceRequest):
    Ip: Ip
    DestinationPoolName: PoolName

class PutDedicatedIpInPoolResponse(TypedDict, total=False):
    pass

class PutDedicatedIpPoolScalingAttributesRequest(ServiceRequest):
    PoolName: PoolName
    ScalingMode: ScalingMode

class PutDedicatedIpPoolScalingAttributesResponse(TypedDict, total=False):
    pass

class PutDedicatedIpWarmupAttributesRequest(ServiceRequest):
    Ip: Ip
    WarmupPercentage: Percentage100Wrapper

class PutDedicatedIpWarmupAttributesResponse(TypedDict, total=False):
    pass

class PutDeliverabilityDashboardOptionRequest(ServiceRequest):
    DashboardEnabled: Enabled
    SubscribedDomains: DomainDeliverabilityTrackingOptions | None

class PutDeliverabilityDashboardOptionResponse(TypedDict, total=False):
    pass

class PutEmailIdentityConfigurationSetAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    ConfigurationSetName: ConfigurationSetName | None

class PutEmailIdentityConfigurationSetAttributesResponse(TypedDict, total=False):
    pass

class PutEmailIdentityDkimAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    SigningEnabled: Enabled | None

class PutEmailIdentityDkimAttributesResponse(TypedDict, total=False):
    pass

class PutEmailIdentityDkimSigningAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    SigningAttributesOrigin: DkimSigningAttributesOrigin
    SigningAttributes: DkimSigningAttributes | None

class PutEmailIdentityDkimSigningAttributesResponse(TypedDict, total=False):
    DkimStatus: DkimStatus | None
    DkimTokens: DnsTokenList | None
    SigningHostedZone: HostedZone | None

class PutEmailIdentityFeedbackAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    EmailForwardingEnabled: Enabled | None

class PutEmailIdentityFeedbackAttributesResponse(TypedDict, total=False):
    pass

class PutEmailIdentityMailFromAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    MailFromDomain: MailFromDomainName | None
    BehaviorOnMxFailure: BehaviorOnMxFailure | None

class PutEmailIdentityMailFromAttributesResponse(TypedDict, total=False):
    pass

class PutSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason

class PutSuppressedDestinationResponse(TypedDict, total=False):
    pass

class SendBulkEmailRequest(ServiceRequest):
    FromEmailAddress: EmailAddress | None
    FromEmailAddressIdentityArn: AmazonResourceName | None
    ReplyToAddresses: EmailAddressList | None
    FeedbackForwardingEmailAddress: EmailAddress | None
    FeedbackForwardingEmailAddressIdentityArn: AmazonResourceName | None
    DefaultEmailTags: MessageTagList | None
    DefaultContent: BulkEmailContent
    BulkEmailEntries: BulkEmailEntryList
    ConfigurationSetName: ConfigurationSetName | None
    EndpointId: EndpointId | None
    TenantName: TenantName | None

class SendBulkEmailResponse(TypedDict, total=False):
    BulkEmailEntryResults: BulkEmailEntryResultList

class SendCustomVerificationEmailRequest(ServiceRequest):
    EmailAddress: EmailAddress
    TemplateName: EmailTemplateName
    ConfigurationSetName: ConfigurationSetName | None

class SendCustomVerificationEmailResponse(TypedDict, total=False):
    MessageId: OutboundMessageId | None

class SendEmailRequest(ServiceRequest):
    FromEmailAddress: EmailAddress | None
    FromEmailAddressIdentityArn: AmazonResourceName | None
    Destination: Destination | None
    ReplyToAddresses: EmailAddressList | None
    FeedbackForwardingEmailAddress: EmailAddress | None
    FeedbackForwardingEmailAddressIdentityArn: AmazonResourceName | None
    Content: EmailContent
    EmailTags: MessageTagList | None
    ConfigurationSetName: ConfigurationSetName | None
    EndpointId: EndpointId | None
    TenantName: TenantName | None
    ListManagementOptions: ListManagementOptions | None

class SendEmailResponse(TypedDict, total=False):
    MessageId: OutboundMessageId | None

TagKeyList = list[TagKey]
class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList

class TagResourceResponse(TypedDict, total=False):
    pass

class TestRenderEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateData: EmailTemplateData

class TestRenderEmailTemplateResponse(TypedDict, total=False):
    RenderedTemplate: RenderedEmailTemplate

class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList

class UntagResourceResponse(TypedDict, total=False):
    pass

class UpdateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName
    EventDestination: EventDestinationDefinition

class UpdateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass

class UpdateContactListRequest(ServiceRequest):
    ContactListName: ContactListName
    Topics: Topics | None
    Description: Description | None

class UpdateContactListResponse(TypedDict, total=False):
    pass

class UpdateContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress
    TopicPreferences: TopicPreferenceList | None
    UnsubscribeAll: UnsubscribeAll | None
    AttributesData: AttributesData | None

class UpdateContactResponse(TypedDict, total=False):
    pass

class UpdateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    FromEmailAddress: EmailAddress
    TemplateSubject: EmailTemplateSubject
    TemplateContent: TemplateContent
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL

class UpdateCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass

class UpdateEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName
    Policy: Policy

class UpdateEmailIdentityPolicyResponse(TypedDict, total=False):
    pass

class UpdateEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent

class UpdateEmailTemplateResponse(TypedDict, total=False):
    pass

class UpdateReputationEntityCustomerManagedStatusRequest(ServiceRequest):
    ReputationEntityType: ReputationEntityType
    ReputationEntityReference: ReputationEntityReference
    SendingStatus: SendingStatus

class UpdateReputationEntityCustomerManagedStatusResponse(TypedDict, total=False):
    pass

class UpdateReputationEntityPolicyRequest(ServiceRequest):
    ReputationEntityType: ReputationEntityType
    ReputationEntityReference: ReputationEntityReference
    ReputationEntityPolicy: AmazonResourceName

class UpdateReputationEntityPolicyResponse(TypedDict, total=False):
    pass

class Sesv2Api:

    service: str = "sesv2"
    version: str = "2019-09-27"

    @handler("BatchGetMetricData")
    def batch_get_metric_data(self, context: RequestContext, queries: BatchGetMetricDataQueries, **kwargs) -> BatchGetMetricDataResponse:
        raise NotImplementedError

    @handler("CancelExportJob")
    def cancel_export_job(self, context: RequestContext, job_id: JobId, **kwargs) -> CancelExportJobResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSet")
    def create_configuration_set(self, context: RequestContext, configuration_set_name: ConfigurationSetName, tracking_options: TrackingOptions | None = None, delivery_options: DeliveryOptions | None = None, reputation_options: ReputationOptions | None = None, sending_options: SendingOptions | None = None, tags: TagList | None = None, suppression_options: SuppressionOptions | None = None, vdm_options: VdmOptions | None = None, archiving_options: ArchivingOptions | None = None, **kwargs) -> CreateConfigurationSetResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSetEventDestination")
    def create_configuration_set_event_destination(self, context: RequestContext, configuration_set_name: ConfigurationSetName, event_destination_name: EventDestinationName, event_destination: EventDestinationDefinition, **kwargs) -> CreateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("CreateContact")
    def create_contact(self, context: RequestContext, contact_list_name: ContactListName, email_address: EmailAddress, topic_preferences: TopicPreferenceList | None = None, unsubscribe_all: UnsubscribeAll | None = None, attributes_data: AttributesData | None = None, **kwargs) -> CreateContactResponse:
        raise NotImplementedError

    @handler("CreateContactList")
    def create_contact_list(self, context: RequestContext, contact_list_name: ContactListName, topics: Topics | None = None, description: Description | None = None, tags: TagList | None = None, **kwargs) -> CreateContactListResponse:
        raise NotImplementedError

    @handler("CreateCustomVerificationEmailTemplate")
    def create_custom_verification_email_template(self, context: RequestContext, template_name: EmailTemplateName, from_email_address: EmailAddress, template_subject: EmailTemplateSubject, template_content: TemplateContent, success_redirection_url: SuccessRedirectionURL, failure_redirection_url: FailureRedirectionURL, tags: TagList | None = None, **kwargs) -> CreateCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("CreateDedicatedIpPool")
    def create_dedicated_ip_pool(self, context: RequestContext, pool_name: PoolName, tags: TagList | None = None, scaling_mode: ScalingMode | None = None, **kwargs) -> CreateDedicatedIpPoolResponse:
        raise NotImplementedError

    @handler("CreateDeliverabilityTestReport")
    def create_deliverability_test_report(self, context: RequestContext, from_email_address: EmailAddress, content: EmailContent, report_name: ReportName | None = None, tags: TagList | None = None, **kwargs) -> CreateDeliverabilityTestReportResponse:
        raise NotImplementedError

    @handler("CreateEmailIdentity")
    def create_email_identity(self, context: RequestContext, email_identity: Identity, tags: TagList | None = None, dkim_signing_attributes: DkimSigningAttributes | None = None, configuration_set_name: ConfigurationSetName | None = None, **kwargs) -> CreateEmailIdentityResponse:
        raise NotImplementedError

    @handler("CreateEmailIdentityPolicy")
    def create_email_identity_policy(self, context: RequestContext, email_identity: Identity, policy_name: PolicyName, policy: Policy, **kwargs) -> CreateEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("CreateEmailTemplate")
    def create_email_template(self, context: RequestContext, template_name: EmailTemplateName, template_content: EmailTemplateContent, tags: TagList | None = None, **kwargs) -> CreateEmailTemplateResponse:
        raise NotImplementedError

    @handler("CreateExportJob")
    def create_export_job(self, context: RequestContext, export_data_source: ExportDataSource, export_destination: ExportDestination, **kwargs) -> CreateExportJobResponse:
        raise NotImplementedError

    @handler("CreateImportJob")
    def create_import_job(self, context: RequestContext, import_destination: ImportDestination, import_data_source: ImportDataSource, **kwargs) -> CreateImportJobResponse:
        raise NotImplementedError

    @handler("CreateMultiRegionEndpoint")
    def create_multi_region_endpoint(self, context: RequestContext, endpoint_name: EndpointName, details: Details, tags: TagList | None = None, **kwargs) -> CreateMultiRegionEndpointResponse:
        raise NotImplementedError

    @handler("CreateTenant")
    def create_tenant(self, context: RequestContext, tenant_name: TenantName, tags: TagList | None = None, **kwargs) -> CreateTenantResponse:
        raise NotImplementedError

    @handler("CreateTenantResourceAssociation")
    def create_tenant_resource_association(self, context: RequestContext, tenant_name: TenantName, resource_arn: AmazonResourceName, **kwargs) -> CreateTenantResourceAssociationResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSet")
    def delete_configuration_set(self, context: RequestContext, configuration_set_name: ConfigurationSetName, **kwargs) -> DeleteConfigurationSetResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSetEventDestination")
    def delete_configuration_set_event_destination(self, context: RequestContext, configuration_set_name: ConfigurationSetName, event_destination_name: EventDestinationName, **kwargs) -> DeleteConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("DeleteContact")
    def delete_contact(self, context: RequestContext, contact_list_name: ContactListName, email_address: EmailAddress, **kwargs) -> DeleteContactResponse:
        raise NotImplementedError

    @handler("DeleteContactList")
    def delete_contact_list(self, context: RequestContext, contact_list_name: ContactListName, **kwargs) -> DeleteContactListResponse:
        raise NotImplementedError

    @handler("DeleteCustomVerificationEmailTemplate")
    def delete_custom_verification_email_template(self, context: RequestContext, template_name: EmailTemplateName, **kwargs) -> DeleteCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("DeleteDedicatedIpPool")
    def delete_dedicated_ip_pool(self, context: RequestContext, pool_name: PoolName, **kwargs) -> DeleteDedicatedIpPoolResponse:
        raise NotImplementedError

    @handler("DeleteEmailIdentity")
    def delete_email_identity(self, context: RequestContext, email_identity: Identity, **kwargs) -> DeleteEmailIdentityResponse:
        raise NotImplementedError

    @handler("DeleteEmailIdentityPolicy")
    def delete_email_identity_policy(self, context: RequestContext, email_identity: Identity, policy_name: PolicyName, **kwargs) -> DeleteEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("DeleteEmailTemplate")
    def delete_email_template(self, context: RequestContext, template_name: EmailTemplateName, **kwargs) -> DeleteEmailTemplateResponse:
        raise NotImplementedError

    @handler("DeleteMultiRegionEndpoint")
    def delete_multi_region_endpoint(self, context: RequestContext, endpoint_name: EndpointName, **kwargs) -> DeleteMultiRegionEndpointResponse:
        raise NotImplementedError

    @handler("DeleteSuppressedDestination")
    def delete_suppressed_destination(self, context: RequestContext, email_address: EmailAddress, **kwargs) -> DeleteSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("DeleteTenant")
    def delete_tenant(self, context: RequestContext, tenant_name: TenantName, **kwargs) -> DeleteTenantResponse:
        raise NotImplementedError

    @handler("DeleteTenantResourceAssociation")
    def delete_tenant_resource_association(self, context: RequestContext, tenant_name: TenantName, resource_arn: AmazonResourceName, **kwargs) -> DeleteTenantResourceAssociationResponse:
        raise NotImplementedError

    @handler("GetAccount")
    def get_account(self, context: RequestContext, **kwargs) -> GetAccountResponse:
        raise NotImplementedError

    @handler("GetBlacklistReports")
    def get_blacklist_reports(self, context: RequestContext, blacklist_item_names: BlacklistItemNames, **kwargs) -> GetBlacklistReportsResponse:
        raise NotImplementedError

    @handler("GetConfigurationSet")
    def get_configuration_set(self, context: RequestContext, configuration_set_name: ConfigurationSetName, **kwargs) -> GetConfigurationSetResponse:
        raise NotImplementedError

    @handler("GetConfigurationSetEventDestinations")
    def get_configuration_set_event_destinations(self, context: RequestContext, configuration_set_name: ConfigurationSetName, **kwargs) -> GetConfigurationSetEventDestinationsResponse:
        raise NotImplementedError

    @handler("GetContact")
    def get_contact(self, context: RequestContext, contact_list_name: ContactListName, email_address: EmailAddress, **kwargs) -> GetContactResponse:
        raise NotImplementedError

    @handler("GetContactList")
    def get_contact_list(self, context: RequestContext, contact_list_name: ContactListName, **kwargs) -> GetContactListResponse:
        raise NotImplementedError

    @handler("GetCustomVerificationEmailTemplate")
    def get_custom_verification_email_template(self, context: RequestContext, template_name: EmailTemplateName, **kwargs) -> GetCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("GetDedicatedIp")
    def get_dedicated_ip(self, context: RequestContext, ip: Ip, **kwargs) -> GetDedicatedIpResponse:
        raise NotImplementedError

    @handler("GetDedicatedIpPool")
    def get_dedicated_ip_pool(self, context: RequestContext, pool_name: PoolName, **kwargs) -> GetDedicatedIpPoolResponse:
        raise NotImplementedError

    @handler("GetDedicatedIps")
    def get_dedicated_ips(self, context: RequestContext, pool_name: PoolName | None = None, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> GetDedicatedIpsResponse:
        raise NotImplementedError

    @handler("GetDeliverabilityDashboardOptions")
    def get_deliverability_dashboard_options(self, context: RequestContext, **kwargs) -> GetDeliverabilityDashboardOptionsResponse:
        raise NotImplementedError

    @handler("GetDeliverabilityTestReport")
    def get_deliverability_test_report(self, context: RequestContext, report_id: ReportId, **kwargs) -> GetDeliverabilityTestReportResponse:
        raise NotImplementedError

    @handler("GetDomainDeliverabilityCampaign")
    def get_domain_deliverability_campaign(self, context: RequestContext, campaign_id: CampaignId, **kwargs) -> GetDomainDeliverabilityCampaignResponse:
        raise NotImplementedError

    @handler("GetDomainStatisticsReport")
    def get_domain_statistics_report(self, context: RequestContext, domain: Identity, start_date: Timestamp, end_date: Timestamp, **kwargs) -> GetDomainStatisticsReportResponse:
        raise NotImplementedError

    @handler("GetEmailAddressInsights")
    def get_email_address_insights(self, context: RequestContext, email_address: EmailAddress, **kwargs) -> GetEmailAddressInsightsResponse:
        raise NotImplementedError

    @handler("GetEmailIdentity")
    def get_email_identity(self, context: RequestContext, email_identity: Identity, **kwargs) -> GetEmailIdentityResponse:
        raise NotImplementedError

    @handler("GetEmailIdentityPolicies")
    def get_email_identity_policies(self, context: RequestContext, email_identity: Identity, **kwargs) -> GetEmailIdentityPoliciesResponse:
        raise NotImplementedError

    @handler("GetEmailTemplate")
    def get_email_template(self, context: RequestContext, template_name: EmailTemplateName, **kwargs) -> GetEmailTemplateResponse:
        raise NotImplementedError

    @handler("GetExportJob")
    def get_export_job(self, context: RequestContext, job_id: JobId, **kwargs) -> GetExportJobResponse:
        raise NotImplementedError

    @handler("GetImportJob")
    def get_import_job(self, context: RequestContext, job_id: JobId, **kwargs) -> GetImportJobResponse:
        raise NotImplementedError

    @handler("GetMessageInsights")
    def get_message_insights(self, context: RequestContext, message_id: OutboundMessageId, **kwargs) -> GetMessageInsightsResponse:
        raise NotImplementedError

    @handler("GetMultiRegionEndpoint")
    def get_multi_region_endpoint(self, context: RequestContext, endpoint_name: EndpointName, **kwargs) -> GetMultiRegionEndpointResponse:
        raise NotImplementedError

    @handler("GetReputationEntity")
    def get_reputation_entity(self, context: RequestContext, reputation_entity_reference: ReputationEntityReference, reputation_entity_type: ReputationEntityType, **kwargs) -> GetReputationEntityResponse:
        raise NotImplementedError

    @handler("GetSuppressedDestination")
    def get_suppressed_destination(self, context: RequestContext, email_address: EmailAddress, **kwargs) -> GetSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("GetTenant")
    def get_tenant(self, context: RequestContext, tenant_name: TenantName, **kwargs) -> GetTenantResponse:
        raise NotImplementedError

    @handler("ListConfigurationSets")
    def list_configuration_sets(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListConfigurationSetsResponse:
        raise NotImplementedError

    @handler("ListContactLists")
    def list_contact_lists(self, context: RequestContext, page_size: MaxItems | None = None, next_token: NextToken | None = None, **kwargs) -> ListContactListsResponse:
        raise NotImplementedError

    @handler("ListContacts")
    def list_contacts(self, context: RequestContext, contact_list_name: ContactListName, filter: ListContactsFilter | None = None, page_size: MaxItems | None = None, next_token: NextToken | None = None, **kwargs) -> ListContactsResponse:
        raise NotImplementedError

    @handler("ListCustomVerificationEmailTemplates")
    def list_custom_verification_email_templates(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListCustomVerificationEmailTemplatesResponse:
        raise NotImplementedError

    @handler("ListDedicatedIpPools")
    def list_dedicated_ip_pools(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListDedicatedIpPoolsResponse:
        raise NotImplementedError

    @handler("ListDeliverabilityTestReports")
    def list_deliverability_test_reports(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListDeliverabilityTestReportsResponse:
        raise NotImplementedError

    @handler("ListDomainDeliverabilityCampaigns")
    def list_domain_deliverability_campaigns(self, context: RequestContext, start_date: Timestamp, end_date: Timestamp, subscribed_domain: Domain, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListDomainDeliverabilityCampaignsResponse:
        raise NotImplementedError

    @handler("ListEmailIdentities")
    def list_email_identities(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListEmailIdentitiesResponse:
        raise NotImplementedError

    @handler("ListEmailTemplates")
    def list_email_templates(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListEmailTemplatesResponse:
        raise NotImplementedError

    @handler("ListExportJobs")
    def list_export_jobs(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, export_source_type: ExportSourceType | None = None, job_status: JobStatus | None = None, **kwargs) -> ListExportJobsResponse:
        raise NotImplementedError

    @handler("ListImportJobs")
    def list_import_jobs(self, context: RequestContext, import_destination_type: ImportDestinationType | None = None, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListImportJobsResponse:
        raise NotImplementedError

    @handler("ListMultiRegionEndpoints")
    def list_multi_region_endpoints(self, context: RequestContext, next_token: NextTokenV2 | None = None, page_size: PageSizeV2 | None = None, **kwargs) -> ListMultiRegionEndpointsResponse:
        raise NotImplementedError

    @handler("ListRecommendations")
    def list_recommendations(self, context: RequestContext, filter: ListRecommendationsFilter | None = None, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListRecommendationsResponse:
        raise NotImplementedError

    @handler("ListReputationEntities")
    def list_reputation_entities(self, context: RequestContext, filter: ReputationEntityFilter | None = None, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListReputationEntitiesResponse:
        raise NotImplementedError

    @handler("ListResourceTenants")
    def list_resource_tenants(self, context: RequestContext, resource_arn: AmazonResourceName, page_size: MaxItems | None = None, next_token: NextToken | None = None, **kwargs) -> ListResourceTenantsResponse:
        raise NotImplementedError

    @handler("ListSuppressedDestinations")
    def list_suppressed_destinations(self, context: RequestContext, reasons: SuppressionListReasons | None = None, start_date: Timestamp | None = None, end_date: Timestamp | None = None, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListSuppressedDestinationsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTenantResources")
    def list_tenant_resources(self, context: RequestContext, tenant_name: TenantName, filter: ListTenantResourcesFilter | None = None, page_size: MaxItems | None = None, next_token: NextToken | None = None, **kwargs) -> ListTenantResourcesResponse:
        raise NotImplementedError

    @handler("ListTenants")
    def list_tenants(self, context: RequestContext, next_token: NextToken | None = None, page_size: MaxItems | None = None, **kwargs) -> ListTenantsResponse:
        raise NotImplementedError

    @handler("PutAccountDedicatedIpWarmupAttributes")
    def put_account_dedicated_ip_warmup_attributes(self, context: RequestContext, auto_warmup_enabled: Enabled | None = None, **kwargs) -> PutAccountDedicatedIpWarmupAttributesResponse:
        raise NotImplementedError

    @handler("PutAccountDetails")
    def put_account_details(self, context: RequestContext, mail_type: MailType, website_url: WebsiteURL, contact_language: ContactLanguage | None = None, use_case_description: UseCaseDescription | None = None, additional_contact_email_addresses: AdditionalContactEmailAddresses | None = None, production_access_enabled: EnabledWrapper | None = None, **kwargs) -> PutAccountDetailsResponse:
        raise NotImplementedError

    @handler("PutAccountSendingAttributes")
    def put_account_sending_attributes(self, context: RequestContext, sending_enabled: Enabled | None = None, **kwargs) -> PutAccountSendingAttributesResponse:
        raise NotImplementedError

    @handler("PutAccountSuppressionAttributes")
    def put_account_suppression_attributes(self, context: RequestContext, suppressed_reasons: SuppressionListReasons | None = None, validation_attributes: SuppressionValidationAttributes | None = None, **kwargs) -> PutAccountSuppressionAttributesResponse:
        raise NotImplementedError

    @handler("PutAccountVdmAttributes")
    def put_account_vdm_attributes(self, context: RequestContext, vdm_attributes: VdmAttributes, **kwargs) -> PutAccountVdmAttributesResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetArchivingOptions")
    def put_configuration_set_archiving_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, archive_arn: ArchiveArn | None = None, **kwargs) -> PutConfigurationSetArchivingOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetDeliveryOptions")
    def put_configuration_set_delivery_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, tls_policy: TlsPolicy | None = None, sending_pool_name: SendingPoolName | None = None, max_delivery_seconds: MaxDeliverySeconds | None = None, **kwargs) -> PutConfigurationSetDeliveryOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetReputationOptions")
    def put_configuration_set_reputation_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, reputation_metrics_enabled: Enabled | None = None, **kwargs) -> PutConfigurationSetReputationOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetSendingOptions")
    def put_configuration_set_sending_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, sending_enabled: Enabled | None = None, **kwargs) -> PutConfigurationSetSendingOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetSuppressionOptions")
    def put_configuration_set_suppression_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, suppressed_reasons: SuppressionListReasons | None = None, validation_options: SuppressionValidationOptions | None = None, **kwargs) -> PutConfigurationSetSuppressionOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetTrackingOptions")
    def put_configuration_set_tracking_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, custom_redirect_domain: CustomRedirectDomain | None = None, https_policy: HttpsPolicy | None = None, **kwargs) -> PutConfigurationSetTrackingOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetVdmOptions")
    def put_configuration_set_vdm_options(self, context: RequestContext, configuration_set_name: ConfigurationSetName, vdm_options: VdmOptions | None = None, **kwargs) -> PutConfigurationSetVdmOptionsResponse:
        raise NotImplementedError

    @handler("PutDedicatedIpInPool")
    def put_dedicated_ip_in_pool(self, context: RequestContext, ip: Ip, destination_pool_name: PoolName, **kwargs) -> PutDedicatedIpInPoolResponse:
        raise NotImplementedError

    @handler("PutDedicatedIpPoolScalingAttributes")
    def put_dedicated_ip_pool_scaling_attributes(self, context: RequestContext, pool_name: PoolName, scaling_mode: ScalingMode, **kwargs) -> PutDedicatedIpPoolScalingAttributesResponse:
        raise NotImplementedError

    @handler("PutDedicatedIpWarmupAttributes")
    def put_dedicated_ip_warmup_attributes(self, context: RequestContext, ip: Ip, warmup_percentage: Percentage100Wrapper, **kwargs) -> PutDedicatedIpWarmupAttributesResponse:
        raise NotImplementedError

    @handler("PutDeliverabilityDashboardOption")
    def put_deliverability_dashboard_option(self, context: RequestContext, dashboard_enabled: Enabled, subscribed_domains: DomainDeliverabilityTrackingOptions | None = None, **kwargs) -> PutDeliverabilityDashboardOptionResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityConfigurationSetAttributes")
    def put_email_identity_configuration_set_attributes(self, context: RequestContext, email_identity: Identity, configuration_set_name: ConfigurationSetName | None = None, **kwargs) -> PutEmailIdentityConfigurationSetAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityDkimAttributes")
    def put_email_identity_dkim_attributes(self, context: RequestContext, email_identity: Identity, signing_enabled: Enabled | None = None, **kwargs) -> PutEmailIdentityDkimAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityDkimSigningAttributes")
    def put_email_identity_dkim_signing_attributes(self, context: RequestContext, email_identity: Identity, signing_attributes_origin: DkimSigningAttributesOrigin, signing_attributes: DkimSigningAttributes | None = None, **kwargs) -> PutEmailIdentityDkimSigningAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityFeedbackAttributes")
    def put_email_identity_feedback_attributes(self, context: RequestContext, email_identity: Identity, email_forwarding_enabled: Enabled | None = None, **kwargs) -> PutEmailIdentityFeedbackAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityMailFromAttributes")
    def put_email_identity_mail_from_attributes(self, context: RequestContext, email_identity: Identity, mail_from_domain: MailFromDomainName | None = None, behavior_on_mx_failure: BehaviorOnMxFailure | None = None, **kwargs) -> PutEmailIdentityMailFromAttributesResponse:
        raise NotImplementedError

    @handler("PutSuppressedDestination")
    def put_suppressed_destination(self, context: RequestContext, email_address: EmailAddress, reason: SuppressionListReason, **kwargs) -> PutSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("SendBulkEmail")
    def send_bulk_email(self, context: RequestContext, default_content: BulkEmailContent, bulk_email_entries: BulkEmailEntryList, from_email_address: EmailAddress | None = None, from_email_address_identity_arn: AmazonResourceName | None = None, reply_to_addresses: EmailAddressList | None = None, feedback_forwarding_email_address: EmailAddress | None = None, feedback_forwarding_email_address_identity_arn: AmazonResourceName | None = None, default_email_tags: MessageTagList | None = None, configuration_set_name: ConfigurationSetName | None = None, endpoint_id: EndpointId | None = None, tenant_name: TenantName | None = None, **kwargs) -> SendBulkEmailResponse:
        raise NotImplementedError

    @handler("SendCustomVerificationEmail")
    def send_custom_verification_email(self, context: RequestContext, email_address: EmailAddress, template_name: EmailTemplateName, configuration_set_name: ConfigurationSetName | None = None, **kwargs) -> SendCustomVerificationEmailResponse:
        raise NotImplementedError

    @handler("SendEmail")
    def send_email(self, context: RequestContext, content: EmailContent, from_email_address: EmailAddress | None = None, from_email_address_identity_arn: AmazonResourceName | None = None, destination: Destination | None = None, reply_to_addresses: EmailAddressList | None = None, feedback_forwarding_email_address: EmailAddress | None = None, feedback_forwarding_email_address_identity_arn: AmazonResourceName | None = None, email_tags: MessageTagList | None = None, configuration_set_name: ConfigurationSetName | None = None, endpoint_id: EndpointId | None = None, tenant_name: TenantName | None = None, list_management_options: ListManagementOptions | None = None, **kwargs) -> SendEmailResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestRenderEmailTemplate")
    def test_render_email_template(self, context: RequestContext, template_name: EmailTemplateName, template_data: EmailTemplateData, **kwargs) -> TestRenderEmailTemplateResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList, **kwargs) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateConfigurationSetEventDestination")
    def update_configuration_set_event_destination(self, context: RequestContext, configuration_set_name: ConfigurationSetName, event_destination_name: EventDestinationName, event_destination: EventDestinationDefinition, **kwargs) -> UpdateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("UpdateContact")
    def update_contact(self, context: RequestContext, contact_list_name: ContactListName, email_address: EmailAddress, topic_preferences: TopicPreferenceList | None = None, unsubscribe_all: UnsubscribeAll | None = None, attributes_data: AttributesData | None = None, **kwargs) -> UpdateContactResponse:
        raise NotImplementedError

    @handler("UpdateContactList")
    def update_contact_list(self, context: RequestContext, contact_list_name: ContactListName, topics: Topics | None = None, description: Description | None = None, **kwargs) -> UpdateContactListResponse:
        raise NotImplementedError

    @handler("UpdateCustomVerificationEmailTemplate")
    def update_custom_verification_email_template(self, context: RequestContext, template_name: EmailTemplateName, from_email_address: EmailAddress, template_subject: EmailTemplateSubject, template_content: TemplateContent, success_redirection_url: SuccessRedirectionURL, failure_redirection_url: FailureRedirectionURL, **kwargs) -> UpdateCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("UpdateEmailIdentityPolicy")
    def update_email_identity_policy(self, context: RequestContext, email_identity: Identity, policy_name: PolicyName, policy: Policy, **kwargs) -> UpdateEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("UpdateEmailTemplate")
    def update_email_template(self, context: RequestContext, template_name: EmailTemplateName, template_content: EmailTemplateContent, **kwargs) -> UpdateEmailTemplateResponse:
        raise NotImplementedError

    @handler("UpdateReputationEntityCustomerManagedStatus")
    def update_reputation_entity_customer_managed_status(self, context: RequestContext, reputation_entity_type: ReputationEntityType, reputation_entity_reference: ReputationEntityReference, sending_status: SendingStatus, **kwargs) -> UpdateReputationEntityCustomerManagedStatusResponse:
        raise NotImplementedError

    @handler("UpdateReputationEntityPolicy")
    def update_reputation_entity_policy(self, context: RequestContext, reputation_entity_type: ReputationEntityType, reputation_entity_reference: ReputationEntityReference, reputation_entity_policy: AmazonResourceName, **kwargs) -> UpdateReputationEntityPolicyResponse:
        raise NotImplementedError
