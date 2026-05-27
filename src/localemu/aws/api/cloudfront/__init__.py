from datetime import datetime
from enum import StrEnum
from typing import IO, TypedDict
from collections.abc import Iterable, Iterator

from localemu.aws.api import handler, RequestContext, ServiceException, ServiceRequest
AnycastIpListName = str
CaCertificatesBundleS3LocationRegionString = str
CommentType = str
CreateDistributionTenantRequestNameString = str
FunctionARN = str
FunctionName = str
KeyValueStoreARN = str
KeyValueStoreComment = str
KeyValueStoreName = str
LambdaFunctionARN = str
OriginShieldRegion = str
ParameterName = str
ParameterValue = str
ResourceARN = str
ResourceId = str
SamplingRate = float
ServerCertificateId = str
TagKey = str
TagValue = str
aliasString = str
boolean = bool
distributionIdString = str
float = float
integer = int
listConflictingAliasesMaxItemsInteger = int
sensitiveStringType = str
string = str
class CachePolicyCookieBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"
    allExcept = "allExcept"
    all = "all"

class CachePolicyHeaderBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"

class CachePolicyQueryStringBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"
    allExcept = "allExcept"
    all = "all"

class CachePolicyType(StrEnum):
    managed = "managed"
    custom = "custom"

class CertificateSource(StrEnum):
    cloudfront = "cloudfront"
    iam = "iam"
    acm = "acm"

class CertificateTransparencyLoggingPreference(StrEnum):
    enabled = "enabled"
    disabled = "disabled"

class ConnectionMode(StrEnum):
    direct = "direct"
    tenant_only = "tenant-only"

class ContinuousDeploymentPolicyType(StrEnum):
    SingleWeight = "SingleWeight"
    SingleHeader = "SingleHeader"

class CustomizationActionType(StrEnum):
    override = "override"
    disable = "disable"

class DistributionResourceType(StrEnum):
    distribution = "distribution"
    distribution_tenant = "distribution-tenant"

class DnsConfigurationStatus(StrEnum):
    valid_configuration = "valid-configuration"
    invalid_configuration = "invalid-configuration"
    unknown_configuration = "unknown-configuration"

class DomainStatus(StrEnum):
    active = "active"
    inactive = "inactive"

class EventType(StrEnum):
    viewer_request = "viewer-request"
    viewer_response = "viewer-response"
    origin_request = "origin-request"
    origin_response = "origin-response"

class Format(StrEnum):
    URLEncoded = "URLEncoded"

class FrameOptionsList(StrEnum):
    DENY = "DENY"
    SAMEORIGIN = "SAMEORIGIN"

class FunctionRuntime(StrEnum):
    cloudfront_js_1_0 = "cloudfront-js-1.0"
    cloudfront_js_2_0 = "cloudfront-js-2.0"

class FunctionStage(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    LIVE = "LIVE"

class GeoRestrictionType(StrEnum):
    blacklist = "blacklist"
    whitelist = "whitelist"
    none = "none"

class HttpVersion(StrEnum):
    http1_1 = "http1.1"
    http2 = "http2"
    http3 = "http3"
    http2and3 = "http2and3"

class ICPRecordalStatus(StrEnum):
    APPROVED = "APPROVED"
    SUSPENDED = "SUSPENDED"
    PENDING = "PENDING"

class ImportSourceType(StrEnum):
    S3 = "S3"

class IpAddressType(StrEnum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    dualstack = "dualstack"

class IpamCidrStatus(StrEnum):
    provisioned = "provisioned"
    failed_provision = "failed-provision"
    provisioning = "provisioning"
    deprovisioned = "deprovisioned"
    failed_deprovision = "failed-deprovision"
    deprovisioning = "deprovisioning"
    advertised = "advertised"
    failed_advertise = "failed-advertise"
    advertising = "advertising"
    withdrawn = "withdrawn"
    failed_withdraw = "failed-withdraw"
    withdrawing = "withdrawing"

class ItemSelection(StrEnum):
    none = "none"
    whitelist = "whitelist"
    all = "all"

class ManagedCertificateStatus(StrEnum):
    pending_validation = "pending-validation"
    issued = "issued"
    inactive = "inactive"
    expired = "expired"
    validation_timed_out = "validation-timed-out"
    revoked = "revoked"
    failed = "failed"

class Method(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    DELETE = "DELETE"

class MinimumProtocolVersion(StrEnum):
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_2016 = "TLSv1_2016"
    TLSv1_1_2016 = "TLSv1.1_2016"
    TLSv1_2_2018 = "TLSv1.2_2018"
    TLSv1_2_2019 = "TLSv1.2_2019"
    TLSv1_2_2021 = "TLSv1.2_2021"
    TLSv1_3_2025 = "TLSv1.3_2025"
    TLSv1_2_2025 = "TLSv1.2_2025"

class OriginAccessControlOriginTypes(StrEnum):
    s3 = "s3"
    mediastore = "mediastore"
    mediapackagev2 = "mediapackagev2"
    lambda_ = "lambda"

class OriginAccessControlSigningBehaviors(StrEnum):
    never = "never"
    always = "always"
    no_override = "no-override"

class OriginAccessControlSigningProtocols(StrEnum):
    sigv4 = "sigv4"

class OriginGroupSelectionCriteria(StrEnum):
    default = "default"
    media_quality_based = "media-quality-based"

class OriginProtocolPolicy(StrEnum):
    http_only = "http-only"
    match_viewer = "match-viewer"
    https_only = "https-only"

class OriginRequestPolicyCookieBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"
    all = "all"
    allExcept = "allExcept"

class OriginRequestPolicyHeaderBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"
    allViewer = "allViewer"
    allViewerAndWhitelistCloudFront = "allViewerAndWhitelistCloudFront"
    allExcept = "allExcept"

class OriginRequestPolicyQueryStringBehavior(StrEnum):
    none = "none"
    whitelist = "whitelist"
    all = "all"
    allExcept = "allExcept"

class OriginRequestPolicyType(StrEnum):
    managed = "managed"
    custom = "custom"

class PriceClass(StrEnum):
    PriceClass_100 = "PriceClass_100"
    PriceClass_200 = "PriceClass_200"
    PriceClass_All = "PriceClass_All"
    None_ = "None"

class RealtimeMetricsSubscriptionStatus(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"

class ReferrerPolicyList(StrEnum):
    no_referrer = "no-referrer"
    no_referrer_when_downgrade = "no-referrer-when-downgrade"
    origin = "origin"
    origin_when_cross_origin = "origin-when-cross-origin"
    same_origin = "same-origin"
    strict_origin = "strict-origin"
    strict_origin_when_cross_origin = "strict-origin-when-cross-origin"
    unsafe_url = "unsafe-url"

class ResponseHeadersPolicyAccessControlAllowMethodsValues(StrEnum):
    GET = "GET"
    POST = "POST"
    OPTIONS = "OPTIONS"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    ALL = "ALL"

class ResponseHeadersPolicyType(StrEnum):
    managed = "managed"
    custom = "custom"

class SSLSupportMethod(StrEnum):
    sni_only = "sni-only"
    vip = "vip"
    static_ip = "static-ip"

class SslProtocol(StrEnum):
    SSLv3 = "SSLv3"
    TLSv1 = "TLSv1"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"

class TrustStoreStatus(StrEnum):
    pending = "pending"
    active = "active"
    failed = "failed"

class ValidationTokenHost(StrEnum):
    cloudfront = "cloudfront"
    self_hosted = "self-hosted"

class ViewerMtlsMode(StrEnum):
    required = "required"
    optional = "optional"

class ViewerProtocolPolicy(StrEnum):
    allow_all = "allow-all"
    https_only = "https-only"
    redirect_to_https = "redirect-to-https"

class AccessDenied(ServiceException):
    code: str = "AccessDenied"
    sender_fault: bool = True
    status_code: int = 403

class BatchTooLarge(ServiceException):
    code: str = "BatchTooLarge"
    sender_fault: bool = True
    status_code: int = 413

class CNAMEAlreadyExists(ServiceException):
    code: str = "CNAMEAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class CachePolicyAlreadyExists(ServiceException):
    code: str = "CachePolicyAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class CachePolicyInUse(ServiceException):
    code: str = "CachePolicyInUse"
    sender_fault: bool = True
    status_code: int = 409

class CannotChangeImmutablePublicKeyFields(ServiceException):
    code: str = "CannotChangeImmutablePublicKeyFields"
    sender_fault: bool = True
    status_code: int = 400

class CannotDeleteEntityWhileInUse(ServiceException):
    code: str = "CannotDeleteEntityWhileInUse"
    sender_fault: bool = True
    status_code: int = 409

class CannotUpdateEntityWhileInUse(ServiceException):
    code: str = "CannotUpdateEntityWhileInUse"
    sender_fault: bool = True
    status_code: int = 409

class CloudFrontOriginAccessIdentityAlreadyExists(ServiceException):
    code: str = "CloudFrontOriginAccessIdentityAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class CloudFrontOriginAccessIdentityInUse(ServiceException):
    code: str = "CloudFrontOriginAccessIdentityInUse"
    sender_fault: bool = True
    status_code: int = 409

class ContinuousDeploymentPolicyAlreadyExists(ServiceException):
    code: str = "ContinuousDeploymentPolicyAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class ContinuousDeploymentPolicyInUse(ServiceException):
    code: str = "ContinuousDeploymentPolicyInUse"
    sender_fault: bool = True
    status_code: int = 409

class DistributionAlreadyExists(ServiceException):
    code: str = "DistributionAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class DistributionNotDisabled(ServiceException):
    code: str = "DistributionNotDisabled"
    sender_fault: bool = True
    status_code: int = 409

class EntityAlreadyExists(ServiceException):
    code: str = "EntityAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class EntityLimitExceeded(ServiceException):
    code: str = "EntityLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400

class EntityNotFound(ServiceException):
    code: str = "EntityNotFound"
    sender_fault: bool = True
    status_code: int = 404

class EntitySizeLimitExceeded(ServiceException):
    code: str = "EntitySizeLimitExceeded"
    sender_fault: bool = True
    status_code: int = 413

class FieldLevelEncryptionConfigAlreadyExists(ServiceException):
    code: str = "FieldLevelEncryptionConfigAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class FieldLevelEncryptionConfigInUse(ServiceException):
    code: str = "FieldLevelEncryptionConfigInUse"
    sender_fault: bool = True
    status_code: int = 409

class FieldLevelEncryptionProfileAlreadyExists(ServiceException):
    code: str = "FieldLevelEncryptionProfileAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class FieldLevelEncryptionProfileInUse(ServiceException):
    code: str = "FieldLevelEncryptionProfileInUse"
    sender_fault: bool = True
    status_code: int = 409

class FieldLevelEncryptionProfileSizeExceeded(ServiceException):
    code: str = "FieldLevelEncryptionProfileSizeExceeded"
    sender_fault: bool = True
    status_code: int = 400

class FunctionAlreadyExists(ServiceException):
    code: str = "FunctionAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class FunctionInUse(ServiceException):
    code: str = "FunctionInUse"
    sender_fault: bool = True
    status_code: int = 409

class FunctionSizeLimitExceeded(ServiceException):
    code: str = "FunctionSizeLimitExceeded"
    sender_fault: bool = True
    status_code: int = 413

class IllegalDelete(ServiceException):
    code: str = "IllegalDelete"
    sender_fault: bool = True
    status_code: int = 400

class IllegalFieldLevelEncryptionConfigAssociationWithCacheBehavior(ServiceException):
    code: str = "IllegalFieldLevelEncryptionConfigAssociationWithCacheBehavior"
    sender_fault: bool = True
    status_code: int = 400

class IllegalOriginAccessConfiguration(ServiceException):
    code: str = "IllegalOriginAccessConfiguration"
    sender_fault: bool = True
    status_code: int = 400

class IllegalUpdate(ServiceException):
    code: str = "IllegalUpdate"
    sender_fault: bool = True
    status_code: int = 400

class InconsistentQuantities(ServiceException):
    code: str = "InconsistentQuantities"
    sender_fault: bool = True
    status_code: int = 400

class InvalidArgument(ServiceException):
    code: str = "InvalidArgument"
    sender_fault: bool = True
    status_code: int = 400

class InvalidAssociation(ServiceException):
    code: str = "InvalidAssociation"
    sender_fault: bool = True
    status_code: int = 409

class InvalidDefaultRootObject(ServiceException):
    code: str = "InvalidDefaultRootObject"
    sender_fault: bool = True
    status_code: int = 400

class InvalidDomainNameForOriginAccessControl(ServiceException):
    code: str = "InvalidDomainNameForOriginAccessControl"
    sender_fault: bool = True
    status_code: int = 400

class InvalidErrorCode(ServiceException):
    code: str = "InvalidErrorCode"
    sender_fault: bool = True
    status_code: int = 400

class InvalidForwardCookies(ServiceException):
    code: str = "InvalidForwardCookies"
    sender_fault: bool = True
    status_code: int = 400

class InvalidFunctionAssociation(ServiceException):
    code: str = "InvalidFunctionAssociation"
    sender_fault: bool = True
    status_code: int = 400

class InvalidGeoRestrictionParameter(ServiceException):
    code: str = "InvalidGeoRestrictionParameter"
    sender_fault: bool = True
    status_code: int = 400

class InvalidHeadersForS3Origin(ServiceException):
    code: str = "InvalidHeadersForS3Origin"
    sender_fault: bool = True
    status_code: int = 400

class InvalidIfMatchVersion(ServiceException):
    code: str = "InvalidIfMatchVersion"
    sender_fault: bool = True
    status_code: int = 400

class InvalidLambdaFunctionAssociation(ServiceException):
    code: str = "InvalidLambdaFunctionAssociation"
    sender_fault: bool = True
    status_code: int = 400

class InvalidLocationCode(ServiceException):
    code: str = "InvalidLocationCode"
    sender_fault: bool = True
    status_code: int = 400

class InvalidMinimumProtocolVersion(ServiceException):
    code: str = "InvalidMinimumProtocolVersion"
    sender_fault: bool = True
    status_code: int = 400

class InvalidOrigin(ServiceException):
    code: str = "InvalidOrigin"
    sender_fault: bool = True
    status_code: int = 400

class InvalidOriginAccessControl(ServiceException):
    code: str = "InvalidOriginAccessControl"
    sender_fault: bool = True
    status_code: int = 400

class InvalidOriginAccessIdentity(ServiceException):
    code: str = "InvalidOriginAccessIdentity"
    sender_fault: bool = True
    status_code: int = 400

class InvalidOriginKeepaliveTimeout(ServiceException):
    code: str = "InvalidOriginKeepaliveTimeout"
    sender_fault: bool = True
    status_code: int = 400

class InvalidOriginReadTimeout(ServiceException):
    code: str = "InvalidOriginReadTimeout"
    sender_fault: bool = True
    status_code: int = 400

class InvalidProtocolSettings(ServiceException):
    code: str = "InvalidProtocolSettings"
    sender_fault: bool = True
    status_code: int = 400

class InvalidQueryStringParameters(ServiceException):
    code: str = "InvalidQueryStringParameters"
    sender_fault: bool = True
    status_code: int = 400

class InvalidRelativePath(ServiceException):
    code: str = "InvalidRelativePath"
    sender_fault: bool = True
    status_code: int = 400

class InvalidRequiredProtocol(ServiceException):
    code: str = "InvalidRequiredProtocol"
    sender_fault: bool = True
    status_code: int = 400

class InvalidResponseCode(ServiceException):
    code: str = "InvalidResponseCode"
    sender_fault: bool = True
    status_code: int = 400

class InvalidTTLOrder(ServiceException):
    code: str = "InvalidTTLOrder"
    sender_fault: bool = True
    status_code: int = 400

class InvalidTagging(ServiceException):
    code: str = "InvalidTagging"
    sender_fault: bool = True
    status_code: int = 400

class InvalidViewerCertificate(ServiceException):
    code: str = "InvalidViewerCertificate"
    sender_fault: bool = True
    status_code: int = 400

class InvalidWebACLId(ServiceException):
    code: str = "InvalidWebACLId"
    sender_fault: bool = True
    status_code: int = 400

class KeyGroupAlreadyExists(ServiceException):
    code: str = "KeyGroupAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class MissingBody(ServiceException):
    code: str = "MissingBody"
    sender_fault: bool = True
    status_code: int = 400

class MonitoringSubscriptionAlreadyExists(ServiceException):
    code: str = "MonitoringSubscriptionAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class NoSuchCachePolicy(ServiceException):
    code: str = "NoSuchCachePolicy"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchCloudFrontOriginAccessIdentity(ServiceException):
    code: str = "NoSuchCloudFrontOriginAccessIdentity"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchContinuousDeploymentPolicy(ServiceException):
    code: str = "NoSuchContinuousDeploymentPolicy"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchDistribution(ServiceException):
    code: str = "NoSuchDistribution"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchFieldLevelEncryptionConfig(ServiceException):
    code: str = "NoSuchFieldLevelEncryptionConfig"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchFieldLevelEncryptionProfile(ServiceException):
    code: str = "NoSuchFieldLevelEncryptionProfile"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchFunctionExists(ServiceException):
    code: str = "NoSuchFunctionExists"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchInvalidation(ServiceException):
    code: str = "NoSuchInvalidation"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchMonitoringSubscription(ServiceException):
    code: str = "NoSuchMonitoringSubscription"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchOrigin(ServiceException):
    code: str = "NoSuchOrigin"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchOriginAccessControl(ServiceException):
    code: str = "NoSuchOriginAccessControl"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchOriginRequestPolicy(ServiceException):
    code: str = "NoSuchOriginRequestPolicy"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchPublicKey(ServiceException):
    code: str = "NoSuchPublicKey"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchRealtimeLogConfig(ServiceException):
    code: str = "NoSuchRealtimeLogConfig"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchResource(ServiceException):
    code: str = "NoSuchResource"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchResponseHeadersPolicy(ServiceException):
    code: str = "NoSuchResponseHeadersPolicy"
    sender_fault: bool = True
    status_code: int = 404

class NoSuchStreamingDistribution(ServiceException):
    code: str = "NoSuchStreamingDistribution"
    sender_fault: bool = True
    status_code: int = 404

class OriginAccessControlAlreadyExists(ServiceException):
    code: str = "OriginAccessControlAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class OriginAccessControlInUse(ServiceException):
    code: str = "OriginAccessControlInUse"
    sender_fault: bool = True
    status_code: int = 409

class OriginRequestPolicyAlreadyExists(ServiceException):
    code: str = "OriginRequestPolicyAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class OriginRequestPolicyInUse(ServiceException):
    code: str = "OriginRequestPolicyInUse"
    sender_fault: bool = True
    status_code: int = 409

class PreconditionFailed(ServiceException):
    code: str = "PreconditionFailed"
    sender_fault: bool = True
    status_code: int = 412

class PublicKeyAlreadyExists(ServiceException):
    code: str = "PublicKeyAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class PublicKeyInUse(ServiceException):
    code: str = "PublicKeyInUse"
    sender_fault: bool = True
    status_code: int = 409

class QueryArgProfileEmpty(ServiceException):
    code: str = "QueryArgProfileEmpty"
    sender_fault: bool = True
    status_code: int = 400

class RealtimeLogConfigAlreadyExists(ServiceException):
    code: str = "RealtimeLogConfigAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class RealtimeLogConfigInUse(ServiceException):
    code: str = "RealtimeLogConfigInUse"
    sender_fault: bool = True
    status_code: int = 400

class RealtimeLogConfigOwnerMismatch(ServiceException):
    code: str = "RealtimeLogConfigOwnerMismatch"
    sender_fault: bool = True
    status_code: int = 401

class ResourceInUse(ServiceException):
    code: str = "ResourceInUse"
    sender_fault: bool = True
    status_code: int = 409

class ResourceNotDisabled(ServiceException):
    code: str = "ResourceNotDisabled"
    sender_fault: bool = True
    status_code: int = 409

class ResponseHeadersPolicyAlreadyExists(ServiceException):
    code: str = "ResponseHeadersPolicyAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class ResponseHeadersPolicyInUse(ServiceException):
    code: str = "ResponseHeadersPolicyInUse"
    sender_fault: bool = True
    status_code: int = 409

class StagingDistributionInUse(ServiceException):
    code: str = "StagingDistributionInUse"
    sender_fault: bool = True
    status_code: int = 409

class StreamingDistributionAlreadyExists(ServiceException):
    code: str = "StreamingDistributionAlreadyExists"
    sender_fault: bool = True
    status_code: int = 409

class StreamingDistributionNotDisabled(ServiceException):
    code: str = "StreamingDistributionNotDisabled"
    sender_fault: bool = True
    status_code: int = 409

class TestFunctionFailed(ServiceException):
    code: str = "TestFunctionFailed"
    sender_fault: bool = False
    status_code: int = 500

class TooLongCSPInResponseHeadersPolicy(ServiceException):
    code: str = "TooLongCSPInResponseHeadersPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCacheBehaviors(ServiceException):
    code: str = "TooManyCacheBehaviors"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCachePolicies(ServiceException):
    code: str = "TooManyCachePolicies"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCertificates(ServiceException):
    code: str = "TooManyCertificates"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCloudFrontOriginAccessIdentities(ServiceException):
    code: str = "TooManyCloudFrontOriginAccessIdentities"
    sender_fault: bool = True
    status_code: int = 400

class TooManyContinuousDeploymentPolicies(ServiceException):
    code: str = "TooManyContinuousDeploymentPolicies"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCookieNamesInWhiteList(ServiceException):
    code: str = "TooManyCookieNamesInWhiteList"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCookiesInCachePolicy(ServiceException):
    code: str = "TooManyCookiesInCachePolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCookiesInOriginRequestPolicy(ServiceException):
    code: str = "TooManyCookiesInOriginRequestPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyCustomHeadersInResponseHeadersPolicy(ServiceException):
    code: str = "TooManyCustomHeadersInResponseHeadersPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionCNAMEs(ServiceException):
    code: str = "TooManyDistributionCNAMEs"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributions(ServiceException):
    code: str = "TooManyDistributions"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToCachePolicy(ServiceException):
    code: str = "TooManyDistributionsAssociatedToCachePolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToFieldLevelEncryptionConfig(ServiceException):
    code: str = "TooManyDistributionsAssociatedToFieldLevelEncryptionConfig"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToKeyGroup(ServiceException):
    code: str = "TooManyDistributionsAssociatedToKeyGroup"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToOriginAccessControl(ServiceException):
    code: str = "TooManyDistributionsAssociatedToOriginAccessControl"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToOriginRequestPolicy(ServiceException):
    code: str = "TooManyDistributionsAssociatedToOriginRequestPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsAssociatedToResponseHeadersPolicy(ServiceException):
    code: str = "TooManyDistributionsAssociatedToResponseHeadersPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsWithFunctionAssociations(ServiceException):
    code: str = "TooManyDistributionsWithFunctionAssociations"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsWithLambdaAssociations(ServiceException):
    code: str = "TooManyDistributionsWithLambdaAssociations"
    sender_fault: bool = True
    status_code: int = 400

class TooManyDistributionsWithSingleFunctionARN(ServiceException):
    code: str = "TooManyDistributionsWithSingleFunctionARN"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionConfigs(ServiceException):
    code: str = "TooManyFieldLevelEncryptionConfigs"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionContentTypeProfiles(ServiceException):
    code: str = "TooManyFieldLevelEncryptionContentTypeProfiles"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionEncryptionEntities(ServiceException):
    code: str = "TooManyFieldLevelEncryptionEncryptionEntities"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionFieldPatterns(ServiceException):
    code: str = "TooManyFieldLevelEncryptionFieldPatterns"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionProfiles(ServiceException):
    code: str = "TooManyFieldLevelEncryptionProfiles"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFieldLevelEncryptionQueryArgProfiles(ServiceException):
    code: str = "TooManyFieldLevelEncryptionQueryArgProfiles"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFunctionAssociations(ServiceException):
    code: str = "TooManyFunctionAssociations"
    sender_fault: bool = True
    status_code: int = 400

class TooManyFunctions(ServiceException):
    code: str = "TooManyFunctions"
    sender_fault: bool = True
    status_code: int = 400

class TooManyHeadersInCachePolicy(ServiceException):
    code: str = "TooManyHeadersInCachePolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyHeadersInForwardedValues(ServiceException):
    code: str = "TooManyHeadersInForwardedValues"
    sender_fault: bool = True
    status_code: int = 400

class TooManyHeadersInOriginRequestPolicy(ServiceException):
    code: str = "TooManyHeadersInOriginRequestPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyInvalidationsInProgress(ServiceException):
    code: str = "TooManyInvalidationsInProgress"
    sender_fault: bool = True
    status_code: int = 400

class TooManyKeyGroups(ServiceException):
    code: str = "TooManyKeyGroups"
    sender_fault: bool = True
    status_code: int = 400

class TooManyKeyGroupsAssociatedToDistribution(ServiceException):
    code: str = "TooManyKeyGroupsAssociatedToDistribution"
    sender_fault: bool = True
    status_code: int = 400

class TooManyLambdaFunctionAssociations(ServiceException):
    code: str = "TooManyLambdaFunctionAssociations"
    sender_fault: bool = True
    status_code: int = 400

class TooManyOriginAccessControls(ServiceException):
    code: str = "TooManyOriginAccessControls"
    sender_fault: bool = True
    status_code: int = 400

class TooManyOriginCustomHeaders(ServiceException):
    code: str = "TooManyOriginCustomHeaders"
    sender_fault: bool = True
    status_code: int = 400

class TooManyOriginGroupsPerDistribution(ServiceException):
    code: str = "TooManyOriginGroupsPerDistribution"
    sender_fault: bool = True
    status_code: int = 400

class TooManyOriginRequestPolicies(ServiceException):
    code: str = "TooManyOriginRequestPolicies"
    sender_fault: bool = True
    status_code: int = 400

class TooManyOrigins(ServiceException):
    code: str = "TooManyOrigins"
    sender_fault: bool = True
    status_code: int = 400

class TooManyPublicKeys(ServiceException):
    code: str = "TooManyPublicKeys"
    sender_fault: bool = True
    status_code: int = 400

class TooManyPublicKeysInKeyGroup(ServiceException):
    code: str = "TooManyPublicKeysInKeyGroup"
    sender_fault: bool = True
    status_code: int = 400

class TooManyQueryStringParameters(ServiceException):
    code: str = "TooManyQueryStringParameters"
    sender_fault: bool = True
    status_code: int = 400

class TooManyQueryStringsInCachePolicy(ServiceException):
    code: str = "TooManyQueryStringsInCachePolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyQueryStringsInOriginRequestPolicy(ServiceException):
    code: str = "TooManyQueryStringsInOriginRequestPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyRealtimeLogConfigs(ServiceException):
    code: str = "TooManyRealtimeLogConfigs"
    sender_fault: bool = True
    status_code: int = 400

class TooManyRemoveHeadersInResponseHeadersPolicy(ServiceException):
    code: str = "TooManyRemoveHeadersInResponseHeadersPolicy"
    sender_fault: bool = True
    status_code: int = 400

class TooManyResponseHeadersPolicies(ServiceException):
    code: str = "TooManyResponseHeadersPolicies"
    sender_fault: bool = True
    status_code: int = 400

class TooManyStreamingDistributionCNAMEs(ServiceException):
    code: str = "TooManyStreamingDistributionCNAMEs"
    sender_fault: bool = True
    status_code: int = 400

class TooManyStreamingDistributions(ServiceException):
    code: str = "TooManyStreamingDistributions"
    sender_fault: bool = True
    status_code: int = 400

class TooManyTrustedSigners(ServiceException):
    code: str = "TooManyTrustedSigners"
    sender_fault: bool = True
    status_code: int = 400

class TrustedKeyGroupDoesNotExist(ServiceException):
    code: str = "TrustedKeyGroupDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400

class TrustedSignerDoesNotExist(ServiceException):
    code: str = "TrustedSignerDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400

class UnsupportedOperation(ServiceException):
    code: str = "UnsupportedOperation"
    sender_fault: bool = True
    status_code: int = 400

AccessControlAllowHeadersList = list[string]
AccessControlAllowMethodsList = list[ResponseHeadersPolicyAccessControlAllowMethodsValues]
AccessControlAllowOriginsList = list[string]
AccessControlExposeHeadersList = list[string]
KeyPairIdList = list[string]
class KeyPairIds(TypedDict, total=False):
    Quantity: integer
    Items: KeyPairIdList | None

class KGKeyPairIds(TypedDict, total=False):
    KeyGroupId: string | None
    KeyPairIds: KeyPairIds | None

KGKeyPairIdsList = list[KGKeyPairIds]
class ActiveTrustedKeyGroups(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: KGKeyPairIdsList | None

class Signer(TypedDict, total=False):
    AwsAccountNumber: string | None
    KeyPairIds: KeyPairIds | None

SignerList = list[Signer]
class ActiveTrustedSigners(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: SignerList | None

class AliasICPRecordal(TypedDict, total=False):
    CNAME: string | None
    ICPRecordalStatus: ICPRecordalStatus | None

AliasICPRecordals = list[AliasICPRecordal]
AliasList = list[string]
class Aliases(TypedDict, total=False):
    Quantity: integer
    Items: AliasList | None

MethodsList = list[Method]
class CachedMethods(TypedDict, total=False):
    Quantity: integer
    Items: MethodsList

class AllowedMethods(TypedDict, total=False):
    Quantity: integer
    Items: MethodsList
    CachedMethods: CachedMethods | None

timestamp = datetime
AnycastIps = list[string]
class IpamCidrConfig(TypedDict, total=False):
    Cidr: string
    IpamPoolArn: string
    AnycastIp: string | None
    Status: IpamCidrStatus | None

IpamCidrConfigList = list[IpamCidrConfig]
class IpamConfig(TypedDict, total=False):
    Quantity: integer
    IpamCidrConfigs: IpamCidrConfigList

class AnycastIpList(TypedDict, total=False):
    Id: string
    Name: AnycastIpListName
    Status: string
    Arn: string
    IpAddressType: IpAddressType | None
    IpamConfig: IpamConfig | None
    AnycastIps: AnycastIps
    IpCount: integer
    LastModifiedTime: timestamp

class AnycastIpListSummary(TypedDict, total=False):
    Id: string
    Name: AnycastIpListName
    Status: string
    Arn: string
    IpCount: integer
    LastModifiedTime: timestamp
    IpAddressType: IpAddressType | None
    ETag: string | None
    IpamConfig: IpamConfig | None

AnycastIpListSummaries = list[AnycastIpListSummary]
class AnycastIpListCollection(TypedDict, total=False):
    Items: AnycastIpListSummaries | None
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer

class AssociateAliasRequest(ServiceRequest):
    TargetDistributionId: string
    Alias: string

class AssociateDistributionTenantWebACLRequest(ServiceRequest):
    Id: string
    WebACLArn: string
    IfMatch: string | None

class AssociateDistributionTenantWebACLResult(TypedDict, total=False):
    Id: string | None
    WebACLArn: string | None
    ETag: string | None

class AssociateDistributionWebACLRequest(ServiceRequest):
    Id: string
    WebACLArn: string
    IfMatch: string | None

class AssociateDistributionWebACLResult(TypedDict, total=False):
    Id: string | None
    WebACLArn: string | None
    ETag: string | None

AwsAccountNumberList = list[string]
class CaCertificatesBundleS3Location(TypedDict, total=False):
    Bucket: string
    Key: string
    Region: CaCertificatesBundleS3LocationRegionString
    Version: string | None

class CaCertificatesBundleSource(TypedDict, total=False):
    CaCertificatesBundleS3Location: CaCertificatesBundleS3Location | None

long = int
QueryStringCacheKeysList = list[string]
class QueryStringCacheKeys(TypedDict, total=False):
    Quantity: integer
    Items: QueryStringCacheKeysList | None

HeaderList = list[string]
class Headers(TypedDict, total=False):
    Quantity: integer
    Items: HeaderList | None

CookieNameList = list[string]
class CookieNames(TypedDict, total=False):
    Quantity: integer
    Items: CookieNameList | None

class CookiePreference(TypedDict, total=False):
    Forward: ItemSelection
    WhitelistedNames: CookieNames | None

class ForwardedValues(TypedDict, total=False):
    QueryString: boolean
    Cookies: CookiePreference
    Headers: Headers | None
    QueryStringCacheKeys: QueryStringCacheKeys | None

class GrpcConfig(TypedDict, total=False):
    Enabled: boolean

class FunctionAssociation(TypedDict, total=False):
    FunctionARN: FunctionARN
    EventType: EventType

FunctionAssociationList = list[FunctionAssociation]
class FunctionAssociations(TypedDict, total=False):
    Quantity: integer
    Items: FunctionAssociationList | None

class LambdaFunctionAssociation(TypedDict, total=False):
    LambdaFunctionARN: LambdaFunctionARN
    EventType: EventType
    IncludeBody: boolean | None

LambdaFunctionAssociationList = list[LambdaFunctionAssociation]
class LambdaFunctionAssociations(TypedDict, total=False):
    Quantity: integer
    Items: LambdaFunctionAssociationList | None

TrustedKeyGroupIdList = list[string]
class TrustedKeyGroups(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: TrustedKeyGroupIdList | None

class TrustedSigners(TypedDict, total=False):
    Enabled: boolean
    Quantity: integer
    Items: AwsAccountNumberList | None

class CacheBehavior(TypedDict, total=False):
    PathPattern: string
    TargetOriginId: string
    TrustedSigners: TrustedSigners | None
    TrustedKeyGroups: TrustedKeyGroups | None
    ViewerProtocolPolicy: ViewerProtocolPolicy
    AllowedMethods: AllowedMethods | None
    SmoothStreaming: boolean | None
    Compress: boolean | None
    LambdaFunctionAssociations: LambdaFunctionAssociations | None
    FunctionAssociations: FunctionAssociations | None
    FieldLevelEncryptionId: string | None
    RealtimeLogConfigArn: string | None
    CachePolicyId: string | None
    OriginRequestPolicyId: string | None
    ResponseHeadersPolicyId: string | None
    GrpcConfig: GrpcConfig | None
    ForwardedValues: ForwardedValues | None
    MinTTL: long | None
    DefaultTTL: long | None
    MaxTTL: long | None

CacheBehaviorList = list[CacheBehavior]
class CacheBehaviors(TypedDict, total=False):
    Quantity: integer
    Items: CacheBehaviorList | None

QueryStringNamesList = list[string]
class QueryStringNames(TypedDict, total=False):
    Quantity: integer
    Items: QueryStringNamesList | None

class CachePolicyQueryStringsConfig(TypedDict, total=False):
    QueryStringBehavior: CachePolicyQueryStringBehavior
    QueryStrings: QueryStringNames | None

class CachePolicyCookiesConfig(TypedDict, total=False):
    CookieBehavior: CachePolicyCookieBehavior
    Cookies: CookieNames | None

class CachePolicyHeadersConfig(TypedDict, total=False):
    HeaderBehavior: CachePolicyHeaderBehavior
    Headers: Headers | None

class ParametersInCacheKeyAndForwardedToOrigin(TypedDict, total=False):
    EnableAcceptEncodingGzip: boolean
    EnableAcceptEncodingBrotli: boolean | None
    HeadersConfig: CachePolicyHeadersConfig
    CookiesConfig: CachePolicyCookiesConfig
    QueryStringsConfig: CachePolicyQueryStringsConfig

class CachePolicyConfig(TypedDict, total=False):
    Comment: string | None
    Name: string
    DefaultTTL: long | None
    MaxTTL: long | None
    MinTTL: long
    ParametersInCacheKeyAndForwardedToOrigin: ParametersInCacheKeyAndForwardedToOrigin | None

class CachePolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    CachePolicyConfig: CachePolicyConfig

class CachePolicySummary(TypedDict, total=False):
    Type: CachePolicyType
    CachePolicy: CachePolicy

CachePolicySummaryList = list[CachePolicySummary]
class CachePolicyList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: CachePolicySummaryList | None

class Certificate(TypedDict, total=False):
    Arn: string

class CloudFrontOriginAccessIdentityConfig(TypedDict, total=False):
    CallerReference: string
    Comment: string

class CloudFrontOriginAccessIdentity(TypedDict, total=False):
    Id: string
    S3CanonicalUserId: string
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig | None

class CloudFrontOriginAccessIdentitySummary(TypedDict, total=False):
    Id: string
    S3CanonicalUserId: string
    Comment: string

CloudFrontOriginAccessIdentitySummaryList = list[CloudFrontOriginAccessIdentitySummary]
class CloudFrontOriginAccessIdentityList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: CloudFrontOriginAccessIdentitySummaryList | None

class ConflictingAlias(TypedDict, total=False):
    Alias: string | None
    DistributionId: string | None
    AccountId: string | None

ConflictingAliases = list[ConflictingAlias]
class ConflictingAliasesList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer | None
    Quantity: integer | None
    Items: ConflictingAliases | None

class ConnectionFunctionAssociation(TypedDict, total=False):
    Id: ResourceId

class KeyValueStoreAssociation(TypedDict, total=False):
    KeyValueStoreARN: KeyValueStoreARN

KeyValueStoreAssociationList = list[KeyValueStoreAssociation]
class KeyValueStoreAssociations(TypedDict, total=False):
    Quantity: integer
    Items: KeyValueStoreAssociationList | None

class FunctionConfig(TypedDict, total=False):
    Comment: string
    Runtime: FunctionRuntime
    KeyValueStoreAssociations: KeyValueStoreAssociations | None

class ConnectionFunctionSummary(TypedDict, total=False):
    Name: FunctionName
    Id: ResourceId
    ConnectionFunctionConfig: FunctionConfig
    ConnectionFunctionArn: string
    Status: string
    Stage: FunctionStage
    CreatedTime: timestamp
    LastModifiedTime: timestamp

ConnectionFunctionSummaryList = list[ConnectionFunctionSummary]
FunctionExecutionLogList = list[string]
class ConnectionFunctionTestResult(TypedDict, total=False):
    ConnectionFunctionSummary: ConnectionFunctionSummary | None
    ComputeUtilization: string | None
    ConnectionFunctionExecutionLogs: FunctionExecutionLogList | None
    ConnectionFunctionErrorMessage: sensitiveStringType | None
    ConnectionFunctionOutput: sensitiveStringType | None

class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue | None

TagList = list[Tag]
class Tags(TypedDict, total=False):
    Items: TagList | None

class ConnectionGroup(TypedDict, total=False):
    Id: string | None
    Name: string | None
    Arn: string | None
    CreatedTime: timestamp | None
    LastModifiedTime: timestamp | None
    Tags: Tags | None
    Ipv6Enabled: boolean | None
    RoutingEndpoint: string | None
    AnycastIpListId: string | None
    Status: string | None
    Enabled: boolean | None
    IsDefault: boolean | None

class ConnectionGroupAssociationFilter(TypedDict, total=False):
    AnycastIpListId: string | None

class ConnectionGroupSummary(TypedDict, total=False):
    Id: string
    Name: string
    Arn: string
    RoutingEndpoint: string
    CreatedTime: timestamp
    LastModifiedTime: timestamp
    ETag: string
    AnycastIpListId: string | None
    Enabled: boolean | None
    Status: string | None
    IsDefault: boolean | None

ConnectionGroupSummaryList = list[ConnectionGroupSummary]
class ContentTypeProfile(TypedDict, total=False):
    Format: Format
    ProfileId: string | None
    ContentType: string

ContentTypeProfileList = list[ContentTypeProfile]
class ContentTypeProfiles(TypedDict, total=False):
    Quantity: integer
    Items: ContentTypeProfileList | None

class ContentTypeProfileConfig(TypedDict, total=False):
    ForwardWhenContentTypeIsUnknown: boolean
    ContentTypeProfiles: ContentTypeProfiles | None

class ContinuousDeploymentSingleHeaderConfig(TypedDict, total=False):
    Header: string
    Value: string

class SessionStickinessConfig(TypedDict, total=False):
    IdleTTL: integer
    MaximumTTL: integer

class ContinuousDeploymentSingleWeightConfig(TypedDict, total=False):
    Weight: float
    SessionStickinessConfig: SessionStickinessConfig | None

class TrafficConfig(TypedDict, total=False):
    SingleWeightConfig: ContinuousDeploymentSingleWeightConfig | None
    SingleHeaderConfig: ContinuousDeploymentSingleHeaderConfig | None
    Type: ContinuousDeploymentPolicyType

StagingDistributionDnsNameList = list[string]
class StagingDistributionDnsNames(TypedDict, total=False):
    Quantity: integer
    Items: StagingDistributionDnsNameList | None

class ContinuousDeploymentPolicyConfig(TypedDict, total=False):
    StagingDistributionDnsNames: StagingDistributionDnsNames
    Enabled: boolean
    TrafficConfig: TrafficConfig | None

class ContinuousDeploymentPolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    ContinuousDeploymentPolicyConfig: ContinuousDeploymentPolicyConfig

class ContinuousDeploymentPolicySummary(TypedDict, total=False):
    ContinuousDeploymentPolicy: ContinuousDeploymentPolicy

ContinuousDeploymentPolicySummaryList = list[ContinuousDeploymentPolicySummary]
class ContinuousDeploymentPolicyList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: ContinuousDeploymentPolicySummaryList | None

class CopyDistributionRequest(ServiceRequest):
    PrimaryDistributionId: string
    Staging: boolean | None
    IfMatch: string | None
    CallerReference: string
    Enabled: boolean | None

class TrustStoreConfig(TypedDict, total=False):
    TrustStoreId: string
    AdvertiseTrustStoreCaNames: boolean | None
    IgnoreCertificateExpiry: boolean | None

class ViewerMtlsConfig(TypedDict, total=False):
    Mode: ViewerMtlsMode | None
    TrustStoreConfig: TrustStoreConfig | None

class StringSchemaConfig(TypedDict, total=False):
    Comment: sensitiveStringType | None
    DefaultValue: ParameterValue | None
    Required: boolean

class ParameterDefinitionSchema(TypedDict, total=False):
    StringSchema: StringSchemaConfig | None

class ParameterDefinition(TypedDict, total=False):
    Name: ParameterName
    Definition: ParameterDefinitionSchema

ParameterDefinitions = list[ParameterDefinition]
class TenantConfig(TypedDict, total=False):
    ParameterDefinitions: ParameterDefinitions | None

LocationList = list[string]
class GeoRestriction(TypedDict, total=False):
    RestrictionType: GeoRestrictionType
    Quantity: integer
    Items: LocationList | None

class Restrictions(TypedDict, total=False):
    GeoRestriction: GeoRestriction

class ViewerCertificate(TypedDict, total=False):
    CloudFrontDefaultCertificate: boolean | None
    IAMCertificateId: ServerCertificateId | None
    ACMCertificateArn: string | None
    SSLSupportMethod: SSLSupportMethod | None
    MinimumProtocolVersion: MinimumProtocolVersion | None
    Certificate: string | None
    CertificateSource: CertificateSource | None

class LoggingConfig(TypedDict, total=False):
    Enabled: boolean | None
    IncludeCookies: boolean | None
    Bucket: string | None
    Prefix: string | None

class CustomErrorResponse(TypedDict, total=False):
    ErrorCode: integer
    ResponsePagePath: string | None
    ResponseCode: string | None
    ErrorCachingMinTTL: long | None

CustomErrorResponseList = list[CustomErrorResponse]
class CustomErrorResponses(TypedDict, total=False):
    Quantity: integer
    Items: CustomErrorResponseList | None

class DefaultCacheBehavior(TypedDict, total=False):
    TargetOriginId: string
    TrustedSigners: TrustedSigners | None
    TrustedKeyGroups: TrustedKeyGroups | None
    ViewerProtocolPolicy: ViewerProtocolPolicy
    AllowedMethods: AllowedMethods | None
    SmoothStreaming: boolean | None
    Compress: boolean | None
    LambdaFunctionAssociations: LambdaFunctionAssociations | None
    FunctionAssociations: FunctionAssociations | None
    FieldLevelEncryptionId: string | None
    RealtimeLogConfigArn: string | None
    CachePolicyId: string | None
    OriginRequestPolicyId: string | None
    ResponseHeadersPolicyId: string | None
    GrpcConfig: GrpcConfig | None
    ForwardedValues: ForwardedValues | None
    MinTTL: long | None
    DefaultTTL: long | None
    MaxTTL: long | None

class OriginGroupMember(TypedDict, total=False):
    OriginId: string

OriginGroupMemberList = list[OriginGroupMember]
class OriginGroupMembers(TypedDict, total=False):
    Quantity: integer
    Items: OriginGroupMemberList

StatusCodeList = list[integer]
class StatusCodes(TypedDict, total=False):
    Quantity: integer
    Items: StatusCodeList

class OriginGroupFailoverCriteria(TypedDict, total=False):
    StatusCodes: StatusCodes

class OriginGroup(TypedDict, total=False):
    Id: string
    FailoverCriteria: OriginGroupFailoverCriteria
    Members: OriginGroupMembers
    SelectionCriteria: OriginGroupSelectionCriteria | None

OriginGroupList = list[OriginGroup]
class OriginGroups(TypedDict, total=False):
    Quantity: integer
    Items: OriginGroupList | None

class OriginShield(TypedDict, total=False):
    Enabled: boolean
    OriginShieldRegion: OriginShieldRegion | None

class VpcOriginConfig(TypedDict, total=False):
    VpcOriginId: string
    OwnerAccountId: string | None
    OriginReadTimeout: integer | None
    OriginKeepaliveTimeout: integer | None

class OriginMtlsConfig(TypedDict, total=False):
    ClientCertificateArn: string

SslProtocolsList = list[SslProtocol]
class OriginSslProtocols(TypedDict, total=False):
    Quantity: integer
    Items: SslProtocolsList

class CustomOriginConfig(TypedDict, total=False):
    HTTPPort: integer
    HTTPSPort: integer
    OriginProtocolPolicy: OriginProtocolPolicy
    OriginSslProtocols: OriginSslProtocols | None
    OriginReadTimeout: integer | None
    OriginKeepaliveTimeout: integer | None
    IpAddressType: IpAddressType | None
    OriginMtlsConfig: OriginMtlsConfig | None

class S3OriginConfig(TypedDict, total=False):
    OriginAccessIdentity: string
    OriginReadTimeout: integer | None

class OriginCustomHeader(TypedDict, total=False):
    HeaderName: string
    HeaderValue: sensitiveStringType

OriginCustomHeadersList = list[OriginCustomHeader]
class CustomHeaders(TypedDict, total=False):
    Quantity: integer
    Items: OriginCustomHeadersList | None

class Origin(TypedDict, total=False):
    Id: string
    DomainName: string
    OriginPath: string | None
    CustomHeaders: CustomHeaders | None
    S3OriginConfig: S3OriginConfig | None
    CustomOriginConfig: CustomOriginConfig | None
    VpcOriginConfig: VpcOriginConfig | None
    ConnectionAttempts: integer | None
    ConnectionTimeout: integer | None
    ResponseCompletionTimeout: integer | None
    OriginShield: OriginShield | None
    OriginAccessControlId: string | None

OriginList = list[Origin]
class Origins(TypedDict, total=False):
    Quantity: integer
    Items: OriginList

class DistributionConfig(TypedDict, total=False):
    CallerReference: string
    Aliases: Aliases | None
    DefaultRootObject: string | None
    Origins: Origins
    OriginGroups: OriginGroups | None
    DefaultCacheBehavior: DefaultCacheBehavior
    CacheBehaviors: CacheBehaviors | None
    CustomErrorResponses: CustomErrorResponses | None
    Comment: CommentType
    Logging: LoggingConfig | None
    PriceClass: PriceClass | None
    Enabled: boolean
    ViewerCertificate: ViewerCertificate | None
    Restrictions: Restrictions | None
    WebACLId: string | None
    HttpVersion: HttpVersion | None
    IsIPV6Enabled: boolean | None
    ContinuousDeploymentPolicyId: string | None
    Staging: boolean | None
    AnycastIpListId: string | None
    TenantConfig: TenantConfig | None
    ConnectionMode: ConnectionMode | None
    ViewerMtlsConfig: ViewerMtlsConfig | None
    ConnectionFunctionAssociation: ConnectionFunctionAssociation | None

class Distribution(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp
    InProgressInvalidationBatches: integer
    DomainName: string
    ActiveTrustedSigners: ActiveTrustedSigners | None
    ActiveTrustedKeyGroups: ActiveTrustedKeyGroups | None
    DistributionConfig: DistributionConfig
    AliasICPRecordals: AliasICPRecordals | None

class CopyDistributionResult(TypedDict, total=False):
    Distribution: Distribution | None
    Location: string | None
    ETag: string | None

class CreateAnycastIpListRequest(ServiceRequest):
    Name: AnycastIpListName
    IpCount: integer
    Tags: Tags | None
    IpAddressType: IpAddressType | None
    IpamCidrConfigs: IpamCidrConfigList | None

class CreateAnycastIpListResult(TypedDict, total=False):
    AnycastIpList: AnycastIpList | None
    ETag: string | None

class CreateCachePolicyRequest(ServiceRequest):
    CachePolicyConfig: CachePolicyConfig

class CreateCachePolicyResult(TypedDict, total=False):
    CachePolicy: CachePolicy | None
    Location: string | None
    ETag: string | None

class CreateCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig

class CreateCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: CloudFrontOriginAccessIdentity | None
    Location: string | None
    ETag: string | None

FunctionBlob = bytes
class CreateConnectionFunctionRequest(ServiceRequest):
    Name: FunctionName
    ConnectionFunctionConfig: FunctionConfig
    ConnectionFunctionCode: FunctionBlob
    Tags: Tags | None

class CreateConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionSummary: ConnectionFunctionSummary | None
    Location: string | None
    ETag: string | None

class CreateConnectionGroupRequest(ServiceRequest):
    Name: string
    Ipv6Enabled: boolean | None
    Tags: Tags | None
    AnycastIpListId: string | None
    Enabled: boolean | None

class CreateConnectionGroupResult(TypedDict, total=False):
    ConnectionGroup: ConnectionGroup | None
    ETag: string | None

class CreateContinuousDeploymentPolicyRequest(ServiceRequest):
    ContinuousDeploymentPolicyConfig: ContinuousDeploymentPolicyConfig

class CreateContinuousDeploymentPolicyResult(TypedDict, total=False):
    ContinuousDeploymentPolicy: ContinuousDeploymentPolicy | None
    Location: string | None
    ETag: string | None

class CreateDistributionRequest(ServiceRequest):
    DistributionConfig: DistributionConfig

class CreateDistributionResult(TypedDict, total=False):
    Distribution: Distribution | None
    Location: string | None
    ETag: string | None

class ManagedCertificateRequest(TypedDict, total=False):
    ValidationTokenHost: ValidationTokenHost
    PrimaryDomainName: string | None
    CertificateTransparencyLoggingPreference: CertificateTransparencyLoggingPreference | None

class Parameter(TypedDict, total=False):
    Name: ParameterName
    Value: ParameterValue

Parameters = list[Parameter]
class GeoRestrictionCustomization(TypedDict, total=False):
    RestrictionType: GeoRestrictionType
    Locations: LocationList | None

class WebAclCustomization(TypedDict, total=False):
    Action: CustomizationActionType
    Arn: string | None

class Customizations(TypedDict, total=False):
    WebAcl: WebAclCustomization | None
    Certificate: Certificate | None
    GeoRestrictions: GeoRestrictionCustomization | None

class DomainItem(TypedDict, total=False):
    Domain: string

DomainList = list[DomainItem]
class CreateDistributionTenantRequest(ServiceRequest):
    DistributionId: string
    Name: CreateDistributionTenantRequestNameString
    Domains: DomainList
    Tags: Tags | None
    Customizations: Customizations | None
    Parameters: Parameters | None
    ConnectionGroupId: string | None
    ManagedCertificateRequest: ManagedCertificateRequest | None
    Enabled: boolean | None

class DomainResult(TypedDict, total=False):
    Domain: string
    Status: DomainStatus | None

DomainResultList = list[DomainResult]
class DistributionTenant(TypedDict, total=False):
    Id: string | None
    DistributionId: string | None
    Name: string | None
    Arn: string | None
    Domains: DomainResultList | None
    Tags: Tags | None
    Customizations: Customizations | None
    Parameters: Parameters | None
    ConnectionGroupId: string | None
    CreatedTime: timestamp | None
    LastModifiedTime: timestamp | None
    Enabled: boolean | None
    Status: string | None

class CreateDistributionTenantResult(TypedDict, total=False):
    DistributionTenant: DistributionTenant | None
    ETag: string | None

class DistributionConfigWithTags(TypedDict, total=False):
    DistributionConfig: DistributionConfig
    Tags: Tags

class CreateDistributionWithTagsRequest(ServiceRequest):
    DistributionConfigWithTags: DistributionConfigWithTags

class CreateDistributionWithTagsResult(TypedDict, total=False):
    Distribution: Distribution | None
    Location: string | None
    ETag: string | None

class QueryArgProfile(TypedDict, total=False):
    QueryArg: string
    ProfileId: string

QueryArgProfileList = list[QueryArgProfile]
class QueryArgProfiles(TypedDict, total=False):
    Quantity: integer
    Items: QueryArgProfileList | None

class QueryArgProfileConfig(TypedDict, total=False):
    ForwardWhenQueryArgProfileIsUnknown: boolean
    QueryArgProfiles: QueryArgProfiles | None

class FieldLevelEncryptionConfig(TypedDict, total=False):
    CallerReference: string
    Comment: string | None
    QueryArgProfileConfig: QueryArgProfileConfig | None
    ContentTypeProfileConfig: ContentTypeProfileConfig | None

class CreateFieldLevelEncryptionConfigRequest(ServiceRequest):
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig

class FieldLevelEncryption(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig

class CreateFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryption: FieldLevelEncryption | None
    Location: string | None
    ETag: string | None

FieldPatternList = list[string]
class FieldPatterns(TypedDict, total=False):
    Quantity: integer
    Items: FieldPatternList | None

class EncryptionEntity(TypedDict, total=False):
    PublicKeyId: string
    ProviderId: string
    FieldPatterns: FieldPatterns

EncryptionEntityList = list[EncryptionEntity]
class EncryptionEntities(TypedDict, total=False):
    Quantity: integer
    Items: EncryptionEntityList | None

class FieldLevelEncryptionProfileConfig(TypedDict, total=False):
    Name: string
    CallerReference: string
    Comment: string | None
    EncryptionEntities: EncryptionEntities

class CreateFieldLevelEncryptionProfileRequest(ServiceRequest):
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig

class FieldLevelEncryptionProfile(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig

class CreateFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: FieldLevelEncryptionProfile | None
    Location: string | None
    ETag: string | None

class CreateFunctionRequest(ServiceRequest):
    Name: FunctionName
    FunctionConfig: FunctionConfig
    FunctionCode: FunctionBlob

class FunctionMetadata(TypedDict, total=False):
    FunctionARN: string
    Stage: FunctionStage | None
    CreatedTime: timestamp | None
    LastModifiedTime: timestamp

class FunctionSummary(TypedDict, total=False):
    Name: FunctionName
    Status: string | None
    FunctionConfig: FunctionConfig
    FunctionMetadata: FunctionMetadata

class CreateFunctionResult(TypedDict, total=False):
    FunctionSummary: FunctionSummary | None
    Location: string | None
    ETag: string | None

PathList = list[string]
class Paths(TypedDict, total=False):
    Quantity: integer
    Items: PathList | None

class InvalidationBatch(TypedDict, total=False):
    Paths: Paths
    CallerReference: string

class CreateInvalidationForDistributionTenantRequest(ServiceRequest):
    Id: string
    InvalidationBatch: InvalidationBatch

class Invalidation(TypedDict, total=False):
    Id: string
    Status: string
    CreateTime: timestamp
    InvalidationBatch: InvalidationBatch

class CreateInvalidationForDistributionTenantResult(TypedDict, total=False):
    Location: string | None
    Invalidation: Invalidation | None

class CreateInvalidationRequest(ServiceRequest):
    DistributionId: string
    InvalidationBatch: InvalidationBatch

class CreateInvalidationResult(TypedDict, total=False):
    Location: string | None
    Invalidation: Invalidation | None

PublicKeyIdList = list[string]
class KeyGroupConfig(TypedDict, total=False):
    Name: string
    Items: PublicKeyIdList
    Comment: string | None

class CreateKeyGroupRequest(ServiceRequest):
    KeyGroupConfig: KeyGroupConfig

class KeyGroup(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    KeyGroupConfig: KeyGroupConfig

class CreateKeyGroupResult(TypedDict, total=False):
    KeyGroup: KeyGroup | None
    Location: string | None
    ETag: string | None

class ImportSource(TypedDict, total=False):
    SourceType: ImportSourceType
    SourceARN: string

class CreateKeyValueStoreRequest(ServiceRequest):
    Name: KeyValueStoreName
    Comment: KeyValueStoreComment | None
    ImportSource: ImportSource | None

class KeyValueStore(TypedDict, total=False):
    Name: string
    Id: string
    Comment: string
    ARN: string
    Status: string | None
    LastModifiedTime: timestamp

class CreateKeyValueStoreResult(TypedDict, total=False):
    KeyValueStore: KeyValueStore | None
    ETag: string | None
    Location: string | None

class RealtimeMetricsSubscriptionConfig(TypedDict, total=False):
    RealtimeMetricsSubscriptionStatus: RealtimeMetricsSubscriptionStatus

class MonitoringSubscription(TypedDict, total=False):
    RealtimeMetricsSubscriptionConfig: RealtimeMetricsSubscriptionConfig | None

class CreateMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string
    MonitoringSubscription: MonitoringSubscription

class CreateMonitoringSubscriptionResult(TypedDict, total=False):
    MonitoringSubscription: MonitoringSubscription | None

class OriginAccessControlConfig(TypedDict, total=False):
    Name: string
    Description: string | None
    SigningProtocol: OriginAccessControlSigningProtocols
    SigningBehavior: OriginAccessControlSigningBehaviors
    OriginAccessControlOriginType: OriginAccessControlOriginTypes

class CreateOriginAccessControlRequest(ServiceRequest):
    OriginAccessControlConfig: OriginAccessControlConfig

class OriginAccessControl(TypedDict, total=False):
    Id: string
    OriginAccessControlConfig: OriginAccessControlConfig | None

class CreateOriginAccessControlResult(TypedDict, total=False):
    OriginAccessControl: OriginAccessControl | None
    Location: string | None
    ETag: string | None

class OriginRequestPolicyQueryStringsConfig(TypedDict, total=False):
    QueryStringBehavior: OriginRequestPolicyQueryStringBehavior
    QueryStrings: QueryStringNames | None

class OriginRequestPolicyCookiesConfig(TypedDict, total=False):
    CookieBehavior: OriginRequestPolicyCookieBehavior
    Cookies: CookieNames | None

class OriginRequestPolicyHeadersConfig(TypedDict, total=False):
    HeaderBehavior: OriginRequestPolicyHeaderBehavior
    Headers: Headers | None

class OriginRequestPolicyConfig(TypedDict, total=False):
    Comment: string | None
    Name: string
    HeadersConfig: OriginRequestPolicyHeadersConfig
    CookiesConfig: OriginRequestPolicyCookiesConfig
    QueryStringsConfig: OriginRequestPolicyQueryStringsConfig

class CreateOriginRequestPolicyRequest(ServiceRequest):
    OriginRequestPolicyConfig: OriginRequestPolicyConfig

class OriginRequestPolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    OriginRequestPolicyConfig: OriginRequestPolicyConfig

class CreateOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: OriginRequestPolicy | None
    Location: string | None
    ETag: string | None

class PublicKeyConfig(TypedDict, total=False):
    CallerReference: string
    Name: string
    EncodedKey: string
    Comment: string | None

class CreatePublicKeyRequest(ServiceRequest):
    PublicKeyConfig: PublicKeyConfig

class PublicKey(TypedDict, total=False):
    Id: string
    CreatedTime: timestamp
    PublicKeyConfig: PublicKeyConfig

class CreatePublicKeyResult(TypedDict, total=False):
    PublicKey: PublicKey | None
    Location: string | None
    ETag: string | None

FieldList = list[string]
class KinesisStreamConfig(TypedDict, total=False):
    RoleARN: string
    StreamARN: string

class EndPoint(TypedDict, total=False):
    StreamType: string
    KinesisStreamConfig: KinesisStreamConfig | None

EndPointList = list[EndPoint]
class CreateRealtimeLogConfigRequest(ServiceRequest):
    EndPoints: EndPointList
    Fields: FieldList
    Name: string
    SamplingRate: long

class RealtimeLogConfig(TypedDict, total=False):
    ARN: string
    Name: string
    SamplingRate: long
    EndPoints: EndPointList
    Fields: FieldList

class CreateRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: RealtimeLogConfig | None

class ResponseHeadersPolicyRemoveHeader(TypedDict, total=False):
    Header: string

ResponseHeadersPolicyRemoveHeaderList = list[ResponseHeadersPolicyRemoveHeader]
class ResponseHeadersPolicyRemoveHeadersConfig(TypedDict, total=False):
    Quantity: integer
    Items: ResponseHeadersPolicyRemoveHeaderList | None

class ResponseHeadersPolicyCustomHeader(TypedDict, total=False):
    Header: string
    Value: string
    Override: boolean

ResponseHeadersPolicyCustomHeaderList = list[ResponseHeadersPolicyCustomHeader]
class ResponseHeadersPolicyCustomHeadersConfig(TypedDict, total=False):
    Quantity: integer
    Items: ResponseHeadersPolicyCustomHeaderList | None

class ResponseHeadersPolicyServerTimingHeadersConfig(TypedDict, total=False):
    Enabled: boolean
    SamplingRate: SamplingRate | None

class ResponseHeadersPolicyStrictTransportSecurity(TypedDict, total=False):
    Override: boolean
    IncludeSubdomains: boolean | None
    Preload: boolean | None
    AccessControlMaxAgeSec: integer

class ResponseHeadersPolicyContentTypeOptions(TypedDict, total=False):
    Override: boolean

class ResponseHeadersPolicyContentSecurityPolicy(TypedDict, total=False):
    Override: boolean
    ContentSecurityPolicy: string

class ResponseHeadersPolicyReferrerPolicy(TypedDict, total=False):
    Override: boolean
    ReferrerPolicy: ReferrerPolicyList

class ResponseHeadersPolicyFrameOptions(TypedDict, total=False):
    Override: boolean
    FrameOption: FrameOptionsList

class ResponseHeadersPolicyXSSProtection(TypedDict, total=False):
    Override: boolean
    Protection: boolean
    ModeBlock: boolean | None
    ReportUri: string | None

class ResponseHeadersPolicySecurityHeadersConfig(TypedDict, total=False):
    XSSProtection: ResponseHeadersPolicyXSSProtection | None
    FrameOptions: ResponseHeadersPolicyFrameOptions | None
    ReferrerPolicy: ResponseHeadersPolicyReferrerPolicy | None
    ContentSecurityPolicy: ResponseHeadersPolicyContentSecurityPolicy | None
    ContentTypeOptions: ResponseHeadersPolicyContentTypeOptions | None
    StrictTransportSecurity: ResponseHeadersPolicyStrictTransportSecurity | None

class ResponseHeadersPolicyAccessControlExposeHeaders(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlExposeHeadersList | None

class ResponseHeadersPolicyAccessControlAllowMethods(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowMethodsList

class ResponseHeadersPolicyAccessControlAllowHeaders(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowHeadersList

class ResponseHeadersPolicyAccessControlAllowOrigins(TypedDict, total=False):
    Quantity: integer
    Items: AccessControlAllowOriginsList

class ResponseHeadersPolicyCorsConfig(TypedDict, total=False):
    AccessControlAllowOrigins: ResponseHeadersPolicyAccessControlAllowOrigins
    AccessControlAllowHeaders: ResponseHeadersPolicyAccessControlAllowHeaders
    AccessControlAllowMethods: ResponseHeadersPolicyAccessControlAllowMethods
    AccessControlAllowCredentials: boolean
    AccessControlExposeHeaders: ResponseHeadersPolicyAccessControlExposeHeaders | None
    AccessControlMaxAgeSec: integer | None
    OriginOverride: boolean

class ResponseHeadersPolicyConfig(TypedDict, total=False):
    Comment: string | None
    Name: string
    CorsConfig: ResponseHeadersPolicyCorsConfig | None
    SecurityHeadersConfig: ResponseHeadersPolicySecurityHeadersConfig | None
    ServerTimingHeadersConfig: ResponseHeadersPolicyServerTimingHeadersConfig | None
    CustomHeadersConfig: ResponseHeadersPolicyCustomHeadersConfig | None
    RemoveHeadersConfig: ResponseHeadersPolicyRemoveHeadersConfig | None

class CreateResponseHeadersPolicyRequest(ServiceRequest):
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig

class ResponseHeadersPolicy(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig

class CreateResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: ResponseHeadersPolicy | None
    Location: string | None
    ETag: string | None

class StreamingLoggingConfig(TypedDict, total=False):
    Enabled: boolean
    Bucket: string
    Prefix: string

class S3Origin(TypedDict, total=False):
    DomainName: string
    OriginAccessIdentity: string

class StreamingDistributionConfig(TypedDict, total=False):
    CallerReference: string
    S3Origin: S3Origin
    Aliases: Aliases | None
    Comment: string
    Logging: StreamingLoggingConfig | None
    TrustedSigners: TrustedSigners
    PriceClass: PriceClass | None
    Enabled: boolean

class CreateStreamingDistributionRequest(ServiceRequest):
    StreamingDistributionConfig: StreamingDistributionConfig

class StreamingDistribution(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp | None
    DomainName: string
    ActiveTrustedSigners: ActiveTrustedSigners
    StreamingDistributionConfig: StreamingDistributionConfig

class CreateStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: StreamingDistribution | None
    Location: string | None
    ETag: string | None

class StreamingDistributionConfigWithTags(TypedDict, total=False):
    StreamingDistributionConfig: StreamingDistributionConfig
    Tags: Tags

class CreateStreamingDistributionWithTagsRequest(ServiceRequest):
    StreamingDistributionConfigWithTags: StreamingDistributionConfigWithTags

class CreateStreamingDistributionWithTagsResult(TypedDict, total=False):
    StreamingDistribution: StreamingDistribution | None
    Location: string | None
    ETag: string | None

class CreateTrustStoreRequest(ServiceRequest):
    Name: string
    CaCertificatesBundleSource: CaCertificatesBundleSource
    Tags: Tags | None

class TrustStore(TypedDict, total=False):
    Id: string | None
    Arn: string | None
    Name: string | None
    Status: TrustStoreStatus | None
    NumberOfCaCertificates: integer | None
    LastModifiedTime: timestamp | None
    Reason: string | None

class CreateTrustStoreResult(TypedDict, total=False):
    TrustStore: TrustStore | None
    ETag: string | None

class VpcOriginEndpointConfig(TypedDict, total=False):
    Name: string
    Arn: string
    HTTPPort: integer
    HTTPSPort: integer
    OriginProtocolPolicy: OriginProtocolPolicy
    OriginSslProtocols: OriginSslProtocols | None

class CreateVpcOriginRequest(ServiceRequest):
    VpcOriginEndpointConfig: VpcOriginEndpointConfig
    Tags: Tags | None

class VpcOrigin(TypedDict, total=False):
    Id: string
    Arn: string
    AccountId: string | None
    Status: string
    CreatedTime: timestamp
    LastModifiedTime: timestamp
    VpcOriginEndpointConfig: VpcOriginEndpointConfig

class CreateVpcOriginResult(TypedDict, total=False):
    VpcOrigin: VpcOrigin | None
    Location: string | None
    ETag: string | None

class DeleteAnycastIpListRequest(ServiceRequest):
    Id: string
    IfMatch: string

class DeleteCachePolicyRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteConnectionFunctionRequest(ServiceRequest):
    Id: ResourceId
    IfMatch: string

class DeleteConnectionGroupRequest(ServiceRequest):
    Id: string
    IfMatch: string

class DeleteContinuousDeploymentPolicyRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteDistributionRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteDistributionTenantRequest(ServiceRequest):
    Id: string
    IfMatch: string

class DeleteFieldLevelEncryptionConfigRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteFieldLevelEncryptionProfileRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteFunctionRequest(ServiceRequest):
    Name: FunctionName
    IfMatch: string

class DeleteKeyGroupRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteKeyValueStoreRequest(ServiceRequest):
    Name: KeyValueStoreName
    IfMatch: string

class DeleteMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string

class DeleteMonitoringSubscriptionResult(TypedDict, total=False):
    pass

class DeleteOriginAccessControlRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteOriginRequestPolicyRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeletePublicKeyRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteRealtimeLogConfigRequest(ServiceRequest):
    Name: string | None
    ARN: string | None

class DeleteResourcePolicyRequest(ServiceRequest):
    ResourceArn: string

class DeleteResponseHeadersPolicyRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteStreamingDistributionRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DeleteTrustStoreRequest(ServiceRequest):
    Id: ResourceId
    IfMatch: string

class DeleteVpcOriginRequest(ServiceRequest):
    Id: string
    IfMatch: string

class DeleteVpcOriginResult(TypedDict, total=False):
    VpcOrigin: VpcOrigin | None
    ETag: string | None

class DescribeConnectionFunctionRequest(ServiceRequest):
    Identifier: string
    Stage: FunctionStage | None

class DescribeConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionSummary: ConnectionFunctionSummary | None
    ETag: string | None

class DescribeFunctionRequest(ServiceRequest):
    Name: FunctionName
    Stage: FunctionStage | None

class DescribeFunctionResult(TypedDict, total=False):
    FunctionSummary: FunctionSummary | None
    ETag: string | None

class DescribeKeyValueStoreRequest(ServiceRequest):
    Name: KeyValueStoreName

class DescribeKeyValueStoreResult(TypedDict, total=False):
    KeyValueStore: KeyValueStore | None
    ETag: string | None

class DisassociateDistributionTenantWebACLRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DisassociateDistributionTenantWebACLResult(TypedDict, total=False):
    Id: string | None
    ETag: string | None

class DisassociateDistributionWebACLRequest(ServiceRequest):
    Id: string
    IfMatch: string | None

class DisassociateDistributionWebACLResult(TypedDict, total=False):
    Id: string | None
    ETag: string | None

DistributionIdListSummary = list[string]
class DistributionIdList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: DistributionIdListSummary | None

class DistributionIdOwner(TypedDict, total=False):
    DistributionId: string
    OwnerAccountId: string

DistributionIdOwnerItemList = list[DistributionIdOwner]
class DistributionIdOwnerList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: DistributionIdOwnerItemList | None

class DistributionSummary(TypedDict, total=False):
    Id: string
    ARN: string
    ETag: string | None
    Status: string
    LastModifiedTime: timestamp
    DomainName: string
    Aliases: Aliases
    Origins: Origins
    OriginGroups: OriginGroups | None
    DefaultCacheBehavior: DefaultCacheBehavior
    CacheBehaviors: CacheBehaviors
    CustomErrorResponses: CustomErrorResponses
    Comment: sensitiveStringType
    PriceClass: PriceClass
    Enabled: boolean
    ViewerCertificate: ViewerCertificate
    Restrictions: Restrictions
    WebACLId: string
    HttpVersion: HttpVersion
    IsIPV6Enabled: boolean
    AliasICPRecordals: AliasICPRecordals | None
    Staging: boolean
    ConnectionMode: ConnectionMode | None
    AnycastIpListId: string | None
    ViewerMtlsConfig: ViewerMtlsConfig | None
    ConnectionFunctionAssociation: ConnectionFunctionAssociation | None

DistributionSummaryList = list[DistributionSummary]
class DistributionList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: DistributionSummaryList | None

class DistributionResourceId(TypedDict, total=False):
    DistributionId: string | None
    DistributionTenantId: string | None

class DistributionTenantAssociationFilter(TypedDict, total=False):
    DistributionId: string | None
    ConnectionGroupId: string | None

class DistributionTenantSummary(TypedDict, total=False):
    Id: string
    DistributionId: string
    Name: string
    Arn: string
    Domains: DomainResultList
    ConnectionGroupId: string | None
    Customizations: Customizations | None
    CreatedTime: timestamp
    LastModifiedTime: timestamp
    ETag: string
    Enabled: boolean | None
    Status: string | None

DistributionTenantList = list[DistributionTenantSummary]
class DnsConfiguration(TypedDict, total=False):
    Domain: string
    Status: DnsConfigurationStatus
    Reason: string | None

DnsConfigurationList = list[DnsConfiguration]
class DomainConflict(TypedDict, total=False):
    Domain: string
    ResourceType: DistributionResourceType
    ResourceId: string
    AccountId: string

DomainConflictsList = list[DomainConflict]
class FieldLevelEncryptionSummary(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    Comment: string | None
    QueryArgProfileConfig: QueryArgProfileConfig | None
    ContentTypeProfileConfig: ContentTypeProfileConfig | None

FieldLevelEncryptionSummaryList = list[FieldLevelEncryptionSummary]
class FieldLevelEncryptionList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: FieldLevelEncryptionSummaryList | None

class FieldLevelEncryptionProfileSummary(TypedDict, total=False):
    Id: string
    LastModifiedTime: timestamp
    Name: string
    EncryptionEntities: EncryptionEntities
    Comment: string | None

FieldLevelEncryptionProfileSummaryList = list[FieldLevelEncryptionProfileSummary]
class FieldLevelEncryptionProfileList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: FieldLevelEncryptionProfileSummaryList | None

FunctionEventObject = bytes
FunctionSummaryList = list[FunctionSummary]
class FunctionList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: FunctionSummaryList | None

class GetAnycastIpListRequest(ServiceRequest):
    Id: string

class GetAnycastIpListResult(TypedDict, total=False):
    AnycastIpList: AnycastIpList | None
    ETag: string | None

class GetCachePolicyConfigRequest(ServiceRequest):
    Id: string

class GetCachePolicyConfigResult(TypedDict, total=False):
    CachePolicyConfig: CachePolicyConfig | None
    ETag: string | None

class GetCachePolicyRequest(ServiceRequest):
    Id: string

class GetCachePolicyResult(TypedDict, total=False):
    CachePolicy: CachePolicy | None
    ETag: string | None

class GetCloudFrontOriginAccessIdentityConfigRequest(ServiceRequest):
    Id: string

class GetCloudFrontOriginAccessIdentityConfigResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig | None
    ETag: string | None

class GetCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    Id: string

class GetCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: CloudFrontOriginAccessIdentity | None
    ETag: string | None

class GetConnectionFunctionRequest(ServiceRequest):
    Identifier: string
    Stage: FunctionStage | None

class GetConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionCode: FunctionBlob | IO[FunctionBlob] | Iterable[FunctionBlob] | None
    ETag: string | None
    ContentType: string | None

class GetConnectionGroupByRoutingEndpointRequest(ServiceRequest):
    RoutingEndpoint: string

class GetConnectionGroupByRoutingEndpointResult(TypedDict, total=False):
    ConnectionGroup: ConnectionGroup | None
    ETag: string | None

class GetConnectionGroupRequest(ServiceRequest):
    Identifier: string

class GetConnectionGroupResult(TypedDict, total=False):
    ConnectionGroup: ConnectionGroup | None
    ETag: string | None

class GetContinuousDeploymentPolicyConfigRequest(ServiceRequest):
    Id: string

class GetContinuousDeploymentPolicyConfigResult(TypedDict, total=False):
    ContinuousDeploymentPolicyConfig: ContinuousDeploymentPolicyConfig | None
    ETag: string | None

class GetContinuousDeploymentPolicyRequest(ServiceRequest):
    Id: string

class GetContinuousDeploymentPolicyResult(TypedDict, total=False):
    ContinuousDeploymentPolicy: ContinuousDeploymentPolicy | None
    ETag: string | None

class GetDistributionConfigRequest(ServiceRequest):
    Id: string

class GetDistributionConfigResult(TypedDict, total=False):
    DistributionConfig: DistributionConfig | None
    ETag: string | None

class GetDistributionRequest(ServiceRequest):
    Id: string

class GetDistributionResult(TypedDict, total=False):
    Distribution: Distribution | None
    ETag: string | None

class GetDistributionTenantByDomainRequest(ServiceRequest):
    Domain: string

class GetDistributionTenantByDomainResult(TypedDict, total=False):
    DistributionTenant: DistributionTenant | None
    ETag: string | None

class GetDistributionTenantRequest(ServiceRequest):
    Identifier: string

class GetDistributionTenantResult(TypedDict, total=False):
    DistributionTenant: DistributionTenant | None
    ETag: string | None

class GetFieldLevelEncryptionConfigRequest(ServiceRequest):
    Id: string

class GetFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig | None
    ETag: string | None

class GetFieldLevelEncryptionProfileConfigRequest(ServiceRequest):
    Id: string

class GetFieldLevelEncryptionProfileConfigResult(TypedDict, total=False):
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig | None
    ETag: string | None

class GetFieldLevelEncryptionProfileRequest(ServiceRequest):
    Id: string

class GetFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: FieldLevelEncryptionProfile | None
    ETag: string | None

class GetFieldLevelEncryptionRequest(ServiceRequest):
    Id: string

class GetFieldLevelEncryptionResult(TypedDict, total=False):
    FieldLevelEncryption: FieldLevelEncryption | None
    ETag: string | None

class GetFunctionRequest(ServiceRequest):
    Name: FunctionName
    Stage: FunctionStage | None

class GetFunctionResult(TypedDict, total=False):
    FunctionCode: FunctionBlob | IO[FunctionBlob] | Iterable[FunctionBlob] | None
    ETag: string | None
    ContentType: string | None

class GetInvalidationForDistributionTenantRequest(ServiceRequest):
    DistributionTenantId: string
    Id: string

class GetInvalidationForDistributionTenantResult(TypedDict, total=False):
    Invalidation: Invalidation | None

class GetInvalidationRequest(ServiceRequest):
    DistributionId: string
    Id: string

class GetInvalidationResult(TypedDict, total=False):
    Invalidation: Invalidation | None

class GetKeyGroupConfigRequest(ServiceRequest):
    Id: string

class GetKeyGroupConfigResult(TypedDict, total=False):
    KeyGroupConfig: KeyGroupConfig | None
    ETag: string | None

class GetKeyGroupRequest(ServiceRequest):
    Id: string

class GetKeyGroupResult(TypedDict, total=False):
    KeyGroup: KeyGroup | None
    ETag: string | None

class GetManagedCertificateDetailsRequest(ServiceRequest):
    Identifier: string

class ValidationTokenDetail(TypedDict, total=False):
    Domain: string
    RedirectTo: string | None
    RedirectFrom: string | None

ValidationTokenDetailList = list[ValidationTokenDetail]
class ManagedCertificateDetails(TypedDict, total=False):
    CertificateArn: string | None
    CertificateStatus: ManagedCertificateStatus | None
    ValidationTokenHost: ValidationTokenHost | None
    ValidationTokenDetails: ValidationTokenDetailList | None

class GetManagedCertificateDetailsResult(TypedDict, total=False):
    ManagedCertificateDetails: ManagedCertificateDetails | None

class GetMonitoringSubscriptionRequest(ServiceRequest):
    DistributionId: string

class GetMonitoringSubscriptionResult(TypedDict, total=False):
    MonitoringSubscription: MonitoringSubscription | None

class GetOriginAccessControlConfigRequest(ServiceRequest):
    Id: string

class GetOriginAccessControlConfigResult(TypedDict, total=False):
    OriginAccessControlConfig: OriginAccessControlConfig | None
    ETag: string | None

class GetOriginAccessControlRequest(ServiceRequest):
    Id: string

class GetOriginAccessControlResult(TypedDict, total=False):
    OriginAccessControl: OriginAccessControl | None
    ETag: string | None

class GetOriginRequestPolicyConfigRequest(ServiceRequest):
    Id: string

class GetOriginRequestPolicyConfigResult(TypedDict, total=False):
    OriginRequestPolicyConfig: OriginRequestPolicyConfig | None
    ETag: string | None

class GetOriginRequestPolicyRequest(ServiceRequest):
    Id: string

class GetOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: OriginRequestPolicy | None
    ETag: string | None

class GetPublicKeyConfigRequest(ServiceRequest):
    Id: string

class GetPublicKeyConfigResult(TypedDict, total=False):
    PublicKeyConfig: PublicKeyConfig | None
    ETag: string | None

class GetPublicKeyRequest(ServiceRequest):
    Id: string

class GetPublicKeyResult(TypedDict, total=False):
    PublicKey: PublicKey | None
    ETag: string | None

class GetRealtimeLogConfigRequest(ServiceRequest):
    Name: string | None
    ARN: string | None

class GetRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: RealtimeLogConfig | None

class GetResourcePolicyRequest(ServiceRequest):
    ResourceArn: string

class GetResourcePolicyResult(TypedDict, total=False):
    ResourceArn: string | None
    PolicyDocument: string | None

class GetResponseHeadersPolicyConfigRequest(ServiceRequest):
    Id: string

class GetResponseHeadersPolicyConfigResult(TypedDict, total=False):
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig | None
    ETag: string | None

class GetResponseHeadersPolicyRequest(ServiceRequest):
    Id: string

class GetResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: ResponseHeadersPolicy | None
    ETag: string | None

class GetStreamingDistributionConfigRequest(ServiceRequest):
    Id: string

class GetStreamingDistributionConfigResult(TypedDict, total=False):
    StreamingDistributionConfig: StreamingDistributionConfig | None
    ETag: string | None

class GetStreamingDistributionRequest(ServiceRequest):
    Id: string

class GetStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: StreamingDistribution | None
    ETag: string | None

class GetTrustStoreRequest(ServiceRequest):
    Identifier: string

class GetTrustStoreResult(TypedDict, total=False):
    TrustStore: TrustStore | None
    ETag: string | None

class GetVpcOriginRequest(ServiceRequest):
    Id: string

class GetVpcOriginResult(TypedDict, total=False):
    VpcOrigin: VpcOrigin | None
    ETag: string | None

class InvalidationSummary(TypedDict, total=False):
    Id: string
    CreateTime: timestamp
    Status: string

InvalidationSummaryList = list[InvalidationSummary]
class InvalidationList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: InvalidationSummaryList | None

class KeyGroupSummary(TypedDict, total=False):
    KeyGroup: KeyGroup

KeyGroupSummaryList = list[KeyGroupSummary]
class KeyGroupList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: KeyGroupSummaryList | None

KeyValueStoreSummaryList = list[KeyValueStore]
class KeyValueStoreList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: KeyValueStoreSummaryList | None

class ListAnycastIpListsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: integer | None

class ListAnycastIpListsResult(TypedDict, total=False):
    AnycastIpLists: AnycastIpListCollection | None

class ListCachePoliciesRequest(ServiceRequest):
    Type: CachePolicyType | None
    Marker: string | None
    MaxItems: string | None

class ListCachePoliciesResult(TypedDict, total=False):
    CachePolicyList: CachePolicyList | None

class ListCloudFrontOriginAccessIdentitiesRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListCloudFrontOriginAccessIdentitiesResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentityList: CloudFrontOriginAccessIdentityList | None

class ListConflictingAliasesRequest(ServiceRequest):
    DistributionId: distributionIdString
    Alias: aliasString
    Marker: string | None
    MaxItems: listConflictingAliasesMaxItemsInteger | None

class ListConflictingAliasesResult(TypedDict, total=False):
    ConflictingAliasesList: ConflictingAliasesList | None

class ListConnectionFunctionsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: integer | None
    Stage: FunctionStage | None

class ListConnectionFunctionsResult(TypedDict, total=False):
    NextMarker: string | None
    ConnectionFunctions: ConnectionFunctionSummaryList | None

class ListConnectionGroupsRequest(ServiceRequest):
    AssociationFilter: ConnectionGroupAssociationFilter | None
    Marker: string | None
    MaxItems: integer | None

class ListConnectionGroupsResult(TypedDict, total=False):
    NextMarker: string | None
    ConnectionGroups: ConnectionGroupSummaryList | None

class ListContinuousDeploymentPoliciesRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListContinuousDeploymentPoliciesResult(TypedDict, total=False):
    ContinuousDeploymentPolicyList: ContinuousDeploymentPolicyList | None

class ListDistributionTenantsByCustomizationRequest(ServiceRequest):
    WebACLArn: string | None
    CertificateArn: string | None
    Marker: string | None
    MaxItems: integer | None

class ListDistributionTenantsByCustomizationResult(TypedDict, total=False):
    NextMarker: string | None
    DistributionTenantList: DistributionTenantList | None

class ListDistributionTenantsRequest(ServiceRequest):
    AssociationFilter: DistributionTenantAssociationFilter | None
    Marker: string | None
    MaxItems: integer | None

class ListDistributionTenantsResult(TypedDict, total=False):
    NextMarker: string | None
    DistributionTenantList: DistributionTenantList | None

class ListDistributionsByAnycastIpListIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    AnycastIpListId: string

class ListDistributionsByAnycastIpListIdResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsByCachePolicyIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    CachePolicyId: string

class ListDistributionsByCachePolicyIdResult(TypedDict, total=False):
    DistributionIdList: DistributionIdList | None

class ListDistributionsByConnectionFunctionRequest(ServiceRequest):
    Marker: string | None
    MaxItems: integer | None
    ConnectionFunctionIdentifier: string

class ListDistributionsByConnectionFunctionResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsByConnectionModeRequest(ServiceRequest):
    Marker: string | None
    MaxItems: integer | None
    ConnectionMode: ConnectionMode

class ListDistributionsByConnectionModeResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsByKeyGroupRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    KeyGroupId: string

class ListDistributionsByKeyGroupResult(TypedDict, total=False):
    DistributionIdList: DistributionIdList | None

class ListDistributionsByOriginRequestPolicyIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    OriginRequestPolicyId: string

class ListDistributionsByOriginRequestPolicyIdResult(TypedDict, total=False):
    DistributionIdList: DistributionIdList | None

class ListDistributionsByOwnedResourceRequest(ServiceRequest):
    ResourceArn: string
    Marker: string | None
    MaxItems: string | None

class ListDistributionsByOwnedResourceResult(TypedDict, total=False):
    DistributionList: DistributionIdOwnerList | None

class ListDistributionsByRealtimeLogConfigRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    RealtimeLogConfigName: string | None
    RealtimeLogConfigArn: string | None

class ListDistributionsByRealtimeLogConfigResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsByResponseHeadersPolicyIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    ResponseHeadersPolicyId: string

class ListDistributionsByResponseHeadersPolicyIdResult(TypedDict, total=False):
    DistributionIdList: DistributionIdList | None

class ListDistributionsByTrustStoreRequest(ServiceRequest):
    TrustStoreIdentifier: string
    Marker: string | None
    MaxItems: string | None

class ListDistributionsByTrustStoreResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsByVpcOriginIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    VpcOriginId: string

class ListDistributionsByVpcOriginIdResult(TypedDict, total=False):
    DistributionIdList: DistributionIdList | None

class ListDistributionsByWebACLIdRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    WebACLId: string

class ListDistributionsByWebACLIdResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDistributionsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListDistributionsResult(TypedDict, total=False):
    DistributionList: DistributionList | None

class ListDomainConflictsRequest(ServiceRequest):
    Domain: string
    DomainControlValidationResource: DistributionResourceId
    MaxItems: integer | None
    Marker: string | None

class ListDomainConflictsResult(TypedDict, total=False):
    DomainConflicts: DomainConflictsList | None
    NextMarker: string | None

class ListFieldLevelEncryptionConfigsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListFieldLevelEncryptionConfigsResult(TypedDict, total=False):
    FieldLevelEncryptionList: FieldLevelEncryptionList | None

class ListFieldLevelEncryptionProfilesRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListFieldLevelEncryptionProfilesResult(TypedDict, total=False):
    FieldLevelEncryptionProfileList: FieldLevelEncryptionProfileList | None

class ListFunctionsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    Stage: FunctionStage | None

class ListFunctionsResult(TypedDict, total=False):
    FunctionList: FunctionList | None

class ListInvalidationsForDistributionTenantRequest(ServiceRequest):
    Id: string
    Marker: string | None
    MaxItems: integer | None

class ListInvalidationsForDistributionTenantResult(TypedDict, total=False):
    InvalidationList: InvalidationList | None

class ListInvalidationsRequest(ServiceRequest):
    DistributionId: string
    Marker: string | None
    MaxItems: string | None

class ListInvalidationsResult(TypedDict, total=False):
    InvalidationList: InvalidationList | None

class ListKeyGroupsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class ListKeyGroupsResult(TypedDict, total=False):
    KeyGroupList: KeyGroupList | None

class ListKeyValueStoresRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None
    Status: string | None

class ListKeyValueStoresResult(TypedDict, total=False):
    KeyValueStoreList: KeyValueStoreList | None

class ListOriginAccessControlsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class OriginAccessControlSummary(TypedDict, total=False):
    Id: string
    Description: string
    Name: string
    SigningProtocol: OriginAccessControlSigningProtocols
    SigningBehavior: OriginAccessControlSigningBehaviors
    OriginAccessControlOriginType: OriginAccessControlOriginTypes

OriginAccessControlSummaryList = list[OriginAccessControlSummary]
class OriginAccessControlList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: OriginAccessControlSummaryList | None

class ListOriginAccessControlsResult(TypedDict, total=False):
    OriginAccessControlList: OriginAccessControlList | None

class ListOriginRequestPoliciesRequest(ServiceRequest):
    Type: OriginRequestPolicyType | None
    Marker: string | None
    MaxItems: string | None

class OriginRequestPolicySummary(TypedDict, total=False):
    Type: OriginRequestPolicyType
    OriginRequestPolicy: OriginRequestPolicy

OriginRequestPolicySummaryList = list[OriginRequestPolicySummary]
class OriginRequestPolicyList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: OriginRequestPolicySummaryList | None

class ListOriginRequestPoliciesResult(TypedDict, total=False):
    OriginRequestPolicyList: OriginRequestPolicyList | None

class ListPublicKeysRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class PublicKeySummary(TypedDict, total=False):
    Id: string
    Name: string
    CreatedTime: timestamp
    EncodedKey: string
    Comment: string | None

PublicKeySummaryList = list[PublicKeySummary]
class PublicKeyList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: PublicKeySummaryList | None

class ListPublicKeysResult(TypedDict, total=False):
    PublicKeyList: PublicKeyList | None

class ListRealtimeLogConfigsRequest(ServiceRequest):
    MaxItems: string | None
    Marker: string | None

RealtimeLogConfigList = list[RealtimeLogConfig]
class RealtimeLogConfigs(TypedDict, total=False):
    MaxItems: integer
    Items: RealtimeLogConfigList | None
    IsTruncated: boolean
    Marker: string
    NextMarker: string | None

class ListRealtimeLogConfigsResult(TypedDict, total=False):
    RealtimeLogConfigs: RealtimeLogConfigs | None

class ListResponseHeadersPoliciesRequest(ServiceRequest):
    Type: ResponseHeadersPolicyType | None
    Marker: string | None
    MaxItems: string | None

class ResponseHeadersPolicySummary(TypedDict, total=False):
    Type: ResponseHeadersPolicyType
    ResponseHeadersPolicy: ResponseHeadersPolicy

ResponseHeadersPolicySummaryList = list[ResponseHeadersPolicySummary]
class ResponseHeadersPolicyList(TypedDict, total=False):
    NextMarker: string | None
    MaxItems: integer
    Quantity: integer
    Items: ResponseHeadersPolicySummaryList | None

class ListResponseHeadersPoliciesResult(TypedDict, total=False):
    ResponseHeadersPolicyList: ResponseHeadersPolicyList | None

class ListStreamingDistributionsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class StreamingDistributionSummary(TypedDict, total=False):
    Id: string
    ARN: string
    Status: string
    LastModifiedTime: timestamp
    DomainName: string
    S3Origin: S3Origin
    Aliases: Aliases
    TrustedSigners: TrustedSigners
    Comment: string
    PriceClass: PriceClass
    Enabled: boolean

StreamingDistributionSummaryList = list[StreamingDistributionSummary]
class StreamingDistributionList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: StreamingDistributionSummaryList | None

class ListStreamingDistributionsResult(TypedDict, total=False):
    StreamingDistributionList: StreamingDistributionList | None

class ListTagsForResourceRequest(ServiceRequest):
    Resource: ResourceARN

class ListTagsForResourceResult(TypedDict, total=False):
    Tags: Tags

class ListTrustStoresRequest(ServiceRequest):
    Marker: string | None
    MaxItems: integer | None

class TrustStoreSummary(TypedDict, total=False):
    Id: string
    Arn: string
    Name: string
    Status: TrustStoreStatus
    NumberOfCaCertificates: integer
    LastModifiedTime: timestamp
    Reason: string | None
    ETag: string

TrustStoreList = list[TrustStoreSummary]
class ListTrustStoresResult(TypedDict, total=False):
    NextMarker: string | None
    TrustStoreList: TrustStoreList | None

class ListVpcOriginsRequest(ServiceRequest):
    Marker: string | None
    MaxItems: string | None

class VpcOriginSummary(TypedDict, total=False):
    Id: string
    Name: string
    Status: string
    CreatedTime: timestamp
    LastModifiedTime: timestamp
    Arn: string
    AccountId: string | None
    OriginEndpointArn: string

VpcOriginSummaryList = list[VpcOriginSummary]
class VpcOriginList(TypedDict, total=False):
    Marker: string
    NextMarker: string | None
    MaxItems: integer
    IsTruncated: boolean
    Quantity: integer
    Items: VpcOriginSummaryList | None

class ListVpcOriginsResult(TypedDict, total=False):
    VpcOriginList: VpcOriginList | None

class PublishConnectionFunctionRequest(ServiceRequest):
    Id: ResourceId
    IfMatch: string

class PublishConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionSummary: ConnectionFunctionSummary | None

class PublishFunctionRequest(ServiceRequest):
    Name: FunctionName
    IfMatch: string

class PublishFunctionResult(TypedDict, total=False):
    FunctionSummary: FunctionSummary | None

class PutResourcePolicyRequest(ServiceRequest):
    ResourceArn: string
    PolicyDocument: string

class PutResourcePolicyResult(TypedDict, total=False):
    ResourceArn: string | None

TagKeyList = list[TagKey]
class TagKeys(TypedDict, total=False):
    Items: TagKeyList | None

class TagResourceRequest(ServiceRequest):
    Resource: ResourceARN
    Tags: Tags

class TestConnectionFunctionRequest(ServiceRequest):
    Id: ResourceId
    IfMatch: string
    Stage: FunctionStage | None
    ConnectionObject: FunctionEventObject

class TestConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionTestResult: ConnectionFunctionTestResult | None

class TestFunctionRequest(ServiceRequest):
    Name: FunctionName
    IfMatch: string
    Stage: FunctionStage | None
    EventObject: FunctionEventObject

class TestResult(TypedDict, total=False):
    FunctionSummary: FunctionSummary | None
    ComputeUtilization: string | None
    FunctionExecutionLogs: FunctionExecutionLogList | None
    FunctionErrorMessage: sensitiveStringType | None
    FunctionOutput: sensitiveStringType | None

class TestFunctionResult(TypedDict, total=False):
    TestResult: TestResult | None

class UntagResourceRequest(ServiceRequest):
    Resource: ResourceARN
    TagKeys: TagKeys

class UpdateAnycastIpListRequest(ServiceRequest):
    Id: string
    IpAddressType: IpAddressType | None
    IfMatch: string

class UpdateAnycastIpListResult(TypedDict, total=False):
    AnycastIpList: AnycastIpList | None
    ETag: string | None

class UpdateCachePolicyRequest(ServiceRequest):
    CachePolicyConfig: CachePolicyConfig
    Id: string
    IfMatch: string | None

class UpdateCachePolicyResult(TypedDict, total=False):
    CachePolicy: CachePolicy | None
    ETag: string | None

class UpdateCloudFrontOriginAccessIdentityRequest(ServiceRequest):
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentityConfig
    Id: string
    IfMatch: string | None

class UpdateCloudFrontOriginAccessIdentityResult(TypedDict, total=False):
    CloudFrontOriginAccessIdentity: CloudFrontOriginAccessIdentity | None
    ETag: string | None

class UpdateConnectionFunctionRequest(ServiceRequest):
    Id: ResourceId
    IfMatch: string
    ConnectionFunctionConfig: FunctionConfig
    ConnectionFunctionCode: FunctionBlob

class UpdateConnectionFunctionResult(TypedDict, total=False):
    ConnectionFunctionSummary: ConnectionFunctionSummary | None
    ETag: string | None

class UpdateConnectionGroupRequest(ServiceRequest):
    Id: string
    Ipv6Enabled: boolean | None
    IfMatch: string
    AnycastIpListId: string | None
    Enabled: boolean | None

class UpdateConnectionGroupResult(TypedDict, total=False):
    ConnectionGroup: ConnectionGroup | None
    ETag: string | None

class UpdateContinuousDeploymentPolicyRequest(ServiceRequest):
    ContinuousDeploymentPolicyConfig: ContinuousDeploymentPolicyConfig
    Id: string
    IfMatch: string | None

class UpdateContinuousDeploymentPolicyResult(TypedDict, total=False):
    ContinuousDeploymentPolicy: ContinuousDeploymentPolicy | None
    ETag: string | None

class UpdateDistributionRequest(ServiceRequest):
    DistributionConfig: DistributionConfig
    Id: string
    IfMatch: string | None

class UpdateDistributionResult(TypedDict, total=False):
    Distribution: Distribution | None
    ETag: string | None

class UpdateDistributionTenantRequest(ServiceRequest):
    Id: string
    DistributionId: string | None
    Domains: DomainList | None
    Customizations: Customizations | None
    Parameters: Parameters | None
    ConnectionGroupId: string | None
    IfMatch: string
    ManagedCertificateRequest: ManagedCertificateRequest | None
    Enabled: boolean | None

class UpdateDistributionTenantResult(TypedDict, total=False):
    DistributionTenant: DistributionTenant | None
    ETag: string | None

class UpdateDistributionWithStagingConfigRequest(ServiceRequest):
    Id: string
    StagingDistributionId: string | None
    IfMatch: string | None

class UpdateDistributionWithStagingConfigResult(TypedDict, total=False):
    Distribution: Distribution | None
    ETag: string | None

class UpdateDomainAssociationRequest(ServiceRequest):
    Domain: string
    TargetResource: DistributionResourceId
    IfMatch: string | None

class UpdateDomainAssociationResult(TypedDict, total=False):
    Domain: string | None
    ResourceId: string | None
    ETag: string | None

class UpdateFieldLevelEncryptionConfigRequest(ServiceRequest):
    FieldLevelEncryptionConfig: FieldLevelEncryptionConfig
    Id: string
    IfMatch: string | None

class UpdateFieldLevelEncryptionConfigResult(TypedDict, total=False):
    FieldLevelEncryption: FieldLevelEncryption | None
    ETag: string | None

class UpdateFieldLevelEncryptionProfileRequest(ServiceRequest):
    FieldLevelEncryptionProfileConfig: FieldLevelEncryptionProfileConfig
    Id: string
    IfMatch: string | None

class UpdateFieldLevelEncryptionProfileResult(TypedDict, total=False):
    FieldLevelEncryptionProfile: FieldLevelEncryptionProfile | None
    ETag: string | None

class UpdateFunctionRequest(ServiceRequest):
    Name: FunctionName
    IfMatch: string
    FunctionConfig: FunctionConfig
    FunctionCode: FunctionBlob

class UpdateFunctionResult(TypedDict, total=False):
    FunctionSummary: FunctionSummary | None
    ETag: string | None

class UpdateKeyGroupRequest(ServiceRequest):
    KeyGroupConfig: KeyGroupConfig
    Id: string
    IfMatch: string | None

class UpdateKeyGroupResult(TypedDict, total=False):
    KeyGroup: KeyGroup | None
    ETag: string | None

class UpdateKeyValueStoreRequest(ServiceRequest):
    Name: KeyValueStoreName
    Comment: KeyValueStoreComment
    IfMatch: string

class UpdateKeyValueStoreResult(TypedDict, total=False):
    KeyValueStore: KeyValueStore | None
    ETag: string | None

class UpdateOriginAccessControlRequest(ServiceRequest):
    OriginAccessControlConfig: OriginAccessControlConfig
    Id: string
    IfMatch: string | None

class UpdateOriginAccessControlResult(TypedDict, total=False):
    OriginAccessControl: OriginAccessControl | None
    ETag: string | None

class UpdateOriginRequestPolicyRequest(ServiceRequest):
    OriginRequestPolicyConfig: OriginRequestPolicyConfig
    Id: string
    IfMatch: string | None

class UpdateOriginRequestPolicyResult(TypedDict, total=False):
    OriginRequestPolicy: OriginRequestPolicy | None
    ETag: string | None

class UpdatePublicKeyRequest(ServiceRequest):
    PublicKeyConfig: PublicKeyConfig
    Id: string
    IfMatch: string | None

class UpdatePublicKeyResult(TypedDict, total=False):
    PublicKey: PublicKey | None
    ETag: string | None

class UpdateRealtimeLogConfigRequest(ServiceRequest):
    EndPoints: EndPointList | None
    Fields: FieldList | None
    Name: string | None
    ARN: string | None
    SamplingRate: long | None

class UpdateRealtimeLogConfigResult(TypedDict, total=False):
    RealtimeLogConfig: RealtimeLogConfig | None

class UpdateResponseHeadersPolicyRequest(ServiceRequest):
    ResponseHeadersPolicyConfig: ResponseHeadersPolicyConfig
    Id: string
    IfMatch: string | None

class UpdateResponseHeadersPolicyResult(TypedDict, total=False):
    ResponseHeadersPolicy: ResponseHeadersPolicy | None
    ETag: string | None

class UpdateStreamingDistributionRequest(ServiceRequest):
    StreamingDistributionConfig: StreamingDistributionConfig
    Id: string
    IfMatch: string | None

class UpdateStreamingDistributionResult(TypedDict, total=False):
    StreamingDistribution: StreamingDistribution | None
    ETag: string | None

class UpdateTrustStoreRequest(ServiceRequest):
    Id: ResourceId
    CaCertificatesBundleSource: CaCertificatesBundleSource
    IfMatch: string

class UpdateTrustStoreResult(TypedDict, total=False):
    TrustStore: TrustStore | None
    ETag: string | None

class UpdateVpcOriginRequest(ServiceRequest):
    VpcOriginEndpointConfig: VpcOriginEndpointConfig
    Id: string
    IfMatch: string

class UpdateVpcOriginResult(TypedDict, total=False):
    VpcOrigin: VpcOrigin | None
    ETag: string | None

class VerifyDnsConfigurationRequest(ServiceRequest):
    Domain: string | None
    Identifier: string

class VerifyDnsConfigurationResult(TypedDict, total=False):
    DnsConfigurationList: DnsConfigurationList | None

class CloudfrontApi:

    service: str = "cloudfront"
    version: str = "2020-05-31"

    @handler("AssociateAlias")
    def associate_alias(self, context: RequestContext, target_distribution_id: string, alias: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("AssociateDistributionTenantWebACL")
    def associate_distribution_tenant_web_acl(self, context: RequestContext, id: string, web_acl_arn: string, if_match: string | None = None, **kwargs) -> AssociateDistributionTenantWebACLResult:
        raise NotImplementedError

    @handler("AssociateDistributionWebACL")
    def associate_distribution_web_acl(self, context: RequestContext, id: string, web_acl_arn: string, if_match: string | None = None, **kwargs) -> AssociateDistributionWebACLResult:
        raise NotImplementedError

    @handler("CopyDistribution")
    def copy_distribution(self, context: RequestContext, primary_distribution_id: string, caller_reference: string, staging: boolean | None = None, if_match: string | None = None, enabled: boolean | None = None, **kwargs) -> CopyDistributionResult:
        raise NotImplementedError

    @handler("CreateAnycastIpList")
    def create_anycast_ip_list(self, context: RequestContext, name: AnycastIpListName, ip_count: integer, tags: Tags | None = None, ip_address_type: IpAddressType | None = None, ipam_cidr_configs: IpamCidrConfigList | None = None, **kwargs) -> CreateAnycastIpListResult:
        raise NotImplementedError

    @handler("CreateCachePolicy")
    def create_cache_policy(self, context: RequestContext, cache_policy_config: CachePolicyConfig, **kwargs) -> CreateCachePolicyResult:
        raise NotImplementedError

    @handler("CreateCloudFrontOriginAccessIdentity")
    def create_cloud_front_origin_access_identity(self, context: RequestContext, cloud_front_origin_access_identity_config: CloudFrontOriginAccessIdentityConfig, **kwargs) -> CreateCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("CreateConnectionFunction")
    def create_connection_function(self, context: RequestContext, name: FunctionName, connection_function_config: FunctionConfig, connection_function_code: FunctionBlob, tags: Tags | None = None, **kwargs) -> CreateConnectionFunctionResult:
        raise NotImplementedError

    @handler("CreateConnectionGroup")
    def create_connection_group(self, context: RequestContext, name: string, ipv6_enabled: boolean | None = None, tags: Tags | None = None, anycast_ip_list_id: string | None = None, enabled: boolean | None = None, **kwargs) -> CreateConnectionGroupResult:
        raise NotImplementedError

    @handler("CreateContinuousDeploymentPolicy")
    def create_continuous_deployment_policy(self, context: RequestContext, continuous_deployment_policy_config: ContinuousDeploymentPolicyConfig, **kwargs) -> CreateContinuousDeploymentPolicyResult:
        raise NotImplementedError

    @handler("CreateDistribution")
    def create_distribution(self, context: RequestContext, distribution_config: DistributionConfig, **kwargs) -> CreateDistributionResult:
        raise NotImplementedError

    @handler("CreateDistributionTenant")
    def create_distribution_tenant(self, context: RequestContext, distribution_id: string, name: CreateDistributionTenantRequestNameString, domains: DomainList, tags: Tags | None = None, customizations: Customizations | None = None, parameters: Parameters | None = None, connection_group_id: string | None = None, managed_certificate_request: ManagedCertificateRequest | None = None, enabled: boolean | None = None, **kwargs) -> CreateDistributionTenantResult:
        raise NotImplementedError

    @handler("CreateDistributionWithTags")
    def create_distribution_with_tags(self, context: RequestContext, distribution_config_with_tags: DistributionConfigWithTags, **kwargs) -> CreateDistributionWithTagsResult:
        raise NotImplementedError

    @handler("CreateFieldLevelEncryptionConfig")
    def create_field_level_encryption_config(self, context: RequestContext, field_level_encryption_config: FieldLevelEncryptionConfig, **kwargs) -> CreateFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("CreateFieldLevelEncryptionProfile")
    def create_field_level_encryption_profile(self, context: RequestContext, field_level_encryption_profile_config: FieldLevelEncryptionProfileConfig, **kwargs) -> CreateFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("CreateFunction")
    def create_function(self, context: RequestContext, name: FunctionName, function_config: FunctionConfig, function_code: FunctionBlob, **kwargs) -> CreateFunctionResult:
        raise NotImplementedError

    @handler("CreateInvalidation")
    def create_invalidation(self, context: RequestContext, distribution_id: string, invalidation_batch: InvalidationBatch, **kwargs) -> CreateInvalidationResult:
        raise NotImplementedError

    @handler("CreateInvalidationForDistributionTenant")
    def create_invalidation_for_distribution_tenant(self, context: RequestContext, id: string, invalidation_batch: InvalidationBatch, **kwargs) -> CreateInvalidationForDistributionTenantResult:
        raise NotImplementedError

    @handler("CreateKeyGroup")
    def create_key_group(self, context: RequestContext, key_group_config: KeyGroupConfig, **kwargs) -> CreateKeyGroupResult:
        raise NotImplementedError

    @handler("CreateKeyValueStore")
    def create_key_value_store(self, context: RequestContext, name: KeyValueStoreName, comment: KeyValueStoreComment | None = None, import_source: ImportSource | None = None, **kwargs) -> CreateKeyValueStoreResult:
        raise NotImplementedError

    @handler("CreateMonitoringSubscription")
    def create_monitoring_subscription(self, context: RequestContext, distribution_id: string, monitoring_subscription: MonitoringSubscription, **kwargs) -> CreateMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("CreateOriginAccessControl")
    def create_origin_access_control(self, context: RequestContext, origin_access_control_config: OriginAccessControlConfig, **kwargs) -> CreateOriginAccessControlResult:
        raise NotImplementedError

    @handler("CreateOriginRequestPolicy")
    def create_origin_request_policy(self, context: RequestContext, origin_request_policy_config: OriginRequestPolicyConfig, **kwargs) -> CreateOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("CreatePublicKey")
    def create_public_key(self, context: RequestContext, public_key_config: PublicKeyConfig, **kwargs) -> CreatePublicKeyResult:
        raise NotImplementedError

    @handler("CreateRealtimeLogConfig")
    def create_realtime_log_config(self, context: RequestContext, end_points: EndPointList, fields: FieldList, name: string, sampling_rate: long, **kwargs) -> CreateRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("CreateResponseHeadersPolicy")
    def create_response_headers_policy(self, context: RequestContext, response_headers_policy_config: ResponseHeadersPolicyConfig, **kwargs) -> CreateResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("CreateStreamingDistribution")
    def create_streaming_distribution(self, context: RequestContext, streaming_distribution_config: StreamingDistributionConfig, **kwargs) -> CreateStreamingDistributionResult:
        raise NotImplementedError

    @handler("CreateStreamingDistributionWithTags")
    def create_streaming_distribution_with_tags(self, context: RequestContext, streaming_distribution_config_with_tags: StreamingDistributionConfigWithTags, **kwargs) -> CreateStreamingDistributionWithTagsResult:
        raise NotImplementedError

    @handler("CreateTrustStore")
    def create_trust_store(self, context: RequestContext, name: string, ca_certificates_bundle_source: CaCertificatesBundleSource, tags: Tags | None = None, **kwargs) -> CreateTrustStoreResult:
        raise NotImplementedError

    @handler("CreateVpcOrigin")
    def create_vpc_origin(self, context: RequestContext, vpc_origin_endpoint_config: VpcOriginEndpointConfig, tags: Tags | None = None, **kwargs) -> CreateVpcOriginResult:
        raise NotImplementedError

    @handler("DeleteAnycastIpList")
    def delete_anycast_ip_list(self, context: RequestContext, id: string, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteCachePolicy")
    def delete_cache_policy(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteCloudFrontOriginAccessIdentity")
    def delete_cloud_front_origin_access_identity(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteConnectionFunction")
    def delete_connection_function(self, context: RequestContext, id: ResourceId, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteConnectionGroup")
    def delete_connection_group(self, context: RequestContext, id: string, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteContinuousDeploymentPolicy")
    def delete_continuous_deployment_policy(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteDistribution")
    def delete_distribution(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteDistributionTenant")
    def delete_distribution_tenant(self, context: RequestContext, id: string, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteFieldLevelEncryptionConfig")
    def delete_field_level_encryption_config(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteFieldLevelEncryptionProfile")
    def delete_field_level_encryption_profile(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteFunction")
    def delete_function(self, context: RequestContext, name: FunctionName, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteKeyGroup")
    def delete_key_group(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteKeyValueStore")
    def delete_key_value_store(self, context: RequestContext, name: KeyValueStoreName, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteMonitoringSubscription")
    def delete_monitoring_subscription(self, context: RequestContext, distribution_id: string, **kwargs) -> DeleteMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("DeleteOriginAccessControl")
    def delete_origin_access_control(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteOriginRequestPolicy")
    def delete_origin_request_policy(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeletePublicKey")
    def delete_public_key(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteRealtimeLogConfig")
    def delete_realtime_log_config(self, context: RequestContext, name: string | None = None, arn: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteResourcePolicy")
    def delete_resource_policy(self, context: RequestContext, resource_arn: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteResponseHeadersPolicy")
    def delete_response_headers_policy(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteStreamingDistribution")
    def delete_streaming_distribution(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteTrustStore")
    def delete_trust_store(self, context: RequestContext, id: ResourceId, if_match: string, **kwargs) -> None:
        raise NotImplementedError

    @handler("DeleteVpcOrigin")
    def delete_vpc_origin(self, context: RequestContext, id: string, if_match: string, **kwargs) -> DeleteVpcOriginResult:
        raise NotImplementedError

    @handler("DescribeConnectionFunction")
    def describe_connection_function(self, context: RequestContext, identifier: string, stage: FunctionStage | None = None, **kwargs) -> DescribeConnectionFunctionResult:
        raise NotImplementedError

    @handler("DescribeFunction")
    def describe_function(self, context: RequestContext, name: FunctionName, stage: FunctionStage | None = None, **kwargs) -> DescribeFunctionResult:
        raise NotImplementedError

    @handler("DescribeKeyValueStore")
    def describe_key_value_store(self, context: RequestContext, name: KeyValueStoreName, **kwargs) -> DescribeKeyValueStoreResult:
        raise NotImplementedError

    @handler("DisassociateDistributionTenantWebACL")
    def disassociate_distribution_tenant_web_acl(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> DisassociateDistributionTenantWebACLResult:
        raise NotImplementedError

    @handler("DisassociateDistributionWebACL")
    def disassociate_distribution_web_acl(self, context: RequestContext, id: string, if_match: string | None = None, **kwargs) -> DisassociateDistributionWebACLResult:
        raise NotImplementedError

    @handler("GetAnycastIpList")
    def get_anycast_ip_list(self, context: RequestContext, id: string, **kwargs) -> GetAnycastIpListResult:
        raise NotImplementedError

    @handler("GetCachePolicy")
    def get_cache_policy(self, context: RequestContext, id: string, **kwargs) -> GetCachePolicyResult:
        raise NotImplementedError

    @handler("GetCachePolicyConfig")
    def get_cache_policy_config(self, context: RequestContext, id: string, **kwargs) -> GetCachePolicyConfigResult:
        raise NotImplementedError

    @handler("GetCloudFrontOriginAccessIdentity")
    def get_cloud_front_origin_access_identity(self, context: RequestContext, id: string, **kwargs) -> GetCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("GetCloudFrontOriginAccessIdentityConfig")
    def get_cloud_front_origin_access_identity_config(self, context: RequestContext, id: string, **kwargs) -> GetCloudFrontOriginAccessIdentityConfigResult:
        raise NotImplementedError

    @handler("GetConnectionFunction")
    def get_connection_function(self, context: RequestContext, identifier: string, stage: FunctionStage | None = None, **kwargs) -> GetConnectionFunctionResult:
        raise NotImplementedError

    @handler("GetConnectionGroup")
    def get_connection_group(self, context: RequestContext, identifier: string, **kwargs) -> GetConnectionGroupResult:
        raise NotImplementedError

    @handler("GetConnectionGroupByRoutingEndpoint")
    def get_connection_group_by_routing_endpoint(self, context: RequestContext, routing_endpoint: string, **kwargs) -> GetConnectionGroupByRoutingEndpointResult:
        raise NotImplementedError

    @handler("GetContinuousDeploymentPolicy")
    def get_continuous_deployment_policy(self, context: RequestContext, id: string, **kwargs) -> GetContinuousDeploymentPolicyResult:
        raise NotImplementedError

    @handler("GetContinuousDeploymentPolicyConfig")
    def get_continuous_deployment_policy_config(self, context: RequestContext, id: string, **kwargs) -> GetContinuousDeploymentPolicyConfigResult:
        raise NotImplementedError

    @handler("GetDistribution")
    def get_distribution(self, context: RequestContext, id: string, **kwargs) -> GetDistributionResult:
        raise NotImplementedError

    @handler("GetDistributionConfig")
    def get_distribution_config(self, context: RequestContext, id: string, **kwargs) -> GetDistributionConfigResult:
        raise NotImplementedError

    @handler("GetDistributionTenant")
    def get_distribution_tenant(self, context: RequestContext, identifier: string, **kwargs) -> GetDistributionTenantResult:
        raise NotImplementedError

    @handler("GetDistributionTenantByDomain")
    def get_distribution_tenant_by_domain(self, context: RequestContext, domain: string, **kwargs) -> GetDistributionTenantByDomainResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryption")
    def get_field_level_encryption(self, context: RequestContext, id: string, **kwargs) -> GetFieldLevelEncryptionResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionConfig")
    def get_field_level_encryption_config(self, context: RequestContext, id: string, **kwargs) -> GetFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionProfile")
    def get_field_level_encryption_profile(self, context: RequestContext, id: string, **kwargs) -> GetFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("GetFieldLevelEncryptionProfileConfig")
    def get_field_level_encryption_profile_config(self, context: RequestContext, id: string, **kwargs) -> GetFieldLevelEncryptionProfileConfigResult:
        raise NotImplementedError

    @handler("GetFunction")
    def get_function(self, context: RequestContext, name: FunctionName, stage: FunctionStage | None = None, **kwargs) -> GetFunctionResult:
        raise NotImplementedError

    @handler("GetInvalidation")
    def get_invalidation(self, context: RequestContext, distribution_id: string, id: string, **kwargs) -> GetInvalidationResult:
        raise NotImplementedError

    @handler("GetInvalidationForDistributionTenant")
    def get_invalidation_for_distribution_tenant(self, context: RequestContext, distribution_tenant_id: string, id: string, **kwargs) -> GetInvalidationForDistributionTenantResult:
        raise NotImplementedError

    @handler("GetKeyGroup")
    def get_key_group(self, context: RequestContext, id: string, **kwargs) -> GetKeyGroupResult:
        raise NotImplementedError

    @handler("GetKeyGroupConfig")
    def get_key_group_config(self, context: RequestContext, id: string, **kwargs) -> GetKeyGroupConfigResult:
        raise NotImplementedError

    @handler("GetManagedCertificateDetails")
    def get_managed_certificate_details(self, context: RequestContext, identifier: string, **kwargs) -> GetManagedCertificateDetailsResult:
        raise NotImplementedError

    @handler("GetMonitoringSubscription")
    def get_monitoring_subscription(self, context: RequestContext, distribution_id: string, **kwargs) -> GetMonitoringSubscriptionResult:
        raise NotImplementedError

    @handler("GetOriginAccessControl")
    def get_origin_access_control(self, context: RequestContext, id: string, **kwargs) -> GetOriginAccessControlResult:
        raise NotImplementedError

    @handler("GetOriginAccessControlConfig")
    def get_origin_access_control_config(self, context: RequestContext, id: string, **kwargs) -> GetOriginAccessControlConfigResult:
        raise NotImplementedError

    @handler("GetOriginRequestPolicy")
    def get_origin_request_policy(self, context: RequestContext, id: string, **kwargs) -> GetOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("GetOriginRequestPolicyConfig")
    def get_origin_request_policy_config(self, context: RequestContext, id: string, **kwargs) -> GetOriginRequestPolicyConfigResult:
        raise NotImplementedError

    @handler("GetPublicKey")
    def get_public_key(self, context: RequestContext, id: string, **kwargs) -> GetPublicKeyResult:
        raise NotImplementedError

    @handler("GetPublicKeyConfig")
    def get_public_key_config(self, context: RequestContext, id: string, **kwargs) -> GetPublicKeyConfigResult:
        raise NotImplementedError

    @handler("GetRealtimeLogConfig")
    def get_realtime_log_config(self, context: RequestContext, name: string | None = None, arn: string | None = None, **kwargs) -> GetRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("GetResourcePolicy")
    def get_resource_policy(self, context: RequestContext, resource_arn: string, **kwargs) -> GetResourcePolicyResult:
        raise NotImplementedError

    @handler("GetResponseHeadersPolicy")
    def get_response_headers_policy(self, context: RequestContext, id: string, **kwargs) -> GetResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("GetResponseHeadersPolicyConfig")
    def get_response_headers_policy_config(self, context: RequestContext, id: string, **kwargs) -> GetResponseHeadersPolicyConfigResult:
        raise NotImplementedError

    @handler("GetStreamingDistribution")
    def get_streaming_distribution(self, context: RequestContext, id: string, **kwargs) -> GetStreamingDistributionResult:
        raise NotImplementedError

    @handler("GetStreamingDistributionConfig")
    def get_streaming_distribution_config(self, context: RequestContext, id: string, **kwargs) -> GetStreamingDistributionConfigResult:
        raise NotImplementedError

    @handler("GetTrustStore")
    def get_trust_store(self, context: RequestContext, identifier: string, **kwargs) -> GetTrustStoreResult:
        raise NotImplementedError

    @handler("GetVpcOrigin")
    def get_vpc_origin(self, context: RequestContext, id: string, **kwargs) -> GetVpcOriginResult:
        raise NotImplementedError

    @handler("ListAnycastIpLists")
    def list_anycast_ip_lists(self, context: RequestContext, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListAnycastIpListsResult:
        raise NotImplementedError

    @handler("ListCachePolicies", expand=False)
    def list_cache_policies(self, context: RequestContext, request: ListCachePoliciesRequest, **kwargs) -> ListCachePoliciesResult:
        raise NotImplementedError

    @handler("ListCloudFrontOriginAccessIdentities")
    def list_cloud_front_origin_access_identities(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListCloudFrontOriginAccessIdentitiesResult:
        raise NotImplementedError

    @handler("ListConflictingAliases")
    def list_conflicting_aliases(self, context: RequestContext, distribution_id: distributionIdString, alias: aliasString, marker: string | None = None, max_items: listConflictingAliasesMaxItemsInteger | None = None, **kwargs) -> ListConflictingAliasesResult:
        raise NotImplementedError

    @handler("ListConnectionFunctions")
    def list_connection_functions(self, context: RequestContext, marker: string | None = None, max_items: integer | None = None, stage: FunctionStage | None = None, **kwargs) -> ListConnectionFunctionsResult:
        raise NotImplementedError

    @handler("ListConnectionGroups")
    def list_connection_groups(self, context: RequestContext, association_filter: ConnectionGroupAssociationFilter | None = None, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListConnectionGroupsResult:
        raise NotImplementedError

    @handler("ListContinuousDeploymentPolicies")
    def list_continuous_deployment_policies(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListContinuousDeploymentPoliciesResult:
        raise NotImplementedError

    @handler("ListDistributionTenants")
    def list_distribution_tenants(self, context: RequestContext, association_filter: DistributionTenantAssociationFilter | None = None, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListDistributionTenantsResult:
        raise NotImplementedError

    @handler("ListDistributionTenantsByCustomization")
    def list_distribution_tenants_by_customization(self, context: RequestContext, web_acl_arn: string | None = None, certificate_arn: string | None = None, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListDistributionTenantsByCustomizationResult:
        raise NotImplementedError

    @handler("ListDistributions")
    def list_distributions(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsResult:
        raise NotImplementedError

    @handler("ListDistributionsByAnycastIpListId")
    def list_distributions_by_anycast_ip_list_id(self, context: RequestContext, anycast_ip_list_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByAnycastIpListIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByCachePolicyId")
    def list_distributions_by_cache_policy_id(self, context: RequestContext, cache_policy_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByCachePolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByConnectionFunction")
    def list_distributions_by_connection_function(self, context: RequestContext, connection_function_identifier: string, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListDistributionsByConnectionFunctionResult:
        raise NotImplementedError

    @handler("ListDistributionsByConnectionMode")
    def list_distributions_by_connection_mode(self, context: RequestContext, connection_mode: ConnectionMode, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListDistributionsByConnectionModeResult:
        raise NotImplementedError

    @handler("ListDistributionsByKeyGroup")
    def list_distributions_by_key_group(self, context: RequestContext, key_group_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByKeyGroupResult:
        raise NotImplementedError

    @handler("ListDistributionsByOriginRequestPolicyId")
    def list_distributions_by_origin_request_policy_id(self, context: RequestContext, origin_request_policy_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByOriginRequestPolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByOwnedResource")
    def list_distributions_by_owned_resource(self, context: RequestContext, resource_arn: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByOwnedResourceResult:
        raise NotImplementedError

    @handler("ListDistributionsByRealtimeLogConfig")
    def list_distributions_by_realtime_log_config(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, realtime_log_config_name: string | None = None, realtime_log_config_arn: string | None = None, **kwargs) -> ListDistributionsByRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("ListDistributionsByResponseHeadersPolicyId")
    def list_distributions_by_response_headers_policy_id(self, context: RequestContext, response_headers_policy_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByResponseHeadersPolicyIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByTrustStore")
    def list_distributions_by_trust_store(self, context: RequestContext, trust_store_identifier: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByTrustStoreResult:
        raise NotImplementedError

    @handler("ListDistributionsByVpcOriginId")
    def list_distributions_by_vpc_origin_id(self, context: RequestContext, vpc_origin_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByVpcOriginIdResult:
        raise NotImplementedError

    @handler("ListDistributionsByWebACLId")
    def list_distributions_by_web_acl_id(self, context: RequestContext, web_acl_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListDistributionsByWebACLIdResult:
        raise NotImplementedError

    @handler("ListDomainConflicts")
    def list_domain_conflicts(self, context: RequestContext, domain: string, domain_control_validation_resource: DistributionResourceId, max_items: integer | None = None, marker: string | None = None, **kwargs) -> ListDomainConflictsResult:
        raise NotImplementedError

    @handler("ListFieldLevelEncryptionConfigs")
    def list_field_level_encryption_configs(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListFieldLevelEncryptionConfigsResult:
        raise NotImplementedError

    @handler("ListFieldLevelEncryptionProfiles")
    def list_field_level_encryption_profiles(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListFieldLevelEncryptionProfilesResult:
        raise NotImplementedError

    @handler("ListFunctions")
    def list_functions(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, stage: FunctionStage | None = None, **kwargs) -> ListFunctionsResult:
        raise NotImplementedError

    @handler("ListInvalidations")
    def list_invalidations(self, context: RequestContext, distribution_id: string, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListInvalidationsResult:
        raise NotImplementedError

    @handler("ListInvalidationsForDistributionTenant")
    def list_invalidations_for_distribution_tenant(self, context: RequestContext, id: string, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListInvalidationsForDistributionTenantResult:
        raise NotImplementedError

    @handler("ListKeyGroups")
    def list_key_groups(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListKeyGroupsResult:
        raise NotImplementedError

    @handler("ListKeyValueStores")
    def list_key_value_stores(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, status: string | None = None, **kwargs) -> ListKeyValueStoresResult:
        raise NotImplementedError

    @handler("ListOriginAccessControls")
    def list_origin_access_controls(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListOriginAccessControlsResult:
        raise NotImplementedError

    @handler("ListOriginRequestPolicies", expand=False)
    def list_origin_request_policies(self, context: RequestContext, request: ListOriginRequestPoliciesRequest, **kwargs) -> ListOriginRequestPoliciesResult:
        raise NotImplementedError

    @handler("ListPublicKeys")
    def list_public_keys(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListPublicKeysResult:
        raise NotImplementedError

    @handler("ListRealtimeLogConfigs")
    def list_realtime_log_configs(self, context: RequestContext, max_items: string | None = None, marker: string | None = None, **kwargs) -> ListRealtimeLogConfigsResult:
        raise NotImplementedError

    @handler("ListResponseHeadersPolicies", expand=False)
    def list_response_headers_policies(self, context: RequestContext, request: ListResponseHeadersPoliciesRequest, **kwargs) -> ListResponseHeadersPoliciesResult:
        raise NotImplementedError

    @handler("ListStreamingDistributions")
    def list_streaming_distributions(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListStreamingDistributionsResult:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(self, context: RequestContext, resource: ResourceARN, **kwargs) -> ListTagsForResourceResult:
        raise NotImplementedError

    @handler("ListTrustStores")
    def list_trust_stores(self, context: RequestContext, marker: string | None = None, max_items: integer | None = None, **kwargs) -> ListTrustStoresResult:
        raise NotImplementedError

    @handler("ListVpcOrigins")
    def list_vpc_origins(self, context: RequestContext, marker: string | None = None, max_items: string | None = None, **kwargs) -> ListVpcOriginsResult:
        raise NotImplementedError

    @handler("PublishConnectionFunction")
    def publish_connection_function(self, context: RequestContext, id: ResourceId, if_match: string, **kwargs) -> PublishConnectionFunctionResult:
        raise NotImplementedError

    @handler("PublishFunction")
    def publish_function(self, context: RequestContext, name: FunctionName, if_match: string, **kwargs) -> PublishFunctionResult:
        raise NotImplementedError

    @handler("PutResourcePolicy")
    def put_resource_policy(self, context: RequestContext, resource_arn: string, policy_document: string, **kwargs) -> PutResourcePolicyResult:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource: ResourceARN, tags: Tags, **kwargs) -> None:
        raise NotImplementedError

    @handler("TestConnectionFunction")
    def test_connection_function(self, context: RequestContext, id: ResourceId, if_match: string, connection_object: FunctionEventObject, stage: FunctionStage | None = None, **kwargs) -> TestConnectionFunctionResult:
        raise NotImplementedError

    @handler("TestFunction")
    def test_function(self, context: RequestContext, name: FunctionName, if_match: string, event_object: FunctionEventObject, stage: FunctionStage | None = None, **kwargs) -> TestFunctionResult:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(self, context: RequestContext, resource: ResourceARN, tag_keys: TagKeys, **kwargs) -> None:
        raise NotImplementedError

    @handler("UpdateAnycastIpList")
    def update_anycast_ip_list(self, context: RequestContext, id: string, if_match: string, ip_address_type: IpAddressType | None = None, **kwargs) -> UpdateAnycastIpListResult:
        raise NotImplementedError

    @handler("UpdateCachePolicy")
    def update_cache_policy(self, context: RequestContext, cache_policy_config: CachePolicyConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateCachePolicyResult:
        raise NotImplementedError

    @handler("UpdateCloudFrontOriginAccessIdentity")
    def update_cloud_front_origin_access_identity(self, context: RequestContext, cloud_front_origin_access_identity_config: CloudFrontOriginAccessIdentityConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateCloudFrontOriginAccessIdentityResult:
        raise NotImplementedError

    @handler("UpdateConnectionFunction")
    def update_connection_function(self, context: RequestContext, id: ResourceId, if_match: string, connection_function_config: FunctionConfig, connection_function_code: FunctionBlob, **kwargs) -> UpdateConnectionFunctionResult:
        raise NotImplementedError

    @handler("UpdateConnectionGroup")
    def update_connection_group(self, context: RequestContext, id: string, if_match: string, ipv6_enabled: boolean | None = None, anycast_ip_list_id: string | None = None, enabled: boolean | None = None, **kwargs) -> UpdateConnectionGroupResult:
        raise NotImplementedError

    @handler("UpdateContinuousDeploymentPolicy")
    def update_continuous_deployment_policy(self, context: RequestContext, continuous_deployment_policy_config: ContinuousDeploymentPolicyConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateContinuousDeploymentPolicyResult:
        raise NotImplementedError

    @handler("UpdateDistribution")
    def update_distribution(self, context: RequestContext, distribution_config: DistributionConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateDistributionResult:
        raise NotImplementedError

    @handler("UpdateDistributionTenant")
    def update_distribution_tenant(self, context: RequestContext, id: string, if_match: string, distribution_id: string | None = None, domains: DomainList | None = None, customizations: Customizations | None = None, parameters: Parameters | None = None, connection_group_id: string | None = None, managed_certificate_request: ManagedCertificateRequest | None = None, enabled: boolean | None = None, **kwargs) -> UpdateDistributionTenantResult:
        raise NotImplementedError

    @handler("UpdateDistributionWithStagingConfig")
    def update_distribution_with_staging_config(self, context: RequestContext, id: string, staging_distribution_id: string | None = None, if_match: string | None = None, **kwargs) -> UpdateDistributionWithStagingConfigResult:
        raise NotImplementedError

    @handler("UpdateDomainAssociation")
    def update_domain_association(self, context: RequestContext, domain: string, target_resource: DistributionResourceId, if_match: string | None = None, **kwargs) -> UpdateDomainAssociationResult:
        raise NotImplementedError

    @handler("UpdateFieldLevelEncryptionConfig")
    def update_field_level_encryption_config(self, context: RequestContext, field_level_encryption_config: FieldLevelEncryptionConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateFieldLevelEncryptionConfigResult:
        raise NotImplementedError

    @handler("UpdateFieldLevelEncryptionProfile")
    def update_field_level_encryption_profile(self, context: RequestContext, field_level_encryption_profile_config: FieldLevelEncryptionProfileConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateFieldLevelEncryptionProfileResult:
        raise NotImplementedError

    @handler("UpdateFunction")
    def update_function(self, context: RequestContext, name: FunctionName, if_match: string, function_config: FunctionConfig, function_code: FunctionBlob, **kwargs) -> UpdateFunctionResult:
        raise NotImplementedError

    @handler("UpdateKeyGroup")
    def update_key_group(self, context: RequestContext, key_group_config: KeyGroupConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateKeyGroupResult:
        raise NotImplementedError

    @handler("UpdateKeyValueStore")
    def update_key_value_store(self, context: RequestContext, name: KeyValueStoreName, comment: KeyValueStoreComment, if_match: string, **kwargs) -> UpdateKeyValueStoreResult:
        raise NotImplementedError

    @handler("UpdateOriginAccessControl")
    def update_origin_access_control(self, context: RequestContext, origin_access_control_config: OriginAccessControlConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateOriginAccessControlResult:
        raise NotImplementedError

    @handler("UpdateOriginRequestPolicy")
    def update_origin_request_policy(self, context: RequestContext, origin_request_policy_config: OriginRequestPolicyConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateOriginRequestPolicyResult:
        raise NotImplementedError

    @handler("UpdatePublicKey")
    def update_public_key(self, context: RequestContext, public_key_config: PublicKeyConfig, id: string, if_match: string | None = None, **kwargs) -> UpdatePublicKeyResult:
        raise NotImplementedError

    @handler("UpdateRealtimeLogConfig")
    def update_realtime_log_config(self, context: RequestContext, end_points: EndPointList | None = None, fields: FieldList | None = None, name: string | None = None, arn: string | None = None, sampling_rate: long | None = None, **kwargs) -> UpdateRealtimeLogConfigResult:
        raise NotImplementedError

    @handler("UpdateResponseHeadersPolicy")
    def update_response_headers_policy(self, context: RequestContext, response_headers_policy_config: ResponseHeadersPolicyConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateResponseHeadersPolicyResult:
        raise NotImplementedError

    @handler("UpdateStreamingDistribution")
    def update_streaming_distribution(self, context: RequestContext, streaming_distribution_config: StreamingDistributionConfig, id: string, if_match: string | None = None, **kwargs) -> UpdateStreamingDistributionResult:
        raise NotImplementedError

    @handler("UpdateTrustStore")
    def update_trust_store(self, context: RequestContext, id: ResourceId, ca_certificates_bundle_source: CaCertificatesBundleSource, if_match: string, **kwargs) -> UpdateTrustStoreResult:
        raise NotImplementedError

    @handler("UpdateVpcOrigin")
    def update_vpc_origin(self, context: RequestContext, vpc_origin_endpoint_config: VpcOriginEndpointConfig, id: string, if_match: string, **kwargs) -> UpdateVpcOriginResult:
        raise NotImplementedError

    @handler("VerifyDnsConfiguration")
    def verify_dns_configuration(self, context: RequestContext, identifier: string, domain: string | None = None, **kwargs) -> VerifyDnsConfigurationResult:
        raise NotImplementedError
