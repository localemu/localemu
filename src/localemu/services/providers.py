from localemu.services.plugins import (
    Service,
    aws_provider,
)


@aws_provider()
def acm():
    from localemu.services.acm.provider import AcmProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = AcmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def apigateway():
    from localemu.services.apigateway.next_gen.provider import ApigatewayNextGenProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = ApigatewayNextGenProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="apigateway", name="next_gen")
def apigateway_next_gen():
    from localemu.services.apigateway.next_gen.provider import ApigatewayNextGenProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = ApigatewayNextGenProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="apigateway", name="legacy")
def apigateway_legacy():
    from localemu.services.apigateway.legacy.provider import ApigatewayProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = ApigatewayProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="cloudformation", name="engine-legacy")
def cloudformation():
    from localemu.services.cloudformation.provider import CloudformationProvider

    provider = CloudformationProvider()
    return Service.for_provider(provider)


@aws_provider(api="cloudformation")
def cloudformation_v2():
    from localemu.services.cloudformation.v2.provider import CloudformationProviderV2

    provider = CloudformationProviderV2()
    return Service.for_provider(provider)


@aws_provider(api="config")
def awsconfig():
    from localemu.services.configservice.provider import ConfigProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = ConfigProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="cloudwatch", name="default")
def cloudwatch():
    from localemu.services.cloudwatch.provider_v2 import CloudwatchProvider

    provider = CloudwatchProvider()
    return Service.for_provider(provider)


@aws_provider(api="cloudwatch", name="v1")
def cloudwatch_v1():
    from localemu.services.cloudwatch.provider import CloudwatchProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = CloudwatchProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="cloudwatch", name="v2")
def cloudwatch_v2():
    from localemu.services.cloudwatch.provider_v2 import CloudwatchProvider

    provider = CloudwatchProvider()
    return Service.for_provider(provider)


@aws_provider()
def dynamodb():
    from localemu.services.dynamodb.provider import DynamoDBProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = DynamoDBProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def dynamodbstreams():
    from localemu.services.dynamodbstreams.provider import DynamoDBStreamsProvider

    provider = DynamoDBStreamsProvider()
    return Service.for_provider(provider)


@aws_provider()
def ec2():
    from localemu.services.ec2.provider import Ec2Provider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = Ec2Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def es():
    from localemu.services.es.provider import EsProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = EsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def firehose():
    from localemu.services.firehose.provider import FirehoseProvider

    provider = FirehoseProvider()
    return Service.for_provider(provider)


@aws_provider()
def iam():
    from localemu.services.iam.provider import IamProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = IamProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sts():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.sts.provider import StsProvider

    provider = StsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def kinesis():
    from localemu.services.kinesis.provider import KinesisProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = KinesisProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def kms():
    from localemu.services.kms.provider import KmsProvider

    provider = KmsProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda")
def lambda_():
    from localemu.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda", name="asf")
def lambda_asf():
    from localemu.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider(api="lambda", name="v2")
def lambda_v2():
    from localemu.services.lambda_.provider import LambdaProvider

    provider = LambdaProvider()
    return Service.for_provider(provider)


@aws_provider()
def logs():
    from localemu.services.logs.provider import LogsProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = LogsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def opensearch():
    from localemu.services.opensearch.docker.provider import create_opensearch_service

    return create_opensearch_service()


@aws_provider()
def redshift():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.redshift.provider import RedshiftProvider

    provider = RedshiftProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.route53.provider import Route53Provider

    provider = Route53Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def route53resolver():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.route53resolver.provider import Route53ResolverProvider

    provider = Route53ResolverProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def s3():
    from localemu.services.s3.provider import S3Provider

    provider = S3Provider()
    return Service.for_provider(provider)


@aws_provider()
def s3control():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.s3control.provider import S3ControlProvider

    provider = S3ControlProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def scheduler():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.scheduler.provider import SchedulerProvider

    provider = SchedulerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def secretsmanager():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.secretsmanager.provider import SecretsmanagerProvider

    provider = SecretsmanagerProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def ses():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.ses.provider import SesProvider

    provider = SesProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def sns():
    from localemu.services.sns.provider import SnsProvider

    provider = SnsProvider()
    return Service.for_provider(provider)


@aws_provider()
def sqs():
    from localemu.services.sqs.provider import SqsProvider

    provider = SqsProvider()
    return Service.for_provider(provider)


@aws_provider()
def ssm():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.ssm.provider import SsmProvider

    provider = SsmProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="events", name="default")
def events():
    from localemu.services.events.provider import EventsProvider

    provider = EventsProvider()
    return Service.for_provider(provider)


@aws_provider(api="events", name="v2")
def events_v2():
    from localemu.services.events.provider import EventsProvider

    provider = EventsProvider()
    return Service.for_provider(provider)


@aws_provider(api="events", name="v1")
def events_v1():
    from localemu.services.events.v1.provider import EventsProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider(api="events", name="legacy")
def events_legacy():
    from localemu.services.events.v1.provider import EventsProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = EventsProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def stepfunctions():
    from localemu.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(provider)


# TODO: remove with 4.1.0 to allow smooth deprecation path for users that have v2 set manually
@aws_provider(api="stepfunctions", name="v2")
def stepfunctions_v2():
    # provider for people still manually using `v2`
    from localemu.services.stepfunctions.provider import StepFunctionsProvider

    provider = StepFunctionsProvider()
    return Service.for_provider(provider)


@aws_provider()
def swf():
    return _moto_service("swf")


@aws_provider()
def resourcegroupstaggingapi():
    return _moto_service("resourcegroupstaggingapi")


@aws_provider(api="resource-groups")
def resource_groups():
    return _moto_service("resource-groups")


@aws_provider()
def support():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.support.provider import SupportProvider

    provider = SupportProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def transcribe():
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.transcribe.provider import TranscribeProvider

    provider = TranscribeProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


# ---------------------------------------------------------------------------
# Tier 1 services -pure Moto backends, no custom provider needed
# Uses MotoOnlyDispatcher which routes all operations directly to Moto.
# ---------------------------------------------------------------------------


def _moto_service(service_name: str) -> Service:
    """Create a Service backed entirely by Moto."""
    from localemu.aws.skeleton import Skeleton
    from localemu.aws.spec import load_service
    from localemu.services.moto import MotoOnlyDispatcher

    service_model = load_service(service_name)
    dispatch_table = MotoOnlyDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name=service_name, skeleton=skeleton)


@aws_provider()
def ecs():
    from localemu.services.ecs.provider import create_ecs_service

    return create_ecs_service()


@aws_provider()
def eks():
    from localemu.services.eks.provider import create_eks_service

    return create_eks_service()


@aws_provider()
def ecr():
    return _moto_service("ecr")


@aws_provider()
def elbv2():
    from localemu.services.elbv2.provider import create_elbv2_service

    return create_elbv2_service()


@aws_provider()
def rds():
    from localemu.services.rds.provider import create_rds_service

    return create_rds_service()


@aws_provider(api="cognito-idp")
def cognito_idp():
    from localemu.services.cognito_idp.provider import create_cognito_idp_service

    return create_cognito_idp_service()


@aws_provider(api="cognito-identity")
def cognito_identity():
    return _moto_service("cognito-identity")


# ---------------------------------------------------------------------------
# Tier 2 services -high value, pure Moto backends
# ---------------------------------------------------------------------------


@aws_provider()
def appsync():
    return _moto_service("appsync")


@aws_provider()
def glue():
    return _moto_service("glue")


@aws_provider()
def athena():
    from localemu.services.athena.provider import create_athena_service

    return create_athena_service()


@aws_provider()
def efs():
    return _moto_service("efs")


@aws_provider()
def backup():
    return _moto_service("backup")


@aws_provider()
def pipes():
    """Real Pipes runtime — see :mod:`localemu.services.pipes.provider`.

    Replaces the previous moto-only stub. The custom provider intercepts
    every API verb, owns a per-pipe background poller that long-polls
    the source, and dispatches matched events via the EventBridge
    TargetSender family.
    """
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.pipes.provider import PipesProvider

    provider = PipesProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def codebuild():
    return _moto_service("codebuild")


# ---------------------------------------------------------------------------
# Tier 3 services -completeness
# ---------------------------------------------------------------------------


@aws_provider()
def wafv2():
    return _moto_service("wafv2")


@aws_provider()
def elasticache():
    return _moto_service("elasticache")


@aws_provider()
def servicediscovery():
    return _moto_service("servicediscovery")


@aws_provider()
def iot():
    return _moto_service("iot")


@aws_provider()
def batch():
    return _moto_service("batch")


@aws_provider()
def cloudfront():
    from localemu.services.cloudfront.provider import CloudFrontProvider
    from localemu.services.moto import MotoFallbackDispatcher

    provider = CloudFrontProvider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


@aws_provider()
def cloudtrail():
    from localemu.services.cloudtrail.provider import create_cloudtrail_service

    return create_cloudtrail_service()


@aws_provider()
def sesv2():
    """Real SESv2 provider — see :mod:`localemu.services.sesv2.provider`.

    Replaces the moto-only stub. Overrides SendEmail so the message
    actually reaches the v1 retrospection mailbox at ``/_aws/ses``; all
    other ops still flow through moto via the fallback dispatcher until
    we implement them explicitly.
    """
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.sesv2.provider import Sesv2Provider

    provider = Sesv2Provider()
    return Service.for_provider(provider, dispatch_table_factory=MotoFallbackDispatcher)


# ---------------------------------------------------------------------------
# Additional services (Tier A + B + C) - pure Moto backends
# Total: 132 services
# ---------------------------------------------------------------------------


@aws_provider(api="acm-pca")
def acmpca():
    return _moto_service("acm-pca")


@aws_provider()
def amp():
    return _moto_service("amp")


@aws_provider()
def apigatewayv2():
    from localemu.services.apigatewayv2.provider import create_apigatewayv2_service

    return create_apigatewayv2_service()


@aws_provider()
def appconfig():
    return _moto_service("appconfig")


@aws_provider(api="application-autoscaling")
def application_autoscaling():
    return _moto_service("application-autoscaling")


@aws_provider()
def appmesh():
    return _moto_service("appmesh")


@aws_provider()
def autoscaling():
    from localemu.aws.skeleton import create_dispatch_table
    from localemu.aws.spec import load_service
    from localemu.services.autoscaling.provider import AutoscalingProvider
    from localemu.services.moto import _proxy_moto

    provider = AutoscalingProvider()
    # autoscaling has no generated ASF Api class, so the @handler markers
    # on AutoscalingProvider only register the membership-mutating verbs.
    # Build a dispatch table that defaults every operation to moto, then
    # override with the provider's own implementations.
    service_model = load_service("autoscaling")
    table = {op: _proxy_moto for op in service_model.operation_names}
    table.update(create_dispatch_table(provider))
    return Service.for_provider(
        provider, dispatch_table_factory=lambda _p: table,
    )


@aws_provider()
def bedrock():
    return _moto_service("bedrock")


@aws_provider()
def budgets():
    return _moto_service("budgets")


@aws_provider()
def ce():
    return _moto_service("ce")


@aws_provider()
def cloudhsmv2():
    return _moto_service("cloudhsmv2")


@aws_provider()
def codecommit():
    return _moto_service("codecommit")


@aws_provider()
def codedeploy():
    return _moto_service("codedeploy")


@aws_provider()
def codepipeline():
    return _moto_service("codepipeline")


@aws_provider()
def comprehend():
    # moto's comprehend backend exists but skips DetectDominantLanguage /
    # DetectSentiment / DetectEntities / etc. — the stub provider fills
    # those gaps and falls through to moto for everything else.
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("comprehend")


@aws_provider()
def databrew():
    return _moto_service("databrew")


@aws_provider()
def datasync():
    return _moto_service("datasync")


@aws_provider()
def dax():
    return _moto_service("dax")


@aws_provider()
def directconnect():
    return _moto_service("directconnect")


@aws_provider()
def dms():
    return _moto_service("dms")


@aws_provider()
def ds():
    return _moto_service("ds")


@aws_provider()
def ebs():
    return _moto_service("ebs")


@aws_provider()
def elasticbeanstalk():
    return _moto_service("elasticbeanstalk")


@aws_provider()
def elb():
    return _moto_service("elb")


@aws_provider()
def emr():
    return _moto_service("emr")


@aws_provider(api="emr-containers")
def emr_containers():
    return _moto_service("emr-containers")


@aws_provider(api="emr-serverless")
def emr_serverless():
    return _moto_service("emr-serverless")


@aws_provider()
def fsx():
    return _moto_service("fsx")


@aws_provider()
def glacier():
    return _moto_service("glacier")


@aws_provider()
def guardduty():
    return _moto_service("guardduty")


@aws_provider()
def identitystore():
    return _moto_service("identitystore")


@aws_provider()
def inspector2():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("inspector2")


@aws_provider(api="iot-data")
def iot_data():
    return _moto_service("iot-data")


@aws_provider()
def kafka():
    """Real Docker-backed Amazon MSK provider.

    Opt-in via ``MSK_DOCKER_BACKEND=1``; otherwise falls through to moto
    for metadata-only operation so non-Docker environments still work.
    """
    from localemu.services.kafka.provider import create_kafka_service

    return create_kafka_service()


@aws_provider()
def lakeformation():
    return _moto_service("lakeformation")


@aws_provider()
def managedblockchain():
    return _moto_service("managedblockchain")


@aws_provider()
def mediaconnect():
    return _moto_service("mediaconnect")


@aws_provider()
def medialive():
    return _moto_service("medialive")


@aws_provider()
def mediapackage():
    return _moto_service("mediapackage")


@aws_provider()
def mediapackagev2():
    return _moto_service("mediapackagev2")


@aws_provider()
def memorydb():
    return _moto_service("memorydb")


@aws_provider()
def mq():
    """Real Docker-backed Amazon MQ provider.

    Opt-in via ``MQ_DOCKER_BACKEND=1``; otherwise falls through to moto's
    in-memory metadata layer so unit tests don't need a Docker daemon.
    """
    from localemu.services.mq.provider import create_mq_service

    return create_mq_service()


@aws_provider()
def neptune():
    return _moto_service("neptune")


@aws_provider()
def opensearchserverless():
    return _moto_service("opensearchserverless")


@aws_provider()
def organizations():
    return _moto_service("organizations")


@aws_provider()
def personalize():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("personalize")


@aws_provider()
def pinpoint():
    return _moto_service("pinpoint")


@aws_provider()
def polly():
    return _moto_service("polly")


@aws_provider()
def quicksight():
    return _moto_service("quicksight")


@aws_provider()
def ram():
    return _moto_service("ram")


@aws_provider(api="rds-data")
def rds_data():
    return _moto_service("rds-data")


@aws_provider(api="redshift-data")
def redshift_data():
    return _moto_service("redshift-data")


@aws_provider()
def rekognition():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("rekognition")


@aws_provider()
def resiliencehub():
    return _moto_service("resiliencehub")


@aws_provider()
def route53domains():
    return _moto_service("route53domains")


@aws_provider()
def sagemaker():
    return _moto_service("sagemaker")


@aws_provider(api="sagemaker-runtime")
def sagemaker_runtime():
    return _moto_service("sagemaker-runtime")


@aws_provider()
def securityhub():
    return _moto_service("securityhub")


@aws_provider(api="service-quotas")
def service_quotas():
    return _moto_service("service-quotas")


@aws_provider()
def servicecatalog():
    return _moto_service("servicecatalog")


@aws_provider()
def shield():
    return _moto_service("shield")


@aws_provider()
def signer():
    return _moto_service("signer")


@aws_provider()
def textract():
    return _moto_service("textract")


@aws_provider(api="timestream-write")
def timestream_write():
    return _moto_service("timestream-write")


@aws_provider()
def transfer():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("transfer")


@aws_provider()
def translate():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("translate")


@aws_provider()
def mediaconvert():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("mediaconvert")


@aws_provider()
def storagegateway():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("storagegateway")


@aws_provider()
def apprunner():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("apprunner")


@aws_provider()
def amplify():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("amplify")


@aws_provider()
def waf():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("waf")


@aws_provider()
def snowball():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("snowball")


@aws_provider()
def macie2():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("macie2")


@aws_provider()
def forecast():
    from localemu.services.stub_providers import create_stub_service

    return create_stub_service("forecast")


@aws_provider()
def xray():
    return _moto_service("xray")
