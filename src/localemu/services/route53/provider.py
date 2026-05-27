from datetime import datetime

import moto.route53.models as route53_models
from botocore.exceptions import ClientError
from moto.route53.models import route53_backends

from localemu.aws.api import RequestContext
from localemu.aws.api.route53 import (
    VPC,
    ChangeInfo,
    ChangeStatus,
    CreateHostedZoneResponse,
    DeleteHealthCheckResponse,
    DeleteHostedZoneResponse,
    DNSName,
    GetChangeResponse,
    GetHealthCheckResponse,
    HealthCheck,
    HealthCheckId,
    HostedZoneConfig,
    InvalidInput,
    InvalidVPCId,
    Nonce,
    NoSuchHealthCheck,
    ResourceId,
    Route53Api,
)
from localemu.aws.connect import connect_to
from localemu.services.moto import call_moto
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.route53.models import route53_stores
from localemu.state import StateVisitor


class Route53Provider(Route53Api, ServiceLifecycleHook):
    def accept_state_visitor(self, visitor: StateVisitor):

        visitor.visit(route53_backends)
        visitor.visit(route53_stores)

    # No tag deletion logic to handle in Community. Overwritten in Pro implementation.
    def remove_resource_tags(
        self, context: RequestContext, resource_type: str, resource_id: str
    ) -> None:
        return

    def create_hosted_zone(
        self,
        context: RequestContext,
        name: DNSName,
        caller_reference: Nonce,
        vpc: VPC = None,
        hosted_zone_config: HostedZoneConfig = None,
        delegation_set_id: ResourceId = None,
        **kwargs,
    ) -> CreateHostedZoneResponse:
        # private hosted zones cannot be created in a VPC that does not exist
        # check that the VPC exists
        if vpc:
            vpc_id = vpc.get("VPCId")
            vpc_region = vpc.get("VPCRegion")
            if not vpc_id or not vpc_region:
                raise InvalidInput(
                    "VPCId and VPCRegion must be specified when creating a private hosted zone",
                    sender_fault=True,
                )
            try:
                connect_to(
                    aws_access_key_id=context.account_id, region_name=vpc_region
                ).ec2.describe_vpcs(VpcIds=[vpc_id])
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    raise InvalidVPCId("The VPC ID is invalid.", sender_fault=True) from e
                raise e

        response = call_moto(context)

        # moto does not populate the VPC struct of the response if creating a private hosted zone
        if (
            hosted_zone_config
            and hosted_zone_config.get("PrivateZone", False)
            and "VPC" in response
            and vpc
        ):
            response["VPC"]["VPCId"] = response["VPC"]["VPCId"] or vpc.get("VPCId", "")
            response["VPC"]["VPCRegion"] = response["VPC"]["VPCRegion"] or vpc.get("VPCRegion", "")

        return response

    def get_change(self, context: RequestContext, id: ResourceId, **kwargs) -> GetChangeResponse:
        # AWS returns NoSuchChange for unknown change ids. The backend stores
        # the ids of every ChangeResourceRecordSets call in ``change_list``.
        # If we can't find any record of this id across the backend, surface
        # an error rather than returning a fabricated INSYNC status.
        if not id or not isinstance(id, str):
            raise InvalidInput("The change id is invalid.", sender_fault=True)
        backend = route53_backends[context.account_id][context.partition]
        change_list = getattr(backend, "change_list", None)
        if change_list is not None:
            known_ids = {getattr(c, "id", c) for c in change_list}
            # moto prepends "/change/" to ids in some versions
            normalized = id.replace("/change/", "")
            if id not in known_ids and normalized not in known_ids:
                # Be lenient: if the backend tracks changes but the id is
                # missing, raise the proper route53 NotFound equivalent.
                from localemu.aws.api.route53 import NoSuchChange

                raise NoSuchChange(f"No change with id {id} was found.", sender_fault=True)
        change_info = ChangeInfo(Id=id, Status=ChangeStatus.INSYNC, SubmittedAt=datetime.now())
        return GetChangeResponse(ChangeInfo=change_info)

    def get_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId, **kwargs
    ) -> GetHealthCheckResponse:
        health_check: route53_models.HealthCheck | None = route53_backends[context.account_id][
            context.partition
        ].health_checks.get(health_check_id, None)
        if not health_check:
            raise NoSuchHealthCheck(
                f"No health check exists with the specified ID {health_check_id}"
            )
        health_check_config = {
            "Disabled": health_check.disabled,
            "EnableSNI": health_check.enable_sni,
            "FailureThreshold": health_check.failure_threshold,
            "FullyQualifiedDomainName": health_check.fqdn,
            "HealthThreshold": health_check.health_threshold,
            "Inverted": health_check.inverted,
            "IPAddress": health_check.ip_address,
            "MeasureLatency": health_check.measure_latency,
            "Port": health_check.port,
            "RequestInterval": health_check.request_interval,
            "ResourcePath": health_check.resource_path,
            "Type": health_check.type_,
        }
        return GetHealthCheckResponse(
            HealthCheck=HealthCheck(
                Id=health_check.id,
                CallerReference=health_check.caller_reference,
                HealthCheckConfig=health_check_config,
            )
        )

    def delete_hosted_zone(
        self, context: RequestContext, id: ResourceId, **kwargs
    ) -> DeleteHostedZoneResponse:
        response = call_moto(context)
        self.remove_resource_tags(context=context, resource_type="hostedzone", resource_id=id)
        return response

    def delete_health_check(
        self, context: RequestContext, health_check_id: HealthCheckId, **kwargs
    ) -> DeleteHealthCheckResponse:
        if (
            health_check_id
            not in route53_backends[context.account_id][context.partition].health_checks
        ):
            raise NoSuchHealthCheck(
                f"No health check exists with the specified ID {health_check_id}"
            )

        route53_backends[context.account_id][context.partition].delete_health_check(health_check_id)
        self.remove_resource_tags(
            context=context, resource_type="healthcheck", resource_id=health_check_id
        )

        return DeleteHealthCheckResponse()
