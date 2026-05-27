import calendar
import copy
import json
import logging
import os
from abc import ABC

from localemu.aws.api import CommonServiceException, RequestContext, handler
from localemu.aws.api.ssm import (
    AlarmConfiguration,
    BaselineDescription,
    BaselineId,
    BaselineName,
    Boolean,
    ClientToken,
    CreateMaintenanceWindowResult,
    CreatePatchBaselineResult,
    DeleteMaintenanceWindowResult,
    DeleteParameterResult,
    DeletePatchBaselineResult,
    DeregisterTargetFromMaintenanceWindowResult,
    DeregisterTaskFromMaintenanceWindowResult,
    DescribeMaintenanceWindowsResult,
    DescribeMaintenanceWindowTargetsResult,
    DescribeMaintenanceWindowTasksResult,
    DescribePatchBaselinesResult,
    GetParameterResult,
    GetParametersResult,
    LabelParameterVersionResult,
    LoggingInfo,
    MaintenanceWindowAllowUnassociatedTargets,
    MaintenanceWindowCutoff,
    MaintenanceWindowDescription,
    MaintenanceWindowDurationHours,
    MaintenanceWindowFilterList,
    MaintenanceWindowId,
    MaintenanceWindowMaxResults,
    MaintenanceWindowName,
    MaintenanceWindowOffset,
    MaintenanceWindowResourceType,
    MaintenanceWindowSchedule,
    MaintenanceWindowStringDateTime,
    MaintenanceWindowTargetId,
    MaintenanceWindowTaskArn,
    MaintenanceWindowTaskCutoffBehavior,
    MaintenanceWindowTaskId,
    MaintenanceWindowTaskInvocationParameters,
    MaintenanceWindowTaskParameters,
    MaintenanceWindowTaskPriority,
    MaintenanceWindowTaskType,
    MaintenanceWindowTimezone,
    MaxConcurrency,
    MaxErrors,
    NextToken,
    OperatingSystem,
    OwnerInformation,
    ParameterLabelList,
    ParameterName,
    ParameterNameList,
    PatchAction,
    PatchBaselineMaxResults,
    PatchComplianceLevel,
    PatchComplianceStatus,
    PatchFilterGroup,
    PatchIdList,
    PatchOrchestratorFilterList,
    PatchRuleGroup,
    PatchSourceList,
    PSParameterName,
    PSParameterVersion,
    PutParameterRequest,
    PutParameterResult,
    RegisterTargetWithMaintenanceWindowResult,
    RegisterTaskWithMaintenanceWindowResult,
    ServiceRole,
    SsmApi,
    TagList,
    Targets,
)
from localemu.aws.connect import connect_to
from localemu.services.moto import call_moto, call_moto_with_request
from localemu.services.ssm import patches as _ssm_patches  # noqa: F401
from localemu.state import StateVisitor
from localemu.utils.aws.arns import extract_resource_from_arn, is_arn
from localemu.utils.bootstrap import is_api_enabled
from localemu.utils.collections import remove_attributes
from localemu.utils.objects import keys_to_lower

LOG = logging.getLogger(__name__)

PARAM_PREFIX_SECRETSMANAGER = "/aws/reference/secretsmanager"


def _resolve_targets_to_instance_ids(
    context: RequestContext, targets: list,
) -> list[str]:
    """Resolve SSM ``Targets=[{Key, Values}]`` into a flat instance-id list.

    Supports the two most common keys: ``InstanceIds`` (direct) and
    ``tag:<key>`` (EC2 tag-filter). Anything else is logged and skipped.
    """
    out: list[str] = []
    try:
        import moto.backends as moto_backends

        ec2_backend = moto_backends.get_backend("ec2")[context.account_id][
            context.region
        ]
    except Exception:
        return out
    for tgt in targets or []:
        key = tgt.get("Key") if isinstance(tgt, dict) else getattr(tgt, "Key", None)
        values = (
            tgt.get("Values") if isinstance(tgt, dict) else getattr(tgt, "Values", None)
        ) or []
        if not key:
            continue
        if key == "InstanceIds":
            out.extend(values)
        elif key.startswith("tag:"):
            tag_key = key[len("tag:"):]
            for inst in ec2_backend.all_instances():
                tags = getattr(inst, "tags", {}) or {}
                v = tags.get(tag_key) if isinstance(tags, dict) else None
                if v in values:
                    out.append(getattr(inst, "id", ""))
        else:
            LOG.debug("SSM target key %s not supported — skipped", key)
    # De-dup while preserving order.
    seen = set()
    uniq = []
    for i in out:
        if i and i not in seen:
            seen.add(i)
            uniq.append(i)
    return uniq


class ValidationException(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("ValidationException", message=message, sender_fault=True)


class InvalidParameterNameException(ValidationException):
    def __init__(self):
        msg = (
            'Parameter name: can\'t be prefixed with "ssm" (case-insensitive). '
            "If formed as a path, it can consist of sub-paths divided by slash symbol; "
            "each sub-path can be formed as a mix of letters, numbers and the following 3 symbols .-_"
        )
        super().__init__(msg)


# TODO: check if _normalize_name(..) calls are still required here
class SsmProvider(SsmApi, ABC):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.ssm.models import ssm_backends

        visitor.visit(ssm_backends)

    # ------------------------------------------------------------------
    # SendCommand / GetCommandInvocation — execute via docker exec on
    # the target EC2 instance's Docker container (no SSM agent in guest).
    # See LocalEmuResearch/DockerEmulation/DESIGN_SSM_EC2.md.
    # ------------------------------------------------------------------

    @handler("SendCommand", expand=False)
    def send_command(self, context: RequestContext, request: dict = None, **kwargs):
        # Let moto create the Command + per-instance Invocation records
        # and assign a CommandId.
        result = call_moto(context)

        try:
            from localemu.services.ssm.docker_executor import get_executor

            command = result.get("Command") or {}
            command_id = command.get("CommandId")
            if not command_id:
                return result
            document_name = (
                kwargs.get("document_name") or command.get("DocumentName") or ""
            )
            parameters = kwargs.get("parameters") or command.get("Parameters") or {}
            instance_ids = list(
                kwargs.get("instance_ids")
                or command.get("InstanceIds")
                or [],
            )
            # Resolve Targets → instance ids if no explicit list was given.
            if not instance_ids and kwargs.get("targets"):
                instance_ids = _resolve_targets_to_instance_ids(
                    context, kwargs["targets"],
                )
            timeout_seconds = (
                kwargs.get("timeout_seconds") or command.get("TimeoutSeconds") or 3600
            )
            output_s3_bucket = (
                kwargs.get("output_s3_bucket_name") or command.get("OutputS3BucketName")
            )
            output_s3_prefix = (
                kwargs.get("output_s3_key_prefix") or command.get("OutputS3KeyPrefix")
            )
            get_executor().dispatch(
                command_id=command_id,
                document_name=document_name,
                parameters=parameters,
                instance_ids=instance_ids,
                account_id=context.account_id,
                region=context.region,
                timeout_seconds=int(timeout_seconds),
                output_s3_bucket_name=output_s3_bucket,
                output_s3_key_prefix=output_s3_prefix,
            )
        except Exception:
            LOG.warning(
                "SSM SendCommand: docker-exec dispatch failed",
                exc_info=True,
            )
        return result

    @handler("GetCommandInvocation", expand=False)
    def get_command_invocation(self, context: RequestContext, request: dict = None, **kwargs):
        # moto stores the record; the executor has mutated it in place.
        return call_moto(context)

    @handler("DescribeInstanceInformation", expand=False)
    def describe_instance_information(self, context: RequestContext, request: dict = None, **kwargs):
        """Return every running EC2 Docker container as an SSM-managed
        instance. Moto's SSM backend does NOT implement this operation
        at all, so we own the entire response — no moto passthrough."""
        info_list: list[dict] = []
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_container_for_instance,
            )
            import moto.backends as moto_backends

            ec2_backend = moto_backends.get_backend("ec2")[context.account_id][
                context.region
            ]
            for inst in ec2_backend.all_instances():
                iid = getattr(inst, "id", None)
                if not iid:
                    continue
                cname = get_container_for_instance(
                    context.account_id, context.region, iid,
                )
                if cname is None:
                    continue
                info_list.append({
                    "InstanceId": iid,
                    "PingStatus": "Online",
                    "LastPingDateTime": None,
                    "AgentVersion": "3.3.0.0-localemu",
                    "IsLatestVersion": True,
                    "PlatformType": "Linux",
                    "PlatformName": "Ubuntu",
                    "PlatformVersion": "22.04",
                    "ResourceType": "EC2Instance",
                    "IPAddress": getattr(inst, "private_ip_address", "") or "",
                    "ComputerName": iid,
                })
        except Exception:
            LOG.debug("describe_instance_information failed", exc_info=True)
        return {"InstanceInformationList": info_list}

    @handler("StartSession", expand=False)
    def start_session(self, context: RequestContext, request: dict = None, **kwargs):
        """Start an interactive Session Manager session.

        Returns the AWS-shaped ``SessionId`` / ``TokenValue`` /
        ``StreamUrl`` triple. The ``StreamUrl`` points at the LocalEmu
        WebSocket bridge — the AWS CLI's SessionManagerPlugin will dial
        it, present the TokenValue, and end up with a real shell inside
        the target instance's Docker container.

        The target instance MUST have a live Docker container; missing
        containers surface AWS's ``TargetNotConnected`` error.
        """
        target = (kwargs.get("target") or (request or {}).get("Target") or "").strip()
        if not target:
            raise CommonServiceException(
                code="ValidationException",
                message="Target is required.",
                status_code=400,
                sender_fault=True,
            )
        try:
            from localemu.services.ec2.docker.vm_manager import (
                get_container_for_instance,
            )
        except Exception:
            container_name = None
        else:
            try:
                container_name = get_container_for_instance(
                    context.account_id, context.region, target,
                )
            except Exception:
                container_name = None
        if not container_name:
            raise CommonServiceException(
                code="TargetNotConnected",
                message=(
                    f"{target} is not connected. It must be a running EC2 "
                    "instance backed by a Docker container in LocalEmu."
                ),
                status_code=400,
                sender_fault=True,
            )

        from localemu.services.ssm.session_manager import get_session_registry
        from localemu.services.ssm.session_ws_server import get_ws_server

        ws_port = get_ws_server().start()
        sess = get_session_registry().create(
            target_instance_id=target,
            container_name=container_name,
            account_id=context.account_id,
            region=context.region,
        )
        # Surface the bridge URL. ``localhost`` is the canonical host
        # for clients running on the same machine as LocalEmu; for
        # remote clients, set ``SSM_SESSION_WS_PORT`` to a stable port
        # and put a reverse proxy in front.
        from localemu import config
        host_override = os.environ.get("SSM_SESSION_WS_HOST", "").strip()
        host = host_override or "localhost"
        stream_url = (
            f"ws://{host}:{ws_port}/v1/data-channel/{sess.session_id}"
            f"?role=publish_subscribe"
        )
        # Touch config so it isn't reported as unused on the rare branch
        # where SSM_SESSION_WS_HOST is empty and config carries the bind.
        _ = config
        return {
            "SessionId": sess.session_id,
            "TokenValue": sess.token_value,
            "StreamUrl": stream_url,
        }

    @handler("TerminateSession", expand=False)
    def terminate_session(self, context: RequestContext, request: dict = None, **kwargs):
        from localemu.services.ssm.session_manager import get_session_registry

        session_id = (
            kwargs.get("session_id") or (request or {}).get("SessionId") or ""
        )
        if not session_id:
            raise CommonServiceException(
                code="ValidationException",
                message="SessionId is required.",
                status_code=400,
                sender_fault=True,
            )
        get_session_registry().remove(session_id)
        return {"SessionId": session_id}

    @handler("DescribeSessions", expand=False)
    def describe_sessions(self, context: RequestContext, request: dict = None, **kwargs):
        from localemu.services.ssm.session_manager import get_session_registry

        state = (kwargs.get("state") or (request or {}).get("State") or "").strip()
        # AWS exposes "Active" and "History" — we only have active records.
        if state and state.lower() == "history":
            return {"Sessions": []}
        sessions = [
            {
                "SessionId": s.session_id,
                "Target": s.target_instance_id,
                "Status": "Connected",
                "StartDate": s.created_at,
                "Owner": f"arn:aws:iam::{s.account_id}:user/localemu",
            }
            for s in get_session_registry().list()
        ]
        return {"Sessions": sessions}

    def get_parameters(
        self,
        context: RequestContext,
        names: ParameterNameList,
        with_decryption: Boolean = None,
        **kwargs,
    ) -> GetParametersResult:
        if SsmProvider._has_secrets(names):
            return SsmProvider._get_params_and_secrets(context.account_id, context.region, names)

        norm_names = [SsmProvider._normalize_name(name, validate=True) for name in names]
        request = {"Names": norm_names, "WithDecryption": bool(with_decryption)}
        res = call_moto_with_request(context, request)

        if not res.get("InvalidParameters"):
            # Match returned parameters to the original requested names by
            # comparing names with leading slash stripped, avoiding index
            # misalignment when moto reorders/drops entries.
            original_by_stripped = {name.lstrip("/"): name for name in names}
            for param in res["Parameters"]:
                stripped = param.get("Name", "").lstrip("/")
                if stripped in original_by_stripped:
                    self._denormalize_param_name_in_response(
                        param, original_by_stripped[stripped]
                    )

        return GetParametersResult(**res)

    def put_parameter(
        self, context: RequestContext, request: PutParameterRequest, **kwargs
    ) -> PutParameterResult:
        from moto.ssm.models import ssm_backends

        name = request["Name"]
        nname = SsmProvider._normalize_name(name)
        # Determine whether this is a new parameter (Create) or an existing one (Update)
        # BEFORE delegating to moto, so we can emit the correct event type.
        backend = ssm_backends[context.account_id][context.region]
        existed = nname in getattr(backend, "_parameters", {}) or nname in getattr(
            backend, "parameters", {}
        )
        if name != nname:
            request.update({"Name": nname})
            moto_res = call_moto_with_request(context, request)
        else:
            moto_res = call_moto(context)
        event_type = "Update" if existed else "Create"
        SsmProvider._notify_event_subscribers(
            context.account_id, context.region, nname, event_type
        )
        return PutParameterResult(**moto_res)

    def get_parameter(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean = None,
        **kwargs,
    ) -> GetParameterResult:
        result = None

        norm_name = self._normalize_name(name, validate=True)
        details = norm_name.split("/")
        if len(details) > 4:
            service = details[3]
            if service == "secretsmanager":
                resource_name = "/".join(details[4:])
                result = SsmProvider._get_secrets_information(
                    context.account_id, context.region, norm_name, resource_name
                )

        if not result:
            result = call_moto_with_request(
                context, {"Name": norm_name, "WithDecryption": bool(with_decryption)}
            )

        self._denormalize_param_name_in_response(result["Parameter"], name)

        return GetParameterResult(**result)

    def delete_parameter(
        self, context: RequestContext, name: PSParameterName, **kwargs
    ) -> DeleteParameterResult:
        # Delegate to moto first — it validates the parameter exists and raises
        # ParameterNotFound otherwise. Emitting the Delete event only after a
        # successful deletion prevents spurious notifications for missing params.
        call_moto(context)  # Return type is an empty type.
        SsmProvider._notify_event_subscribers(context.account_id, context.region, name, "Delete")
        return DeleteParameterResult()

    def label_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        labels: ParameterLabelList,
        parameter_version: PSParameterVersion = None,
        **kwargs,
    ) -> LabelParameterVersionResult:
        SsmProvider._notify_event_subscribers(
            context.account_id, context.region, name, "LabelParameterVersion"
        )
        return LabelParameterVersionResult(**call_moto(context))

    def create_patch_baseline(
        self,
        context: RequestContext,
        name: BaselineName,
        operating_system: OperatingSystem = None,
        global_filters: PatchFilterGroup = None,
        approval_rules: PatchRuleGroup = None,
        approved_patches: PatchIdList = None,
        approved_patches_compliance_level: PatchComplianceLevel = None,
        approved_patches_enable_non_security: Boolean = None,
        rejected_patches: PatchIdList = None,
        rejected_patches_action: PatchAction = None,
        description: BaselineDescription = None,
        sources: PatchSourceList = None,
        available_security_updates_compliance_status: PatchComplianceStatus = None,
        client_token: ClientToken = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreatePatchBaselineResult:
        return CreatePatchBaselineResult(**call_moto(context))

    def delete_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId, **kwargs
    ) -> DeletePatchBaselineResult:
        return DeletePatchBaselineResult(**call_moto(context))

    def describe_patch_baselines(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList = None,
        max_results: PatchBaselineMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribePatchBaselinesResult:
        return DescribePatchBaselinesResult(**call_moto(context))

    def register_target_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        resource_type: MaintenanceWindowResourceType,
        targets: Targets,
        owner_information: OwnerInformation = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
        **kwargs,
    ) -> RegisterTargetWithMaintenanceWindowResult:
        return RegisterTargetWithMaintenanceWindowResult(**call_moto(context))

    def deregister_target_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        safe: Boolean = None,
        **kwargs,
    ) -> DeregisterTargetFromMaintenanceWindowResult:
        return DeregisterTargetFromMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_window_targets(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTargetsResult:
        return DescribeMaintenanceWindowTargetsResult(**call_moto(context))

    def create_maintenance_window(
        self,
        context: RequestContext,
        name: MaintenanceWindowName,
        schedule: MaintenanceWindowSchedule,
        duration: MaintenanceWindowDurationHours,
        cutoff: MaintenanceWindowCutoff,
        allow_unassociated_targets: MaintenanceWindowAllowUnassociatedTargets,
        description: MaintenanceWindowDescription = None,
        start_date: MaintenanceWindowStringDateTime = None,
        end_date: MaintenanceWindowStringDateTime = None,
        schedule_timezone: MaintenanceWindowTimezone = None,
        schedule_offset: MaintenanceWindowOffset = None,
        client_token: ClientToken = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateMaintenanceWindowResult:
        return CreateMaintenanceWindowResult(**call_moto(context))

    def delete_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId, **kwargs
    ) -> DeleteMaintenanceWindowResult:
        return DeleteMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_windows(
        self,
        context: RequestContext,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowsResult:
        return DescribeMaintenanceWindowsResult(**call_moto(context))

    def register_task_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        task_arn: MaintenanceWindowTaskArn,
        task_type: MaintenanceWindowTaskType,
        targets: Targets = None,
        service_role_arn: ServiceRole = None,
        task_parameters: MaintenanceWindowTaskParameters = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters = None,
        priority: MaintenanceWindowTaskPriority = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        logging_info: LoggingInfo = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior = None,
        alarm_configuration: AlarmConfiguration = None,
        **kwargs,
    ) -> RegisterTaskWithMaintenanceWindowResult:
        return RegisterTaskWithMaintenanceWindowResult(**call_moto(context))

    def deregister_task_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        **kwargs,
    ) -> DeregisterTaskFromMaintenanceWindowResult:
        return DeregisterTaskFromMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_window_tasks(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTasksResult:
        return DescribeMaintenanceWindowTasksResult(**call_moto(context))

    # utility methods below

    @staticmethod
    def _denormalize_param_name_in_response(param_result: dict, param_name: str):
        result_name = param_result["Name"]
        if result_name != param_name and result_name.lstrip("/") == param_name.lstrip("/"):
            param_result["Name"] = param_name

    @staticmethod
    def _has_secrets(names: ParameterNameList) -> Boolean:
        maybe_secret = next(
            filter(lambda n: n.startswith(PARAM_PREFIX_SECRETSMANAGER), names), None
        )
        return maybe_secret is not None

    @staticmethod
    def _normalize_name(param_name: ParameterName, validate=False) -> ParameterName:
        if is_arn(param_name):
            resource_name = extract_resource_from_arn(param_name).replace("parameter/", "")
            # if the parameter name is only the root path we want to look up without the leading slash.
            # Otherwise, we add the leading slash
            if "/" in resource_name:
                resource_name = f"/{resource_name}"
            return resource_name

        if validate:
            if "//" in param_name or ("/" in param_name and not param_name.startswith("/")):
                raise InvalidParameterNameException()
        param_name = param_name.strip("/")
        param_name = param_name.replace("//", "/")
        if "/" in param_name:
            param_name = f"/{param_name}"
        return param_name

    @staticmethod
    def _get_secrets_information(
        account_id: str, region_name: str, name: ParameterName, resource_name: str
    ) -> GetParameterResult | None:
        client = connect_to(aws_access_key_id=account_id, region_name=region_name).secretsmanager
        try:
            secret_info = client.get_secret_value(SecretId=resource_name)
            secret_info.pop("ResponseMetadata", None)
            # Use UTC epoch conversion — time.mktime() interprets the struct as
            # local time, producing incorrect timestamps on non-UTC hosts.
            created_date_timestamp = calendar.timegm(
                secret_info["CreatedDate"].utctimetuple()
            )
            secret_info["CreatedDate"] = created_date_timestamp
            secret_info_lower = keys_to_lower(
                remove_attributes(copy.deepcopy(secret_info), ["ARN"])
            )
            secret_info_lower["ARN"] = secret_info["ARN"]
            result = {
                "Parameter": {
                    "SourceResult": json.dumps(secret_info_lower, default=str),
                    "Name": name,
                    "Value": secret_info.get("SecretString"),
                    "Type": "SecureString",
                    "LastModifiedDate": created_date_timestamp,
                }
            }
            return GetParameterResult(**result)
        except client.exceptions.ResourceNotFoundException:
            return None

    @staticmethod
    def _get_params_and_secrets(
        account_id: str, region_name: str, names: ParameterNameList
    ) -> GetParametersResult:
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        result = {"Parameters": [], "InvalidParameters": []}

        for name in names:
            if name.startswith(PARAM_PREFIX_SECRETSMANAGER):
                secret = SsmProvider._get_secrets_information(
                    account_id, region_name, name, name[len(PARAM_PREFIX_SECRETSMANAGER) + 1 :]
                )
                if secret is not None:
                    secret = secret["Parameter"]
                    result["Parameters"].append(secret)
                else:
                    result["InvalidParameters"].append(name)
            else:
                try:
                    param = ssm_client.get_parameter(Name=name)
                    # Use UTC epoch conversion to avoid local-timezone drift.
                    param["Parameter"]["LastModifiedDate"] = calendar.timegm(
                        param["Parameter"]["LastModifiedDate"].utctimetuple()
                    )
                    result["Parameters"].append(param["Parameter"])
                except ssm_client.exceptions.ParameterNotFound:
                    result["InvalidParameters"].append(name)

        return GetParametersResult(**result)

    @staticmethod
    def _notify_event_subscribers(
        account_id: str, region_name: str, name: ParameterName, operation: str
    ):
        if not is_api_enabled("events"):
            LOG.warning(
                "Service 'events' is not enabled: skip emitting SSM event. "
                "Please check your 'SERVICES' configuration variable."
            )
            return
        """Publish an EventBridge event to notify subscribers of changes."""
        events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
        detail = {"name": name, "operation": operation}
        event = {
            "Source": "aws.ssm",
            "Detail": json.dumps(detail),
            "DetailType": "Parameter Store Change",
        }
        events.put_events(Entries=[event])
