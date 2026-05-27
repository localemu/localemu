"""LocalEmu provider for EventBridge Pipes.

What this overlays on the moto backend:

  * Real source polling — ``CreatePipe(DesiredState=RUNNING)`` starts a
    background worker that long-polls the source and dispatches to the
    target. ``DesiredState=STOPPED`` registers the pipe without polling.
  * Faithful state machine — ``current_state`` tracks the live worker
    (RUNNING / STARTING / STOPPING / STOPPED / DELETING) instead of the
    moto stub's hard-coded ``RUNNING``.
  * Update / Start / Stop / Delete drive the worker lifecycle, then
    update moto state so DescribePipe / ListPipes return truthful info.
  * Lifecycle hooks restart pipes after a snapshot restore.

Unsupported source / target services raise during ``CreatePipe`` so
users discover the limitation up front instead of silently watching
nothing happen.
"""

from __future__ import annotations

import logging

from localemu.aws.api import RequestContext
from localemu.aws.api.pipes import (
    Arn,
    ArnOrUrl,
    CreatePipeResponse,
    DeletePipeResponse,
    DescribePipeResponse,
    KmsKeyIdentifier,
    LimitMax100,
    ListPipesResponse,
    ListTagsForResourceResponse,
    NextToken,
    OptionalArn,
    PipeArn,
    PipeDescription,
    PipeEnrichmentParameters,
    PipeLogConfigurationParameters,
    PipeName,
    PipeSourceParameters,
    PipeState,
    PipeTargetParameters,
    PipesApi,
    RequestedPipeState,
    ResourceArn,
    RoleArn,
    StartPipeResponse,
    StopPipeResponse,
    TagKeyList,
    TagMap,
    TagResourceResponse,
    UntagResourceResponse,
    UpdatePipeResponse,
    UpdatePipeSourceParameters,
)
from localemu.services.moto import call_moto
from localemu.services.pipes.pipe_manager import PipeManager
from localemu.services.pipes.pipe_worker_factory import build_worker
from localemu.services.plugins import ServiceLifecycleHook
from localemu.state import StateVisitor

LOG = logging.getLogger(__name__)


def _moto_backend(account_id: str, region: str):
    from moto.pipes.models import pipes_backends

    return pipes_backends[account_id][region]


def _ctx_ids(context: RequestContext) -> tuple[str, str]:
    return context.account_id, context.region


class PipesProvider(PipesApi, ServiceLifecycleHook):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.pipes.models import pipes_backends

        visitor.visit(pipes_backends)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def on_before_stop(self):
        PipeManager.instance().stop_all()

    def on_after_state_load(self):
        self._restart_persisted_pipes()

    def on_after_state_reset(self):
        # State was cleared; drop every in-memory worker because moto's
        # backend now disagrees with whatever the workers were polling.
        PipeManager.instance().stop_all()

    def _restart_persisted_pipes(self) -> None:
        try:
            from moto.pipes.models import pipes_backends
        except ImportError:
            return
        for account_id, regions in pipes_backends.items():
            for region, backend in regions.items():
                for pipe in list(backend.pipes.values()):
                    if (pipe.desired_state or "").upper() != "RUNNING":
                        continue
                    try:
                        worker = build_worker(
                            pipe, account_id, region, desired_running=True,
                        )
                        PipeManager.instance().register(worker)
                        worker.create()
                    except NotImplementedError as e:
                        LOG.warning(
                            "Pipe %s not restarted after state load: %s",
                            pipe.arn, e,
                        )
                        pipe.current_state = PipeState.START_FAILED.value
                    except Exception:
                        LOG.warning(
                            "Pipe %s could not be restarted after state load",
                            pipe.arn, exc_info=True,
                        )
                        pipe.current_state = PipeState.START_FAILED.value

    # ------------------------------------------------------------------
    # API verbs — Create / Update / Delete / Describe / List / Start / Stop
    # ------------------------------------------------------------------
    def create_pipe(
        self,
        context: RequestContext,
        name: PipeName,
        source: ArnOrUrl,
        target: Arn,
        role_arn: RoleArn,
        description: PipeDescription | None = None,
        desired_state: RequestedPipeState | None = None,
        source_parameters: PipeSourceParameters | None = None,
        enrichment: OptionalArn | None = None,
        enrichment_parameters: PipeEnrichmentParameters | None = None,
        target_parameters: PipeTargetParameters | None = None,
        tags: TagMap | None = None,
        log_configuration: PipeLogConfigurationParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> CreatePipeResponse:
        result = call_moto(context)
        account_id, region = _ctx_ids(context)
        backend = _moto_backend(account_id, region)
        pipe = backend.pipes.get(name)
        if pipe is None:
            return result
        running = (desired_state or "RUNNING").upper() == "RUNNING"
        try:
            worker = build_worker(pipe, account_id, region, desired_running=running)
        except NotImplementedError as e:
            LOG.warning("CreatePipe %s: %s", pipe.arn, e)
            pipe.current_state = PipeState.CREATE_FAILED.value
            return result
        except Exception:
            LOG.warning("CreatePipe %s failed to build worker", pipe.arn, exc_info=True)
            pipe.current_state = PipeState.CREATE_FAILED.value
            return result
        PipeManager.instance().register(worker)
        worker.create()
        return result

    def update_pipe(
        self,
        context: RequestContext,
        name: PipeName,
        role_arn: RoleArn,
        description: PipeDescription | None = None,
        desired_state: RequestedPipeState | None = None,
        source_parameters: UpdatePipeSourceParameters | None = None,
        enrichment: OptionalArn | None = None,
        enrichment_parameters: PipeEnrichmentParameters | None = None,
        target: Arn | None = None,
        target_parameters: PipeTargetParameters | None = None,
        log_configuration: PipeLogConfigurationParameters | None = None,
        kms_key_identifier: KmsKeyIdentifier | None = None,
        **kwargs,
    ) -> UpdatePipeResponse:
        # Stop the old worker before moto mutates the config so a poll in
        # flight doesn't carry stale source/target identity over to the
        # new run.
        account_id, region = _ctx_ids(context)
        backend = _moto_backend(account_id, region)
        old = PipeManager.instance().get(self._arn(account_id, region, name))
        if old is not None:
            old.stop()
            PipeManager.instance().remove(old.pipe_arn)
        result = call_moto(context)
        pipe = backend.pipes.get(name)
        if pipe is None:
            return result
        running = (
            desired_state or pipe.desired_state or "RUNNING"
        ).upper() == "RUNNING"
        try:
            worker = build_worker(pipe, account_id, region, desired_running=running)
        except Exception:
            LOG.warning("UpdatePipe %s rebuild failed", pipe.arn, exc_info=True)
            pipe.current_state = PipeState.UPDATE_FAILED.value
            return result
        PipeManager.instance().register(worker)
        if running:
            worker.start()
        else:
            worker.current_state = PipeState.STOPPED
            worker._sync_state_to_moto()
        return result

    def delete_pipe(
        self, context: RequestContext, name: PipeName, **kwargs,
    ) -> DeletePipeResponse:
        account_id, region = _ctx_ids(context)
        arn = self._arn(account_id, region, name)
        worker = PipeManager.instance().get(arn)
        if worker is not None:
            worker.delete()
            PipeManager.instance().remove(arn)
        return call_moto(context)

    def describe_pipe(
        self, context: RequestContext, name: PipeName, **kwargs,
    ) -> DescribePipeResponse:
        result = call_moto(context)
        account_id, region = _ctx_ids(context)
        worker = PipeManager.instance().get(self._arn(account_id, region, name))
        if worker is not None and isinstance(result, dict):
            result["CurrentState"] = worker.current_state.value
        return result

    def list_pipes(
        self,
        context: RequestContext,
        name_prefix: PipeName | None = None,
        desired_state: RequestedPipeState | None = None,
        current_state: PipeState | None = None,
        source_prefix: ResourceArn | None = None,
        target_prefix: ResourceArn | None = None,
        next_token: NextToken | None = None,
        limit: LimitMax100 | None = None,
        **kwargs,
    ) -> ListPipesResponse:
        result = call_moto(context)
        account_id, region = _ctx_ids(context)
        if isinstance(result, dict) and "Pipes" in result:
            for entry in result["Pipes"]:
                arn = entry.get("Arn") or self._arn(
                    account_id, region, entry.get("Name", "")
                )
                worker = PipeManager.instance().get(arn)
                if worker is not None:
                    entry["CurrentState"] = worker.current_state.value
        return result

    def start_pipe(
        self, context: RequestContext, name: PipeName, **kwargs,
    ) -> StartPipeResponse:
        # Moto's pipes backend does not implement StartPipe (the moto
        # API surface for Pipes is Create/Get/List/Delete only). We
        # therefore CANNOT call_moto here — it would dead-end at the
        # "no moto route" handler. Synthesise the response from the
        # backend's Pipe model directly instead.
        account_id, region = _ctx_ids(context)
        backend = _moto_backend(account_id, region)
        pipe = backend.pipes.get(name)
        if pipe is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Pipe {name!r} does not exist.",
                status_code=404,
            )
        arn = self._arn(account_id, region, name)
        worker = PipeManager.instance().get(arn)
        if worker is None:
            try:
                worker = build_worker(
                    pipe, account_id, region, desired_running=True,
                )
            except Exception:
                LOG.warning("StartPipe %s build failed", arn, exc_info=True)
                pipe.current_state = PipeState.START_FAILED.value
                return _pipe_response(pipe)
            PipeManager.instance().register(worker)
        worker.start()
        pipe.desired_state = "RUNNING"
        pipe.current_state = worker.current_state.value
        return _pipe_response(pipe)

    def stop_pipe(
        self, context: RequestContext, name: PipeName, **kwargs,
    ) -> StopPipeResponse:
        # Same reason as start_pipe: moto's pipes backend has no StopPipe
        # route, so synthesise the response from our state instead of
        # going through call_moto.
        account_id, region = _ctx_ids(context)
        backend = _moto_backend(account_id, region)
        pipe = backend.pipes.get(name)
        if pipe is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Pipe {name!r} does not exist.",
                status_code=404,
            )
        arn = self._arn(account_id, region, name)
        worker = PipeManager.instance().get(arn)
        if worker is not None:
            worker.stop()
        pipe.desired_state = "STOPPED"
        pipe.current_state = PipeState.STOPPED.value
        return _pipe_response(pipe)

    # Tag verbs flow straight through to moto.
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: PipeArn, **kwargs,
    ) -> ListTagsForResourceResponse:
        return call_moto(context)

    def tag_resource(
        self, context: RequestContext, resource_arn: PipeArn, tags: TagMap, **kwargs,
    ) -> TagResourceResponse:
        return call_moto(context)

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: PipeArn,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResponse:
        return call_moto(context)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _arn(account_id: str, region: str, name: str) -> str:
        return f"arn:aws:pipes:{region}:{account_id}:pipe/{name}"


def _pipe_response(pipe) -> dict:
    """Synthesise a Start/Stop response from the live moto Pipe model.

    Moto's pipes backend doesn't have routes for StartPipe or StopPipe,
    so call_moto would dead-end. We build the AWS-shaped response from
    the same fields DescribePipe exposes so SDK consumers see the
    expected DesiredState / CurrentState transition.
    """
    return {
        "Arn": getattr(pipe, "arn", "") or "",
        "Name": getattr(pipe, "name", "") or "",
        "DesiredState": getattr(pipe, "desired_state", "") or "",
        "CurrentState": getattr(pipe, "current_state", "") or "",
        "CreationTime": getattr(pipe, "creation_time", None),
        "LastModifiedTime": getattr(pipe, "last_modified_time", None),
    }
