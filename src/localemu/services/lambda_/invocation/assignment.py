import contextlib
import logging
import threading
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor

from localemu.services.lambda_.invocation.execution_environment import (
    EnvironmentStartupTimeoutException,
    ExecutionEnvironment,
    InvalidStatusException,
)
from localemu.services.lambda_.invocation.executor_endpoint import StatusErrorException
from localemu.services.lambda_.invocation.lambda_models import (
    FunctionVersion,
    InitializationType,
    OtherServiceEndpoint,
)

LOG = logging.getLogger(__name__)


class AssignmentException(Exception):
    pass


class AssignmentService(OtherServiceEndpoint):
    """
    scope: LocalEmu global
    """

    # function_version manager id => runtime_environment_id => runtime_environment
    environments: dict[str, dict[str, ExecutionEnvironment]]
    # Lock protecting all mutations to the environments dict
    environments_lock: threading.RLock

    # Global pool for spawning and killing provisioned Lambda runtime environments
    provisioning_pool: ThreadPoolExecutor

    # Semaphore limiting the number of on-demand containers starting simultaneously.
    # Concurrent container starts are I/O-heavy (Docker API calls, copying runtime files)
    # and can exhaust OS file descriptor limits on machines with low ulimits.
    on_demand_start_semaphore: threading.Semaphore

    def __init__(self):
        self.environments = defaultdict(dict)
        self.environments_lock = threading.RLock()
        self.provisioning_pool = ThreadPoolExecutor(thread_name_prefix="lambda-provisioning-pool")
        # TODO: make this value configurable; 16 is a conservative default
        self.on_demand_start_semaphore = threading.Semaphore(16)

    @contextlib.contextmanager
    def get_environment(
        self,
        version_manager_id: str,
        function_version: FunctionVersion,
        provisioning_type: InitializationType,
    ) -> Iterator[ExecutionEnvironment]:
        # Snapshot the values list under lock to avoid skipped entries
        # that can be caused by concurrent invocations
        with self.environments_lock:
            applicable_envs = [
                env
                for env in list(self.environments[version_manager_id].values())
                if env.initialization_type == provisioning_type
            ]
        execution_environment = None
        for environment in applicable_envs:
            try:
                environment.reserve()
                execution_environment = environment
                break
            except InvalidStatusException:
                pass

        if execution_environment is None:
            if provisioning_type == InitializationType.provisioned_concurrency:
                raise AssignmentException(
                    "No provisioned concurrency environment available despite lease."
                )
            elif provisioning_type == InitializationType.on_demand:
                with self.on_demand_start_semaphore:
                    execution_environment = self.start_environment(
                        version_manager_id, function_version
                    )
                with self.environments_lock:
                    self.environments[version_manager_id][execution_environment.id] = (
                        execution_environment
                    )
                execution_environment.reserve()
            else:
                raise ValueError(f"Invalid provisioning type {provisioning_type}")

        try:
            yield execution_environment
            execution_environment.release()
        except InvalidStatusException as invalid_e:
            LOG.error("InvalidStatusException: %s", invalid_e)
        except Exception as e:
            LOG.error(
                "Failed invocation <%s>: %s", type(e), e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )
            if execution_environment.initialization_type == InitializationType.on_demand:
                self.stop_environment(execution_environment)
            else:
                # Try to restore to READY rather than stopping.
                # Transient errors (e.g., OS-level connection failures) should not
                # permanently remove healthy provisioned containers from the pool.
                try:
                    execution_environment.release()
                except InvalidStatusException:
                    self.stop_environment(execution_environment)
            raise e

    def start_environment(
        self, version_manager_id: str, function_version: FunctionVersion
    ) -> ExecutionEnvironment:
        LOG.debug("Starting new environment")
        initialization_type = InitializationType.on_demand
        if function_version.config.capacity_provider_config:
            initialization_type = InitializationType.lambda_managed_instances
        execution_environment = ExecutionEnvironment(
            function_version=function_version,
            initialization_type=initialization_type,
            on_timeout=self.on_timeout,
            version_manager_id=version_manager_id,
        )
        try:
            execution_environment.start()
        except StatusErrorException:
            raise
        except EnvironmentStartupTimeoutException:
            raise
        except Exception as e:
            message = f"Could not start new environment: {type(e).__name__}:{e}"
            raise AssignmentException(message) from e
        return execution_environment

    def on_timeout(self, version_manager_id: str, environment_id: str) -> None:
        """Callback for deleting environment after function times out"""
        with self.environments_lock:
            self.environments[version_manager_id].pop(environment_id, None)

    def stop_environment(self, environment: ExecutionEnvironment) -> None:
        version_manager_id = environment.version_manager_id
        try:
            environment.stop()
            with self.environments_lock:
                envs = self.environments.get(version_manager_id)
                if envs:
                    envs.pop(environment.id, None)
        except Exception as e:
            LOG.debug(
                "Error while stopping environment for lambda %s, manager id %s, environment: %s, error: %s",
                environment.function_version.qualified_arn,
                version_manager_id,
                environment.id,
                e,
            )

    def stop_environments_for_version(self, version_manager_id: str):
        # Materialize list under lock, then stop outside lock (stop is I/O-heavy)
        with self.environments_lock:
            environments_to_stop = list(self.environments.get(version_manager_id, {}).values())
        for env in environments_to_stop:
            self.stop_environment(env)

    def scale_provisioned_concurrency(
        self,
        version_manager_id: str,
        function_version: FunctionVersion,
        target_provisioned_environments: int,
    ) -> list[Future[None]]:
        with self.environments_lock:
            current_provisioned_environments = [
                e
                for e in self.environments[version_manager_id].values()
                if e.initialization_type == InitializationType.provisioned_concurrency
            ]
        current_count = len(current_provisioned_environments)
        diff = target_provisioned_environments - current_count

        futures = []
        if diff > 0:
            # Scale up: add new environments
            for _ in range(diff):
                execution_environment = ExecutionEnvironment(
                    function_version=function_version,
                    initialization_type=InitializationType.provisioned_concurrency,
                    on_timeout=self.on_timeout,
                    version_manager_id=version_manager_id,
                )
                with self.environments_lock:
                    self.environments[version_manager_id][execution_environment.id] = execution_environment
                futures.append(self.provisioning_pool.submit(execution_environment.start))
        elif diff < 0:
            # Scale down: remove excess environments
            to_remove = current_provisioned_environments[:abs(diff)]
            for env in to_remove:
                futures.append(self.provisioning_pool.submit(self.stop_environment, env))
        # diff == 0: nothing to do

        return futures

    def stop(self):
        self.provisioning_pool.shutdown(cancel_futures=True)
