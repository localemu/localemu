import dataclasses
import json
import logging
import re
import shutil
import tempfile
import threading
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from localemu import config
from localemu.aws.api.lambda_ import Architecture, PackageType, Runtime
from localemu.services.lambda_ import hooks as lambda_hooks
from localemu.services.lambda_.invocation.executor_endpoint import (
    INVOCATION_PORT,
    ExecutorEndpoint,
)
from localemu.services.lambda_.invocation.lambda_models import FunctionVersion
from localemu.services.lambda_.invocation.runtime_executor import (
    ChmodPath,
    LambdaPrebuildContext,
    LambdaRuntimeException,
    RuntimeExecutor,
)
from localemu.services.lambda_.lambda_utils import HINT_LOG
from localemu.services.lambda_.networking import (
    get_all_container_networks_for_lambda,
    get_main_endpoint_from_container,
)
from localemu.services.lambda_.packages import get_runtime_client_path
from localemu.services.lambda_.runtimes import IMAGE_MAPPING
from localemu.utils.container_networking import get_main_container_name
from localemu.utils.container_utils.container_client import (
    BindMount,
    ContainerConfiguration,
    DockerNotAvailable,
    DockerPlatform,
    NoSuchContainer,
    NoSuchImage,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localemu.utils.files import chmod_r, rm_rf
from localemu.utils.net import get_free_tcp_port
from localemu.utils.strings import short_uid, truncate

LOG = logging.getLogger(__name__)

IMAGE_PREFIX = "public.ecr.aws/lambda/"
# IMAGE_PREFIX = "amazon/aws-lambda-"

RAPID_ENTRYPOINT = "/var/rapid/init"

LAMBDA_DOCKERFILE = """FROM {base_img}
COPY init {rapid_entrypoint}
COPY code/ /var/task
"""

PULLED_IMAGES: set[tuple[str, DockerPlatform]] = set()
PULL_LOCKS: dict[tuple[str, DockerPlatform], threading.RLock] = defaultdict(threading.RLock)

HOT_RELOADING_ENV_VARIABLE = "LOCALEMU_HOT_RELOADING_PATHS"

# Timeout in seconds when stopping a Lambda container before force-killing it.
CONTAINER_STOP_TIMEOUT_SECONDS = 5


"""Map AWS Lambda architecture to Docker platform flags. Example: arm64 => linux/arm64"""
ARCHITECTURE_PLATFORM_MAPPING: dict[Architecture, DockerPlatform] = {
    Architecture.x86_64: DockerPlatform.linux_amd64,
    Architecture.arm64: DockerPlatform.linux_arm64,
}


def docker_platform(lambda_architecture: Architecture) -> DockerPlatform | None:
    """
    Convert an AWS Lambda architecture into a Docker platform flag. Examples:
    * docker_platform("x86_64") == "linux/amd64"
    * docker_platform("arm64") == "linux/arm64"

    :param lambda_architecture: the instruction set that the function supports
    :return: Docker platform in the format ``os[/arch[/variant]]`` or None if configured to ignore the architecture
    """
    if config.LAMBDA_IGNORE_ARCHITECTURE:
        return None
    return ARCHITECTURE_PLATFORM_MAPPING[lambda_architecture]


def get_image_name_for_function(function_version: FunctionVersion) -> str:
    return f"localemu/prebuild-lambda-{function_version.id.qualified_arn().replace(':', '_').replace('$', '_').lower()}"


def get_default_image_for_runtime(runtime: Runtime) -> str:
    postfix = IMAGE_MAPPING.get(runtime)
    if not postfix:
        raise ValueError(f"Unsupported runtime {runtime}!")
    return f"{IMAGE_PREFIX}{postfix}"


def _ensure_runtime_image_present(image: str, platform: DockerPlatform) -> None:
    # Pull image for a given platform upon function creation such that invocations do not time out.
    if (image, platform) in PULLED_IMAGES:
        return
    # use a lock to avoid concurrent pulling of the same image
    with PULL_LOCKS[(image, platform)]:
        if (image, platform) in PULLED_IMAGES:
            return
        try:
            CONTAINER_CLIENT.pull_image(image, platform)
            PULLED_IMAGES.add((image, platform))
        except NoSuchImage as e:
            LOG.debug("Unable to pull image %s for runtime executor preparation.", image)
            raise e
        except DockerNotAvailable as e:
            HINT_LOG.error(
                "Failed to pull Docker image because Docker is not available in the LocalEmu container "
                "but required to run Lambda functions. Please add the Docker volume mount "
                '"/var/run/docker.sock:/var/run/docker.sock" to your LocalEmu startup. '
                "https://localemu.cloud/docs/lambda"
            )
            raise e


class RuntimeImageResolver:
    """
    Resolves Lambda runtimes to corresponding docker images
    The default behavior resolves based on a prefix (including the repository) and a suffix (per runtime).

    This can be customized via the LAMBDA_RUNTIME_IMAGE_MAPPING config in 2 distinct ways:

    Option A: use a pattern string for the config variable that includes the "<runtime>" string
        e.g. "myrepo/lambda:<runtime>-custom" would resolve the runtime "python3.9" to "myrepo/lambda:python3.9-custom"

    Option B: use a JSON dict string for the config variable, mapping the runtime to the full image name & tag
        e.g. {"python3.9": "myrepo/lambda:python3.9-custom", "python3.8": "myotherrepo/pylambda:3.8"}

        Note that with Option B this will only apply to the runtimes included in the dict.
        All other (non-included) runtimes will fall back to the default behavior.
    """

    _mapping: dict[Runtime, str]
    _default_resolve_fn: Callable[[Runtime], str]

    def __init__(
        self, default_resolve_fn: Callable[[Runtime], str] = get_default_image_for_runtime
    ):
        self._mapping = {}
        self._default_resolve_fn = default_resolve_fn

    def _resolve(self, runtime: Runtime, custom_image_mapping: str = "") -> str:
        if runtime not in IMAGE_MAPPING:
            raise ValueError(f"Unsupported runtime {runtime}")

        if not custom_image_mapping:
            return self._default_resolve_fn(runtime)

        # Option A (pattern string that includes <runtime> to replace)
        if "<runtime>" in custom_image_mapping:
            return custom_image_mapping.replace("<runtime>", runtime)

        # Option B (json dict mapping with fallback)
        try:
            mapping: dict = json.loads(custom_image_mapping)
            # at this point we're loading the whole dict to avoid parsing multiple times
            for k, v in mapping.items():
                if k not in IMAGE_MAPPING:
                    raise ValueError(
                        f"Unsupported runtime ({runtime}) provided in LAMBDA_RUNTIME_IMAGE_MAPPING"
                    )
                self._mapping[k] = v

            if runtime in self._mapping:
                return self._mapping[runtime]

            # fall back to default behavior if the runtime was not present in the custom config
            return self._default_resolve_fn(runtime)

        except Exception:
            LOG.error(
                "Failed to load config from LAMBDA_RUNTIME_IMAGE_MAPPING=%s",
                custom_image_mapping,
            )
            raise  # TODO: validate config at start and prevent startup

    def get_image_for_runtime(self, runtime: Runtime) -> str:
        if runtime not in self._mapping:
            resolved_image = self._resolve(runtime, config.LAMBDA_RUNTIME_IMAGE_MAPPING)
            self._mapping[runtime] = resolved_image

        return self._mapping[runtime]


resolver = RuntimeImageResolver()


def prepare_image(function_version: FunctionVersion, platform: DockerPlatform) -> None:
    if not function_version.config.runtime:
        raise NotImplementedError(
            "Custom images are currently not supported with image prebuilding"
        )

    # create dockerfile
    docker_file = LAMBDA_DOCKERFILE.format(
        base_img=resolver.get_image_for_runtime(function_version.config.runtime),
        rapid_entrypoint=RAPID_ENTRYPOINT,
    )

    code_path = function_version.config.code.get_unzipped_code_location()
    context_path = Path(
        f"{tempfile.gettempdir()}/lambda/prebuild_tmp/{function_version.id.function_name}-{short_uid()}"
    )
    context_path.mkdir(parents=True)
    prebuild_context = LambdaPrebuildContext(
        docker_file_content=docker_file,
        context_path=context_path,
        function_version=function_version,
    )
    lambda_hooks.prebuild_environment_image.run(prebuild_context)
    LOG.debug(
        "Prebuilding image for function %s from context %s and Dockerfile %s",
        function_version.qualified_arn,
        str(prebuild_context.context_path),
        prebuild_context.docker_file_content,
    )
    # save dockerfile
    docker_file_path = prebuild_context.context_path / "Dockerfile"
    with docker_file_path.open(mode="w") as f:
        f.write(prebuild_context.docker_file_content)

    # copy init file — use the function's declared architecture so
    # the RAPID binary matches the target container's arch even when
    # the host differs (Apple Silicon + linux/amd64 container).
    init_destination_path = prebuild_context.context_path / "init"
    fn_arch = function_version.config.architectures[0]
    src_init = f"{get_runtime_client_path(arch=fn_arch)}/var/rapid/init"
    shutil.copy(src_init, init_destination_path)
    init_destination_path.chmod(0o755)

    # copy function code
    context_code_path = prebuild_context.context_path / "code"
    shutil.copytree(
        f"{str(code_path)}/",
        str(context_code_path),
        dirs_exist_ok=True,
    )
    # if layers are present, permissions should be 0755
    if prebuild_context.function_version.config.layers:
        chmod_r(str(context_code_path), 0o755)

    try:
        image_name = get_image_name_for_function(function_version)
        CONTAINER_CLIENT.build_image(
            dockerfile_path=str(docker_file_path),
            image_name=image_name,
            platform=platform,
        )
    except Exception as e:
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.exception(
                "Error while building prebuilt lambda image for '%s'",
                function_version.qualified_arn,
            )
        else:
            LOG.error(
                "Error while building prebuilt lambda image for '%s', Error: %s",
                function_version.qualified_arn,
                e,
            )
    finally:
        rm_rf(str(prebuild_context.context_path))


@dataclasses.dataclass
class LambdaContainerConfiguration(ContainerConfiguration):
    copy_folders: list[tuple[str, str]] = dataclasses.field(default_factory=list)


class DockerRuntimeExecutor(RuntimeExecutor):
    ip: str | None
    executor_endpoint: ExecutorEndpoint | None
    container_name: str

    def __init__(self, id: str, function_version: FunctionVersion) -> None:
        super().__init__(id=id, function_version=function_version)
        self.ip = None
        self.executor_endpoint = ExecutorEndpoint(self.id)
        self.container_name = self._generate_container_name()
        LOG.debug("Assigning container name of %s to executor %s", self.container_name, self.id)

    def get_image(self) -> str:
        if not self.function_version.config.runtime:
            # Container-image Lambda (PackageType=Image): the ImageCode
            # object lives on ``config.image``, NOT ``config.code``.
            # ``config.code`` is the S3Code/HotReloadingCode used by
            # zip-based Lambdas and is ``None`` for image-based ones;
            # reading it here meant every Image-lambda invocation
            # raised "Lambda function has no runtime and no container
            # image URI" even when the image was set correctly at
            # CreateFunction time.
            img = getattr(self.function_version.config, "image", None)
            if img is not None:
                if getattr(img, "image_uri", None):
                    return img.image_uri
                if getattr(img, "resolved_image_uri", None):
                    return img.resolved_image_uri
            raise RuntimeError(
                "Lambda function has no runtime and no container image URI. "
                "Specify either a runtime (e.g. python3.12) or a container image."
            )
        return (
            get_image_name_for_function(self.function_version)
            if config.LAMBDA_PREBUILD_IMAGES
            else resolver.get_image_for_runtime(self.function_version.config.runtime)
        )

    def _generate_container_name(self):
        """
        Format <main-container-name>-lambda-<function-name>-<executor-id>
        TODO: make the format configurable
        """
        # Sanitize function name for Docker container naming rules: [a-zA-Z0-9][a-zA-Z0-9_.-]*
        sanitized_name = re.sub(r"[^a-zA-Z0-9-]", "-", self.function_version.id.function_name.lower())
        container_name = "-".join(
            [
                get_main_container_name() or "localemu",
                "lambda",
                sanitized_name,
            ]
        )
        return f"{container_name}-{self.id}"

    def start(self, env_vars: dict[str, str]) -> None:
        self.executor_endpoint.start()
        try:
            self._do_start(env_vars)
        except Exception:
            try:
                self.executor_endpoint.shutdown()
            except Exception as cleanup_err:
                LOG.debug("Failed to clean up executor endpoint after start failure: %s", cleanup_err)
            raise

    def _do_start(self, env_vars: dict[str, str]) -> None:
        main_network, *additional_networks = self._get_networks_for_executor()
        container_config = LambdaContainerConfiguration(
            image_name=None,
            name=self.container_name,
            env_vars=env_vars,
            network=main_network,
            entrypoint=RAPID_ENTRYPOINT,
            platform=docker_platform(self.function_version.config.architectures[0]),
            additional_flags=config.LAMBDA_DOCKER_FLAGS,
        )

        if self.function_version.config.package_type == PackageType.Zip:
            if self.function_version.config.code.is_hot_reloading():
                container_config.env_vars[HOT_RELOADING_ENV_VARIABLE] = "/var/task"
                if container_config.volumes is None:
                    container_config.volumes = VolumeMappings()
                container_config.volumes.add(
                    BindMount(
                        str(self.function_version.config.code.get_unzipped_code_location()),
                        "/var/task",
                        read_only=True,
                    )
                )
            else:
                container_config.copy_folders.append(
                    (
                        f"{str(self.function_version.config.code.get_unzipped_code_location())}/.",
                        "/var/task",
                    )
                )

        # always chmod /tmp to 700
        chmod_paths = [ChmodPath(path="/tmp", mode="0700")]

        lambda_hooks.start_docker_executor.run(container_config, self.function_version)

        if not container_config.image_name:
            container_config.image_name = self.get_image()
        if config.LAMBDA_DEV_PORT_EXPOSE:
            self.executor_endpoint.container_port = get_free_tcp_port()
            if container_config.ports is None:
                container_config.ports = PortMappings()
            container_config.ports.add(self.executor_endpoint.container_port, INVOCATION_PORT)

        if config.LAMBDA_INIT_DEBUG:
            container_config.entrypoint = "/debug-bootstrap.sh"
            if not container_config.ports:
                container_config.ports = PortMappings()
            container_config.ports.add(config.LAMBDA_INIT_DELVE_PORT, config.LAMBDA_INIT_DELVE_PORT)

        if (
            self.function_version.config.layers
            and not config.LAMBDA_PREBUILD_IMAGES
            and self.function_version.config.package_type == PackageType.Zip
        ):
            # avoid chmod on mounted code paths
            hot_reloading_env = container_config.env_vars.get(HOT_RELOADING_ENV_VARIABLE, "")
            if "/opt" not in hot_reloading_env:
                chmod_paths.append(ChmodPath(path="/opt", mode="0755"))
            if "/var/task" not in hot_reloading_env:
                chmod_paths.append(ChmodPath(path="/var/task", mode="0755"))
        container_config.env_vars["LOCALEMU_CHMOD_PATHS"] = json.dumps(chmod_paths)

        CONTAINER_CLIENT.create_container_from_config(container_config)
        if (
            not config.LAMBDA_PREBUILD_IMAGES
            or self.function_version.config.package_type != PackageType.Zip
        ):
            # Pass the function's architecture so the RAPID binary we
            # copy matches the CONTAINER's arch, not the host's. This
            # matters for container-image Lambdas on Apple Silicon
            # running a linux/amd64 image via Rosetta — copying the
            # host-native arm64 init in would give "exec format error"
            # and the runtime would silently time out during startup.
            fn_arch = self.function_version.config.architectures[0]
            CONTAINER_CLIENT.copy_into_container(
                self.container_name,
                f"{str(get_runtime_client_path(arch=fn_arch))}/.", "/",
            )
            # tiny bit inefficient since we actually overwrite the init, but otherwise the path might not exist
            if config.LAMBDA_INIT_BIN_PATH:
                CONTAINER_CLIENT.copy_into_container(
                    self.container_name, config.LAMBDA_INIT_BIN_PATH, "/var/rapid/init"
                )
            if config.LAMBDA_INIT_DEBUG:
                CONTAINER_CLIENT.copy_into_container(
                    self.container_name, config.LAMBDA_INIT_DELVE_PATH, "/var/rapid/dlv"
                )
                CONTAINER_CLIENT.copy_into_container(
                    self.container_name, config.LAMBDA_INIT_BOOTSTRAP_PATH, "/debug-bootstrap.sh"
                )

        if not config.LAMBDA_PREBUILD_IMAGES:
            # copy_folders should be empty here if package type is not zip
            for source, target in container_config.copy_folders:
                CONTAINER_CLIENT.copy_into_container(self.container_name, source, target)

        if additional_networks:
            for additional_network in additional_networks:
                CONTAINER_CLIENT.connect_container_to_network(
                    additional_network, self.container_name
                )

        CONTAINER_CLIENT.start_container(self.container_name)
        if config.is_in_docker:
            # Inside Docker: get the container's IP on the main network
            self.ip = CONTAINER_CLIENT.get_container_ipv4_for_network(
                container_name_or_id=self.container_name, container_network=main_network
            )
        else:
            # Host mode: Lambda container reaches LocalEmu via the mapped port on localhost
            self.ip = "127.0.0.1"
        if config.LAMBDA_DEV_PORT_EXPOSE:
            self.ip = "127.0.0.1"
        self.executor_endpoint.container_address = self.ip

        self.executor_endpoint.wait_for_startup()

    def stop(self) -> None:
        CONTAINER_CLIENT.stop_container(container_name=self.container_name, timeout=CONTAINER_STOP_TIMEOUT_SECONDS)
        if config.LAMBDA_REMOVE_CONTAINERS:
            CONTAINER_CLIENT.remove_container(container_name=self.container_name)
        try:
            self.executor_endpoint.shutdown()
        except Exception as e:
            LOG.debug(
                "Error while stopping executor endpoint for lambda %s, error: %s",
                self.function_version.qualified_arn,
                e,
            )

    def get_address(self) -> str:
        if not self.ip:
            raise LambdaRuntimeException(f"IP address of executor '{self.id}' unknown")
        return self.ip

    def get_endpoint_from_executor(self) -> str:
        return get_main_endpoint_from_container()

    def _get_networks_for_executor(self) -> list[str]:
        """Return the ordered list of Docker networks to attach.

        Index 0 is the *primary* network passed to ``create_container``
        (so the Lambda runtime keeps a route to the LocalEmu control
        plane at ``host.docker.internal:4566``). Indices 1+ are
        ``connect_container_to_network``'d after create.

        When the function was created with ``VpcConfig`` containing a
        resolvable ``vpc_id``, append ``localemu-vpc-<vpc_id>`` so the
        Lambda can reach other services' containers on that VPC (RDS
        via its DNS alias, EC2 by IP, etc.). Without this the VPC
        config was stored in the function model but never honored at
        runtime — DescribeFunction echoed it back but calls in to VPC
        resources silently failed.
        """
        base_networks = get_all_container_networks_for_lambda()
        vpc_config = getattr(self.function_version.config, "vpc_config", None)
        vpc_id = getattr(vpc_config, "vpc_id", None) if vpc_config else None
        if vpc_id:
            vpc_network = f"localemu-vpc-{vpc_id}"
            if vpc_network not in base_networks:
                return [*base_networks, vpc_network]
        return base_networks

    def invoke(self, payload: dict[str, str], function_timeout: int | None = None):
        LOG.debug(
            "Sending invoke-payload '%s' to executor '%s'",
            truncate(json.dumps(payload), config.LAMBDA_TRUNCATE_STDOUT),
            self.id,
        )
        return self.executor_endpoint.invoke(payload, function_timeout=function_timeout)

    def get_logs(self) -> str:
        try:
            return CONTAINER_CLIENT.get_container_logs(container_name_or_id=self.container_name)
        except NoSuchContainer:
            return "Container was not created"

    @classmethod
    def prepare_version(cls, function_version: FunctionVersion) -> None:
        lambda_hooks.prepare_docker_executor.run(function_version)
        # Trigger the installation of the Lambda runtime-init binary before invocation and
        # cache the result to save time upon every invocation. Install
        # the arch-specific binary matching the function's declared
        # architecture (matters on cross-arch hosts like Apple Silicon
        # running linux/amd64 container-image Lambdas).
        get_runtime_client_path(arch=function_version.config.architectures[0])
        if function_version.config.code:
            function_version.config.code.prepare_for_execution()
            image_name = resolver.get_image_for_runtime(function_version.config.runtime)
            platform = docker_platform(function_version.config.architectures[0])
            _ensure_runtime_image_present(image_name, platform)
            if config.LAMBDA_PREBUILD_IMAGES:
                prepare_image(function_version, platform)

    @classmethod
    def cleanup_version(cls, function_version: FunctionVersion) -> None:
        if config.LAMBDA_PREBUILD_IMAGES:
            image_name = get_image_name_for_function(function_version)
            LOG.debug("Cleaning up prebuilt image %s for version %s", image_name, function_version.qualified_arn)
            try:
                CONTAINER_CLIENT.remove_image(image_name, force=False)
            except NoSuchImage:
                LOG.debug("Image %s already removed or never built", image_name)
            except Exception as e:
                # Gracefully handle race conditions (e.g., concurrent build/delete
                # or intermediate layers shared with another version).
                LOG.debug(
                    "Could not remove image %s for version %s: %s",
                    image_name,
                    function_version.qualified_arn,
                    e,
                )

    def get_runtime_endpoint(self) -> str:
        return f"http://{self.get_endpoint_from_executor()}:{config.GATEWAY_LISTEN[0].port}{self.executor_endpoint.get_endpoint_prefix()}"

    @classmethod
    def validate_environment(cls) -> bool:
        if not CONTAINER_CLIENT.has_docker():
            LOG.debug(
                "Docker not available. Lambda functions require Docker to be running."
            )
            return False
        return True
