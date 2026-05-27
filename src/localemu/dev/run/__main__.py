import dataclasses
import os
from collections.abc import Iterable

import click
from rich.console import Console
from rich.rule import Rule

from localemu import config
from localemu.dev.run.configurators import (
    ConfigEnvironmentConfigurator,
    DependencyMountConfigurator,
    EntryPointMountConfigurator,
    ImageConfigurator,
    PortConfigurator,
    SourceVolumeMountConfigurator,
)
from localemu.dev.run.paths import HOST_PATH_MAPPINGS, HostPaths
from localemu.runtime import hooks
from localemu.utils.bootstrap import Container, ContainerConfigurators
from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.container_utils.docker_cmd_client import CmdDockerClient
from localemu.utils.files import cache_dir
from localemu.utils.run import run_interactive
from localemu.utils.strings import short_uid

console = Console()


@click.command("run")
@click.option(
    "--image",
    type=str,
    required=False,
    help="Overwrite the container image to be used (defaults to localemu/localemu or "
    "localemu/localemu).",
)
@click.option(
    "--volume-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    required=False,
    help="The localemu volume on the host, default: ~/.cache/localemu/volume",
)
@click.option(
    "--pro/--community",
    is_flag=True,
    default=None,
    help="Whether to start localemu pro or community. If not set, it will guess from the current directory",
)
@click.option(
    "--develop/--no-develop",
    is_flag=True,
    default=False,
    help="Install debugpy and expose port 5678",
)
@click.option(
    "--randomize",
    is_flag=True,
    default=False,
    help="Randomize container name and ports to start multiple instances",
)
@click.option(
    "--mount-source/--no-mount-source",
    is_flag=True,
    default=True,
    help="Mount source files from localemu and localemu. Use --local-packages for optional dependencies such as moto.",
)
@click.option(
    "--live-reload/--no-live-reload",
    is_flag=True,
    default=False,
    help="Watch mounted source directories for .py file changes and automatically restart the container runtime.",
)
@click.option(
    "--mount-dependencies/--no-mount-dependencies",
    is_flag=True,
    default=False,
    help="Whether to mount the dependencies of the current .venv directory into the container. Note this only works if the dependencies are compatible with the python and platform version from the venv and the container.",
)
@click.option(
    "--mount-entrypoints/--no-mount-entrypoints",
    is_flag=True,
    default=False,
    help="Mount entrypoints",
)
@click.option("--mount-docker-socket/--no-docker-socket", is_flag=True, default=True)
@click.option(
    "--env",
    "-e",
    help="Additional environment variables that are passed to the LocalEmu container",
    multiple=True,
    required=False,
)
@click.option(
    "--volume",
    "-v",
    help="Additional volume mounts that are passed to the LocalEmu container",
    multiple=True,
    required=False,
)
@click.option(
    "--publish",
    "-p",
    help="Additional ports that are published to the host",
    multiple=True,
    required=False,
)
@click.option(
    "--entrypoint",
    type=str,
    required=False,
    help="Additional entrypoint flag passed to docker",
)
@click.option(
    "--network",
    type=str,
    required=False,
    help="Docker network to start the container in",
)
@click.option(
    "--local-packages",
    "-l",
    multiple=True,
    required=False,
    type=click.Choice(HOST_PATH_MAPPINGS.keys(), case_sensitive=False),
    help="Mount specified packages into the container",
)
@click.argument("command", nargs=-1, required=False)
def run(
    image: str = None,
    volume_dir: str = None,
    pro: bool = None,
    develop: bool = False,
    randomize: bool = False,
    mount_source: bool = True,
    live_reload: bool = False,
    mount_dependencies: bool = False,
    mount_entrypoints: bool = False,
    mount_docker_socket: bool = True,
    env: tuple = (),
    volume: tuple = (),
    publish: tuple = (),
    entrypoint: str = None,
    network: str = None,
    local_packages: list[str] | None = None,
    command: str = None,
):
    """
    A tool for localemu developers to start localemu containers. Run this in your localemu or
    localemu source tree to mount local source files or dependencies into the container.
    Here are some examples::

    \b
        python -m localemu.dev.run
        python -m localemu.dev.run -e DEBUG=1
        python -m localemu.dev.run -- bash -c 'echo "hello"'

    Explanations and more examples:

    Start a normal container localemu container. If you run this from the localemu repo,
    it will start localemu::

        python -m localemu.dev.run

    If your local changes are making modifications to plux plugins (e.g., adding new providers or hooks),
    then you also want to mount the newly generated entry_point.txt files into the container::

        python -m localemu.dev.run --mount-entrypoints

    Start a new container with randomized gateway and service ports, and randomized container name::

        python -m localemu.dev.run --randomize

    You can also run custom commands:

        python -m localemu.dev.run bash -c 'echo "hello"'

    Or use custom entrypoints:

        python -m localemu.dev.run --entrypoint /bin/bash -- echo "hello"

    Use the --live-reload flag to restart LocalEmu on code changes. Beware: this will remove any state
    that you had in your LocalEmu instance. Consider using PERSISTENCE to keep resources:

        python -m localemu.dev.run --live-reload

    You can import and expose debugpy:

        python -m localemu.dev.run --develop

    You can also mount local dependencies (e.g., pytest and other test dependencies, and then use that
    in the container)::

    \b
        python -m localemu.dev.run --mount-dependencies \\
            -v $PWD/tests:/opt/code/localemu/tests \\
            -- .venv/bin/python -m pytest tests/unit/http_/

    The script generally assumes that you are executing in either localemu or localemu source
    repositories that are organized like this::

    \b
        somedir                              <- your workspace directory
        ├── localemu                       <- execute script in here
        │   ├── ...
        │   ├── src
        │   │   ├── localemu               <- will be mounted into the container
        │   │   └── localemu_core.egg-info
        │   ├── pyproject.toml
        │   ├── tests
        │   └── ...
        ├── localemu                   <- or execute script in here
        │   ├── ...
        │   │   ├── localemu
        │   │   │   └── pro
        │   │   │       └── core             <- will be mounted into the container
        │   │   ├── localemu_ext.egg-info
        │   │   ├── pyproject.toml
        │   │   └── tests
        │   └── ...
        ├── moto
        │   ├── AUTHORS.md
        │   ├── ...
        │   ├── moto                         <- will be mounted into the container
        │   ├── moto_ext.egg-info
        │   ├── pyproject.toml
        │   ├── tests
        │   └── ...

    You can choose which local source repositories are mounted in. For example, if `moto` and `rolo` are
    both present, only mount `rolo` into the container.

    \b
        python -m localemu.dev.run --local-packages rolo

    If both `rolo` and `moto` are available and both should be mounted, use the flag twice.

    \b
        python -m localemu.dev.run --local-packages rolo --local-packages moto
    """
    with console.status("Configuring") as status:
        env_vars = parse_env_vars(env)

        # run all prepare_host hooks
        hooks.prepare_host.run()

        # set the VOLUME_DIR config variable like in the CLI
        if not os.environ.get("LOCALEMU_VOLUME_DIR", "").strip():
            config.VOLUME_DIR = str(cache_dir() / "volume")

        # setup important paths on the host
        host_paths = HostPaths(
            # we assume that python -m localemu.dev.run is always executed in the repo source
            workspace_dir=os.path.abspath(os.path.join(os.getcwd(), "..")),
            volume_dir=volume_dir or config.VOLUME_DIR,
        )

        # auto-set pro flag
        if pro is None:
            if os.getcwd().endswith("localemu"):
                pro = True
            else:
                pro = False

        # setup base configuration
        container_config = ContainerConfiguration(
            image_name=image,
            name=config.MAIN_CONTAINER_NAME if not randomize else f"localemu-{short_uid()}",
            remove=True,
            interactive=True,
            tty=True,
            env_vars={},
            volumes=VolumeMappings(),
            ports=PortMappings(),
            network=network,
        )

        # setup configurators
        configurators = [
            ImageConfigurator(pro, image),
            PortConfigurator(randomize),
            ConfigEnvironmentConfigurator(pro),
            ContainerConfigurators.mount_localemu_volume(host_paths.volume_dir),
            ContainerConfigurators.config_env_vars,
        ]

        # create stub container with configuration to apply
        c = Container(container_config=container_config)

        # apply existing hooks first that can later be overwritten
        hooks.configure_localemu_container.run(c)

        if command:
            configurators.append(ContainerConfigurators.custom_command(list(command)))
        if entrypoint:
            container_config.entrypoint = entrypoint
        if mount_docker_socket:
            configurators.append(ContainerConfigurators.mount_docker_socket)
        if mount_source:
            configurators.append(
                SourceVolumeMountConfigurator(
                    host_paths=host_paths,
                    pro=pro,
                    chosen_packages=local_packages,
                )
            )
        if mount_entrypoints:
            configurators.append(EntryPointMountConfigurator(host_paths=host_paths, pro=pro))
        if mount_dependencies:
            configurators.append(DependencyMountConfigurator(host_paths=host_paths))
        if develop:
            configurators.append(ContainerConfigurators.develop)

        # make sure anything coming from CLI arguments has priority
        configurators.extend(
            [
                ContainerConfigurators.volume_cli_params(volume),
                ContainerConfigurators.port_cli_params(publish),
                ContainerConfigurators.env_cli_params(env),
            ]
        )

        # run configurators
        for configurator in configurators:
            configurator(container_config)
        # print the config
        print_config(container_config)

        # run the container
        docker = CmdDockerClient()
        status.update("Creating container")
        container_id = docker.create_container_from_config(container_config)

    rule = Rule(f"Interactive session with {container_id[:12]} 💻")
    console.print(rule)
    stop_live_reload_watcher = None
    try:
        if live_reload and mount_source:
            # Some install targets don't include the `watchdog` dependency, and some developers
            # don't install LocalEmu using the `Makefile`, so they find that they don't have
            # the `watchdog` dependency. We lazy import these functions so that we don't trigger
            # an import error for these developers.
            from localemu.dev.run.watcher import collect_watch_directories, start_file_watcher

            if watch_dirs := collect_watch_directories(host_paths, pro, local_packages):
                stop_live_reload_watcher = start_file_watcher(watch_dirs, docker, container_id)

        cmd = [*docker._docker_cmd(), "start", "--interactive", "--attach", container_id]
        run_interactive(cmd)
    finally:
        if stop_live_reload_watcher is not None:
            stop_live_reload_watcher.set()

        if container_config.remove:
            try:
                if docker.is_container_running(container_id):
                    docker.stop_container(container_id)
                docker.remove_container(container_id)
            except Exception:
                pass


def print_config(cfg: ContainerConfiguration):
    d = dataclasses.asdict(cfg)

    d["volumes"] = [v.to_str() for v in d["volumes"].mappings]
    d["ports"] = [p for p in d["ports"].to_list() if p != "-p"]

    for k in list(d.keys()):
        if d[k] is None:
            d.pop(k)

    console.print(d)


def parse_env_vars(params: Iterable[str] = None) -> dict[str, str]:
    env = {}

    if not params:
        return env

    for e in params:
        if "=" in e:
            k, v = e.split("=", maxsplit=1)
            env[k] = v
        else:
            # there's currently no way in our abstraction to only pass the variable name (as
            # you can do in docker) so we resolve the value here.
            env[e] = os.getenv(e)

    return env


def main():
    run()


if __name__ == "__main__":
    main()
