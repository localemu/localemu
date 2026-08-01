import dataclasses
import os
import shlex
import subprocess as sp
from typing import Literal

import click
import yaml

EDGE_SERVICE_NODE_PORT = 30066
NODE_PORT_START = 30010
SERVICE_PORT_START = 4510
NUMBER_OF_SERVICE_PORTS = 50


@dataclasses.dataclass
class MountPoint:
    name: str
    host_path: str
    container_path: str
    node_path: str
    read_only: bool = True
    volume_type: Literal["Directory", "File"] = "Directory"


def generate_mount_points(
    mount_moto: bool = False, mount_entrypoints: bool = False
) -> list[MountPoint]:
    mount_points = []
    # host paths
    root_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
    localemu_code_path = os.path.join(root_path, "src", "localemu")

    # container paths
    target_path = "/opt/code/localemu/"
    venv_path = os.path.join(target_path, ".venv", "lib", "python3.13", "site-packages")

    # Community code: the code is not installed as a package, it lives directly in `/opt/code/localemu`
    mount_points.append(
        MountPoint(
            name="localemu",
            host_path=os.path.normpath(localemu_code_path),
            node_path="/code/localemu",
            container_path=os.path.join(target_path, "src", "localemu"),
        )
    )

    # entrypoints
    if mount_entrypoints:
        # In the community image, the code is not installed as package, so the paths are predictable
        egg_path = os.path.join(root_path, "src", "localemu_core.egg-info/entry_points.txt")
        mount_points.append(
            MountPoint(
                name="entry-points-community",
                host_path=os.path.normpath(egg_path),
                node_path="/code/entry-points-community",
                container_path=os.path.join(
                    target_path,
                    "src",
                    "localemu_core.egg-info",
                    "entry_points.txt",
                ),
                volume_type="File",
            )
        )

    if mount_moto:
        moto_path = os.path.join(root_path, "..", "moto", "moto")
        mount_points.append(
            MountPoint(
                name="moto",
                host_path=os.path.normpath(moto_path),
                node_path="/code/moto",
                container_path=os.path.join(venv_path, "moto"),
            )
        )
    return mount_points


def generate_k8s_cluster_config(
    mount_points: list[MountPoint],
    port: int = 4566,
):
    volumes = [
        {
            "volume": f"{mount_point.host_path}:{mount_point.node_path}",
            "nodeFilters": ["server:*", "agent:*"],
        }
        for mount_point in mount_points
    ]

    ports = [
        # main gateway port
        {
            "nodeFilters": [
                "server:0",
            ],
            "port": f"{port}:{EDGE_SERVICE_NODE_PORT}",
        },
        # 443 https port for main gateway
        {
            "nodeFilters": [
                "server:0",
            ],
            "port": f"443:{EDGE_SERVICE_NODE_PORT}",
        },
        # Node ports
        {
            "nodeFilters": [
                "server:0",
            ],
            "port": f"{SERVICE_PORT_START}-{SERVICE_PORT_START + NUMBER_OF_SERVICE_PORTS - 1}:{NODE_PORT_START}-{NODE_PORT_START + NUMBER_OF_SERVICE_PORTS - 1}",
        },
    ]

    config = {
        "apiVersion": "k3d.io/v1alpha5",
        "kind": "Simple",
        "volumes": volumes,
        "ports": ports,
        "options": {
            "k3s": {
                "extraArgs": [
                    {
                        "arg": "--kubelet-arg=container-log-max-size=1Gi",
                        "nodeFilters": ["server:*"],
                    },
                ],
            },
        },
    }

    return config


def snake_to_kebab_case(string: str):
    return string.lower().replace("_", "-")


def generate_k8s_helm_overrides(mount_points: list[MountPoint], env: list[str] | None = None):
    volumes = [
        {
            "name": mount_point.name,
            "hostPath": {"path": mount_point.node_path, "type": mount_point.volume_type},
        }
        for mount_point in mount_points
    ]

    volume_mounts = [
        {
            "name": mount_point.name,
            "readOnly": mount_point.read_only,
            "mountPath": mount_point.container_path,
        }
        for mount_point in mount_points
    ]

    extra_env_vars = []
    if env:
        for env_variable in env:
            lhs, _, rhs = env_variable.partition("=")
            extra_env_vars.append(
                {
                    "name": lhs,
                    "value": rhs,
                }
            )

    image_repository = "localemu/localemu"

    service = {
        "edgeService": {
            "nodePort": EDGE_SERVICE_NODE_PORT,
        },
        "externalServicePorts": {
            "start": SERVICE_PORT_START,
            "end": SERVICE_PORT_START + NUMBER_OF_SERVICE_PORTS,
            "nodePortStart": NODE_PORT_START,
        },
        "dnsService": {
            "enabled": True,
        },
    }
    overrides = {
        "debug": True,
        "volumes": volumes,
        "volumeMounts": volume_mounts,
        "extraEnvVars": extra_env_vars,
        "image": {"repository": image_repository},
        "lambda": {"executor": "kubernetes"},
        "service": service,
        "readinessProbe": {"initialDelaySeconds": 10},
        "livenessProbe": {"initialDelaySeconds": 10},
    }

    return overrides


def write_file(content: dict, output_path: str):
    with open(output_path, "w") as f:
        f.write(yaml.dump(content))
        f.close()
        print(f"Generated file at {output_path}")


def print_file(content: dict, file_name: str):
    print(f"Generated file:\t{file_name}")
    print("=====================================")
    print(yaml.dump(content))
    print("=====================================")


def generate_k3d_command(config_file_path: str) -> str:
    return f"k3d cluster create --config {config_file_path}"


def generate_helm_command(overrides_file_path: str) -> str:
    return f"helm upgrade --install localemu localemu/localemu -f {overrides_file_path}"


def execute_deployment(config_file_path: str, overrides_file_path: str):
    """
    Use the k3d and helm commands to create a cluster and deploy LocalEmu in one command
    """
    sp.check_call(shlex.split(generate_k3d_command(config_file_path)))
    sp.check_call(shlex.split(generate_helm_command(overrides_file_path)))


@click.command("run")
@click.option(
    "--mount-moto", is_flag=True, default=None, help="Mount the moto code into the cluster."
)
@click.option(
    "--mount-entrypoints", is_flag=True, default=None, help="Mount the entrypoints into the pod."
)
@click.option(
    "--write",
    is_flag=True,
    default=None,
    help="Write the configuration and overrides to files.",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    help="Output directory for generated files.",
)
@click.option(
    "--overrides-file",
    "-of",
    default=None,
    help="Name of the overrides file (default: overrides.yml).",
)
@click.option(
    "--config-file",
    "-cf",
    default=None,
    help="Name of the configuration file (default: configuration.yml).",
)
@click.option(
    "--env", "-e", default=None, help="Environment variable to set in the pod", multiple=True
)
@click.option(
    "--port",
    "-p",
    default=4566,
    help="Port to expose from the kubernetes node",
    type=click.IntRange(0, 65535),
)
@click.option(
    "--execute",
    "-x",
    is_flag=True,
    default=False,
    help="Execute deployment from generated config files. Implies -w/--write.",
)
@click.argument("command", nargs=-1, required=False)
def run(
    mount_moto: bool = False,
    mount_entrypoints: bool = False,
    write: bool = False,
    output_dir=None,
    overrides_file: str = None,
    config_file: str = None,
    command: str = None,
    env: list[str] = None,
    port: int = None,
    execute: bool = False,
):
    """
    A tool for localemu developers to generate the kubernetes cluster configuration file and the overrides to mount the localemu code into the cluster.
    """
    mount_points = generate_mount_points(mount_moto, mount_entrypoints)

    config = generate_k8s_cluster_config(mount_points, port=port)

    overrides = generate_k8s_helm_overrides(mount_points, env=env)

    output_dir = output_dir or os.getcwd()
    overrides_file = overrides_file or "overrides.yml"
    config_file = config_file or "configuration.yml"

    overrides_file_path = os.path.join(output_dir, overrides_file)
    config_file_path = os.path.join(output_dir, config_file)

    if write or execute:
        write_file(config, config_file_path)
        write_file(overrides, overrides_file_path)
        if execute:
            execute_deployment(config_file, overrides_file)
    else:
        print_file(config, config_file)
        print_file(overrides, overrides_file)

    print("\nTo create a k3d cluster with the generated configuration, follow these steps:")
    print("1. Run the following command to create the cluster:")
    print(f"\n    {generate_k3d_command(config_file_path)}\n")

    print("2. Once the cluster is created, start LocalEmu with the generated overrides:")
    print("\n    helm repo add localemu https://localemu.github.io/helm-charts # (if required)")
    print(f"\n    {generate_helm_command(overrides_file_path)}\n")


def main():
    run()


if __name__ == "__main__":
    main()
