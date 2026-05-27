"""This is the entrypoint used to start the localemu runtime. It starts the infrastructure and also
manages the interaction with the operating system - mostly signal handlers for now."""

import signal
import sys
import traceback

from localemu import config, constants
from localemu.runtime.exceptions import LocalemuExit


def print_runtime_information(in_docker: bool = False):
    import os

    from localemu.utils.container_networking import get_main_container_name
    from localemu.utils.container_utils.container_client import ContainerException
    from localemu.utils.docker_utils import DOCKER_CLIENT

    GREEN = "\033[32m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    banner = f"""{GREEN}
██╗      ██████╗  ██████╗ █████╗ ██╗     ███████╗███╗   ███╗██╗   ██╗
██║     ██╔═══██╗██╔════╝██╔══██╗██║     ██╔════╝████╗ ████║██║   ██║
██║     ██║   ██║██║     ███████║██║     █████╗  ██╔████╔██║██║   ██║
██║     ██║   ██║██║     ██╔══██║██║     ██╔══╝  ██║╚██╔╝██║██║   ██║
███████╗╚██████╔╝╚██████╗██║  ██║███████╗███████╗██║ ╚═╝ ██║╚██████╔╝
╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝
{RESET}"""
    print(banner)

    # Version
    version = constants.VERSION
    print(f"  Version:    {version}")

    # Python
    python_version = sys.version.split()[0]
    print(f"  Python:     {python_version}")

    # Port
    port = config.GATEWAY_LISTEN[0].port
    print(f"  Port:       {port}")

    # Docker
    try:
        info = DOCKER_CLIENT.get_system_info()
        docker_version = info.get("ServerVersion", "unknown")
        print(f"  Docker:     {docker_version} ({GREEN}running{RESET})")
    except Exception:
        print(f"  Docker:     {DIM}not available{RESET}")

    # Docker container info (when running inside Docker)
    if in_docker:
        try:
            container_name = get_main_container_name()
            print(f"  Container:  {container_name}")
            inspect_result = DOCKER_CLIENT.inspect_container(container_name)
            container_id = inspect_result["Id"]
            print(f"  Container ID: {container_id[:12]}")
        except ContainerException:
            print(
                f"  Container:  {DIM}Failed to inspect container. "
                f"Docker socket may not be mounted.{RESET}"
            )
            if config.DEBUG:
                print("  Docker debug information:")
                traceback.print_exc()
            else:
                print(
                    f"  {DIM}Run with DEBUG=1 for more information.{RESET}"
                )

    # Enabled features
    features = []
    iam_mode = os.environ.get("IAM_ENFORCEMENT", "").strip().lower()
    if iam_mode in ("1", "soft"):
        features.append(f"IAM_ENFORCEMENT={iam_mode}")
    if config.SIMULATE_THROTTLING:
        features.append("SIMULATE_THROTTLING=1")
    if config.SIMULATE_LATENCY:
        features.append(f"SIMULATE_LATENCY={config.SIMULATE_LATENCY}")
    if config.LAMBDA_COLD_START_DELAY > 0:
        features.append(f"LAMBDA_COLD_START_DELAY={config.LAMBDA_COLD_START_DELAY}")
    if features:
        print(f"  Features:   {', '.join(features)}")

    if config.LOCALEMU_BUILD_DATE:
        print(f"  Build date: {config.LOCALEMU_BUILD_DATE}")
    if config.LOCALEMU_BUILD_GIT_HASH:
        print(f"  Git hash:   {config.LOCALEMU_BUILD_GIT_HASH}")

    print()


def main():
    from localemu.logging.setup import setup_logging_from_config
    from localemu.runtime import current

    try:
        setup_logging_from_config()
        runtime = current.initialize_runtime()
    except Exception as e:
        sys.stdout.write(f"ERROR: The LocalEmu Runtime could not be initialized: {e}\n")
        sys.stdout.flush()
        raise

    # TODO: where should this go?
    print_runtime_information()

    # signal handler to make sure SIGTERM properly shuts down localemu
    def _terminate_localemu(sig: int, frame):
        sys.stdout.write(f"LocalEmu runtime received signal {sig}\n")
        sys.stdout.flush()
        runtime.exit(0)

    signal.signal(signal.SIGINT, _terminate_localemu)
    signal.signal(signal.SIGTERM, _terminate_localemu)

    try:
        runtime.run()
    except LocalemuExit as e:
        sys.stdout.write(f"LocalEmu returning with exit code {e.code}. Reason: {e}")
        sys.exit(e.code)
    except Exception as e:
        sys.stdout.write(f"ERROR: the LocalEmu runtime exited unexpectedly: {e}\n")
        sys.stdout.flush()
        raise

    sys.exit(runtime.exit_code)


if __name__ == "__main__":
    main()
