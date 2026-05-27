import itertools
import logging
from multiprocessing.pool import ThreadPool

import click
from rich.console import Console

from localemu import config
from localemu.cli.exceptions import CLIError
from localemu.packages import InstallTarget, Package
from localemu.packages.api import NoSuchPackageException, PackagesPluginManager
from localemu.utils.bootstrap import setup_logging

LOG = logging.getLogger(__name__)

console = Console()


@click.group()
def cli():
    """
    The LocalEmu Package Manager (lpm) CLI is a set of commands to install third-party packages used by localemu
    service providers.

    Here are some handy commands:

    List all packages

        python -m localemu.cli.lpm list

    Install a single package

        python -m localemu.cli.lpm install ffmpeg

    Install every available package, four in parallel:

        python -m localemu.cli.lpm list | xargs python -m localemu.cli.lpm install --parallel 4
    """
    setup_logging()


def _do_install_package(package: Package, version: str = None, target: InstallTarget = None):
    console.print(f"installing... [bold]{package}[/bold]")
    try:
        package.install(version=version, target=target)
        console.print(f"[green]installed[/green] [bold]{package}[/bold]")
    except Exception as e:
        console.print(f"[red]error[/red] installing {package}: {e}")
        raise e


@cli.command()
@click.argument("package", nargs=-1, required=True)
@click.option(
    "--parallel",
    type=int,
    default=1,
    required=False,
    help="how many installers to run in parallel processes",
)
@click.option(
    "--version",
    type=str,
    default=None,
    required=False,
    help="version to install of a package",
)
@click.option(
    "--target",
    type=click.Choice([target.name.lower() for target in InstallTarget]),
    default=None,
    required=False,
    help="target of the installation",
)
def install(
    package: list[str],
    parallel: int | None = 1,
    version: str | None = None,
    target: str | None = None,
):
    """Install one or more packages."""
    try:
        if target:
            target = InstallTarget[str.upper(target)]
        else:
            # LPM is meant to be used at build-time, the default target is static_libs
            target = InstallTarget.STATIC_LIBS

        # collect installers and install in parallel:
        console.print(f"resolving packages: {package}")
        package_manager = PackagesPluginManager()
        package_manager.load_all()
        package_instances = package_manager.get_packages(package, version)

        if parallel > 1:
            console.print(f"install {parallel} packages in parallel:")

        config.dirs.mkdirs()

        with ThreadPool(processes=parallel) as pool:
            pool.starmap(
                _do_install_package,
                zip(package_instances, itertools.repeat(version), itertools.repeat(target)),
            )
    except NoSuchPackageException as e:
        LOG.debug(str(e), exc_info=e)
        raise CLIError(str(e))
    except Exception as e:
        LOG.debug("one or more package installations failed.", exc_info=e)
        raise CLIError("one or more package installations failed.")


@cli.command(name="list")
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    required=False,
    help="Verbose output (show additional info on packages)",
)
def list_packages(verbose: bool):
    """List available packages of all repositories"""
    package_manager = PackagesPluginManager()
    package_manager.load_all()
    packages = package_manager.get_all_packages()
    for package_name, _package_scope, package_instance in packages:
        # Scope is an internal grouping (legacy "community" namespace);
        # not shown to end-users so the CLI surface stays one column.
        console.print(f"[green]{package_name}[/green]")
        if verbose:
            for version in package_instance.get_versions():
                if version == package_instance.default_version:
                    console.print(f"  - [bold]{version} (default)[/bold]", highlight=False)
                else:
                    console.print(f"  - {version}", highlight=False)


if __name__ == "__main__":
    cli()
