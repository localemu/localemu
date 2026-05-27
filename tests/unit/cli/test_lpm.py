import pytest
from click.testing import CliRunner

from localemu.cli.lpm import cli
from localemu.packages import InstallTarget, Package, PackageException, PackageInstaller
from localemu.packages.api import PackagesPluginManager
from localemu.testing.pytest import markers
from localemu.utils.patch import Patch


@pytest.fixture
def runner():
    return CliRunner()


@markers.skip_offline
def test_install_failure_returns_non_zero_exit_code(runner, monkeypatch):
    class FailingPackage(Package):
        def __init__(self):
            super().__init__("Failing Installer", "latest")

        def get_versions(self) -> list[str]:
            return ["latest"]

        def _get_installer(self, version: str) -> PackageInstaller:
            return FailingInstaller()

    class FailingInstaller(PackageInstaller):
        def __init__(self):
            super().__init__("failing-installer", "latest")

        def _get_install_marker_path(self, install_dir: str) -> str:
            # Return a non-existing path to force calling the installer
            return "/non-existing"

        def _install(self, target: InstallTarget) -> None:
            raise PackageException("Failing!")

    class SuccessfulPackage(Package):
        def __init__(self):
            super().__init__("Successful Installer", "latest")

        def get_versions(self) -> list[str]:
            return ["latest"]

        def _get_installer(self, version: str) -> PackageInstaller:
            return SuccessfulInstaller()

    class SuccessfulInstaller(PackageInstaller):
        def __init__(self):
            super().__init__("successful-installer", "latest")

        def _get_install_marker_path(self, install_dir: str) -> str:
            # Return a non-existing path to force calling the installer
            return "/non-existing"

        def _install(self, target: InstallTarget) -> None:
            pass

    def patched_get_packages(*_) -> list[Package]:
        return [FailingPackage(), SuccessfulPackage()]

    with Patch.function(target=PackagesPluginManager.get_packages, fn=patched_get_packages):
        result = runner.invoke(cli, ["install", "successful-installer", "failing-installer"])
        assert result.exit_code == 1
        assert "one or more package installations failed." in result.output
