from localemu.packages import Package, package
from localemu.packages.core import PythonPackageInstaller


@package(name="vosk")
def vosk_package() -> Package[PythonPackageInstaller]:
    from localemu.services.transcribe.packages import vosk_package

    return vosk_package
