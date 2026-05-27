from typing import TYPE_CHECKING

from localemu.packages.api import Package, package

if TYPE_CHECKING:
    from localemu.packages.ffmpeg import FfmpegPackageInstaller


@package(name="ffmpeg")
def ffmpeg_package() -> Package["FfmpegPackageInstaller"]:
    from localemu.packages.ffmpeg import ffmpeg_package

    return ffmpeg_package
