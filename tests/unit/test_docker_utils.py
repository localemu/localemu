from unittest import mock

from localemu.utils.container_utils.container_client import VolumeDirMount, VolumeInfo
from localemu.utils.docker_utils import get_host_path_for_path_in_docker


class TestDockerUtils:
    def test_host_path_for_path_in_docker_windows(self):
        with (
            mock.patch("localemu.utils.docker_utils.get_default_volume_dir_mount") as get_volume,
            mock.patch("localemu.config.is_in_docker", True),
        ):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source=r"C:\Users\localemu\volume\mount",
                destination="/var/lib/localemu",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localemu/some/test/file")
            get_volume.assert_called_once()
            # this path style is kinda weird, but windows will accept it - no need for manual conversion of / to \
            assert result == r"C:\Users\localemu\volume\mount/some/test/file"

    def test_host_path_for_path_in_docker_linux(self):
        with (
            mock.patch("localemu.utils.docker_utils.get_default_volume_dir_mount") as get_volume,
            mock.patch("localemu.config.is_in_docker", True),
        ):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localemu/volume",
                destination="/var/lib/localemu",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localemu/some/test/file")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localemu/volume/some/test/file"

    def test_host_path_for_path_in_docker_linux_volume_dir(self):
        with (
            mock.patch("localemu.utils.docker_utils.get_default_volume_dir_mount") as get_volume,
            mock.patch("localemu.config.is_in_docker", True),
        ):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localemu/volume",
                destination="/var/lib/localemu",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localemu")
            get_volume.assert_called_once()
            assert result == "/home/some-user/.cache/localemu/volume"

    def test_host_path_for_path_in_docker_linux_wrong_path(self):
        with (
            mock.patch("localemu.utils.docker_utils.get_default_volume_dir_mount") as get_volume,
            mock.patch("localemu.config.is_in_docker", True),
        ):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localemu/volume",
                destination="/var/lib/localemu",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            result = get_host_path_for_path_in_docker("/var/lib/localemutest")
            get_volume.assert_called_once()
            assert result == "/var/lib/localemutest"
            result = get_host_path_for_path_in_docker("/etc/some/path")
            assert result == "/etc/some/path"

    def test_volume_dir_mount_linux(self):
        with (
            mock.patch("localemu.utils.docker_utils.get_default_volume_dir_mount") as get_volume,
            mock.patch("localemu.config.is_in_docker", True),
        ):
            get_volume.return_value = VolumeInfo(
                type="bind",
                source="/home/some-user/.cache/localemu/volume",
                destination="/var/lib/localemu",
                mode="rw",
                rw=True,
                propagation="rprivate",
            )
            volume_dir_mount = VolumeDirMount(
                "/var/lib/localemu/some/test/file", "/target/file", read_only=False
            )
            result = volume_dir_mount.to_docker_sdk_parameters()
            get_volume.assert_called_once()
            assert result == (
                "/home/some-user/.cache/localemu/volume/some/test/file",
                {
                    "bind": "/target/file",
                    "mode": "rw",
                },
            )
            result = volume_dir_mount.to_str()
            assert result == "/home/some-user/.cache/localemu/volume/some/test/file:/target/file"
