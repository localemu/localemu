"""Lambda runtime binary - bundled inside the LocalEmu package.

The init binary is a Go executable that implements the AWS Lambda Runtime
Interface Emulator. It's pre-built for arm64 and x86_64 and shipped inside
the pip package. No downloads needed.
"""

import logging
import os
import shutil
import stat
from functools import cache
from pathlib import Path

from localemu.utils.platform import get_arch

LOG = logging.getLogger(__name__)

# Location of the bundled binaries (inside the installed package)
_BUNDLED_DIR = Path(__file__).parent.parent.parent / "runtime" / "lambda-init"


def _get_arch() -> str:
    arch = get_arch()
    return "x86_64" if arch == "amd64" else arch


def _normalize_arch(arch: str | None) -> str:
    """Map a caller-supplied arch label to the bundled-directory name.

    Accepts the names used by Lambda's ``Architectures`` field
    (``x86_64``, ``arm64``) as well as Docker's platform strings
    (``amd64``, ``linux/amd64``, ``aarch64``). Falls back to the
    host arch.
    """
    if not arch:
        return _get_arch()
    arch = arch.lower().rsplit("/", 1)[-1]  # strip "linux/" prefix
    if arch in ("amd64", "x86_64"):
        return "x86_64"
    if arch in ("arm64", "aarch64"):
        return "arm64"
    return _get_arch()


def _get_bundled_init_path(arch: str | None = None) -> Path:
    """Return the path to the bundled init binary for ``arch`` (default: host)."""
    return _BUNDLED_DIR / _normalize_arch(arch) / "init"


def _ensure_installed(target_dir: Path, arch: str | None = None) -> Path:
    """Ensure the Lambda runtime init binary for ``arch`` is installed.

    Copies the arch-specific binary from the bundled location if not
    already present. The returned path is the per-arch subdirectory,
    suitable for passing to ``docker cp`` (it contains ``var/rapid/init``
    at the expected location inside the archive).
    """
    resolved_arch = _normalize_arch(arch)
    init_target = target_dir / resolved_arch / "var" / "rapid" / "init"

    if init_target.exists():
        return target_dir / resolved_arch

    # Copy from bundled
    bundled = _get_bundled_init_path(resolved_arch)
    if not bundled.exists():
        raise FileNotFoundError(
            f"Lambda runtime binary not found at {bundled}. "
            f"This is a packaging error - please reinstall localemu."
        )

    init_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(bundled), str(init_target))

    # Ensure executable
    st = os.stat(str(init_target))
    os.chmod(str(init_target), mode=st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    LOG.debug("Lambda runtime binary installed: %s", init_target)
    return target_dir / resolved_arch


@cache
def get_runtime_client_path(arch: str | None = None) -> Path:
    """Return the directory containing the Lambda runtime init binary.

    ``arch`` is the Lambda function's architecture (``x86_64`` or
    ``arm64``). Passing the function's architecture is REQUIRED for
    correctness when the host's architecture differs from the
    container's — e.g. on Apple Silicon running a linux/amd64
    container-image Lambda via Rosetta, the host-arch arm64 binary
    would fail with "exec format error" and the runtime would time
    out during startup. Defaults to host arch for zip Lambdas where
    LocalEmu has historically always built images natively.
    """
    from localemu import config

    target_dir = Path(config.dirs.static_libs) / "lambda-runtime" / "v1"
    return _ensure_installed(target_dir, arch)
