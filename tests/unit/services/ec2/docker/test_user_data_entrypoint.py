"""Pin the user-data hook on both container entrypoints.

Both ``SSHD_ENTRYPOINT_SCRIPT`` (instances launched with ``--key-name``)
and ``NO_SSH_ENTRYPOINT_SCRIPT`` (the AWS-CLI default — no key) must
invoke ``/var/lib/localemu/user-data.sh`` on container start. Without
the no-key branch a regression would leave the most common user-launch
path silently broken at boot.

The script itself is self-guarded + self-logged by the translator
(:mod:`localemu.services.ec2.docker.user_data`) so the entrypoint just
invokes it and tolerates a non-zero exit.
"""
from __future__ import annotations

import re

from localemu.services.ec2.docker import vm_manager


_HOOK_SHAPE = re.compile(
    r"if \[ -x /var/lib/localemu/user-data\.sh \]; then\s*\n"
    r"\s*/var/lib/localemu/user-data\.sh \|\| true\s*\n"
    r"fi",
    re.MULTILINE,
)


def test_sshd_entrypoint_invokes_user_data_script():
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    assert _HOOK_SHAPE.search(s), (
        "SSHD_ENTRYPOINT_SCRIPT must invoke /var/lib/localemu/user-data.sh "
        "guarded by ``[ -x ... ]`` so a restarted container picks up the "
        "translated cloud-init script written at first boot."
    )


def test_no_ssh_entrypoint_invokes_user_data_script():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert _HOOK_SHAPE.search(s), (
        "NO_SSH_ENTRYPOINT_SCRIPT must invoke /var/lib/localemu/user-data.sh "
        "too — without it, AWS-CLI-default instances (no --key-name) "
        "would never run their user-data after the inline post-start "
        "exec window closes."
    )


def test_no_entrypoint_redirects_user_data_to_legacy_log():
    """Older code redirected the user-data run to ``/var/log/user-data.log``.

    The script now handles its own logging (cloud-init standard paths plus
    a symlink alias from /var/log/user-data.log), so any leftover
    ``> /var/log/user-data.log`` on the entrypoint side would double-redirect
    or clobber output. Make sure neither entrypoint does it.
    """
    for script in (vm_manager.SSHD_ENTRYPOINT_SCRIPT, vm_manager.NO_SSH_ENTRYPOINT_SCRIPT):
        assert "> /var/log/user-data.log" not in script, (
            "user-data hook on the entrypoint must NOT redirect to "
            "/var/log/user-data.log — the translated script owns logging."
        )


def test_entrypoint_does_not_chmod_user_data_inline():
    """Old code did ``chmod +x /var/lib/localemu/user-data.sh`` inside the
    entrypoint as a safety net. The translator now writes the file with
    +x already set, so the in-entrypoint chmod is dead weight.
    """
    for script in (vm_manager.SSHD_ENTRYPOINT_SCRIPT, vm_manager.NO_SSH_ENTRYPOINT_SCRIPT):
        assert "chmod +x /var/lib/localemu/user-data.sh" not in script, (
            "the entrypoint must not chmod the user-data script — the "
            "translator writes it with +x already set, and a stale "
            "chmod here would hide a file-write bug."
        )
