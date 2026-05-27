"""Failing test for the ``awsemu ssm start-session`` shortcut.

Before the fix, the CLI shortcut at ``localemu.cli.awsemu`` hardcoded
``docker exec -it <container> /bin/bash``. Alpine (the default
LocalEmu EC2 AMI) ships no bash, so the exec failed with::

    OCI runtime exec failed: exec failed: unable to start container
    process: exec: "/bin/bash": stat /bin/bash: no such file or
    directory

After the fix, the shortcut runs a small POSIX sh wrapper that
chooses bash when available and falls back to sh. This works on
alpine AND on ubuntu / amazon-linux without changing the call.
"""
from __future__ import annotations

import sys
from unittest import mock

import pytest

from localemu.cli import awsemu as awsemu_cli


@pytest.fixture(autouse=True)
def _stub_argv(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["awsemu", "ssm", "start-session", "--target", "i-deadbeef"],
    )


def _docker_exec_call(exe_mock):
    """Find the ``execvp("docker", [...])`` call. In real flow execvp
    replaces the process, but mocked it doesn't, so subsequent
    ``execvp("aws", ...)`` calls also land in call_args_list."""
    for call in exe_mock.call_args_list:
        prog = call.args[0]
        argv = call.args[1]
        if prog == "docker" and argv[:2] == ["docker", "exec"]:
            return argv
    return None


class TestSsmStartSessionShellSelection:
    def test_shortcut_actually_fires_for_ssm_start_session(self):
        """Guard: the start-session shortcut must intercept and call
        ``docker exec``. If this fails, the user's ``awsemu ssm
        start-session`` is going straight to ``aws`` and the whole
        feature is broken."""
        with mock.patch.object(awsemu_cli.os, "execvp") as exe:
            try:
                awsemu_cli.main()
            except SystemExit:
                pass
        argv = _docker_exec_call(exe)
        assert argv is not None, (
            f"shortcut never called ``docker exec``: "
            f"calls={[c.args for c in exe.call_args_list]}"
        )

    def test_does_not_hardcode_bash(self):
        """The exec call must not assume bash exists. On alpine
        containers (default AMI) this would fail with ``/bin/bash:
        no such file or directory``."""
        with mock.patch.object(awsemu_cli.os, "execvp") as exe:
            try:
                awsemu_cli.main()
            except SystemExit:
                pass
        argv = _docker_exec_call(exe)
        assert argv is not None, "shortcut did not call docker exec"
        # The argv passed to docker must not be a bare ``/bin/bash`` —
        # that hardcodes a shell that minimal images don't ship.
        assert "/bin/bash" not in argv, (
            f"shortcut still hardcodes /bin/bash, breaks alpine: {argv}"
        )

    def test_runs_via_posix_sh_wrapper_with_bash_fallback(self):
        """The shortcut must invoke a POSIX-sh one-liner that prefers
        bash when present and falls back to sh. Same pattern as
        session_ws_server's WebSocket PTY shell."""
        with mock.patch.object(awsemu_cli.os, "execvp") as exe:
            try:
                awsemu_cli.main()
            except SystemExit:
                pass
        argv = _docker_exec_call(exe)
        assert argv is not None, "shortcut did not call docker exec"
        # docker exec -it <container> /bin/sh -c "<wrapper>"
        assert argv[:3] == ["docker", "exec", "-it"], (
            f"unexpected exec prefix: {argv[:5]}"
        )
        assert argv[3] == "localemu-ec2-i-deadbeef", (
            f"wrong container name: {argv[3]}"
        )
        assert argv[4] == "/bin/sh" and argv[5] == "-c", (
            f"shortcut must drive /bin/sh -c <wrapper>, got: {argv[4:6]}"
        )
        wrapper = argv[6]
        assert "command -v bash" in wrapper, (
            f"wrapper must probe for bash before invoking it: {wrapper!r}"
        )
        assert "exec sh" in wrapper, (
            f"wrapper must fall back to sh on bash-less images: {wrapper!r}"
        )
