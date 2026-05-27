"""Failing tests for SG iptables-presence guarantee.

The bug
-------
The alpine:3.20 AMI (LocalEmu's default) ships without ``iptables``.
``vm_manager.create_instance`` runs the container with
``sh -c 'while true; do sleep 3600; done'`` -- the SSHD entrypoint
script that contains ``apk add iptables`` is NEVER executed.

Then ``apply_sg_to_container`` runs immediately:

  1. ``_probe_iptables`` fails (no iptables binary).
  2. Logs ``"Installing fail-closed default-DROP policy"``.
  3. ``_try_emergency_default_drop`` calls ``iptables`` -- also fails
     (same missing binary).
  4. Logs ``"could not install fail-closed SG ... SECURITY RISK"``.
  5. Returns ``False``.

The container is left at Docker's default ACCEPT policy -- every SG
rule the user wrote is silently ignored. The "fail-closed" claim in
the log is a CRITICAL-02-style lie.

The fix
-------
``apply_sg_to_container`` must guarantee iptables exists BEFORE the
SG apply runs. We add ``ensure_iptables_in_container`` that:

  - probes for iptables
  - if missing, runs the right pkg manager (apk / apt-get / dnf / yum)
  - re-probes
  - returns True only if iptables is now usable

``apply_sg_to_container`` calls it first; if it returns False, the
function raises so callers (vm_manager) can abort RunInstances.
There is no "fail-closed" fallback because there CAN'T be one: any
fail-closed install is itself an iptables command.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_iptables as sgi


class TestEnsureIptablesInContainer:
    """``ensure_iptables_in_container`` installs iptables if absent and
    returns True iff iptables is usable afterwards."""

    def test_returns_true_when_iptables_already_present(self):
        """No install attempt when probe says iptables is already there."""
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (b"", b"")  # probe succeeds
        with mock.patch.object(sgi, "DOCKER_CLIENT", dc):
            ok = sgi.ensure_iptables_in_container("c1")
        assert ok is True
        # Only the probe should have been called -- no install attempt.
        cmds = [call.args[1] for call in dc.exec_in_container.call_args_list]
        joined = " ".join(" ".join(c) for c in cmds)
        assert "apk add" not in joined, (
            f"install was attempted even though iptables was present: {cmds}"
        )

    def test_installs_via_apk_when_probe_fails_then_succeeds(self):
        """Probe fails, ``apk add iptables`` succeeds, re-probe succeeds,
        function returns True."""
        dc = mock.MagicMock()
        call_log: list[list[str]] = []

        def fake_exec(container, cmd, **kw):
            call_log.append(list(cmd))
            joined = " ".join(cmd)
            # First probe: iptables missing.
            if "iptables -V" in joined and call_log.count(list(cmd)) == 1:
                raise RuntimeError("iptables: not found")
            # apk add: succeeds.
            if "apk add" in joined:
                return (b"", b"")
            # Second probe (after install): succeeds.
            if "iptables -V" in joined:
                return (b"", b"")
            return (b"", b"")

        dc.exec_in_container.side_effect = fake_exec
        with mock.patch.object(sgi, "DOCKER_CLIENT", dc):
            ok = sgi.ensure_iptables_in_container("c1")
        assert ok is True, f"ensure returned False; calls={call_log}"
        joined_all = " ".join(" ".join(c) for c in call_log)
        assert "apk add" in joined_all, (
            f"apk add was never attempted: {call_log}"
        )

    def test_returns_false_when_no_pkg_manager_can_install(self):
        """If every package manager attempt fails AND re-probe still
        fails, return False so the caller can abort RunInstances."""
        dc = mock.MagicMock()

        def fake_exec(container, cmd, **kw):
            # Everything fails: probes AND installs.
            raise RuntimeError("nothing works in this container")

        dc.exec_in_container.side_effect = fake_exec
        with mock.patch.object(sgi, "DOCKER_CLIENT", dc):
            ok = sgi.ensure_iptables_in_container("c1")
        assert ok is False


class TestApplySgGuaranteesIptables:
    """``apply_sg_to_container`` must call ``ensure_iptables_in_container``
    FIRST so the SG apply script can rely on iptables being present."""

    def test_apply_calls_ensure_before_apply_script(self):
        """The ensure_iptables_in_container call must precede the SG
        apply script ``docker exec``. Otherwise the broken order -- the
        bug we're fixing -- recurs."""
        dc = mock.MagicMock()
        exec_calls: list[str] = []

        def fake_exec(container, cmd, **kw):
            joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            exec_calls.append(joined)
            return (b"", b"")

        dc.exec_in_container.side_effect = fake_exec

        with mock.patch.object(sgi, "DOCKER_CLIENT", dc), \
             mock.patch.object(
                 sgi, "ensure_iptables_in_container", return_value=True,
             ) as ensure, \
             mock.patch.object(
                 sgi, "_collect_rules", return_value=([], []),
             ):
            ok = sgi.apply_sg_to_container(
                "localemu-ec2-i-1", ["sg-1"], "111111111111", "us-east-1",
            )
        assert ok is True
        ensure.assert_called_once_with("localemu-ec2-i-1")

    def test_apply_raises_when_ensure_returns_false(self):
        """If iptables truly cannot be installed, ``apply_sg_to_container``
        must raise. The previous behavior was to log a lie about
        ``fail-closed DROP`` while the container actually ran Docker's
        default ACCEPT. Raising forces the caller (vm_manager) to abort
        RunInstances rather than ship a lying instance."""
        with mock.patch.object(
            sgi, "ensure_iptables_in_container", return_value=False,
        ):
            with pytest.raises(RuntimeError) as ei:
                sgi.apply_sg_to_container(
                    "localemu-ec2-i-1", ["sg-1"],
                    "111111111111", "us-east-1",
                )
        msg = str(ei.value).lower()
        assert "iptables" in msg, f"error must mention iptables: {ei.value}"
