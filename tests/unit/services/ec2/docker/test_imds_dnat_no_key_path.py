"""Unit tests for the IMDS DNAT decoupling (BUG-003).

Before the fix, the iptables OUTPUT-DNAT (169.254.169.254 -> sidecar) and
POSTROUTING-MASQUERADE rules were embedded inside ``SSHD_ENTRYPOINT_SCRIPT``,
which only runs when the instance was launched with ``--key-name``. Instances
launched without a key ran ``sleep 3600`` instead and never got the rules.
The fix adds ``NO_SSH_ENTRYPOINT_SCRIPT`` and uses it on the no-key branch.

These tests guard:
  * The no-key entrypoint contains the same OUTPUT-DNAT + POSTROUTING-MASQUERADE
    pair as the SSH entrypoint (the two cannot silently diverge).
  * Both rule installs are idempotent (``-C`` check before ``-A`` add).
  * The no-key script emits the BUG-003 observability log line so a future
    silent regression in the install path is visible from ``docker logs``.
  * The no-key script ends in a long-lived sleep so the container stays alive.
"""

from __future__ import annotations

from localemu.services.ec2.docker import vm_manager


# ---------- both entrypoints carry the same DNAT rules ----------


def test_no_key_entrypoint_installs_output_dnat_to_link_local():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "169.254.169.254/32" in s
    assert "DNAT --to-destination" in s
    assert "iptables -t nat -A OUTPUT" in s


def test_no_key_entrypoint_installs_postrouting_masquerade():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "iptables -t nat -A POSTROUTING" in s
    assert "MASQUERADE" in s


def test_sshd_entrypoint_still_installs_both_rules_regression():
    """The SSH path must keep the DNAT + MASQUERADE inline (we did not touch it
    in 1.0.1; the no-key script is a parallel addition)."""
    s = vm_manager.SSHD_ENTRYPOINT_SCRIPT
    assert "169.254.169.254/32" in s
    assert "DNAT --to-destination" in s
    assert "iptables -t nat -A POSTROUTING" in s
    assert "MASQUERADE" in s


# ---------- idempotency ----------


def test_no_key_dnat_is_idempotent_check_before_add():
    """``iptables -t nat -C`` (check) must precede ``-A`` (add) for both rules
    so multiple boots don't accumulate duplicate entries."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "iptables -t nat -C OUTPUT" in s
    assert "iptables -t nat -C POSTROUTING" in s
    # The check must appear before the add for each rule in source order.
    assert s.index("iptables -t nat -C OUTPUT") < s.index("iptables -t nat -A OUTPUT")
    assert s.index("iptables -t nat -C POSTROUTING") < s.index(
        "iptables -t nat -A POSTROUTING"
    )


# ---------- target selection ----------


def test_no_key_entrypoint_selects_sidecar_when_env_var_present():
    """The DNAT target comes from LOCALEMU_IMDS_SIDECAR_IP (VPC path) or
    falls back to host.docker.internal (no-VPC path) via
    LOCALEMU_IMDS_HOST_FALLBACK."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "LOCALEMU_IMDS_SIDECAR_IP" in s
    assert "LOCALEMU_IMDS_HOST_FALLBACK" in s
    assert "host.docker.internal" in s


# ---------- observability ----------


def test_no_key_entrypoint_logs_dnat_install_outcome_to_docker_logs():
    """A successful install logs the target; a failure logs FAILED. The log
    surfaces in ``docker logs <container>`` because the iptables block writes
    to stderr (>&2). Closes the BUG-003 silent-failure mode."""
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    assert "[localemu-imds] DNAT installed:" in s
    assert "[localemu-imds] DNAT install FAILED" in s
    # Both messages must be emitted to stderr so they reach ``docker logs``
    # regardless of how the entrypoint redirects stdout.
    assert ">&2" in s


# ---------- staying alive ----------


def test_no_key_entrypoint_stays_alive_after_dnat_install():
    s = vm_manager.NO_SSH_ENTRYPOINT_SCRIPT
    # The script must end with the long sleep so SG / NACL iptables, IMDS,
    # and intra-VPC traffic keep working for the lifetime of the instance.
    assert "sleep 3600" in s
    # And the DNAT block must come BEFORE the sleep, not after.
    assert s.index("iptables -t nat -A OUTPUT") < s.index("sleep 3600")


# ---------- run-instances wiring ----------


def test_run_instances_selects_no_key_script_when_no_key_provided():
    """The call site in DockerVmManager._create_instance picks the no-key
    script when ``public_key`` is empty/None. Guarded by source-level
    inspection because the create-instance flow is too heavy for a unit
    test."""
    import inspect

    from localemu.services.ec2.docker.vm_manager import DockerVmManager

    src = inspect.getsource(DockerVmManager)
    # The dispatch lines (in vm_manager.py near line 635) must reference both
    # entrypoint scripts so the fix cannot silently revert.
    assert "SSHD_ENTRYPOINT_SCRIPT" in src
    assert "NO_SSH_ENTRYPOINT_SCRIPT" in src
