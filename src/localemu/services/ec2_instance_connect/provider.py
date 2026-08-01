"""EC2 Instance Connect: ``SendSSHPublicKey`` end-to-end.

Real AWS's flow :

1. Caller generates an ephemeral SSH keypair.
2. Caller invokes ``aws ec2-instance-connect send-ssh-public-key
   --instance-id <id> --instance-os-user <user> --ssh-public-key
   file://key.pub``.
3. AWS pushes the public key to the target instance ; on the instance,
   the ``eic_run_authorized_keys`` script (part of the
   ``aws-ec2-instance-connect-config`` package) resolves it from IMDS
   and returns it to ``sshd`` via ``AuthorizedKeysCommand``.
4. The key is valid on the instance for **60 seconds**. After that
   window ``sshd`` won't accept authentication with it any more.

LocalEmu's implementation (simpler, achieves the same user-visible
contract) :

* We append the key to ``~<os_user>/.ssh/authorized_keys`` directly,
  wrapped between two marker comments that carry an epoch expiry
  timestamp :

  ::

      # localemu-eic BEGIN 1720000060
      ssh-ed25519 AAAA...
      # localemu-eic END 1720000060

* A ``threading.Timer(60, _cleanup)`` strips both marker lines and the
  key line 60 seconds later. Concurrent EIC pushes for the same or
  different users are safe because each cleanup only removes the
  markers matching its own timestamp.

* Root gets a copy too, matching how real Amazon-Linux ships (root
  SSH is enabled with the same key material as the OS's default user).

Not implemented on purpose : the ``AuthorizedKeysCommand`` +
``eic_run_authorized_keys`` script + IMDS-delivered signed keys chain.
It buys nothing in a local emulator ; the direct-write path is
deterministic and gives the same ``ssh -i <key>`` round-trip AWS ships.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from base64 import b64encode
from typing import Any

from localemu.aws.api import CommonServiceException, RequestContext, handler

LOG = logging.getLogger(__name__)


# Real AWS EIC ephemeral-key lifetime, in seconds.
_TTL_SECONDS = 60


class Ec2InstanceConnectProvider:
    """AWS Service provider for ``ec2-instance-connect``.

    Only ``SendSSHPublicKey`` is implemented ; the (rare and
    console-oriented) ``SendSerialConsoleSSHPublicKey`` returns an
    AWS-shaped "not enabled" error so callers still get a well-typed
    response instead of a LocalEmu ``InternalFailure``.
    """

    service: str = "ec2-instance-connect"

    def __init__(self) -> None:
        # active timers keyed by (container, os_user, expires_at) so the
        # provider can be cleanly shut down (mostly matters in tests).
        self._pending_cleanups: list[threading.Timer] = []
        self._cleanups_lock = threading.Lock()

    # ------------------------------------------------------------------
    # SendSSHPublicKey
    # ------------------------------------------------------------------

    @handler("SendSSHPublicKey", expand=False)
    def send_ssh_public_key(
        self, context: RequestContext, request: dict = None, **kwargs,
    ) -> dict[str, Any]:
        payload = _merge_payload(request, kwargs)
        instance_id = (
            payload.get("InstanceId") or payload.get("instance_id") or ""
        ).strip()
        os_user = (
            payload.get("InstanceOSUser")
            or payload.get("instance_os_user") or ""
        ).strip()
        ssh_public_key = (
            payload.get("SSHPublicKey")
            or payload.get("ssh_public_key") or ""
        ).strip()

        if not instance_id:
            raise CommonServiceException(
                code="ValidationException",
                message="InstanceId is required.",
                status_code=400,
                sender_fault=True,
            )
        if not os_user:
            raise CommonServiceException(
                code="ValidationException",
                message="InstanceOSUser is required.",
                status_code=400,
                sender_fault=True,
            )
        if not ssh_public_key:
            raise CommonServiceException(
                code="ValidationException",
                message="SSHPublicKey is required.",
                status_code=400,
                sender_fault=True,
            )

        container = _resolve_container(context, instance_id)
        if container is None:
            raise CommonServiceException(
                code="EC2InstanceNotFoundException",
                message=(
                    f"Instance {instance_id} not found in LocalEmu."
                ),
                status_code=400,
                sender_fault=True,
            )

        expires_at = int(time.time()) + _TTL_SECONDS
        self._install_ephemeral_key(
            container=container,
            os_user=os_user,
            key_material=ssh_public_key,
            expires_at=expires_at,
        )
        self._schedule_cleanup(
            container=container,
            os_user=os_user,
            expires_at=expires_at,
        )

        return {
            "RequestId": str(uuid.uuid4()),
            "Success": True,
        }

    # ------------------------------------------------------------------
    # SendSerialConsoleSSHPublicKey: AWS-shaped "not supported" answer.
    # ------------------------------------------------------------------

    @handler("SendSerialConsoleSSHPublicKey", expand=False)
    def send_serial_console_ssh_public_key(
        self, context: RequestContext, request: dict = None, **kwargs,
    ) -> dict[str, Any]:
        raise CommonServiceException(
            code="SerialConsoleAccessDisabledException",
            message=(
                "Serial console access is not available in LocalEmu. "
                "Use SendSSHPublicKey against port 22 instead."
            ),
            status_code=400,
            sender_fault=True,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _install_ephemeral_key(
        self,
        *,
        container: str,
        os_user: str,
        key_material: str,
        expires_at: int,
    ) -> None:
        """Append the key to ~<os_user>/.ssh/authorized_keys AND
        /root/.ssh/authorized_keys, wrapped in expiry-tagged markers.

        The base64 hop avoids any shell interpretation of the key's
        comment field (defence against a crafted key containing shell
        metacharacters).
        """
        from localemu.utils.docker_utils import DOCKER_CLIENT

        block = (
            f"# localemu-eic BEGIN {expires_at}\n"
            f"{key_material}\n"
            f"# localemu-eic END {expires_at}\n"
        )
        block_b64 = b64encode(block.encode()).decode()

        for user, home in _target_homes(os_user):
            script = (
                f"mkdir -p {home}/.ssh "
                f"&& chmod 700 {home}/.ssh "
                f"&& echo {block_b64} | base64 -d "
                f">> {home}/.ssh/authorized_keys "
                f"&& chmod 600 {home}/.ssh/authorized_keys "
                f"&& chown -R {user}:{user} {home}/.ssh 2>/dev/null || true"
            )
            try:
                DOCKER_CLIENT.exec_in_container(
                    container, ["sh", "-c", script],
                )
            except Exception as e:
                LOG.info(
                    "EIC: could not install key for %s in %s: %s",
                    user, container, e,
                )

    def _schedule_cleanup(
        self,
        *,
        container: str,
        os_user: str,
        expires_at: int,
    ) -> None:
        """Fire a one-shot Timer that strips the expired block from
        every home we wrote to. Idempotent : re-runs are harmless.
        """
        def _run() -> None:
            from localemu.utils.docker_utils import DOCKER_CLIENT
            marker = f"localemu-eic BEGIN {expires_at}"
            marker_end = f"localemu-eic END {expires_at}"
            for _, home in _target_homes(os_user):
                script = (
                    f"f={home}/.ssh/authorized_keys ; "
                    f"[ -f \"$f\" ] || exit 0 ; "
                    # awk : drop lines from BEGIN marker through END marker.
                    f"awk 'BEGIN{{skip=0}} "
                    f"/{marker}/ {{skip=1; next}} "
                    f"/{marker_end}/ {{skip=0; next}} "
                    f"skip==0' \"$f\" > \"$f.new\" "
                    f"&& mv \"$f.new\" \"$f\" "
                    f"&& chmod 600 \"$f\""
                )
                try:
                    DOCKER_CLIENT.exec_in_container(
                        container, ["sh", "-c", script],
                    )
                except Exception:
                    LOG.debug(
                        "EIC cleanup swallowed error in %s",
                        container, exc_info=True,
                    )

        timer = threading.Timer(_TTL_SECONDS, _run)
        timer.daemon = True
        timer.start()
        with self._cleanups_lock:
            self._pending_cleanups.append(timer)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _merge_payload(request: dict | None, kwargs: dict) -> dict:
    """The handler dispatch layer may pass parameters either as a
    request dict (``expand=False``) or as expanded kwargs. Accept both.
    """
    payload: dict[str, Any] = {}
    if isinstance(request, dict):
        payload.update(request)
    payload.update(kwargs)
    return payload


def _resolve_container(
    context: RequestContext, instance_id: str,
) -> str | None:
    """Return the Docker container name for the target instance, or
    ``None`` when it is not backed by a running LocalEmu container.
    """
    try:
        from localemu.services.ec2.docker.vm_manager import (
            get_container_for_instance,
        )
    except Exception:
        return None
    try:
        return get_container_for_instance(
            context.account_id, context.region, instance_id,
        )
    except Exception:
        return None


def _target_homes(os_user: str) -> list[tuple[str, str]]:
    """Return the ``(user, home)`` pairs to inject the key into.

    * The caller-requested ``os_user`` in its own home. Skipped when
      the user is literally ``root`` (root's home is a separate branch
      below so we do not write it twice).
    * ``root`` in ``/root``. Matches real Amazon-Linux where root SSH
      is enabled with the same material as the OS's default user, and
      keeps back-compat with any script that SSH'd as root.
    """
    homes: list[tuple[str, str]] = []
    if os_user and os_user != "root":
        homes.append((os_user, f"/home/{os_user}"))
    homes.append(("root", "/root"))
    return homes
