"""Cognito User Pool message buffer and sender routing.

LocalEmu does not send real emails or SMS. When a Cognito operation
generates a code-bearing message (SignUp confirmation, ForgotPassword
reset, VerifyUserAttribute, AdminCreateUser temp password, ...), this
module either :

1. **Routes through a configured sender Lambda** (``CustomEmailSender``
   or ``CustomSMSSender``) : the trigger Lambda receives the encrypted
   code blob and is responsible for delivering it. LocalEmu does not
   perform real KMS-AES encryption ; the "encrypted" code is a base64
   placeholder that the sender Lambda can decode with
   ``base64.b64decode``. This shape is enough for tutorials that wire
   up the sender pattern, and the placeholder is documented in the
   trigger event payload.

2. **Stores the message in an in-memory buffer**, keyed by
   ``(account_id, region, pool_id, username)``. The dashboard exposes
   the buffer at ``GET /_localemu/api/cognito-messages/<pool>/<user>``
   so tests and tutorials can read the message body and the plain code
   that would have been sent. AWS never returns the code over the
   wire ; LocalEmu surfaces it ONLY through this dashboard endpoint,
   loopback-restricted like the rest of the dashboard.

The buffer is process-local and not persisted ; LocalEmu treats
Cognito user-pool state as ephemeral unless ``PERSISTENCE=1``, and
restoring messages across a restart is out of scope (Cognito
messages are out-of-band anyway).
"""
from __future__ import annotations

import base64
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger(__name__)


@dataclass
class CognitoMessage:
    """One delivered message. ``code_plain`` is the unencrypted code so
    tests can read it ; Cognito hands the user only the encrypted
    blob and emails the plain code via SES."""
    trigger_source: str
    delivery_medium: str          # "EMAIL" | "SMS" | "EMAIL_AND_SMS"
    code_plain: str
    code_encrypted_b64: str
    sms_message: str = ""
    email_message: str = ""
    email_subject: str = ""
    sent_via_sender_lambda: bool = False
    timestamp: float = field(default_factory=time.time)


# (account_id, region, pool_id, username) -> list[CognitoMessage]
_BUFFER: dict[tuple[str, str, str, str], list[CognitoMessage]] = {}
_LOCK = threading.Lock()


def _key(account_id: str, region: str, pool_id: str, username: str):
    return (account_id, region, pool_id, username)


def _fake_encrypt(code_plain: str) -> str:
    """Stand-in for the KMS-AES encryption AWS performs. On AWS, Cognito encrypts the
    code with the pool's KMS key before handing it to the sender
    Lambda ; LocalEmu uses a base64 placeholder. Sender tutorials can
    decode this directly with ``base64.b64decode`` ; the plain code is
    also visible through the dashboard endpoint."""
    return base64.b64encode(code_plain.encode("utf-8")).decode("ascii")


def store_message(
    *,
    account_id: str,
    region: str,
    pool_id: str,
    username: str,
    trigger_source: str,
    delivery_medium: str,
    code_plain: str,
    sms_message: str = "",
    email_message: str = "",
    email_subject: str = "",
    sent_via_sender_lambda: bool = False,
) -> CognitoMessage:
    """Append a message to the user's buffer ; return the stored entry."""
    msg = CognitoMessage(
        trigger_source=trigger_source,
        delivery_medium=delivery_medium,
        code_plain=code_plain,
        code_encrypted_b64=_fake_encrypt(code_plain),
        sms_message=sms_message,
        email_message=email_message,
        email_subject=email_subject,
        sent_via_sender_lambda=sent_via_sender_lambda,
    )
    with _LOCK:
        _BUFFER.setdefault(_key(account_id, region, pool_id, username), []).append(msg)
    return msg


def get_messages(
    account_id: str, region: str, pool_id: str, username: str,
) -> list[CognitoMessage]:
    """Return a snapshot of messages stored for the user (most-recent last)."""
    with _LOCK:
        return list(_BUFFER.get(_key(account_id, region, pool_id, username), []))


def clear(
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    pool_id: Optional[str] = None,
    username: Optional[str] = None,
) -> None:
    """Drop messages. With no args drops everything (used by tests).
    With any subset, drops matching keys."""
    with _LOCK:
        if account_id is None and region is None and pool_id is None and username is None:
            _BUFFER.clear()
            return
        for k in list(_BUFFER):
            if account_id is not None and k[0] != account_id:
                continue
            if region is not None and k[1] != region:
                continue
            if pool_id is not None and k[2] != pool_id:
                continue
            if username is not None and k[3] != username:
                continue
            _BUFFER.pop(k, None)


def send_code(
    *,
    account_id: str,
    region: str,
    pool_id: str,
    username: str,
    trigger_source: str,
    delivery_medium: str,
    code_plain: str,
    override_sms_message: str = "",
    override_email_message: str = "",
    override_email_subject: str = "",
) -> CognitoMessage:
    """Top-level entry point used by the cognito provider after a code
    has been generated by moto (SignUp, ForgotPassword, ...).

    Routes through ``CustomEmailSender`` / ``CustomSMSSender`` if the
    pool has one configured for the matching medium ; otherwise stores
    the message in the in-memory buffer. Either way the message ends
    up in the buffer for tests to read.

    ``override_*`` arguments are the response of the ``CustomMessage``
    trigger (if it fired). When empty, the buffered message uses
    Cognito-default text (LocalEmu does not synthesise the AWS default
    message templates ; an empty body still pins that the code-send
    fired, which is what matters for end-to-end tests).
    """
    sms_message = override_sms_message
    email_message = override_email_message
    email_subject = override_email_subject

    sent_via_sender_lambda = False
    # Sender Lambdas, if configured, replace the email or SMS send. The
    # sender receives the encrypted code blob and the user attributes
    # and is responsible for the wire delivery. We invoke best-effort ;
    # a failing sender does not break the surrounding op (the buffer
    # still records what would have gone out).
    try:
        from .triggers import get_lambda_config, _invoke, _build_event

        cfg = get_lambda_config(account_id, region, pool_id)

        if delivery_medium in ("EMAIL", "EMAIL_AND_SMS"):
            sender = cfg.get("CustomEmailSender")
            arn = sender.get("LambdaArn") if isinstance(sender, dict) else ""
            if arn:
                event = _build_event(
                    region=region,
                    pool_id=pool_id,
                    username=username,
                    client_id="",
                    trigger_source=f"CustomEmailSender_{trigger_source.split('_')[-1]}"
                                   if "_" in trigger_source else "CustomEmailSender",
                    account_id=account_id,
                    request_extra={
                        "type": "customEmailSenderRequestV1",
                        "code": _fake_encrypt(code_plain),
                        "clientMetadata": {},
                    },
                )
                try:
                    _invoke(region, arn, event)
                    sent_via_sender_lambda = True
                except Exception:
                    LOG.warning(
                        "CustomEmailSender invocation failed ; "
                        "message stored in buffer instead", exc_info=True,
                    )

        if delivery_medium in ("SMS", "EMAIL_AND_SMS"):
            sender = cfg.get("CustomSMSSender")
            arn = sender.get("LambdaArn") if isinstance(sender, dict) else ""
            if arn:
                event = _build_event(
                    region=region,
                    pool_id=pool_id,
                    username=username,
                    client_id="",
                    trigger_source=f"CustomSMSSender_{trigger_source.split('_')[-1]}"
                                   if "_" in trigger_source else "CustomSMSSender",
                    account_id=account_id,
                    request_extra={
                        "type": "customSMSSenderRequestV1",
                        "code": _fake_encrypt(code_plain),
                        "clientMetadata": {},
                    },
                )
                try:
                    _invoke(region, arn, event)
                    sent_via_sender_lambda = True
                except Exception:
                    LOG.warning(
                        "CustomSMSSender invocation failed ; "
                        "message stored in buffer instead", exc_info=True,
                    )
    except Exception:
        LOG.debug("send_code: sender routing failed", exc_info=True)

    # Whether or not a sender Lambda ran, store the message so tests can
    # read it. ``sent_via_sender_lambda`` lets a test assert on the
    # delivery path.
    return store_message(
        account_id=account_id, region=region, pool_id=pool_id, username=username,
        trigger_source=trigger_source,
        delivery_medium=delivery_medium,
        code_plain=code_plain,
        sms_message=sms_message,
        email_message=email_message,
        email_subject=email_subject,
        sent_via_sender_lambda=sent_via_sender_lambda,
    )
