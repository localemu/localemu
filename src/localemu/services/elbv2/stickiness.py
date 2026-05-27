"""ELBv2 session stickiness — ``lb_cookie`` (ALB-generated AWSALB
cookie) implementation.

AWS contract (matched here):
  * Per target-group toggle: ``stickiness.enabled`` /
    ``stickiness.type=lb_cookie`` /
    ``stickiness.lb_cookie.duration_seconds``.
  * On first request from a client (no AWSALB cookie OR an expired
    one OR one that maps to a target that no longer exists): the LB
    picks a target via the normal load-balancing algorithm
    (round-robin here) and emits a ``Set-Cookie: AWSALB=<opaque>``
    response header. Path=``/``. ``Secure`` flag on HTTPS listeners.
  * On subsequent requests carrying that AWSALB cookie within the
    duration: the LB routes to the SAME target — even if it's
    currently marked unhealthy (per AWS spec, stickiness overrides
    health for already-pinned sessions).
  * Cookie payload is opaque; AWS's is encrypted. LocalEmu uses
    a deterministic ID that maps into a per-TG in-memory pin store.

Out of scope (tracked):
  * ``app_cookie`` (mirrors a user-app-issued cookie).
  * ``source_ip`` (NLB-only).
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger(__name__)

AWSALB_COOKIE = "AWSALB"
_DEFAULT_DURATION_SECONDS = 86400  # 1 day, AWS default


@dataclass
class StickinessConfig:
    """Parsed view of a target group's stickiness.* attributes."""
    enabled: bool = False
    cookie_duration: int = _DEFAULT_DURATION_SECONDS
    type: str = "lb_cookie"
    app_cookie_name: Optional[str] = None


@dataclass
class StickyPin:
    """One cookie-ID → target-key binding with an expiry timestamp."""
    target_key: str
    expires_at: float


@dataclass
class StickyStore:
    """Per-TargetGroup in-memory sticky-pin map."""
    pins: dict[str, StickyPin] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def lookup(self, cookie_id: str) -> Optional[StickyPin]:
        if not cookie_id:
            return None
        with self.lock:
            pin = self.pins.get(cookie_id)
            if pin is None:
                return None
            if pin.expires_at <= time.time():
                self.pins.pop(cookie_id, None)
                return None
            return pin

    def remember(self, cookie_id: str, target_key: str, duration: int) -> None:
        with self.lock:
            self.pins[cookie_id] = StickyPin(
                target_key=target_key,
                expires_at=time.time() + max(int(duration), 1),
            )

    def forget(self, cookie_id: str) -> None:
        with self.lock:
            self.pins.pop(cookie_id, None)


def parse_awsalb_cookie(cookie_header: str) -> Optional[str]:
    """Pull the ``AWSALB`` value out of an HTTP ``Cookie`` header.

    Returns None if not present. Handles multiple cookies / spaces
    around the ``=`` (the standard ``cookie`` module would also work
    but it's heavier).
    """
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0].strip() == AWSALB_COOKIE:
            v = kv[1].strip()
            return v or None
    return None


def build_set_cookie(cookie_id: str, duration: int, *, secure: bool) -> str:
    """Build a ``Set-Cookie`` header value matching the AWS shape
    (Path=/, Max-Age, HttpOnly, optional Secure on HTTPS)."""
    parts = [
        f"{AWSALB_COOKIE}={cookie_id}",
        "Path=/",
        f"Max-Age={max(int(duration), 1)}",
        "HttpOnly",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def fresh_cookie_id() -> str:
    """Opaque 24-byte URL-safe ID — enough entropy that a guess-and-
    hijack is impractical without changing the threat model of the
    local emulator."""
    return secrets.token_urlsafe(18)


def parse_target_group_arn(arn: str) -> tuple[str, str]:
    """Extract (account_id, region) from a TG ARN.
    Format: ``arn:aws:elasticloadbalancing:<region>:<account>:targetgroup/<name>/<id>``.
    Returns ("", "") on parse failure (caller treats as no stickiness).
    """
    try:
        parts = arn.split(":", 5)
        # parts = ["arn", "aws", "elasticloadbalancing", region, account, "targetgroup/..."]
        if len(parts) >= 5:
            return parts[4], parts[3]
    except Exception:
        pass
    return "", ""


def read_stickiness_config(tg_arn: str) -> StickinessConfig:
    """Read the live stickiness.* attributes off moto's TargetGroup.

    Returns a StickinessConfig with ``enabled=False`` on any failure
    (missing TG, missing attrs, unparseable ARN) — the proxy then
    falls through to its non-sticky round-robin path.
    """
    account, region = parse_target_group_arn(tg_arn)
    if not account or not region:
        return StickinessConfig()
    try:
        import moto.backends as moto_backends
        backend = moto_backends.get_backend("elbv2")[account][region]
    except Exception:
        return StickinessConfig()
    # moto stores TGs in ``backend.target_groups`` keyed by ARN.
    tg = getattr(backend, "target_groups", {}).get(tg_arn)
    if tg is None:
        return StickinessConfig()
    attrs = getattr(tg, "attributes", {}) or {}
    enabled = (attrs.get("stickiness.enabled", "false").lower() == "true")
    type_ = attrs.get("stickiness.type", "lb_cookie")
    try:
        duration = int(
            attrs.get("stickiness.lb_cookie.duration_seconds",
                       _DEFAULT_DURATION_SECONDS),
        )
    except (TypeError, ValueError):
        duration = _DEFAULT_DURATION_SECONDS
    return StickinessConfig(
        enabled=enabled,
        cookie_duration=duration,
        type=type_,
        app_cookie_name=attrs.get("stickiness.app_cookie.cookie_name"),
    )
