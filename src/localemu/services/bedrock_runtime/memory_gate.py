"""Pre-flight RAM check before LocalEmu attempts to pull/run a local model.

Deliberately simple: a static check against the machine's TOTAL physical
RAM against the model's declared tier (16/32/64GB, per
local_inference.py), done once, no live/available-memory inspection, no
safety margin. A dev machine's free RAM fluctuates by the minute depending
on what else is open - that's not a stable thing to gate on. The tier a
machine belongs to (16GB / 32GB / 64GB) doesn't change, so that's the
question this gate actually answers: "is this the right class of machine
for this model at all," not "is there a free gigabyte available right
this second."
"""
from __future__ import annotations

from localemu.aws.api import CommonServiceException


def total_memory_gb() -> float:
    import psutil

    return psutil.virtual_memory().total / (1024 ** 3)


def check_memory(model_id: str, required_tier_gb: int) -> None:
    """Raise CommonServiceException if the machine's total RAM is below
    the model's declared tier (16, 32, or 64GB)."""
    total = total_memory_gb()
    if total < required_tier_gb:
        raise CommonServiceException(
            code="ServiceQuotaExceededException",
            message=(
                f"{model_id!r} needs a {required_tier_gb}GB-tier machine to run "
                f"locally; this machine has {total:.1f}GB of RAM. Pick a smaller "
                "model, or set BEDROCK_BACKEND=synthetic to skip real inference "
                "for this call."
            ),
            status_code=400,
            sender_fault=True,
        )
