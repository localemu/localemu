"""Per-service import handlers and their registry.

Each handler takes a :class:`Resource` and the current :class:`ImportMode`
and either creates, skips, or replaces the resource on the target. The
registry is keyed by ``(service, resource_type)`` and populated via the
:func:`register_handler` decorator, so adding support for a new resource
type is a single-file change — no giant dispatch ``if`` chains.

Handler return contract (enforced by :class:`ImportRunner`):

* ``("applied", resource_id, None)`` — created successfully.
* ``("skipped", resource_id, reason)`` — intentionally not created.
* ``("failed", resource_id, error_message)`` — create attempted and failed.

Handlers should **never** silently swallow ``AlreadyExists``-style errors
by substring matching. Use ``ClientError.response["Error"]["Code"]`` so we
don't mis-classify unrelated errors as "already exists" (a v1 bug).
"""

from __future__ import annotations

from typing import Callable

from localemu.export.importer.clients import ClientFactory
from localemu.export.ir import Resource

# Type alias for a handler callable. Kept as a plain name to avoid a
# circular import with ``replay`` (which defines ``ImportMode``).
Handler = Callable[[Resource, ClientFactory, object, bool], tuple[str, str, str | None]]

HANDLERS: dict[tuple[str, str], Handler] = {}


def register_handler(service: str, resource_type: str) -> Callable[[Handler], Handler]:
    """Decorator that registers ``func`` as the handler for ``(service, resource_type)``."""

    def decorator(func: Handler) -> Handler:
        key = (service, resource_type)
        if key in HANDLERS:
            raise ValueError(f"handler already registered for {key}")
        HANDLERS[key] = func
        return func

    return decorator


# Import side-effect: each submodule registers its handlers on import.
# Kept at the bottom so ``HANDLERS`` / ``register_handler`` are defined
# before the submodules try to use them.
from localemu.export.importer.handlers import (  # noqa: E402,F401
    dynamodb,
    iam,
    lambda_,
    s3,
    sqs,
)

__all__ = ["HANDLERS", "Handler", "register_handler"]
