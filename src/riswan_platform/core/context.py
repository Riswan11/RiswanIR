"""Trusted execution context and scoped binding for application adapters."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from .exceptions import ContextRequiredError
from .identifiers import require_label

ActorType = Literal["human", "service", "integration", "agent"]


@dataclass(frozen=True, slots=True)
class PlatformContext:
    tenant_id: UUID
    actor_id: str
    actor_type: ActorType
    product_id: str
    request_id: str
    correlation_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID) or not self.tenant_id.int:
            raise ValueError("A non-nil tenant UUID is required.")
        if self.actor_type not in ("human", "service", "integration", "agent"):
            raise ValueError("Unsupported actor type.")
        for value in (self.actor_id, self.product_id, self.request_id, self.correlation_id):
            require_label(value)


_context: ContextVar[PlatformContext | None] = ContextVar("platform_context", default=None)


@contextmanager
def bind_context(context: PlatformContext) -> Iterator[PlatformContext]:
    if not isinstance(context, PlatformContext):
        raise ContextRequiredError("A trusted execution context is required.")
    current = _context.get()
    if current is not None and current != context:
        raise ContextRequiredError("An active execution context cannot be replaced.")
    token = _context.set(context)
    try:
        yield context
    finally:
        _context.reset(token)


def require_context() -> PlatformContext:
    context = _context.get()
    if context is None:
        raise ContextRequiredError("A trusted execution context is required.")
    return context
