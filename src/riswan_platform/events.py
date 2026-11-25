"""Versioned, bounded notification contracts for a single application process."""

import logging
from collections import OrderedDict
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from datetime import datetime
from threading import Lock
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .core.context import PlatformContext, require_context
from .core.exceptions import ContextRequiredError
from .core.identifiers import require_label

EventType = Literal[
    "security.evidence.ingested",
    "security.event.normalized",
    "ir.finding.created",
    "ir.correlation.completed",
    "ir.investigation.created",
    "ir.risk.assessed",
    "ir.investigation.closed",
    "ir.memory.recorded",
    "platform.audit.recorded",
]
TAXONOMY: dict[EventType, tuple[str, str]] = {
    "security.evidence.ingested": ("riswan_security_data.evidence", "evidence_id"),
    "security.event.normalized": ("riswan_security_data.events", "event_reference"),
    "ir.finding.created": ("riswan_ir.detection", "finding_id"),
    "ir.correlation.completed": ("riswan_ir.correlation", "investigation_id"),
    "ir.investigation.created": ("riswan_ir.investigation", "investigation_id"),
    "ir.risk.assessed": ("riswan_ir.risk", "assessment_id"),
    "ir.investigation.closed": ("riswan_ir.investigation", "investigation_id"),
    "ir.memory.recorded": ("riswan_ir.memory", "investigation_id"),
    "platform.audit.recorded": ("riswan_platform.audit", "audit_id"),
}

LOGGER = logging.getLogger(__name__)
_delivering: ContextVar[bool] = ContextVar("delivering_platform_event", default=False)


class DomainEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, revalidate_instances="always"
    )
    event_id: UUID
    event_type: EventType
    schema_version: Literal["1.0"] = "1.0"
    tenant_id: UUID
    product_id: str
    source: str
    occurred_at: datetime
    correlation_id: str
    causation_id: UUID | None = None
    reference: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if not self.tenant_id.int or not self.event_id.int or self.occurred_at.utcoffset() is None:
            raise ValueError("Events require non-nil identifiers and an aware timestamp.")
        if self.source != TAXONOMY[self.event_type][0]:
            raise ValueError("Only the registered source can publish this event type.")
        if self.event_type.startswith("ir.") and self.product_id != "ir":
            raise ValueError("IR events require the IR product scope.")
        for value in (self.product_id, self.correlation_id, self.reference):
            require_label(value)
        return self

    @property
    def payload(self) -> dict[str, str]:
        return {TAXONOMY[self.event_type][1]: self.reference}

    @classmethod
    def from_context(
        cls,
        context: PlatformContext,
        event_type: EventType,
        occurred_at: datetime,
        reference: str,
        *,
        event_id: UUID | None = None,
        causation_id: UUID | None = None,
    ) -> Self:
        return cls(
            event_id=event_id or uuid4(),
            event_type=event_type,
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            source=TAXONOMY[event_type][0],
            occurred_at=occurred_at,
            correlation_id=context.correlation_id,
            causation_id=causation_id,
            reference=reference,
        )


Handler = Callable[[DomainEvent], None]


class EventDispatcher:
    """Synchronous best effort; repeats are suppressed in a bounded per-process cache."""

    def __init__(self, handlers: Mapping[EventType, tuple[Handler, ...]] | None = None):
        self._handlers = {key: tuple(value) for key, value in (handlers or {}).items()}
        if not self._handlers.keys() <= TAXONOMY.keys() or any(
            len(value) > 16 for value in self._handlers.values()
        ):
            raise ValueError("Invalid event handler configuration.")
        self._seen: OrderedDict[tuple[UUID, str, UUID], None] = OrderedDict()
        self._lock = Lock()

    def publish(self, event: DomainEvent) -> int:
        context = require_context()
        event = DomainEvent.model_validate(event)
        if (event.tenant_id, event.product_id, event.correlation_id) != (
            context.tenant_id,
            context.product_id,
            context.correlation_id,
        ):
            raise ContextRequiredError("Event scope does not match the trusted execution context.")
        if _delivering.get():
            raise RuntimeError("Recursive event dispatch is unsupported.")
        key = (event.tenant_id, event.product_id, event.event_id)
        handlers = self._handlers.get(event.event_type, ())
        with self._lock:
            if key in self._seen:
                return 0
            self._seen[key] = None
            if len(self._seen) > 1024:
                self._seen.popitem(last=False)
        token = _delivering.set(True)
        delivered = 0
        try:
            for handler in handlers:
                try:
                    handler(event)
                    delivered += 1
                except Exception:
                    LOGGER.warning("Domain event handler failed for %s", event.event_type)
        finally:
            _delivering.reset(token)
        return delivered
