"""Published evidence and cross-product security finding contracts."""

from typing import Annotated, Literal, Protocol, Self
from uuid import UUID

from pydantic import Field, model_validator

from riswan_platform.core.context import PlatformContext
from riswan_platform.core.identifiers import require_label

from .canonical_event import CanonicalModel, SecurityEvent
from .provenance import EvidenceReference


class EvidenceReader(Protocol):
    def canonical_events(
        self, context: PlatformContext, investigation_id: str
    ) -> tuple[SecurityEvent, ...]:
        """Read authorized case evidence through its owning adapter."""
        ...


class SecurityFinding(CanonicalModel):
    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(min_length=1, max_length=128)
    tenant_id: UUID
    product_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=300)
    evidence: Annotated[tuple[EvidenceReference, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def validate_finding(self) -> Self:
        if not self.tenant_id.int:
            raise ValueError("A non-nil finding tenant is required.")
        require_label(self.product_id)
        require_label(self.id)
        ids = set()
        for item in self.evidence:
            require_label(item.evidence_id)
            require_label(item.parent_evidence_id)
            if not item.source_event_id or item.evidence_id in ids:
                raise ValueError("Finding evidence references must be unique and complete.")
            ids.add(item.evidence_id)
        return self


class FindingReceiver(Protocol):
    def receive(self, context: PlatformContext, finding: SecurityFinding) -> None:
        """Validate context and evidence access before accepting an external product finding."""
        ...
