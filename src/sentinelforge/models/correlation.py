"""Evidence-backed identity, session and activity observations."""

from enum import StrEnum

from pydantic import ConfigDict

from .base import DomainModel


class CorrelationConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IdentityAlias(DomainModel):
    kind: str
    value: str


class Identity(DomainModel):
    id: str
    account_id: str | None
    partition: str | None = None
    kind: str | None
    aliases: list[IdentityAlias]


class CredentialReference(DomainModel):
    id: str


class IdentitySession(DomainModel):
    id: str
    identity_id: str
    credential: CredentialReference | None = None
    created_at: str | None = None
    source_identity: str | None = None


class RoleAssumption(DomainModel):
    event_id: str
    actor_id: str
    role_id: str
    session_id: str
    cross_account: bool


class IdentityRelationship(DomainModel):
    source: str
    target: str
    relationship: str
    confidence: CorrelationConfidence
    reason: str
    evidence_ids: list[str]


class ActivityChain(DomainModel):
    root_event_id: str
    event_ids: list[str]


class IdentityTimeline(DomainModel):
    identity_id: str
    event_ids: list[str]


class CorrelationContext(DomainModel):
    model_config = ConfigDict(frozen=True)

    version: str
    session_clock_tolerance_seconds: int
    request_clock_tolerance_seconds: int


class CorrelationResult(DomainModel):
    context: CorrelationContext
    identities: list[Identity]
    sessions: list[IdentitySession]
    assumptions: list[RoleAssumption]
    relationships: list[IdentityRelationship]
    chains: list[ActivityChain]
    timelines: list[IdentityTimeline]
    unresolved: list[str]

    def supporting_ids(self) -> set[str]:
        ids = {event for edge in self.relationships for event in edge.evidence_ids}
        ids.update(
            event for chain in self.chains for event in [chain.root_event_id, *chain.event_ids]
        )
        ids.update(event for timeline in self.timelines for event in timeline.event_ids)
        ids.update(item.event_id for item in self.assumptions)
        return ids
