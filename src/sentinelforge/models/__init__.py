"""Validated contracts for investigations, evidence, and analyst decisions."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from ..ingestion.exports import export_records
from .base import DomainModel, Text, Timestamp
from .canonical_event import SecurityEvent as CanonicalEvent
from .correlation import CorrelationConfidence, CorrelationResult
from .detection import DetectionReplayResult
from .evidence import Evidence as Evidence
from .provenance import CollectionContext
from .security_event import NormalizedEvent as NormalizedEvent

Reviewer = Annotated[str, StringConstraints(min_length=1, max_length=100, strip_whitespace=True)]
EvidenceReferences = Annotated[list[Text], Field(min_length=1)]
CloudTrailRecord = dict[str, object]


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRATED = "unrated"


class Disposition(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"


class Relationship(StrEnum):
    CALLED = "CALLED"
    TARGETED = "TARGETED"
    ISSUED_CREDENTIAL_USED_IN = "ISSUED_CREDENTIAL_USED_IN"
    ASSUMED_ROLE = "ASSUMED_ROLE"
    ESTABLISHED_SESSION = "ESTABLISHED_SESSION"
    ISSUED_CREDENTIAL = "ISSUED_CREDENTIAL"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    PERFORMED_ACTION = "PERFORMED_ACTION"
    ACCESSED_RESOURCE = "ACCESSED_RESOURCE"
    MODIFIED_RESOURCE = "MODIFIED_RESOURCE"
    BELONGS_TO_ACCOUNT = "BELONGS_TO_ACCOUNT"
    CHAINED_TO = "CHAINED_TO"
    SUPPORTED_BY = "SUPPORTED_BY"
    SHARED_EVENT = "SHARED_EVENT"
    RELATED_REQUEST = "RELATED_REQUEST"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class EvidenceSubmission(DomainModel):
    records: Annotated[list[CloudTrailRecord], Field(max_length=2000)]
    provenance: CollectionContext = Field(default_factory=CollectionContext)

    @field_validator("records", mode="before")
    @classmethod
    def unwrap_export(cls, value: object) -> object:
        return export_records(value)


class InvestigationRequest(EvidenceSubmission):
    title: Text
    principal: Text


class Finding(DomainModel):
    rule_id: Text | None = None
    summary: Text
    evidence_ids: EvidenceReferences
    possible_attack_technique: Text | None = None


class RiskAssessment(DomainModel):
    severity: Severity
    score: Annotated[int, Field(ge=0, strict=True)]
    score_max: Annotated[int, Field(gt=0, strict=True)]
    claims: list[Finding]
    open_questions: list[Text]
    observed_targets: list[str]

    @model_validator(mode="after")
    def validate_score(self) -> Self:
        if self.score > self.score_max:
            raise ValueError("Risk score cannot exceed the maximum.")
        return self


class GraphEdge(DomainModel):
    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)

    source: str = Field(alias="from", min_length=1)
    relationship: Relationship
    target: str = Field(alias="to", min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: CorrelationConfidence | None = None


class AdvisoryAction(DomainModel):
    id: Text
    summary: Text
    mode: Literal["advisory"]
    evidence_ids: EvidenceReferences


class AnalystFeedback(DomainModel):
    reviewer: Reviewer
    disposition: Disposition
    notes: Annotated[str, StringConstraints(max_length=2000)] = ""

    @field_validator("disposition", mode="before")
    @classmethod
    def strip_disposition(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class AnalystReview(AnalystFeedback):
    created_at: Timestamp


class ActionDecision(DomainModel):
    reviewer: Reviewer
    decision: ApprovalDecision
    created_at: Timestamp


class InvestigationSummary(DomainModel):
    id: Text
    title: Text
    created_at: Timestamp


class SimilarInvestigation(DomainModel):
    id: Text
    title: Text
    disposition: Disposition
    shared_events: Annotated[list[Text], Field(min_length=1)]


class InvestigationResult(DomainModel):
    title: Text
    principal: Text
    plan: list[Text]
    evidence: list[Evidence]
    graph: list[GraphEdge]
    assessment: RiskAssessment
    action: AdvisoryAction | None
    correlation: CorrelationResult | None = None
    canonical_events: list[CanonicalEvent] | None = None
    detection: DetectionReplayResult | None = None

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        ids = {item.id for item in self.evidence}
        if len(ids) != len(self.evidence):
            raise ValueError("Evidence IDs must be unique.")
        references = {
            reference for finding in self.assessment.claims for reference in finding.evidence_ids
        }
        if self.detection:
            references.update(
                item for finding in self.detection.findings for item in finding.evidence_ids
            )
            references.update(decision.evidence_id for decision in self.detection.decisions)
        if self.action:
            references.update(self.action.evidence_ids)
        if self.correlation:
            references.update(self.correlation.supporting_ids())
        if self.canonical_events is not None:
            by_id = {item.id: item.reference for item in self.evidence}
            if (
                len(self.canonical_events) != len(self.evidence)
                or {event.id for event in self.canonical_events} != ids
                or any(event.evidence != by_id[event.id] for event in self.canonical_events)
            ):
                raise ValueError("Canonical events must reference their normalized evidence.")
        references.update(item for edge in self.graph for item in edge.evidence_ids)
        references.update(
            item.linked_from_evidence_id for item in self.evidence if item.linked_from_evidence_id
        )
        if not references <= ids:
            raise ValueError("Investigation references unknown evidence IDs.")
        return self


class InvestigationReport(InvestigationResult):
    previous_investigation_id: str | None = None
    id: Text
    created_at: Timestamp
    reviews: list[AnalystReview] = Field(default_factory=list)
    decision: ActionDecision | None = None
    similar_investigations: list[SimilarInvestigation] = Field(default_factory=list)
