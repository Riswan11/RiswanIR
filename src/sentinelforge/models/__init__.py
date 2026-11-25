"""Validated contracts for investigations, evidence, and analyst decisions."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from ..core.fields import utc_timestamp
from ..ingestion.exports import export_records


Text = Annotated[str, StringConstraints(min_length=1, max_length=300, strip_whitespace=True)]
Reviewer = Annotated[str, StringConstraints(min_length=1, max_length=100, strip_whitespace=True)]
EvidenceReferences = Annotated[list[Text], Field(min_length=1)]
CloudTrailRecord = dict[str, object]


def validate_timestamp(value: str) -> str:
    utc_timestamp(value)
    return value


Timestamp = Annotated[str, AfterValidator(validate_timestamp)]


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


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class DomainModel(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    def payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)


class InvestigationRequest(DomainModel):
    title: Text
    principal: Text
    records: Annotated[list[CloudTrailRecord], Field(max_length=2000)]

    @field_validator("records", mode="before")
    @classmethod
    def unwrap_export(cls, value: object) -> object:
        return export_records(value)


class NormalizedEvent(DomainModel):
    id: Text
    source: Literal["aws.cloudtrail"]
    observed_at: Timestamp
    event: Text
    operation: str | None = None
    principal: str | None = None
    target: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    region: str | None = None
    account_id: str | None = None
    recipient_account_id: str | None = None

class Evidence(NormalizedEvent):
    query: Text
    linked_from_evidence_id: Text | None = None
    integrity_hash: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


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

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        ids = {item.id for item in self.evidence}
        if len(ids) != len(self.evidence):
            raise ValueError("Evidence IDs must be unique.")
        references = {reference for finding in self.assessment.claims for reference in finding.evidence_ids}
        if self.action:
            references.update(self.action.evidence_ids)
        references.update(item.linked_from_evidence_id for item in self.evidence if item.linked_from_evidence_id)
        if not references <= ids:
            raise ValueError("Investigation references unknown evidence IDs.")
        return self


class InvestigationReport(InvestigationResult):
    id: Text
    created_at: Timestamp
    reviews: list[AnalystReview] = Field(default_factory=list)
    decision: ActionDecision | None = None
    similar_investigations: list[SimilarInvestigation] = Field(default_factory=list)
