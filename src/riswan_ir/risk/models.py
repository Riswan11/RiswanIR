"""Provider-neutral scoring inputs and immutable assessment contracts."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from ..knowledge_graph.models import GraphId
from ..models.base import Text, Timestamp
from ..models.canonical_event import CanonicalModel
from ..models.detection import ResourceCriticality, Version

Points = Annotated[int, Field(strict=True, ge=0, le=100)]
Weight = Annotated[int, Field(strict=True, ge=1, le=100)]
Kind = Literal["finding", "incident"]
Trigger = Literal["initial", "revision", "analyst_review", "reassessment", "containment"]
Status = Literal["observed", "inferred", "unknown", "conflicting"]


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoringPolicy(CanonicalModel):
    id: Text
    version: Version
    risk: Annotated[dict[Text, Weight], Field(min_length=1, max_length=20)]
    confidence: Annotated[dict[Text, Weight], Field(min_length=1, max_length=20)]
    severity_thresholds: tuple[Points, Points, Points, Points] = (20, 40, 70, 90)
    confidence_review_below: Points = 60

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if sum(self.risk.values()) != 100 or sum(self.confidence.values()) != 100:
            raise ValueError("Each scoring dimension must have weights totaling 100.")
        if not 0 < self.severity_thresholds[0] or any(
            lower >= upper
            for lower, upper in zip(
                self.severity_thresholds, self.severity_thresholds[1:], strict=False
            )
        ):
            raise ValueError("Severity thresholds must be strictly increasing.")
        return self


class Factor(CanonicalModel):
    value: Points | None = None
    status: Status
    explanation: Text
    evidence_references: list[Text] = Field(default_factory=list, max_length=2000)

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        if (self.value is None) != (self.status == "unknown"):
            raise ValueError("Unknown scoring inputs must omit a value.")
        return self


class Contribution(Factor):
    factor: Text
    weight: Weight
    contribution: float | None = None


class Dimension(CanonicalModel):
    score: float | None
    assessed_weight: Points
    contributions: list[Contribution]


class RiskInventory(CanonicalModel):
    asset_criticality: dict[Text, ResourceCriticality] = Field(
        default_factory=dict, max_length=2000
    )
    identity_privilege: dict[Text, Points] = Field(default_factory=dict, max_length=2000)
    resource_exposure: dict[Text, Points] = Field(default_factory=dict, max_length=2000)
    business_impact: dict[Text, Points] = Field(default_factory=dict, max_length=2000)
    historical_recurrence: dict[Text, Points] = Field(default_factory=dict, max_length=2000)
    rule_reliability: dict[Text, Points] = Field(default_factory=dict, max_length=2000)


class Subject(CanonicalModel):
    kind: Kind
    id: Text
    rule_id: Text
    declared_severity: Severity
    event_ids: list[Text] = Field(min_length=1, max_length=2000)
    stages: int | None = Field(default=None, ge=1, le=8)
    relationships: list[GraphId] = Field(default_factory=list)


class AssessmentInputs(CanonicalModel):
    subject: Subject
    risk: dict[Text, Factor]
    confidence: dict[Text, Factor]
    evidence_references: list[Text]
    disposition: Literal["benign", "suspicious", "confirmed", "inconclusive"] | None = None
    containment_reference: Text | None = None
    containment_event_id: Text | None = None
    residual_risk: dict[Text, Factor] | None = None
    recurrence_policy_digest: Text | None = None


class Assessment(CanonicalModel):
    id: GraphId
    investigation_id: Text
    subject_kind: Kind
    subject_id: Text
    previous_assessment_id: GraphId | None
    original_assessment_id: GraphId
    original_risk_score: float | None
    policy_id: Text
    policy_version: Version
    policy_digest: Text
    created_at: Timestamp
    trigger: Trigger
    risk: Dimension
    confidence: Dimension
    residual_risk: Dimension | None
    severity: Severity | None
    investigation_priority: Literal["P0", "P1", "P2", "P3", "P4"]
    recommended_action: Text
    assessment_status: Literal["provisional", "analyst_validated", "dismissed", "assessed"]
    missing_context: list[Text]
    evidence_references: list[Text]
    containment_reference: Text | None


class RiskArchive(CanonicalModel):
    assessment: Assessment
    inputs: AssessmentInputs
    policy: ScoringPolicy


class Reassessment(CanonicalModel):
    subject_kind: Kind
    subject_id: Text
    containment_evidence_id: Text | None = None
