"""Versioned, minimized investigation memory and retrieval contracts."""

from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from ..models.base import Text, Timestamp
from ..models.canonical_event import CanonicalModel
from ..models.detection import Version

Category = Literal[
    "episodic", "semantic", "procedural", "behavioral", "feedback", "response", "organizational"
]
Account = Annotated[str, StringConstraints(pattern=r"^aws(?:-[a-z0-9-]+)?:[0-9]{12}$")]
CaseId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
AssessmentCategory = Literal[
    "confirmed_threat",
    "false_positive",
    "authorized_activity",
    "incorrect_correlation",
    "incorrect_severity",
    "successful_remediation",
    "inconclusive",
]
Retention = Annotated[int, Field(strict=True, ge=1, le=3650)]
WEIGHTS = {
    "attack_patterns": 25,
    "identity_privilege": 20,
    "mitre": 15,
    "graph": 15,
    "resources": 10,
    "rules": 10,
    "environment": 5,
}
CATEGORIES: tuple[Category, ...] = (
    "episodic",
    "semantic",
    "procedural",
    "behavioral",
    "feedback",
    "response",
    "organizational",
)


class MemoryPolicy(CanonicalModel):
    version: Version = "1.0.0"
    observation_days: Retention = 90
    retention_days: Retention = 180
    category_retention: dict[Category, Retention] = Field(default_factory=dict)
    minimum_samples: Annotated[int, Field(strict=True, ge=2, le=100)] = 3
    minimum_coverage: Annotated[int, Field(strict=True, ge=30, le=100)] = 60
    organization_accounts: list[Annotated[list[Account], Field(min_length=2, max_length=20)]] = (
        Field(default_factory=list, max_length=20)
    )
    enabled_categories: set[Category] = Field(default_factory=lambda: set(CATEGORIES))
    playbooks: dict[Text, Text] = Field(default_factory=dict, max_length=100)

    @model_validator(mode="after")
    def disjoint_accounts(self) -> Self:
        accounts = [account for group in self.organization_accounts for account in group]
        if len(set(accounts)) != len(accounts):
            raise ValueError("Organization account groups must be disjoint.")
        return self


class Observation(CanonicalModel):
    reference: Text
    raw_reference: Text
    observed_at: Timestamp
    scope: Account
    dimensions: dict[Text, Text]
    operation: Text
    service: Text
    hour: Annotated[int, Field(ge=0, le=23)]
    weekday: Annotated[int, Field(ge=0, le=6)]
    network: Text | None = None
    authentication: Text | None = None


class Profile(CanonicalModel):
    case_id: CaseId
    lineage_id: CaseId
    created_at: Timestamp
    scope: list[Account] = Field(max_length=20)
    complete_scope: bool
    factors: dict[Text, list[Text]]
    patterns: dict[Text, list[Text]]
    observations: list[Observation] = Field(max_length=2000)
    evidence_references: list[Text] = Field(max_length=2000)
    raw_references: list[Text] = Field(max_length=2000)


class Feedback(CanonicalModel):
    classification: AssessmentCategory
    evidence_references: list[Text] = Field(min_length=1, max_length=100)


class HistoricalMatch(CanonicalModel):
    investigation_id: CaseId
    similarity_score: float
    coverage: int
    factor_scores: dict[Text, float]
    missing_factors: list[Text]
    classification: AssessmentCategory
    evidence_references: list[Text]


class Pattern(CanonicalModel):
    pattern: Text
    cases: int
    confirmed_cases: int
    false_positive_cases: int
    evidence_references: list[Text]


class Baseline(CanonicalModel):
    subject_type: Text
    subject_key: Text
    state: Literal["cold_start", "established"]
    samples: int
    historical_days: int
    seasonal_bucket: Literal["weekday", "weekend", "all"]
    observed_count: int
    expected_daily_count: float | None
    baseline_drift: bool
    signals: list[Text]
    evidence_references: list[Text]


class Intelligence(CanonicalModel):
    investigation_id: CaseId
    as_of: Timestamp
    memory_policy_version: Version
    policy_digest: Text
    similar_investigations: list[HistoricalMatch]
    behavioral_baselines: list[Baseline]
    recurring_patterns: list[Pattern]
    historical_recurrence: dict[Text, int]
    procedural_guidance: list[Text]
    response_history: dict[CaseId, list[Text]]
    recommendations: list[Text]
    limitations: list[Text]


class Record(CanonicalModel):
    schema_version: Version = "1.0.0"
    policy_version: Version
    category: Category
    data: dict[str, object]
