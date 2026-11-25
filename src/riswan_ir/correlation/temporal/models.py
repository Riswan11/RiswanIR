"""Temporal rules, matches, incidents, and replay contracts."""

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StringConstraints, model_validator

from ...knowledge_graph.models import GraphId
from ...models.base import Text, Timestamp
from ...models.canonical_event import CanonicalModel
from ...models.detection import (
    DetectionCondition,
    DetectionContext,
    DetectionRuleVersion,
    MitreMapping,
)

Account = Annotated[str, StringConstraints(pattern=r"^aws(?:-[a-z0-9-]+)?:[0-9]{12}$")]
Count = Annotated[int, Field(strict=True, ge=1, le=10)]
Minutes = Annotated[int, Field(strict=True, ge=1, le=1440)]


class Stage(CanonicalModel):
    name: Text
    operations: Annotated[list[Text], Field(min_length=1, max_length=12)]
    service: Text
    outcomes: Annotated[
        tuple[Literal["success", "failure", "unknown"], ...], Field(min_length=1, max_length=3)
    ] = ("success",)
    conditions: list[DetectionCondition] = Field(default_factory=list, max_length=8)
    findings: list[Text] = Field(default_factory=list, max_length=8)
    count: Count = 1
    optional: StrictBool = False
    requires_chain: StrictBool = False


class TemporalRule(DetectionRuleVersion):
    name: Text
    enabled: StrictBool = True
    window_minutes: Minutes
    suppression_minutes: Minutes | None = None
    group_by: Literal["identity", "session", "lineage", "resource"]
    stages: Annotated[list[Stage], Field(min_length=2, max_length=8)]
    minimum_stages: Annotated[int, Field(strict=True, ge=2, le=8)] = 2
    cross_account: StrictBool = False
    severity: Literal["low", "medium", "high", "critical"]
    mitre: MitreMapping | None = None
    recommendation: Text

    @model_validator(mode="after")
    def validate_sequence(self) -> Self:
        if (
            self.stages[0].optional
            or self.stages[0].requires_chain
            or self.stages[-1].optional
            or (self.group_by != "lineage" and any(stage.requires_chain for stage in self.stages))
            or len({item.name for item in self.stages}) != len(self.stages)
            or self.minimum_stages > len(self.stages)
            or (self.cross_account and self.group_by != "lineage")
        ):
            raise ValueError("Invalid correlation sequence structure.")
        if not self.id.startswith("SF-CORR-"):
            raise ValueError("Use a correlation rule identifier.")
        return self


class AccountTransition(CanonicalModel):
    source: Account
    target: Account

    @model_validator(mode="after")
    def different_accounts(self) -> Self:
        if self.source == self.target:
            raise ValueError("Cross-account policy requires distinct accounts.")
        return self


class TemporalPolicy(CanonicalModel):
    cross_account: list[AccountTransition] = Field(default_factory=list, max_length=100)
    enrichment: DetectionContext = Field(default_factory=DetectionContext)


class TimelineEntry(CanonicalModel):
    stage: Text
    event_id: Text
    observed_at: Timestamp
    ingested_at: Timestamp | None
    evidence_id: Text | None
    operation: Text
    account: str | None
    supporting_findings: list[Text]
    # A graph edge can have multiple proof events, including an issuance observation.
    relationship_ids: list[GraphId]
    relationship_evidence_ids: list[Text]


class SecurityIncident(DetectionRuleVersion):
    incident_id: GraphId
    title: Text
    severity: Literal["low", "medium", "high", "critical"]
    timeline: list[TimelineEntry]
    mitre: MitreMapping | None
    recommendation: Text


class PartialMatch(DetectionRuleVersion):
    group: GraphId
    next_stage: Annotated[int, Field(ge=0)]
    repeat: Annotated[int, Field(ge=0)]
    timeline: list[TimelineEntry]


class CorrelationMetrics(CanonicalModel):
    events: int
    stage_checks: int
    graph_checks: int
    suppressed: int
    excluded: int
    truncated_states: int


class TemporalResult(CanonicalModel):
    engine_version: Text = "1.0.0"
    investigation_id: Text
    lineage_id: Text
    rules: list[DetectionRuleVersion]
    configuration_digest: Text
    incidents: list[SecurityIncident]
    partial_matches: list[PartialMatch]
    metrics: CorrelationMetrics


class TemporalSnapshot(CanonicalModel):
    result: TemporalResult
    rules: list[TemporalRule]
    policy: TemporalPolicy
