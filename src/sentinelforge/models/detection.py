"""Contracts for local detection rules, trusted enrichment and replay."""

from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, StringConstraints, model_validator

from ..core.fields import utc_timestamp
from .base import Text, Timestamp
from .canonical_event import CanonicalModel

FieldPath = Literal[
    "activity.operation",
    "activity.service",
    "activity.authentication",
    "activity.status_id",
    "actor.uid",
    "actor.kind",
    "actor.mfa",
    "actor.session_issuer",
    "cloud.account",
    "cloud.region",
    "resource.uid",
    "resource.criticality",
    "context.environment",
    "context.cross_account",
    "context.role_privileged",
    "context.unseen_relationship",
    "context.unexpected_network",
    "context.unrestricted_ingress",
    "context.public_policy",
    "context.admin_policy",
    "context.external_snapshot",
    "context.monitoring_disabled",
]
Scalar = Text | StrictBool | StrictInt
Version = Annotated[
    str,
    StringConstraints(pattern=r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$"),
]
RuleId = Annotated[
    str, StringConstraints(pattern=r"^SF-[A-Z0-9]+(?:-[A-Z0-9]+){1,4}$", max_length=48)
]
Window = Annotated[int, Field(ge=1, le=10080, strict=True)]
Keys = Annotated[list[FieldPath], Field(min_length=1, max_length=5)]


class ResourceCriticality(StrEnum):
    STANDARD = "standard"
    SENSITIVE = "sensitive"
    CRITICAL = "critical"


class DetectionRuleVersion(CanonicalModel):
    id: RuleId
    version: Version


class DetectionCondition(CanonicalModel):
    field: FieldPath
    operator: Literal["equals", "not_equals", "in", "gte", "lte", "exists"]
    value: Scalar | Annotated[list[Scalar], Field(min_length=1, max_length=30)] | None = None

    @model_validator(mode="after")
    def check_operand(self) -> Self:
        match self.operator:
            case "exists":
                valid = "value" not in self.model_fields_set or self.value is None
            case "in":
                valid = isinstance(self.value, list)
            case "gte" | "lte":
                valid = type(self.value) is int
            case _:
                valid = self.value is not None and not isinstance(self.value, list)
        if not valid:
            raise ValueError("Condition operand does not match its operator.")
        return self


class DetectionThreshold(CanonicalModel):
    minimum: Annotated[int, Field(ge=2, le=100, strict=True)]
    window_minutes: Window
    fields: Keys


class DetectionSuppression(CanonicalModel):
    window_minutes: Window
    fields: Keys


class MitreMapping(CanonicalModel):
    tactics: Annotated[list[Text], Field(min_length=1, max_length=8)]
    techniques: Annotated[
        list[Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]],
        Field(min_length=1, max_length=8),
    ]


class DetectionRule(DetectionRuleVersion):
    name: Text
    enabled: StrictBool = True
    description: Text
    severity: Literal["low", "medium", "high", "critical"]
    provider: Text
    class_uid: Annotated[int, Field(ge=0, strict=True)] | None = None
    outcomes: Annotated[
        tuple[Literal["success", "failure", "unknown"], ...], Field(min_length=1, max_length=3)
    ] = ("success",)
    conditions: Annotated[list[DetectionCondition], Field(min_length=1, max_length=24)]
    any_conditions: Annotated[list[DetectionCondition], Field(max_length=24)] = Field(
        default_factory=list
    )
    threshold: DetectionThreshold | None = None
    suppression: DetectionSuppression | None = None
    mitre: MitreMapping | None = None
    recommendation: Text


class DetectionException(CanonicalModel):
    id: Text
    rule_id: RuleId
    approved_by: Text
    reason: Text
    starts_at: Timestamp
    expires_at: Timestamp
    match: Annotated[dict[FieldPath, Scalar], Field(min_length=1, max_length=5)]

    @model_validator(mode="after")
    def check_window(self) -> Self:
        if utc_timestamp(self.starts_at) >= utc_timestamp(self.expires_at):
            raise ValueError("An exception must have a positive validity window.")
        return self


class DetectionContext(CanonicalModel):
    """Operator-supplied inventory. Unconfigured attributes remain unknown."""

    version: Version = "1.0.0"
    account_environments: Annotated[dict[Text, Text], Field(max_length=1000)] = Field(
        default_factory=dict
    )
    privileged_roles: Annotated[dict[Text, StrictBool], Field(max_length=1000)] = Field(
        default_factory=dict
    )
    resources: Annotated[dict[Text, ResourceCriticality], Field(max_length=1000)] = Field(
        default_factory=dict
    )
    expected_networks: Annotated[
        dict[Text, Annotated[list[IPv4Network | IPv6Network], Field(min_length=1, max_length=32)]],
        Field(max_length=1000),
    ] = Field(default_factory=dict)
    known_relationships: Annotated[
        dict[Text, Annotated[list[Text], Field(max_length=1000)]], Field(max_length=1000)
    ] = Field(default_factory=dict)
    exceptions: Annotated[list[DetectionException], Field(max_length=100)] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def unique_exceptions(self) -> Self:
        if len({entry.id for entry in self.exceptions}) != len(self.exceptions):
            raise ValueError("Duplicate detection exception IDs.")
        return self


class SecurityFinding(DetectionRuleVersion):
    idempotency_key: Text
    severity: Literal["low", "medium", "high", "critical"]
    summary: Text
    evidence_ids: Annotated[list[Text], Field(min_length=1, max_length=100)]
    reasons: list[DetectionCondition]
    threshold: DetectionThreshold | None = None
    recommendation: Text
    mitre: MitreMapping | None = None


class DetectionResult(DetectionRuleVersion):
    evidence_id: Text
    disposition: Literal["exception", "suppressed"]
    exception_id: Text | None = None


class DetectionExecution(CanonicalModel):
    engine_version: Version
    configuration_digest: Text
    context_version: Version
    rules: list[DetectionRuleVersion]
    events: int
    evaluations: int
    findings: int
    suppressed: int
    excepted: int


class DetectionReplayResult(CanonicalModel):
    findings: list[SecurityFinding]
    decisions: list[DetectionResult]
    execution: DetectionExecution


class DetectionSnapshot(CanonicalModel):
    result: DetectionReplayResult
    rules: list[DetectionRule]
    context: DetectionContext
