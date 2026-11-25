"""Provider-independent event contracts for the supported OCSF subset."""

from enum import IntEnum
from typing import Annotated

from pydantic import ConfigDict, Field, IPvAnyAddress, JsonValue

from .base import DomainModel, Text, Timestamp
from .provenance import EvidenceReference


class CanonicalModel(DomainModel):
    model_config = ConfigDict(extra="forbid")


class Status(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2


class EventClassification(CanonicalModel):
    category_uid: Annotated[int, Field(ge=0, strict=True)]
    class_uid: Annotated[int, Field(ge=0, strict=True)]
    activity_id: Annotated[int, Field(ge=0, le=99, strict=True)]
    type_uid: Annotated[int, Field(ge=0, strict=True)]
    severity_id: Annotated[int, Field(ge=0, le=0, strict=True)] = 0


class EventMetadata(CanonicalModel):
    schema_version: Text
    mapping_version: Text
    provider: Text
    source: Text
    product: Text


class Principal(CanonicalModel):
    uid: str | None = None
    name: str | None = None
    arn: str | None = None
    account_uid: str | None = None


class Actor(CanonicalModel):
    user: Principal | None = None
    app_name: str | None = None
    session_created: Timestamp | None = None
    mfa: bool | None = None


class Resource(CanonicalModel):
    uid: str | None = None
    name: str | None = None
    type: str | None = None
    account_uid: str | None = None


class CloudContext(CanonicalModel):
    provider: Text
    account_uid: str | None = None
    region: str | None = None


class NetworkContext(CanonicalModel):
    source_ip: IPvAnyAddress | None = None
    user_agent: str | None = None


class EventOutcome(CanonicalModel):
    status_id: Status
    status_code: str | None = None


class EventActivity(CanonicalModel):
    name: Text
    operation: Text
    service: str | None = None
    target: str | None = None
    read_only: bool | None = None


class SecurityEvent(CanonicalModel):
    id: Text
    observed_at: Timestamp
    classification: EventClassification
    metadata: EventMetadata
    activity: EventActivity
    outcome: EventOutcome
    actor: Actor | None = None
    target_user: Principal | None = None
    cloud: CloudContext | None = None
    network: NetworkContext | None = None
    resources: list[Resource] = Field(default_factory=list)
    extensions: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    evidence: EvidenceReference | None = None
    linked_from_evidence_id: str | None = None

    @property
    def principal_arn(self) -> str | None:
        return self.actor.user.arn if self.actor and self.actor.user else None
