"""Provider-aware normalized security event contract."""

from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import DomainModel, Text, Timestamp
from .identity import CloudIdentity
from .network import TLSDetails
from .resource import CloudResource, PayloadSummary


class EventCategory(StrEnum):
    MANAGEMENT = "Management"
    DATA = "Data"
    NETWORK = "NetworkActivity"
    INSIGHT = "Insight"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ServiceFamily(StrEnum):
    IDENTITY = "identity"
    STORAGE = "storage"
    COMPUTE = "compute"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    MONITORING = "monitoring"
    CONTAINER = "container"
    DATABASE = "database"
    OTHER = "other"


class SecurityEvent(DomainModel):
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
    event_version: str | None = None
    event_source: str | None = None
    event_type: str | None = None
    event_category: EventCategory | None = None
    service_family: ServiceFamily | None = None
    identity: CloudIdentity | None = None
    vpc_endpoint_id: str | None = None
    resources: list[CloudResource] = Field(default_factory=list)
    request_parameters: PayloadSummary | None = None
    response_elements: PayloadSummary | None = None
    outcome: Outcome = Outcome.SUCCESS
    error_code: str | None = None
    error_message: Literal["[redacted]"] | None = None
    read_only: bool | None = None
    request_id: str | None = None
    shared_event_id: str | None = None
    tls_details: TLSDetails | None = None
    additional_event_data: PayloadSummary | None = None


NormalizedEvent = SecurityEvent
