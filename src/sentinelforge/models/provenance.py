"""Provenance and versioned links for retained evidence."""

from enum import StrEnum
from typing import Annotated

from pydantic import StringConstraints

from .base import DomainModel, Text, Timestamp


class CollectionMethod(StrEnum):
    MANUAL = "manual_upload"
    API = "api"
    CONNECTOR = "connector"
    STREAMING = "streaming"


class CollectionContext(DomainModel):
    source_location: Annotated[str, StringConstraints(min_length=1, max_length=2048)] | None = None
    collection_method: CollectionMethod = CollectionMethod.API
    collected_at: Timestamp | None = None
    collector_id: Text | None = None
    collection_account_id: Text | None = None
    collection_region: Text | None = None


class EvidenceProvenance(CollectionContext):
    evidence_id: str
    source_event_id: str
    source_provider: str = "AWS"
    source_service: str = "CloudTrail"
    source_account_id: str | None = None
    source_region: str | None = None
    observed_at: str | None = None
    ingested_at: Timestamp
    raw_integrity_hash: str
    source_authenticity_verified: bool = False


class EvidenceReference(DomainModel):
    evidence_id: str
    parent_evidence_id: str
    source_event_id: str


class EvidenceTransformation(EvidenceReference):
    raw_integrity_hash: str
    normalized_integrity_hash: str
    normalization_version: str
    schema_version: str
    configuration: dict[str, str]
