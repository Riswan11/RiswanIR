"""Persisted evidence, including provenance and integrity digest."""

from typing import Annotated

from pydantic import StringConstraints

from .base import DomainModel, Text
from .provenance import EvidenceReference
from .security_event import SecurityEvent


class Evidence(SecurityEvent):
    query: Text
    linked_from_evidence_id: Text | None = None
    integrity_hash: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    reference: EvidenceReference | None = None


NormalizedEvidence = Evidence


class RawEvidence(DomainModel):
    evidence_id: str
    integrity_hash: str
    record: dict[str, object] | None
