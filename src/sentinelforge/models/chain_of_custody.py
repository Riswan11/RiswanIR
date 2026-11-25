"""Application-level custody entries and verification outcomes."""

from typing import Literal

from pydantic import Field

from .base import DomainModel, Timestamp


class ChainOfCustodyEntry(DomainModel):
    investigation_id: str
    sequence: int
    action: Literal[
        "ingested", "normalized", "verified", "export_prepared", "raw_expired", "revised"
    ]
    actor: Literal["local_application", "local_operator"]
    recorded_at: Timestamp
    previous_hash: str | None
    details: dict[str, object]
    integrity_hash: str


class EvidenceIntegrity(DomainModel):
    raw_checked: int
    normalized_checked: int
    expired_raw: int
    custody_checked: int
    problems: list[str]

    @property
    def valid(self) -> bool:
        return not self.problems


class EvidenceRetentionPolicy(DomainModel):
    days: int = Field(gt=0, le=36500)
