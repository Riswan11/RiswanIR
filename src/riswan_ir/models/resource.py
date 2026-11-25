"""Normalized CloudTrail resource references and payload summaries."""

from .base import DomainModel


class CloudResource(DomainModel):
    arn: str | None = None
    account_id: str | None = None
    type: str | None = None


class PayloadSummary(DomainModel):
    attributes: dict[str, str | bool]
