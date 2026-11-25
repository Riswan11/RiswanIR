"""Bounded collection requests and run summaries."""

from typing import Self

from pydantic import AwareDatetime, model_validator

from .base import DomainModel
from .connector import CollectionError


class CollectionRequest(DomainModel):
    start: AwareDatetime
    end: AwareDatetime
    incremental: bool = True

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.start >= self.end:
            raise ValueError("Collection start must be before end.")
        return self


class CollectionResult(DomainModel):
    scope: str
    window: CollectionRequest
    received: int
    persisted: int
    requests: int
    error: CollectionError | None = None
