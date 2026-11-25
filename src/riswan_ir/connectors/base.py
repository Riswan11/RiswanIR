"""Independent collection contract for sources that yield raw records."""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

from ..models import CloudTrailRecord
from ..models.collection import CollectionRequest
from ..models.connector import CollectionError, ConnectorCapabilities


class CollectionFailure(RuntimeError):
    def __init__(self, operation: str, code: str) -> None:
        self.error = CollectionError(operation=operation, code=code)
        super().__init__(f"{operation}: {code}")


@dataclass(frozen=True)
class CollectedBatch:
    location: str
    records: list[CloudTrailRecord] = field(repr=False)


class TelemetryConnector(Protocol):
    capabilities: ConnectorCapabilities

    def collect(self, window: CollectionRequest) -> Iterator[CollectedBatch]: ...
