"""Record-level errors and deterministic batch normalization results."""

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class NormalizationIssue:
    index: int
    field: str
    code: str


class InvalidRecord(ValueError):
    def __init__(self, field: str, code: str) -> None:
        self.field = field
        self.code = code
        super().__init__(f"{field}: {code}")


@dataclass(frozen=True)
class NormalizationBatch(Generic[T]):
    records: list[T]
    issues: list[NormalizationIssue]
