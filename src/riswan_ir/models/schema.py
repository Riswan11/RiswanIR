"""Registry descriptors and safe validation results."""

from .base import DomainModel


class ClassDefinition(DomainModel):
    category_uid: int
    class_uid: int
    activities: frozenset[int]
    required: tuple[str, ...] = ()


class SchemaDefinition(DomainModel):
    version: str
    upstream_revision: str
    classes: tuple[ClassDefinition, ...]


class SchemaMapping(DomainModel):
    source: str
    version: str
    schema_version: str


class SchemaExtension(DomainModel):
    namespace: str
    source: str
    version: str


class SchemaValidationResult(DomainModel):
    valid: bool
    issues: list[str]
