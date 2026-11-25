"""Validate the pinned OCSF subset and registered provider extensions."""

from dataclasses import dataclass, field

from pydantic import ValidationError

from ..models.base import DomainModel
from ..models.canonical_event import SecurityEvent
from ..models.schema import (
    ClassDefinition,
    SchemaDefinition,
    SchemaExtension,
    SchemaMapping,
    SchemaValidationResult,
)

OCSF_VERSION = "1.6.0"
BASE_EVENT = 0
ACCOUNT_CHANGE = 3001
AUTHENTICATION = 3002
API_ACTIVITY = 6003
OCSF = SchemaDefinition(
    version=OCSF_VERSION,
    upstream_revision="d0cd8a0fef198bf93086044e33fda6d80c74b9ef",
    classes=(
        ClassDefinition(category_uid=0, class_uid=BASE_EVENT, activities=frozenset({0, 99})),
        ClassDefinition(
            category_uid=3,
            class_uid=ACCOUNT_CHANGE,
            activities=frozenset({*range(13), 99}),
            required=("target_user",),
        ),
        ClassDefinition(
            category_uid=3,
            class_uid=AUTHENTICATION,
            activities=frozenset({*range(8), 99}),
            required=("target_user", "service"),
        ),
        ClassDefinition(
            category_uid=6,
            class_uid=API_ACTIVITY,
            activities=frozenset({*range(5), 99}),
            required=("actor", "source_ip"),
        ),
    ),
)


@dataclass
class SchemaRegistry:
    schemas: dict[str, SchemaDefinition] = field(default_factory=dict)
    mappings: dict[tuple[str, str], SchemaMapping] = field(default_factory=dict)
    extensions: dict[str, tuple[SchemaExtension, type[DomainModel]]] = field(default_factory=dict)

    def register_schema(self, descriptor: SchemaDefinition) -> None:
        if descriptor.version in self.schemas:
            raise ValueError("Schema version is already registered.")
        self.schemas[descriptor.version] = descriptor

    def register_mapping(self, descriptor: SchemaMapping) -> None:
        key = (descriptor.source, descriptor.version)
        if key in self.mappings or descriptor.schema_version not in self.schemas:
            raise ValueError("Mapping must be unique and reference a registered schema.")
        self.mappings[key] = descriptor

    def supports(self, source: str, schema_version: str, mapping_version: str) -> bool:
        mapping = self.mappings.get((source, mapping_version))
        return (
            schema_version in self.schemas
            and mapping is not None
            and mapping.schema_version == schema_version
        )

    def register_extension(self, descriptor: SchemaExtension, contract: type[DomainModel]) -> None:
        if (
            descriptor.namespace in self.extensions
            or contract.model_config.get("extra") != "forbid"
        ):
            raise ValueError("Extension namespaces must be unique and forbid extra fields.")
        self.extensions[descriptor.namespace] = (descriptor, contract)

    def validate(self, value: object) -> SchemaValidationResult:
        try:
            event = SecurityEvent.model_validate(
                value.payload() if isinstance(value, SecurityEvent) else value
            )
        except ValidationError as exc:
            # Field names in an invalid submission can themselves contain sensitive data.
            return SchemaValidationResult(
                valid=False,
                issues=sorted(
                    {
                        f"invalid_event:{item['type']}"
                        for item in exc.errors(include_input=False, include_context=False)
                    }
                ),
            )
        issues = []
        metadata = event.metadata
        schema = self.schemas.get(metadata.schema_version)
        if schema is None:
            issues.append("unsupported_schema_version")
        if not self.supports(metadata.source, metadata.schema_version, metadata.mapping_version):
            issues.append("unsupported_mapping_version")
        classification = event.classification
        if schema:
            rule = next(
                (item for item in schema.classes if item.class_uid == classification.class_uid),
                None,
            )
            if (
                rule is None
                or classification.category_uid != rule.category_uid
                or classification.activity_id not in rule.activities
                or classification.type_uid
                != classification.class_uid * 100 + classification.activity_id
            ):
                issues.append("invalid_classification")
            else:
                fields = {
                    "actor": event.actor
                    and (event.actor.user or event.actor.app_name or event.actor.session_created),
                    "target_user": event.target_user
                    and (event.target_user.uid or event.target_user.name or event.target_user.arn),
                    "source_ip": event.network and event.network.source_ip,
                    "service": event.activity.service,
                }
                issues.extend(
                    f"missing_required:{name}" for name in rule.required if not fields[name]
                )
        if event.evidence and event.evidence.source_event_id != event.id:
            issues.append("invalid_evidence_reference")
        for namespace, payload in event.extensions.items():
            extension = self.extensions.get(namespace)
            if extension is None or extension[0].source != metadata.source:
                issues.append("unregistered_extension")
                continue
            descriptor, contract = extension
            try:
                parsed = contract.model_validate(payload)
                if parsed.payload().get("version") != descriptor.version:
                    issues.append("unsupported_extension_version")
            except ValidationError:
                issues.append("invalid_extension")
        return SchemaValidationResult(valid=not issues, issues=sorted(set(issues)))
