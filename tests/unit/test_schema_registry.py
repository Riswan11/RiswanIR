import pytest

from trailhound.models.canonical_event import CanonicalModel
from trailhound.models.schema import SchemaExtension, SchemaMapping
from trailhound.normalization.aws.cloudtrail import normalize
from trailhound.normalization.aws.ocsf_mapper import REGISTRY, map_event
from trailhound.schema.registry import OCSF, SchemaRegistry


class ExampleExtension(CanonicalModel):
    version: str
    region_hint: str


def test_future_provider_extension_uses_same_canonical_contract(cloudtrail):
    registry = SchemaRegistry()
    registry.register_schema(OCSF)
    mapping = SchemaMapping(source="future.events", version="1.0.0", schema_version=OCSF.version)
    registry.register_mapping(mapping)
    extension = SchemaExtension(namespace="future.safe", version="1.0.0", source=mapping.source)
    registry.register_extension(extension, ExampleExtension)
    data = map_event(normalize(cloudtrail["Records"][0])).payload()
    data["metadata"].update(source=mapping.source, provider="Future")
    data["extensions"] = {"future.safe": {"version": "1.0.0", "region_hint": "example"}}
    assert registry.validate(data).valid
    assert not REGISTRY.validate(data).valid
    data["extensions"]["future.safe"]["version"] = "2.0.0"
    assert registry.validate(data).issues == ["unsupported_extension_version"]
    with pytest.raises(ValueError, match="unique"):
        registry.register_extension(extension, ExampleExtension)
    with pytest.raises(ValueError, match="already"):
        registry.register_schema(OCSF)
    with pytest.raises(ValueError, match="registered schema"):
        registry.register_mapping(
            mapping.model_copy(update={"schema_version": "9.9.9", "version": "2.0.0"})
        )


def test_incompatible_versions_invalid_ids_and_missing_class_fields(cloudtrail):
    raw = {**cloudtrail["Records"][0], "sourceIPAddress": "203.0.113.20"}
    data = map_event(normalize(raw)).payload()
    assert REGISTRY.supports("aws.cloudtrail", "1.6.0", "1.0.0")
    data["network"] = None
    assert REGISTRY.validate(data).issues == ["missing_required:source_ip"]
    data["classification"]["type_uid"] = 42
    assert REGISTRY.validate(data).issues == ["invalid_classification"]
    data["metadata"]["schema_version"] = "2.0.0"
    assert REGISTRY.validate(data).issues == [
        "unsupported_mapping_version",
        "unsupported_schema_version",
    ]
