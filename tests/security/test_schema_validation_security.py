import json

from sentinelforge.normalization.aws.cloudtrail import normalize
from sentinelforge.normalization.aws.ocsf_mapper import REGISTRY, map_event


def test_invalid_extensions_cannot_echo_input(cloudtrail):
    data = map_event(normalize(cloudtrail["Records"][0])).payload()
    data["extensions"]["aws.cloudtrail"]["fixture-private-field"] = "fixture-private-value"
    data["extensions"]["fixture-private-namespace"] = {"value": "fixture-private-value"}
    result = REGISTRY.validate(data)
    assert result.issues == ["invalid_extension", "unregistered_extension"]
    assert "fixture-private" not in str(result)
    data["classification"]["class_uid"] = "fixture-private-value"
    assert "fixture-private" not in str(REGISTRY.validate(data))


def test_unmapped_fields_recoverable_from_raw_but_absent_from_export(
    client, store, request_payload, cloudtrail
):
    event = cloudtrail["Records"][0]
    event["arbitraryExtension"] = {"unmappedDetail": "fixture-restricted-provider-value"}
    status, report, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 201
    _, bundle, _ = client("GET", f"/v1/investigations/{report['id']}/events")
    serialized = json.dumps(bundle)
    assert (
        "fixture-restricted-provider-value" not in serialized and "fixture-token" not in serialized
    )
    archive = store.export_evidence(report["id"])
    assert "fixture-restricted-provider-value" in json.dumps(archive)
