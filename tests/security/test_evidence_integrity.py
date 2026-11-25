import hashlib
import json


def canonical_hash(fields):
    serialized = json.dumps(fields, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(serialized.encode()).hexdigest()


def test_persisted_evidence_hash_detects_changed_fields_and_excludes_secrets(
    client, request_payload
):
    assert "fixture-secret" in json.dumps(request_payload)
    status, report, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 201
    evidence = client("GET", f"/v1/investigations/{report['id']}/evidence")[1]
    for forbidden in ("fixture-secret", "fixture-token", "ASIAEXAMPLE", "AKIAEXAMPLE"):
        assert forbidden not in json.dumps(report)
    row = evidence[1].copy()
    digest = row.pop("integrity_hash")
    assert canonical_hash(row) == digest
    row["source_ip"] = "203.0.113.90"
    assert canonical_hash(row) != digest
