import json

import pytest

from trailhound.evidence.integrity import canonical_json, sha256


@pytest.mark.parametrize("target", ["raw", "normalized", "custody", "provenance", "missing"])
def test_independent_verification_detects_tampering(store, investigation_request, target):
    report = store.create(investigation_request)
    with store.connect() as db:
        if target == "raw":
            db.execute("UPDATE raw_evidence_payloads SET payload = ?", ("{}",))
        elif target == "normalized":
            payload = report.payload()
            item = payload["evidence"][0]
            item["region"] = "us-west-2"
            item.pop("integrity_hash")
            item["integrity_hash"] = sha256(canonical_json(item))
            db.execute(
                "UPDATE investigations SET report = ? WHERE id = ?",
                (json.dumps(payload), report.id),
            )
        elif target == "custody":
            db.execute("DELETE FROM evidence_custody WHERE sequence = 1")
        elif target == "provenance":
            row = db.execute(
                "SELECT provenance FROM evidence_receipts WHERE ordinal = 0"
            ).fetchone()
            provenance = json.loads(row["provenance"])
            provenance["source_region"] = "us-west-2"
            db.execute(
                "UPDATE evidence_receipts SET provenance = ? WHERE ordinal = 0",
                (json.dumps(provenance),),
            )
        else:
            db.execute("DELETE FROM raw_evidence_payloads")
    verification = store.verify_evidence(report.id)
    assert not verification.valid and verification.problems
    with pytest.raises(ValueError, match="valid evidence"):
        store.export_evidence(report.id)


def test_raw_evidence_not_available_in_http_or_failure_logs(
    client, store, request_payload, monkeypatch, caplog
):
    status, report, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 201
    assert "fixture-secret" not in json.dumps(report)
    assert client("GET", f"/v1/investigations/{report['id']}/raw")[0] == 404

    def broken(_request):
        raise RuntimeError("fixture-secret")

    monkeypatch.setattr(store, "create", broken)
    status, body, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 500 and "fixture-secret" not in str(body) + caplog.text
