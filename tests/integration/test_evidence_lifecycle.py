import json
import sqlite3
import sys
from datetime import datetime, timezone

import pytest

from sentinelforge.evidence import cli
from sentinelforge.models.chain_of_custody import EvidenceRetentionPolicy
from sentinelforge.storage.sqlite import SCHEMA, Store


def test_raw_deduplication_preserves_receipts_and_versioned_references(
    store, investigation_request, monkeypatch
):
    request = investigation_request.model_copy(deep=True)
    request.records.append(request.records[0])
    request.provenance.source_location = "operator-export.json"
    request.provenance.collector_id = "workstation"
    report = store.create(request)
    assert len(report.evidence) == 3
    assert all(item.reference is not None for item in report.evidence)
    reopened = Store(store.path)
    exported = reopened.export_evidence(report.id)
    raw = exported["raw_evidence"]
    receipts = exported["provenance"]
    transforms = exported["transformations"]
    assert len(raw) == 3 and len(receipts) == 4 and len(transforms) == 3
    assert receipts[0] == receipts[-1]
    assert receipts[0]["source_location"] == "operator-export.json"
    assert receipts[0]["collector_id"] == "workstation"
    assert receipts[0]["source_authenticity_verified"] is False
    original = next(item["record"] for item in raw if item["record"]["eventID"] == "role-issued")
    assert original == request.records[0]
    assert {item["parent_evidence_id"] for item in transforms} == {
        item["evidence_id"] for item in raw
    }
    assert {item["evidence_id"] for item in transforms} == {
        item.reference.evidence_id for item in report.evidence
    }
    assert all(item["normalization_version"] and item["schema_version"] for item in transforms)
    assert [entry["action"] for entry in exported["custody"]] == [
        "ingested",
        "normalized",
        "verified",
        "export_prepared",
    ]
    monkeypatch.setattr("sentinelforge.storage.sqlite.now", lambda: "2025-01-10T04:00:00+00:00")
    next_case = store.create(request)
    assert next_case.evidence[0].reference.evidence_id != report.evidence[0].reference.evidence_id
    assert (
        next_case.evidence[0].reference.parent_evidence_id
        == report.evidence[0].reference.parent_evidence_id
    )
    policy = EvidenceRetentionPolicy(days=5)
    assert store.expire_evidence(policy, datetime(2025, 1, 12, tzinfo=timezone.utc)) == 0
    assert store.expire_evidence(policy, datetime(2025, 1, 20, tzinfo=timezone.utc)) == 3
    assert store.expire_evidence(policy, datetime(2025, 1, 20, tzinfo=timezone.utc)) == 0
    retained = store.export_evidence(report.id)
    assert all(item["record"] is None for item in retained["raw_evidence"])
    assert retained["verification"]["expired_raw"] == 3
    assert any(entry["action"] == "raw_expired" for entry in retained["custody"])


def test_invalid_submission_rolls_back_raw_rows(store, investigation_request):
    request = investigation_request.model_copy(deep=True)
    request.records[0]["eventTime"] = "invalid"
    with pytest.raises(ValueError, match="invalid_timestamp"):
        store.create(request)
    with store.connect() as db:
        for table in (
            "investigations",
            "raw_evidence",
            "raw_evidence_payloads",
            "evidence_receipts",
            "evidence_custody",
        ):
            count = db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            assert count == 0


def test_additive_migration_preserves_legacy_report(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    timestamp = "2025-01-01T00:00:00Z"
    legacy = {
        "id": "legacy",
        "created_at": timestamp,
        "title": "Legacy report",
        "principal": "local",
        "plan": [],
        "evidence": [],
        "graph": [],
        "action": None,
        "assessment": {
            "severity": "unrated",
            "score": 0,
            "score_max": 100,
            "claims": [],
            "open_questions": [],
            "observed_targets": [],
        },
    }
    db = sqlite3.connect(path)
    try:
        with db:
            db.executescript(SCHEMA)
            db.execute(
                "INSERT INTO investigations VALUES (?, ?, ?)",
                ("legacy", timestamp, json.dumps(legacy)),
            )
    finally:
        db.close()
    store = Store(path)
    assert store.get("legacy").title == "Legacy report"
    assert Store(path).verify_evidence("legacy").problems == [
        "Evidence custody anchors unavailable."
    ]


def test_unmatched_raw_events_are_preserved_without_normalized_links(store, investigation_request):
    request = investigation_request.model_copy(deep=True)
    request.principal = "arn:aws:iam::123456789012:user/unrelated"
    report = store.create(request)
    bundle = store.export_evidence(report.id)
    assert len(bundle["raw_evidence"]) == 3
    assert bundle["transformations"] == [] and report.evidence == []


def test_cli_forensic_export_and_confirmation(
    store, investigation_request, monkeypatch, tmp_path, capsys
):
    report = store.create(investigation_request)
    output = tmp_path / "export.json"
    arguments = ["sentinelforge-evidence", "--db", str(store.path)]
    monkeypatch.setattr(sys, "argv", [*arguments, "verify", report.id])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["raw_checked"] == 3
    monkeypatch.setattr(sys, "argv", [*arguments, "export", report.id, str(output)])
    assert cli.main() == 0
    assert "fixture-secret" not in capsys.readouterr().out
    original = output.read_bytes()
    assert b"fixture-secret" in original
    assert cli.main() == 1 and output.read_bytes() == original
    monkeypatch.setattr(sys, "argv", [*arguments, "expire", "--days", "1"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
