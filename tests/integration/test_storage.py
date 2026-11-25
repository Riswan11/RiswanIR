import json
import sqlite3

import pytest

from riswan_ir.core.errors import NotFoundError
from riswan_ir.models import ActionDecision, AnalystFeedback
from riswan_ir.storage.sqlite import Store


def test_persists_and_reopens_reports_reviews_and_decisions(store, investigation_request):
    first = store.create(investigation_request)
    store.feedback(
        first.id, AnalystFeedback(reviewer="Analyst", disposition="benign", notes="Scheduled")
    )
    decision = ActionDecision(reviewer="Analyst", decision="reject", created_at=first.created_at)
    store.decide(first.id, first.action.id, decision)
    reopened = Store(store.path)
    previous = reopened.get(first.id)
    assert previous.decision == decision
    assert previous.reviews[0].notes == "Scheduled"
    assert previous.evidence == first.evidence
    assert reopened.list()[0].id == first.id
    second = reopened.create(investigation_request)
    assert second.similar_investigations[0].id == first.id
    with pytest.raises(FileExistsError):
        reopened.decide(first.id, first.action.id, decision)
    assert reopened.get(first.id).decision == decision


def test_foreign_keys_and_transaction_rollback(store, investigation_request):
    case = store.create(investigation_request)
    insert = "INSERT INTO reviews (investigation_id, reviewer, disposition, notes, created_at) VALUES (?, ?, ?, ?, ?)"
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with store.connect() as db:
            db.execute(insert, (case.id, "Analyst", "benign", "", case.created_at))
            db.execute(insert, ("unknown", "Analyst", "benign", "", case.created_at))
    assert store.get(case.id).reviews == []
    with pytest.raises(NotFoundError):
        store.get("unknown")


def test_invalid_stored_report_raises_storage_error(store):
    with store.connect() as db:
        db.execute(
            "INSERT INTO investigations VALUES (?, ?, ?)", ("invalid", "2025-01-01T00:00:00Z", "{}")
        )
    with pytest.raises(RuntimeError, match="Invalid stored investigation report"):
        store.get("invalid")


def test_reads_legacy_sqlite_payload_without_adding_fields(tmp_path):
    when = "2025-01-01T00:00:00+00:00"
    principal = "arn:aws:iam::123456789012:user/test"
    legacy = {
        "id": "legacy",
        "created_at": when,
        "title": "Legacy investigation",
        "principal": principal,
        "plan": [],
        "graph": [],
        "action": None,
        "evidence": [
            {
                "id": "old",
                "source": "aws.cloudtrail",
                "observed_at": when,
                "event": "AssumeRole",
                "principal": principal,
                "target": None,
                "query": "Exact principal ARN match",
                "integrity_hash": "sha256:" + "a" * 64,
            }
        ],
        "assessment": {
            "severity": "low",
            "score": 20,
            "score_max": 70,
            "observed_targets": [],
            "open_questions": [],
            "claims": [
                {
                    "summary": "Role assumption observed",
                    "evidence_ids": ["old"],
                    "possible_attack_technique": "T1078",
                }
            ],
        },
    }
    store = Store(tmp_path / "legacy.sqlite3")
    with store.connect() as db:
        db.execute(
            "INSERT INTO investigations VALUES (?, ?, ?)", ("legacy", when, json.dumps(legacy))
        )
        db.execute(
            "INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)",
            (1, "legacy", "Analyst", "benign", "", when),
        )
    payload = store.get("legacy").payload()
    assert payload["evidence"] == legacy["evidence"]
    assert payload["assessment"] == legacy["assessment"]
    assert payload["reviews"][0]["disposition"] == "benign"
    assert store.list()[0].title == legacy["title"]
