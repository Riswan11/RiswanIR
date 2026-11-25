import json

BASE = "/v1/investigations"


def test_new_reports_export_anchored_canonical_events(client, store, request_payload, cloudtrail):
    for item in cloudtrail["Records"]:
        item["sourceIPAddress"] = "203.0.113.20"
    status, report, _ = client("POST", BASE, request_payload)
    assert status == 201 and report["assessment"]["severity"] == "high"
    case = f"{BASE}/{report['id']}"
    status, bundle, _ = client("GET", case + "/events")
    assert status == 200 and bundle["representation"] == "stored"
    assert [item["metadata"]["uid"] for item in bundle["events"]] == [
        item["id"] for item in report["evidence"]
    ]
    for raw, event in zip(report["evidence"], bundle["events"], strict=True):
        assert event["unmapped"]["sentinelforge"]["evidence"] == raw["reference"]
    assert store.verify_evidence(report["id"]).valid
    report["canonical_events"][0]["metadata"]["product"] = "changed"
    with store.connect() as db:
        db.execute(
            "UPDATE investigations SET report = ? WHERE id = ?", (json.dumps(report), report["id"])
        )
    assert (
        "Canonical event snapshot verification failed."
        in store.verify_evidence(report["id"]).problems
    )


def test_legacy_projection_does_not_rewrite_old_sqlite_row(client, store):
    case_id = "f" * 32
    when = "2025-01-01T00:00:00Z"
    legacy = {
        "id": case_id,
        "title": "Legacy",
        "created_at": when,
        "principal": "legacy",
        "plan": [],
        "graph": [],
        "action": None,
        "evidence": [
            {
                "id": "old",
                "source": "aws.cloudtrail",
                "event": "UnknownOperation",
                "observed_at": when,
                "query": "Exact principal ARN match",
                "integrity_hash": "sha256:" + "a" * 64,
            }
        ],
        "assessment": {
            "severity": "unrated",
            "score": 0,
            "score_max": 70,
            "claims": [],
            "open_questions": [],
            "observed_targets": [],
        },
    }
    serialized = json.dumps(legacy)
    with store.connect() as db:
        db.execute("INSERT INTO investigations VALUES (?, ?, ?)", (case_id, when, serialized))
    status, projected, _ = client("GET", f"{BASE}/{case_id}/events")
    assert status == 200 and projected["representation"] == "legacy_projection"
    event = projected["events"][0]
    assert event["class_uid"] == 0 and event["metadata"]["uid"] == "old"
    assert event["status_id"] == 0
    assert "evidence" not in event["unmapped"]["sentinelforge"]
    assert "canonical_events" not in client("GET", f"{BASE}/{case_id}")[1]
    with store.connect() as db:
        assert (
            db.execute("SELECT report FROM investigations WHERE id = ?", (case_id,)).fetchone()[0]
            == serialized
        )
