import json

from riswan_ir.storage.sqlite import Store
from tests.integration.test_temporal_correlation import ACCOUNT, BUCKET, ROOT, activity, scenario

BASE = "/v1/investigations"


def submit(client, records):
    status, report, _ = client(
        "POST", BASE, {"title": "Risk review", "principal": ROOT, "records": records}
    )
    assert status == 201
    return report


def restoration(event_id="restore", bucket=BUCKET):
    return activity(
        event_id,
        5,
        "s3",
        "DeleteBucketPolicy",
        recipientAccountId=ACCOUNT,
        requestParameters={"bucketName": bucket},
    )


def assessment(client, report, kind):
    result = client("GET", f"{BASE}/{report['id']}/risk")[1]
    return next(item for item in result["assessments"] if item["subject_kind"] == kind)


def test_persisted_risk_reassessment_preserves_original_and_replays(
    client, store, tmp_path, monkeypatch
):
    report = submit(client, scenario(10) + [restoration()])
    base = f"{BASE}/{report['id']}"
    finding = assessment(client, report, "finding")
    incident = assessment(client, report, "incident")
    assert finding["risk"]["score"] != finding["confidence"]["score"]
    assert incident["evidence_references"]
    assert finding["residual_risk"] is None
    assert finding["original_assessment_id"] == finding["id"]
    assert "risk.historical_recurrence" in finding["missing_context"]
    assert (
        Store(store.path).risk_assessment(report["id"], finding["id"], replay=True).payload()
        == finding
    )

    history = f"{base}/risk/finding/{finding['subject_id']}/history"
    ref = next(
        item["reference"]["evidence_id"] for item in report["evidence"] if item["id"] == "restore"
    )
    payload = {
        "subject_kind": "finding",
        "subject_id": finding["subject_id"],
        "containment_evidence_id": ref,
    }
    status, contained, _ = client("POST", base + "/risk/reassess", payload)
    assert status == 200
    assert contained["trigger"] == "containment"
    assert contained["original_risk_score"] == finding["risk"]["score"]
    assert contained["risk"]["score"] == finding["risk"]["score"]
    assert contained["residual_risk"]["score"] < contained["risk"]["score"]
    assert contained["containment_reference"] == ref and ref in contained["evidence_references"]
    assert client("POST", base + "/risk/reassess", payload)[1]["id"] == contained["id"]
    assert client("GET", history)[1]["assessments"] == [contained, finding]

    config = tmp_path / "risk-inventory.json"
    config.write_text(json.dumps({"business_impact": {BUCKET: 100}}), encoding="utf-8")
    monkeypatch.setenv("RISWAN_IR_RISK_INVENTORY", str(config))
    status, changed, _ = client(
        "POST",
        base + "/risk/reassess",
        {"subject_kind": "finding", "subject_id": finding["subject_id"]},
    )
    assert status == 200 and changed["original_assessment_id"] == finding["id"]
    assert changed["risk"]["score"] != contained["risk"]["score"]
    assert changed["previous_assessment_id"] == contained["id"]
    assert client("GET", base + f"/risk/{changed['id']}/replay")[1] == changed
    assert client("GET", base + f"/risk/{finding['id']}")[1] == finding

    status, _, _ = client(
        "POST", base + "/feedback", {"reviewer": "Local analyst", "disposition": "benign"}
    )
    assert status == 201
    latest = client("GET", history)[1]["assessments"][0]
    assert latest["assessment_status"] == "dismissed"
    assert (
        latest["investigation_priority"] == "P4"
        and latest["original_assessment_id"] == finding["id"]
    )
    assert client("GET", base + f"/risk/{latest['id']}/replay")[1] == latest
    assert client("GET", history, headers={"QUERY_STRING": "limit=1"})[1]["next_offset"] == 1


def test_revisions_keep_original_risk_and_invalidate_superseded_containment(client):
    raw = scenario(10)
    report = submit(client, [*raw, restoration()])
    base = f"{BASE}/{report['id']}"
    original = assessment(client, report, "finding")
    removal = next(item for item in report["evidence"] if item["id"] == "restore")
    args = {
        "subject_kind": "finding",
        "subject_id": original["subject_id"],
        "containment_evidence_id": removal["reference"]["evidence_id"],
    }
    assert client("POST", base + "/risk/reassess", args)[0] == 200
    reopened = {**raw[0], "eventID": "reopened", "eventTime": "2021-01-22T00:06:00Z"}
    status, revised, _ = client("POST", base + "/revisions", {"records": [reopened]})
    assert status == 201
    current = client(
        "GET", f"{BASE}/{revised['id']}/risk/finding/{original['subject_id']}/history"
    )[1]["assessments"]
    (item,) = current
    assert item["trigger"] == "revision" and item["original_assessment_id"] == original["id"]
    assert item["residual_risk"] is None
    assert client("GET", f"{BASE}/{revised['id']}/risk/{item['id']}/replay")[1] == item


def test_new_policy_is_versioned_and_archived_separately(client, monkeypatch, tmp_path):
    from riswan_ir.risk.registry import default_policy

    report = submit(client, scenario(10))
    original = assessment(client, report, "finding")
    config = tmp_path / "scoring.yml"
    policy = default_policy().model_dump(mode="json")
    version = {**policy, "version": "2.0.0", "severity_thresholds": [10, 20, 30, 40]}
    config.write_text(json.dumps([version, policy]), encoding="utf-8")
    monkeypatch.setenv("RISWAN_IR_RISK_POLICY", str(config))
    path = f"{BASE}/{report['id']}/risk"
    status, result, _ = client(
        "POST",
        path + "/reassess",
        {"subject_kind": "finding", "subject_id": original["subject_id"]},
    )
    assert status == 200
    assert result["policy_version"] == "2.0.0" and result["severity"] == "critical"
    assert result["policy_digest"] != original["policy_digest"]
    assert client("GET", path + f"/{original['id']}/replay")[1] == original


def test_case_evidence_integrity_conflict_is_reported(client, store):
    report = submit(client, scenario(10))
    original = assessment(client, report, "finding")
    with store.connect() as db:
        db.execute("UPDATE raw_evidence_payloads SET payload = ?", ('{"changed":true}',))
    path = f"{BASE}/{report['id']}/risk"
    status, result, _ = client(
        "POST",
        path + "/reassess",
        {"subject_kind": "finding", "subject_id": original["subject_id"]},
    )
    assert status == 200
    assert result["risk"] == original["risk"]
    contribution = next(
        item
        for item in result["confidence"]["contributions"]
        if item["factor"] == "evidence_integrity"
    )
    assert contribution["status"] == "conflicting" and contribution["value"] == 0
    assert result["assessment_status"] == "provisional"
