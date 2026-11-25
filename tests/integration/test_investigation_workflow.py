BASE = "/v1/investigations"


def test_investigate_review_and_decide(client, request_payload):
    status, report, _ = client("POST", BASE, request_payload)
    assert status == 201
    path = f"{BASE}/{report['id']}"
    assert report["assessment"]["severity"] == "high"
    status, evidence, _ = client("GET", path + "/evidence")
    assert status == 200
    assert [item["linked_from_evidence_id"] for item in evidence] == [
        None,
        "role-issued",
        "key-created",
    ]
    assert evidence == report["evidence"]
    assert client("GET", path + "/graph")[:2] == (200, report["graph"])
    ids = {item["id"] for item in evidence}
    assert all(set(claim["evidence_ids"]) <= ids for claim in report["assessment"]["claims"])
    assert report["action"]["evidence_ids"] == ["key-created"]
    status, reviewed, _ = client(
        "POST",
        path + "/feedback",
        {"reviewer": "Analyst", "disposition": "confirmed", "notes": "Credential chain reviewed"},
    )
    assert status == 201 and reviewed["reviews"][0]["notes"] == "Credential chain reviewed"
    advisory = path + "/actions/review-access-key"
    status, approved, _ = client("POST", advisory + "/approve", {"reviewer": "Analyst"})
    assert status == 201 and approved["decision"]["decision"] == "approve"
    assert client("POST", advisory + "/reject", {"reviewer": "Analyst"})[0] == 409
    _, next_report, _ = client("POST", BASE, request_payload)
    assert next_report["similar_investigations"][0]["id"] == report["id"]
    assert next_report["similar_investigations"][0]["disposition"] == "confirmed"


def test_empty_investigation_remains_reviewable(client, request_payload):
    status, report, _ = client("POST", BASE, {**request_payload, "records": []})
    assert status == 201
    assert report["assessment"]["severity"] == "unrated"
    assert report["evidence"] == [] and report["graph"] == [] and report["action"] is None
    path = f"{BASE}/{report['id']}"
    assert (
        client("POST", path + "/feedback", {"reviewer": "Analyst", "disposition": "inconclusive"})[
            0
        ]
        == 201
    )
