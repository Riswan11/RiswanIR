from tests.integration.test_historical_memory import clock, memory, records, review
from tests.integration.test_risk_assessment import BASE, submit


def test_feedback_scope_and_custody_controls(client, store, monkeypatch):
    clock(monkeypatch, 1)
    first = submit(client, records(1, "first"))
    clock(monkeypatch, 2)
    second = submit(client, records(2, "second"))
    path = f"{BASE}/{first['id']}/memory"
    ref = first["evidence"][0]["reference"]["evidence_id"]
    foreign = second["evidence"][0]["reference"]["evidence_id"]
    request = {"classification": "authorized_activity", "evidence_references": [ref]}
    assert client("POST", path + "/feedback", request)[0] == 400
    review(client, first)
    assert client("POST", path + "/feedback", request)[0] == 400
    review(client, first, "benign")
    assert (
        client("POST", path + "/feedback", {**request, "evidence_references": [foreign]})[0] == 400
    )
    assert client("POST", path + "/feedback", request)[0] == 201
    assert client("GET", path, headers={"HTTP_HOST": "external.invalid"})[0] == 400
    assert (
        memory(client, second)["similar_investigations"][0]["classification"]
        == "authorized_activity"
    )
    with store.connect() as db:
        db.execute(
            "UPDATE memory_records SET payload = '{}' WHERE case_id = ? AND category = 'semantic'",
            (first["id"],),
        )
    assert memory(client, second)["similar_investigations"] == []
