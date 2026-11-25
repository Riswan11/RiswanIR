import json
from urllib.parse import urlencode

from sentinelforge.storage.sqlite import Store
from tests.integration.test_risk_assessment import BASE, assessment, restoration, submit
from tests.integration.test_temporal_correlation import ACCOUNT, DESTINATION, ROOT, scenario


def clock(monkeypatch, day):
    instant = f"2025-01-{day:02d}T04:00:00+00:00"
    monkeypatch.setattr("sentinelforge.storage.sqlite.now", lambda: instant)
    return instant


def records(day, tag, account=ACCOUNT):
    return [
        {
            **item,
            "eventID": f"{tag}-{item['eventID']}",
            "eventTime": f"2025-01-{day:02d}T03:0{index + 1}:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": account,
            "userIdentity": {
                **item["userIdentity"],
                "type": "IAMUser",
                "arn": ROOT.replace(ACCOUNT, account),
                "accountId": account,
            },
        }
        for index, item in enumerate(scenario(10))
    ]


def review(client, report, disposition="confirmed"):
    status, _, _ = client(
        "POST",
        f"{BASE}/{report['id']}/feedback",
        {
            "reviewer": "Analyst",
            "disposition": disposition,
        },
    )
    assert status == 201


def memory(client, report, **query):
    status, body, _ = client(
        "GET",
        f"{BASE}/{report['id']}/memory",
        headers={
            "QUERY_STRING": urlencode(query),
        },
    )
    assert status == 200
    return body


def test_independent_case_recurrence_scores_risk_and_preserves_replay(client, store, monkeypatch):
    clock(monkeypatch, 1)
    first_records = records(1, "first")
    first = submit(client, first_records)
    review(client, first)
    clock(monkeypatch, 2)
    duplicate = submit(client, first_records)
    review(client, duplicate)
    second = submit(client, records(2, "second"))
    review(client, second)
    clock(monkeypatch, 3)
    current = submit(client, records(3, "current"))
    cutoff = clock(monkeypatch, 4)
    result = memory(client, current, as_of=cutoff)
    assert len(result["similar_investigations"]) == 2
    assert second["id"] in {item["investigation_id"] for item in result["similar_investigations"]}
    assert {item["similarity_score"] for item in result["similar_investigations"]} == {1}
    assert result["historical_recurrence"]["SF-AWS-DATA-003"] == 50
    risk = assessment(client, current, "finding")
    factor = next(
        item for item in risk["risk"]["contributions"] if item["factor"] == "historical_recurrence"
    )
    assert factor["value"] == 50 and "authorized historical" in factor["explanation"]
    assert (
        Store(store.path).risk_assessment(current["id"], risk["id"], replay=True).payload() == risk
    )
    assert memory(client, current, as_of=cutoff) == result
    with store.connect() as db:
        assert (
            db.execute("SELECT COUNT(*) FROM memory_audit WHERE action = 'retrieve'").fetchone()[0]
            == 2
        )
        contents = "".join(row[0] for row in db.execute("SELECT payload FROM memory_records"))
        assert "AKIACREATED7EXAMPLE" not in contents and "192.0.2.9" not in contents


def test_point_in_time_review_and_lifecycle(client, monkeypatch):
    clock(monkeypatch, 1)
    older = submit(client, records(1, "older"))
    cutoff = clock(monkeypatch, 2)
    current = submit(client, records(2, "query"))
    clock(monkeypatch, 3)
    review(client, older)
    assert memory(client, current, as_of=cutoff)["similar_investigations"] == []
    present = memory(client, current)
    assert present["similar_investigations"][0]["investigation_id"] == older["id"]
    case = f"{BASE}/{older['id']}"
    assert client("DELETE", case + "/memory")[0] == 200
    assert client("GET", case + "/memory")[0] == 404
    assert client("GET", case + "/evidence")[0] == 200
    assert client("POST", case + "/memory/index")[1] == {"indexed": False}
    assert memory(client, current)["similar_investigations"] == []
    assert client("GET", f"{BASE}/{current['id']}")[1]["similar_investigations"] == []


def test_expiration_enforces_category_retention(client, store, monkeypatch, tmp_path):
    config = tmp_path / "memory.json"
    config.write_text(
        json.dumps(
            {
                "retention_days": 7,
                "category_retention": {"feedback": 1},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SENTINELFORGE_MEMORY_POLICY", str(config))
    clock(monkeypatch, 1)
    older = submit(client, records(1, "older"))
    review(client, older)
    clock(monkeypatch, 3)
    current = submit(client, records(3, "query"))
    assert memory(client, current)["similar_investigations"] == []
    assert client("POST", "/v1/memory/expire")[1]["expired"] == 1
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM memory_cases").fetchone()[0] == 2


def test_only_custody_backed_residual_risk_can_enter_response_memory(client, monkeypatch):
    clock(monkeypatch, 1)
    earlier = submit(
        client,
        records(1, "historic")
        + [
            {
                **restoration(),
                "eventID": "restore",
                "eventTime": "2025-01-01T03:05:00Z",
                "awsRegion": "us-east-1",
            }
        ],
    )
    review(client, earlier)
    base = f"{BASE}/{earlier['id']}"
    ref = next(
        item["reference"]["evidence_id"] for item in earlier["evidence"] if item["id"] == "restore"
    )
    request = {"classification": "successful_remediation", "evidence_references": [ref]}
    assert client("POST", base + "/memory/feedback", request)[0] == 400
    finding = assessment(client, earlier, "finding")
    assert (
        client(
            "POST",
            base + "/risk/reassess",
            {
                "subject_kind": "finding",
                "subject_id": finding["subject_id"],
                "containment_evidence_id": ref,
            },
        )[0]
        == 200
    )
    assert client("POST", base + "/memory/feedback", request)[0] == 201
    clock(monkeypatch, 2)
    current = submit(client, records(2, "query"))
    assert memory(client, current)["response_history"] == {earlier["id"]: [ref]}


def test_legacy_case_can_be_indexed_from_verified_custody(client, store, monkeypatch):
    clock(monkeypatch, 1)
    older = submit(client, records(1, "legacy"))
    with store.connect() as db:
        db.execute("DELETE FROM memory_records")
        db.execute("DELETE FROM memory_accounts")
        db.execute("DELETE FROM memory_cases")
    path = f"{BASE}/{older['id']}/memory"
    assert client("GET", path)[0] == 404
    assert client("POST", path + "/index")[1] == {"indexed": True}
    assert client("GET", path)[0] == 200


def submit_foreign(client):
    status, report, _ = client(
        "POST",
        BASE,
        {
            "title": "Cross-account historical test",
            "principal": ROOT.replace(ACCOUNT, DESTINATION),
            "records": records(1, "foreign", DESTINATION),
        },
    )
    assert status == 201
    return report


def test_explicit_cross_account_policy_and_revocation(client, monkeypatch, tmp_path):
    clock(monkeypatch, 1)
    foreign = submit_foreign(client)
    review(client, foreign)
    clock(monkeypatch, 2)
    local = submit(client, records(2, "local"))
    assert memory(client, local)["similar_investigations"] == []
    assert client("GET", f"{BASE}/{local['id']}")[1]["similar_investigations"] == []
    policy = tmp_path / "authority.json"
    policy.write_text(
        json.dumps(
            {
                "version": "2.0.0",
                "organization_accounts": [[f"aws:{ACCOUNT}", f"aws:{DESTINATION}"]],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SENTINELFORGE_MEMORY_POLICY", str(policy))
    shared = submit(client, records(2, "authorized"))
    assert memory(client, shared)["similar_investigations"][0]["investigation_id"] == foreign["id"]
    restricted = json.loads(policy.read_text(encoding="utf-8"))
    restricted["cross_account_categories"] = ["episodic", "semantic"]
    policy.write_text(json.dumps(restricted), encoding="utf-8")
    assert memory(client, shared)["similar_investigations"] == []
    assert client("GET", f"{BASE}/{shared['id']}")[1]["similar_investigations"] == []
    monkeypatch.delenv("SENTINELFORGE_MEMORY_POLICY")
    assert memory(client, shared)["similar_investigations"] == []
