import json

import pytest

from riswan_ir.risk.registry import load_policies
from tests.integration.test_risk_assessment import BASE, assessment, restoration, submit
from tests.integration.test_temporal_correlation import scenario


@pytest.mark.parametrize(
    "data",
    [
        b"- !!python/object/apply:os.system ['unused']",
        b"- &a {id: bad}\n- *a",
        b"- {id: x, id: y}",
        b'- {id: x, version: "1.0.0", risk: {a: 99}, confidence: {b: 100}}',
    ],
)
def test_policy_validation_rejects_unsafe_or_inconsistent_input(data):
    with pytest.raises(ValueError):
        load_policies(data)


def test_case_scoping_and_containment_evidence_validation(client):
    first = submit(client, scenario(10) + [restoration(bucket="other-bucket")])
    second = submit(client, scenario(10) + [restoration()])
    finding = assessment(client, first, "finding")
    first_path, second_path = f"{BASE}/{first['id']}/risk", f"{BASE}/{second['id']}/risk"
    assert client("GET", second_path + "/" + finding["id"])[0] == 404
    assert client("GET", first_path, headers={"HTTP_HOST": "attacker.invalid"})[0] == 400
    assert client("GET", first_path, headers={"QUERY_STRING": "limit=101"})[0] == 400
    assert client("GET", first_path, headers={"QUERY_STRING": "limit=1&limit=2"})[0] == 400
    for report in (first, second):
        other = next(item for item in report["evidence"] if item["id"] == "restore")
        payload = {
            "subject_kind": "finding",
            "subject_id": finding["subject_id"],
            "containment_evidence_id": other["reference"]["evidence_id"],
        }
        assert client("POST", first_path + "/reassess", payload)[0] == 400
    injection = {"subject_kind": "finding", "subject_id": finding["subject_id"], "risk_score": 0}
    assert client("POST", first_path + "/reassess", injection)[0] == 400
    assert assessment(client, first, "finding") == finding


def test_resource_inventory_is_scoped_to_each_account(client, tmp_path, monkeypatch):
    from tests.integration.test_temporal_correlation import ACCOUNT, BUCKET, DESTINATION, ROOT

    config = tmp_path / "inventory.json"
    config.write_text(
        json.dumps(
            {
                "asset_criticality": {
                    f"{ACCOUNT}/{BUCKET}": "critical",
                    f"{DESTINATION}/{BUCKET}": "standard",
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RISWAN_IR_RISK_INVENTORY", str(config))
    raw = scenario(10)[0]
    first = submit(client, [raw])
    principal = ROOT.replace(ACCOUNT, DESTINATION)
    other = {
        **raw,
        "eventID": "other-account",
        "recipientAccountId": DESTINATION,
        "userIdentity": {**raw["userIdentity"], "arn": principal, "accountId": DESTINATION},
    }
    status, second, _ = client(
        "POST",
        BASE,
        {
            "title": "Second account",
            "principal": principal,
            "records": [other],
        },
    )
    assert status == 201
    findings = [assessment(client, item, "finding") for item in (first, second)]
    assert [
        item["value"]
        for finding in findings
        for item in finding["risk"]["contributions"]
        if item["factor"] == "asset_criticality"
    ] == [100, 25]
