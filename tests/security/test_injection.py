import pytest


@pytest.mark.parametrize("text", ["Analyst's review; SELECT", "<sample> & \"quoted\"", "SQL comment marker --"])
def test_metacharacters_remain_literal_in_sqlite_and_json(client, text, request_payload):
    base = "/v1/investigations"
    status, report, _ = client("POST", base, {**request_payload, "title": text})
    assert status == 201 and report["title"] == text
    case = f"{base}/{report['id']}"
    status, reviewed, _ = client("POST", case + "/feedback", {
        "reviewer": text, "disposition": "suspicious", "notes": text})
    assert status == 201
    assert reviewed["reviews"][0]["reviewer"] == text
    assert reviewed["reviews"][0]["notes"] == text
    assert client("GET", case)[1]["title"] == text
    assert len(client("GET", base)[1]) == 1
