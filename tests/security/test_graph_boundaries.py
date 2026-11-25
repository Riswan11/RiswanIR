from urllib.parse import urlencode

import pytest

from riswan_ir.knowledge_graph.ontology import Entity
from tests.fixtures.cloudtrail import ROOT, record

BASE = "/v1/investigations"


def test_case_and_account_isolation(client, store):
    account_a, account_b = "111122223333", "444455556666"
    records = [
        record(
            account,
            i,
            "GetObject",
            eventSource="s3.amazonaws.com",
            recipientAccountId=account,
            requestParameters={"bucketName": "same-name"},
        )
        for i, account in enumerate([account_a, account_b], 1)
    ]
    payload = {"title": "Account-scoped graph", "principal": ROOT, "records": records}
    _, first, _ = client("POST", BASE, payload)
    _, second, _ = client("POST", BASE, {**payload, "records": []})
    first_path = f"{BASE}/{first['id']}/knowledge-graph"
    second_path = f"{BASE}/{second['id']}/knowledge-graph"
    graph = store.security_graph(first["id"])
    resources = {node.account: node for node in graph.nodes if node.kind == Entity.RESOURCE}
    assert set(resources) == {account_a, account_b}
    assert resources[account_a].id != resources[account_b].id
    assert resources[account_a].label == resources[account_b].label == "same-name"
    assert client("GET", second_path + f"/nodes/{resources[account_a].id}")[0] == 404
    assert (
        client(
            "GET",
            first_path + f"/nodes/{resources[account_b].id}",
            headers={"QUERY_STRING": f"account={account_a}"},
        )[0]
        == 404
    )
    status, result, _ = client(
        "GET",
        first_path + "/traverse",
        headers={
            "QUERY_STRING": urlencode(
                {"node": resources[account_a].id, "depth": 4, "account": account_a}
            )
        },
    )
    assert status == 200
    assert all(node["account"] == account_a for node in result["nodes"])
    assert all(
        obs["event_id"] == account_a
        for edge in result["relationships"]
        for obs in edge["observations"]
    )


@pytest.mark.parametrize(
    ("suffix", "query"),
    [
        ("", "limit=1000"),
        ("", "limit=1&limit=2"),
        ("", "account=bad"),
        ("", "kind=foreign"),
        ("", "a=" + "x" * 2048),
        ("/traverse", "node=" + "a" * 64 + "&depth=5"),
        ("/traverse", "node=" + "a" * 64 + "&direction=sideways"),
        ("/ontology", "limit=5"),
    ],
)
def test_graph_rejects_invalid_and_unbounded_queries(client, request_payload, suffix, query):
    _, report, _ = client("POST", BASE, request_payload)
    path = f"{BASE}/{report['id']}/knowledge-graph{suffix}"
    assert client("GET", path, headers={"QUERY_STRING": query})[0] == 400
