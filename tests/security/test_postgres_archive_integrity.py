"""Archive integrity failures must deny retrieval before domain processing."""

import json
from unittest.mock import Mock

import pytest

from riswan_app import postgres_graphs, postgres_intelligence
from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import canonical_json, sha256


@pytest.mark.parametrize(
    ("reader", "payload", "digest"),
    [
        (postgres_graphs.read, "graph", sha256("original graph")),
        (postgres_intelligence.temporal_snapshot, "temporal", sha256("original temporal")),
        (
            postgres_intelligence.read_memory,
            {"memory_records": []},
            sha256(canonical_json({"memory_records": [{"id": "removed"}]})),
        ),
    ],
    ids=["graph", "temporal", "memory"],
)
@pytest.mark.parametrize("missing", [True, False], ids=["missing", "modified"])
def test_archive_rejects_missing_or_modified_records(reader, payload, digest, missing):
    db = Mock()
    db.execute.return_value.fetchone.return_value = None if missing else (payload,)
    with pytest.raises(NotFoundError):
        reader(db, "authorized-case", digest)
    assert db.execute.call_args.args[1] == ("authorized-case",)


def test_risk_history_rejects_replaced_initial_assessment():
    initial = {
        "ordinal": 1,
        "id": "original",
        "investigation_id": "authorized-case",
        "kind": "finding",
        "subject_id": "subject",
        "archive": "{}",
    }
    db = Mock()
    db.execute.return_value = [(1, "replacement", "finding", "subject", "{}")]
    with pytest.raises(NotFoundError, match="Risk archive unavailable"):
        postgres_intelligence.risk_rows(
            db, "authorized-case", postgres_intelligence.risk_digest([initial]), 1
        )


def test_graph_archive_cannot_be_reused_for_another_case(store, client, request_payload):
    status, report, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 201
    graph = store.security_graph(report["id"])
    with pytest.raises(NotFoundError, match="Investigation graph unavailable"):
        postgres_graphs.validate("another-case", graph.model_dump_json())


def test_graph_rows_cannot_change_archived_node_metadata(store, client, request_payload):
    status, report, _ = client("POST", "/v1/investigations", request_payload)
    assert status == 201
    graph = store.security_graph(report["id"])
    snapshot = graph.model_dump_json()
    rows = json.loads(snapshot)
    rows["nodes"][0]["label"] = "Changed after archival"
    db = Mock()
    db.execute.side_effect = [
        [(node,) for node in rows["nodes"]],
        [(edge,) for edge in rows["relationships"]],
    ]
    with pytest.raises(NotFoundError, match="Investigation graph unavailable"):
        postgres_graphs.graph_from_rows(db, report["id"], snapshot)
