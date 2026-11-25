from urllib.parse import urlencode

import pytest

from riswan_ir.knowledge_graph.builder import build_security_graph
from riswan_ir.knowledge_graph.ontology import VERSION, Entity, Relation
from riswan_ir.storage.sqlite import Store


def graph_path(report):
    return f"/v1/investigations/{report['id']}/knowledge-graph"


def test_persistent_graph_traverses_correlated_activity_and_provenance(
    client, store, request_payload
):
    _, report, _ = client("POST", "/v1/investigations", request_payload)
    case_id = report["id"]
    graph = Store(store.path).security_graph(case_id)
    assert graph == build_security_graph(store.get(case_id))
    assert graph.ontology_version == VERSION
    nodes = {node.id: node for node in graph.nodes}

    by_relation = {}
    for edge in graph.relationships:
        by_relation.setdefault(edge.relation, []).append(edge)
        for observation in edge.observations:
            assert observation.source == "aws.cloudtrail"
            assert observation.evidence_id
            assert observation.observed_at

    (assumed,) = by_relation[Relation.ASSUMED_ROLE]
    assert nodes[assumed.source].label.endswith("/build")
    assert nodes[assumed.target].label.endswith("/Example")
    assert assumed.observations[0].confidence == "confirmed"
    assert assumed.observations[0].event_id == "role-issued"
    (established,) = by_relation[Relation.ESTABLISHED_SESSION]
    assert nodes[established.target].kind == Entity.SESSION

    (access,) = by_relation[Relation.ACCESSED_RESOURCE]
    assert nodes[access.target].label == "example-archive"
    assert [item.event_id for item in access.observations] == ["key-used"]
    assert any(
        edge.source == access.source and nodes[edge.target].key == "key-used"
        for edge in by_relation[Relation.PERFORMED_ACTION]
    )
    assert len(by_relation[Relation.DERIVED_FROM]) == len(report["evidence"])
    assert by_relation[Relation.INDICATES_TECHNIQUE]
    assert by_relation[Relation.CHAINED_TO]

    base = graph_path(report)
    status, page, _ = client("GET", base, headers={"QUERY_STRING": "limit=2"})
    assert status == 200 and page["next_offset"] == 2 and len(page["nodes"]) == 2
    status, edges, _ = client(
        "GET",
        base + "/relationships",
        headers={"QUERY_STRING": urlencode({"source": access.source, "target": access.target})},
    )
    assert status == 200 and [item["id"] for item in edges["relationships"]] == [access.id]
    status, detail, _ = client("GET", f"{base}/relationships/{access.id}")
    assert status == 200 and detail["evidence"][0]["key"] == access.observations[0].evidence_id
    derived = by_relation[Relation.DERIVED_FROM][0]
    _, lineage, _ = client("GET", f"{base}/relationships/{derived.id}")
    assert {item["metadata"]["representation"] for item in lineage["evidence"]} == {
        "raw",
        "normalized",
    }

    query = urlencode(
        {
            "node": access.target,
            "depth": 2,
            "relations": ["ACCESSED_RESOURCE", "AUTHENTICATED_AS"],
        },
        doseq=True,
    )
    status, traversal, _ = client("GET", base + "/traverse", headers={"QUERY_STRING": query})
    assert status == 200 and {item["kind"] for item in traversal["nodes"]} == {
        "resource",
        "session",
        "identity",
    }
    assert client("GET", base + "/ontology")[1]["version"] == VERSION
    assert client("GET", f"{base}/nodes/{access.target}")[1]["label"] == "example-archive"

    status, _, _ = client(
        "POST",
        base.removesuffix("/knowledge-graph") + "/actions/review-access-key/approve",
        {"reviewer": "Analyst"},
    )
    assert status == 201
    updated = Store(store.path).security_graph(case_id)
    assert updated == build_security_graph(store.get(case_id))
    assert (
        next(node for node in updated.nodes if node.kind == Entity.ACTION).metadata["status"]
        == "approve"
    )


def test_snapshot_upsert_and_legacy_projection(store, investigation_request):
    from riswan_ir.knowledge_graph.repository import SQLiteGraphRepository

    report = store.create(investigation_request)
    graph = store.security_graph(report.id)
    with store.connect() as db:
        repository = SQLiteGraphRepository(db)
        repository.save(graph)
        repository.save(build_security_graph(report))
        assert db.execute("SELECT COUNT(*) FROM security_graphs").fetchone()[0] == 1
        db.execute("DELETE FROM security_graphs WHERE investigation_id = ?", (report.id,))
    assert store.security_graph(report.id) == graph
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM security_graphs").fetchone()[0] == 0


def test_graph_creation_failure_rolls_back_investigation(store, investigation_request, monkeypatch):
    def fail(report):
        raise ValueError("Graph construction failed.")

    monkeypatch.setattr("riswan_ir.storage.sqlite.build_security_graph", fail)
    with pytest.raises(ValueError, match="Graph construction failed"):
        store.create(investigation_request)
    assert store.list() == []
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM security_graphs").fetchone()[0] == 0
