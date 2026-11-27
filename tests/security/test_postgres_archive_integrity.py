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


@pytest.mark.parametrize("kind", ["temporal", "risk"])
def test_valid_archive_from_another_investigation_is_denied(store, kind):
    from riswan_ir.models import InvestigationRequest
    from tests.integration.test_risk_assessment import restoration
    from tests.integration.test_temporal_correlation import ROOT, scenario

    case = store.create(
        InvestigationRequest(
            title="Archive owner", principal=ROOT, records=scenario(10) + [restoration()]
        )
    ).id
    with store.connect() as db:
        if kind == "temporal":
            (snapshot,) = db.execute(
                "SELECT snapshot FROM temporal_correlations WHERE investigation_id = ?", (case,)
            ).fetchone()
            reader = Mock()
            reader.execute.return_value.fetchone.return_value = (snapshot,)
            verified = postgres_intelligence.temporal_snapshot(
                reader, "different-case", sha256(snapshot)
            )
            with pytest.raises(NotFoundError, match="Temporal archive unavailable"):
                postgres_intelligence.parse_temporal("different-case", verified)
        else:
            rows = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM risk_assessments WHERE investigation_id = ?", (case,)
                )
            ]
            assert rows
            for row in rows:
                row["investigation_id"] = "different-case"
            reader = Mock()
            reader.execute.return_value = [
                (row["ordinal"], row["id"], row["kind"], row["subject_id"], row["archive"])
                for row in rows
            ]
            verified = postgres_intelligence.risk_rows(
                reader, "different-case", postgres_intelligence.risk_digest(rows)
            )
            with pytest.raises(NotFoundError, match="Risk archive unavailable"):
                postgres_intelligence.parse_risk("different-case", verified)
        assert reader.execute.call_count == 1
        assert reader.execute.call_args.args[0].lstrip().startswith("SELECT")


def test_memory_journal_rejects_mismatched_case_metadata():
    from riswan_app.postgres_memory import restore_history

    when = "2026-01-25T00:00:00.000000+00:00"
    db = Mock()
    staging = Mock()
    db.execute.return_value = [
        ("feedback", 4, when, [4, "another-case", when, when, "{}", "digest"]),
    ]
    with pytest.raises(NotFoundError, match="Historical memory entry unavailable"):
        restore_history(db, staging, "requested-case", cutoff=when)
    assert db.execute.call_count == 1
    assert db.execute.call_args.args[0].lstrip().startswith("SELECT")
    staging.execute.assert_not_called()
