"""Scoped, append-only graph snapshots for PostgreSQL-backed investigations."""

import json

from riswan_ir.knowledge_graph.models import SecurityGraph
from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import sha256


def append(db, context, case: str, snapshot: str) -> None:
    db.execute(
        "INSERT INTO riswan_data.case_graph_snapshots VALUES (%s, %s, %s, %s)",
        (context.tenant_id, context.product_id, case, snapshot),
    )

    graph = validate(case, snapshot)
    scope = (context.tenant_id, context.product_id, case)
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO riswan_data.case_graph_nodes VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
            [
                (*scope, node.id, i, node.model_dump_json(exclude_unset=True))
                for i, node in enumerate(graph.nodes)
            ],
        )
        cursor.executemany(
            "INSERT INTO riswan_data.case_graph_edges VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)",
            [
                (
                    *scope,
                    edge.id,
                    i,
                    edge.source,
                    edge.target,
                    edge.model_dump_json(exclude_unset=True),
                )
                for i, edge in enumerate(graph.relationships)
            ],
        )


def graph_from_rows(db, case: str, snapshot: str) -> SecurityGraph:
    archived = validate(case, snapshot)
    nodes = [
        row[0]
        for row in db.execute(
            "SELECT node FROM riswan_data.case_graph_nodes WHERE investigation_id = %s ORDER BY ordinal",
            (case,),
        )
    ]
    edges = [
        row[0]
        for row in db.execute(
            "SELECT edge FROM riswan_data.case_graph_edges WHERE investigation_id = %s ORDER BY ordinal",
            (case,),
        )
    ]
    raw = json.loads(snapshot)
    raw.update(nodes=nodes, relationships=edges)
    restored = SecurityGraph.model_validate_json(json.dumps(raw))
    if restored != archived:
        raise NotFoundError("Investigation graph unavailable.")
    return restored


def read(db, case: str, digest: str) -> str:
    row = db.execute(
        "SELECT snapshot FROM riswan_data.case_graph_snapshots WHERE investigation_id = %s",
        (case,),
    ).fetchone()
    if row is None or sha256(row[0]) != digest:
        raise NotFoundError("Investigation graph unavailable.")
    return str(row[0])


def validate(case: str, snapshot: str) -> SecurityGraph:
    graph = SecurityGraph.model_validate_json(snapshot)
    if graph.investigation_id != case:
        raise NotFoundError("Investigation graph unavailable.")
    return graph
