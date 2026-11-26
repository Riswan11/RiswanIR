"""Scoped, append-only graph snapshots for PostgreSQL-backed investigations."""

from riswan_ir.knowledge_graph.models import SecurityGraph
from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import sha256


def append(db, context, case: str, snapshot: str) -> None:
    db.execute(
        "INSERT INTO riswan_data.case_graph_snapshots VALUES (%s, %s, %s, %s)",
        (context.tenant_id, context.product_id, case, snapshot),
    )


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
