"""Store correlation results and immutable rule inputs with their case revision."""

import sqlite3

from .models import TemporalSnapshot

SCHEMA = """
CREATE TABLE IF NOT EXISTS temporal_correlations (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    snapshot TEXT NOT NULL
);
"""


def load(db: sqlite3.Connection, case_id: str) -> TemporalSnapshot | None:
    row = db.execute(
        "SELECT snapshot FROM temporal_correlations WHERE investigation_id = ?", (case_id,)
    ).fetchone()
    if row is None:
        return None
    snapshot = TemporalSnapshot.model_validate_json(row[0])
    if snapshot.result.investigation_id != case_id:
        raise ValueError("Temporal snapshot belongs to another investigation.")
    return snapshot


def save(db: sqlite3.Connection, snapshot: TemporalSnapshot) -> None:
    db.execute(
        "INSERT INTO temporal_correlations VALUES (?, ?)",
        (snapshot.result.investigation_id, snapshot.model_dump_json()),
    )
