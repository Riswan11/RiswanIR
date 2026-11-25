"""SQLite adapter behind a case-scoped graph repository contract."""

import sqlite3
from typing import Protocol

from .models import SecurityGraph

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_graphs (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    snapshot TEXT NOT NULL
);
"""


class GraphRepository(Protocol):
    def get(self, case_id: str) -> SecurityGraph | None: ...
    def save(self, graph: SecurityGraph) -> None: ...


class SQLiteGraphRepository:
    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def get(self, case_id: str) -> SecurityGraph | None:
        row = self.db.execute(
            "SELECT snapshot FROM security_graphs WHERE investigation_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            return None
        graph = SecurityGraph.model_validate_json(row[0])
        if graph.investigation_id != case_id:
            raise ValueError("Graph snapshot does not belong to this investigation.")
        return graph

    def save(self, graph: SecurityGraph) -> None:
        self.db.execute(
            "INSERT INTO security_graphs VALUES (?, ?) "
            "ON CONFLICT(investigation_id) DO UPDATE SET snapshot = excluded.snapshot",
            (graph.investigation_id, graph.model_dump_json()),
        )
