"""Case review queries for application adapters."""

import sqlite3

from ..models import Disposition


def latest_disposition(db: sqlite3.Connection, case_id: str) -> Disposition | None:
    row = db.execute(
        "SELECT disposition FROM reviews WHERE investigation_id = ? ORDER BY id DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    return Disposition(row[0]) if row else None
