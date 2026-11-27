"""Persist case-wide legal holds alongside the records they protect."""

from sqlite3 import Connection
from typing import Any

from riswan_platform.data_protection import ProtectionDenied

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigation_legal_holds (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigation_ownership(investigation_id),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    released_at TEXT,
    released_by TEXT,
    release_reason TEXT
);
CREATE INDEX IF NOT EXISTS active_investigation_holds
ON investigation_legal_holds(investigation_id) WHERE released_at IS NULL;
CREATE TABLE IF NOT EXISTS investigation_hold_audit (
    id INTEGER PRIMARY KEY,
    hold_id TEXT NOT NULL REFERENCES investigation_legal_holds(id),
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    request_id TEXT NOT NULL
);
"""


def require_unheld(db: Connection, case_id: str) -> None:
    if db.execute(
        "SELECT 1 FROM investigation_legal_holds WHERE investigation_id = ? AND released_at IS NULL",
        (case_id,),
    ).fetchone():
        raise ProtectionDenied("Investigation is under legal hold.")


def change(
    db: Connection,
    case: str,
    hold: str,
    actor: str,
    timestamp: str,
    reason: str,
    request_id: str,
    *,
    release: bool,
) -> Any:
    if release:
        row = db.execute(
            """UPDATE investigation_legal_holds SET released_at = ?, released_by = ?, release_reason = ?
            WHERE id = ? AND investigation_id = ? AND released_at IS NULL
            RETURNING created_at, released_at""",
            (timestamp, actor, reason, hold, case),
        ).fetchone()
    else:
        row = db.execute(
            """INSERT INTO investigation_legal_holds
            (id, investigation_id, created_at, created_by, reason)
            VALUES (?, ?, ?, ?, ?) RETURNING created_at, released_at""",
            (hold, case, timestamp, actor, reason),
        ).fetchone()
    if row is not None:
        db.execute(
            """INSERT INTO investigation_hold_audit
            (hold_id, action, actor_id, occurred_at, request_id) VALUES (?, ?, ?, ?, ?)""",
            (hold, "released" if release else "created", actor, timestamp, request_id),
        )
    return row
