"""Durable collection receipts, progress and latest health state."""

import sqlite3
from datetime import timezone

from ..models.collection import CollectionRequest
from ..models.connector import CollectionCheckpoint, ConnectorStatus

SCHEMA = """
CREATE TABLE IF NOT EXISTS collection_receipts (
    scope TEXT NOT NULL, location TEXT NOT NULL, event_id TEXT NOT NULL,
    digest TEXT NOT NULL, PRIMARY KEY(scope, location, event_id)
);
CREATE INDEX IF NOT EXISTS collection_receipts_events ON collection_receipts(scope, event_id);
CREATE TABLE IF NOT EXISTS collection_checkpoints (
    scope TEXT PRIMARY KEY, through TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collection_status (
    scope TEXT PRIMARY KEY, attempted_at TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collection_pending (
    scope TEXT PRIMARY KEY, window TEXT NOT NULL
);
"""


def checkpoint(db: sqlite3.Connection, scope: str) -> CollectionCheckpoint | None:
    row = db.execute(
        "SELECT scope, through FROM collection_checkpoints WHERE scope = ?", (scope,)
    ).fetchone()
    return CollectionCheckpoint.model_validate(dict(row)) if row else None


def save_checkpoint(db: sqlite3.Connection, progress: CollectionCheckpoint) -> None:
    value = progress.through.astimezone(timezone.utc).isoformat(timespec="microseconds")
    db.execute(
        """INSERT INTO collection_checkpoints VALUES (?, ?)
           ON CONFLICT(scope) DO UPDATE SET through = excluded.through WHERE excluded.through > collection_checkpoints.through""",
        (progress.scope, value),
    )


def save_status(db: sqlite3.Connection, status: ConnectorStatus) -> None:
    value = status.attempted_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
    db.execute(
        """INSERT INTO collection_status VALUES (?, ?, ?)
           ON CONFLICT(scope) DO UPDATE SET attempted_at = excluded.attempted_at, status = excluded.status
           WHERE excluded.attempted_at >= collection_status.attempted_at""",
        (status.scope, value, status.model_dump_json()),
    )


def load_status(db: sqlite3.Connection, scope: str) -> ConnectorStatus | None:
    row = db.execute("SELECT status FROM collection_status WHERE scope = ?", (scope,)).fetchone()
    return ConnectorStatus.model_validate_json(row["status"]) if row else None


def pending(db: sqlite3.Connection, scope: str) -> CollectionRequest | None:
    row = db.execute("SELECT window FROM collection_pending WHERE scope = ?", (scope,)).fetchone()
    return CollectionRequest.model_validate_json(row["window"]) if row else None


def reserve(db: sqlite3.Connection, scope: str, window: CollectionRequest) -> None:
    db.execute("INSERT INTO collection_pending VALUES (?, ?)", (scope, window.model_dump_json()))


def release(db: sqlite3.Connection, scope: str, window: CollectionRequest) -> None:
    db.execute(
        "DELETE FROM collection_pending WHERE scope = ? AND window = ?",
        (scope, window.model_dump_json()),
    )


def accept_receipt(
    db: sqlite3.Connection,
    scope: str,
    location: str,
    event_id: str,
    digest: str,
) -> bool:
    existing = db.execute(
        "SELECT digest FROM collection_receipts WHERE scope = ? AND event_id = ? LIMIT 1",
        (scope, event_id),
    ).fetchone()
    if existing and existing["digest"] != digest:
        raise FileExistsError("Conflicting collection receipt.")
    row = db.execute(
        "INSERT OR IGNORE INTO collection_receipts VALUES (?, ?, ?, ?)",
        (scope, location, event_id, digest),
    )
    return bool(row.rowcount)
