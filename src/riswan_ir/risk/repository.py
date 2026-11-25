"""Append-only, investigation-scoped SQLite assessment history."""

import sqlite3

from .models import RiskArchive

SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_assessments (
    ordinal INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    archive TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS risk_subject_history
ON risk_assessments(investigation_id, kind, subject_id, ordinal DESC);
"""


def append(db: sqlite3.Connection, archive: RiskArchive) -> None:
    item = archive.assessment
    db.execute(
        "INSERT INTO risk_assessments (id, investigation_id, kind, subject_id, archive) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            item.id,
            item.investigation_id,
            item.subject_kind,
            item.subject_id,
            archive.model_dump_json(),
        ),
    )


def get(db: sqlite3.Connection, case_id: str, assessment_id: str) -> RiskArchive | None:
    row = db.execute(
        "SELECT archive FROM risk_assessments WHERE investigation_id = ? AND id = ?",
        (case_id, assessment_id),
    ).fetchone()
    return RiskArchive.model_validate_json(row[0]) if row else None


def latest(db: sqlite3.Connection, case_id: str) -> dict[tuple[str, str], RiskArchive]:
    rows = db.execute(
        """SELECT r.kind, r.subject_id, r.archive FROM risk_assessments r JOIN (
               SELECT MAX(ordinal) AS ordinal FROM risk_assessments
               WHERE investigation_id = ? GROUP BY kind, subject_id
           ) recent ON recent.ordinal = r.ordinal""",
        (case_id,),
    )
    return {(row[0], row[1]): RiskArchive.model_validate_json(row[2]) for row in rows}


def page(
    db: sqlite3.Connection,
    case_id: str,
    limit: int,
    offset: int,
    subject: tuple[str, str] | None = None,
) -> list[RiskArchive]:
    if subject:
        rows = db.execute(
            "SELECT archive FROM risk_assessments WHERE investigation_id = ? "
            "AND kind = ? AND subject_id = ? ORDER BY ordinal DESC LIMIT ? OFFSET ?",
            (case_id, *subject, limit, offset),
        )
    else:
        rows = db.execute(
            """SELECT r.archive FROM risk_assessments r JOIN (
                   SELECT MAX(ordinal) AS ordinal FROM risk_assessments
                   WHERE investigation_id = ? GROUP BY kind, subject_id
               ) recent ON recent.ordinal = r.ordinal
               ORDER BY r.ordinal DESC LIMIT ? OFFSET ?""",
            (case_id, limit, offset),
        )
    return [RiskArchive.model_validate_json(row[0]) for row in rows]
