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


# Scoped readers cannot replay or expose scores derived from another case's archive
# or from historical aggregates whose input case IDs were not persisted.
def scoped_page(
    db: sqlite3.Connection,
    case_id: str,
    limit: int,
    offset: int,
    subject: tuple[str, str] | None,
    *,
    assessment_id: str | None = None,
) -> list[RiskArchive]:
    kind, subject_id = subject or (None, None)
    rows = db.execute(
        """
        WITH eligible AS (
            SELECT assessment.* FROM risk_assessments assessment
            JOIN risk_assessments original
              ON original.id = json_extract(assessment.archive, '$.assessment.original_assessment_id')
             AND original.investigation_id = assessment.investigation_id
            LEFT JOIN risk_assessments previous
              ON previous.id = json_extract(assessment.archive, '$.assessment.previous_assessment_id')
            WHERE assessment.investigation_id = :case_id
              AND (json_extract(assessment.archive, '$.assessment.previous_assessment_id') IS NULL
                   OR previous.investigation_id = :case_id)
              AND json_extract(assessment.archive, '$.inputs.recurrence_policy_digest') IS NULL
              AND json_extract(original.archive, '$.inputs.recurrence_policy_digest') IS NULL
        )
        SELECT archive FROM eligible WHERE (
          (:id IS NOT NULL AND id = :id)
          OR (:id IS NULL AND :kind IS NOT NULL AND kind = :kind AND subject_id = :subject_id)
          OR (:id IS NULL AND :kind IS NULL AND ordinal IN (
              SELECT MAX(ordinal) FROM eligible GROUP BY kind, subject_id
          ))
        ) ORDER BY ordinal DESC LIMIT :limit OFFSET :offset
        """,
        {
            "case_id": case_id,
            "kind": kind,
            "subject_id": subject_id,
            "limit": limit,
            "offset": offset,
            "id": assessment_id,
        },
    )
    return [RiskArchive.model_validate_json(row[0]) for row in rows]


def scoped_get(db: sqlite3.Connection, case_id: str, assessment_id: str) -> RiskArchive | None:
    rows = scoped_page(db, case_id, 1, 0, None, assessment_id=assessment_id)
    return rows[0] if rows else None


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
