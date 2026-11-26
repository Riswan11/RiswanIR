"""Independent PostgreSQL archives for initial correlation and risk output."""

from riswan_ir.correlation.temporal.models import TemporalSnapshot
from riswan_ir.risk.models import RiskArchive
from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import canonical_json, sha256


def append(db, context, case, temporal, risks) -> None:
    scope = (context.tenant_id, context.product_id, case)
    db.execute(
        "INSERT INTO riswan_data.case_temporal_snapshots VALUES (%s, %s, %s, %s)",
        (*scope, temporal),
    )
    append_risk(db, context, case, risks)


def append_risk(db, context, case, risks) -> None:
    if not risks:
        return
    scope = (context.tenant_id, context.product_id, case)
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO riswan_data.case_risk_assessments VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            [
                (*scope, row["ordinal"], row["id"], row["kind"], row["subject_id"], row["archive"])
                for row in risks
            ],
        )


def temporal_snapshot(db, case: str, expected: str) -> str:
    row = db.execute(
        "SELECT snapshot FROM riswan_data.case_temporal_snapshots WHERE investigation_id = %s",
        (case,),
    ).fetchone()
    if row is None or sha256(row[0]) != expected:
        raise NotFoundError("Temporal archive unavailable.")
    return str(row[0])


def risk_digest(rows) -> str:
    return sha256(canonical_json(sorted(rows, key=lambda row: row["ordinal"])))


def risk_rows(db, case: str, expected: str, initial_count: int | None = None):
    rows = [
        {
            "ordinal": ordinal,
            "id": identifier,
            "investigation_id": case,
            "kind": kind,
            "subject_id": subject,
            "archive": archive,
        }
        for ordinal, identifier, kind, subject, archive in db.execute(
            """SELECT ordinal, id, kind, subject_id, archive FROM riswan_data.case_risk_assessments
               WHERE investigation_id = %s ORDER BY ordinal""",
            (case,),
        )
    ]
    if risk_digest(rows[:initial_count]) != expected:
        raise NotFoundError("Risk archive unavailable.")
    return rows


def parse_temporal(case: str, snapshot: str) -> TemporalSnapshot:
    result = TemporalSnapshot.model_validate_json(snapshot)
    if result.result.investigation_id != case:
        raise NotFoundError("Temporal archive unavailable.")
    return result


def parse_risk(case: str, rows) -> list[RiskArchive]:
    archived = [RiskArchive.model_validate_json(row["archive"]) for row in rows]
    if any(entry.assessment.investigation_id != case for entry in archived):
        raise NotFoundError("Risk archive unavailable.")
    return archived


MEMORY_ARTIFACTS = ("memory_cases", "memory_accounts", "memory_records")


def save_memory(db, context, case, artifacts) -> None:
    db.execute(
        "INSERT INTO riswan_data.case_memory_snapshots VALUES (%s, %s, %s, %s::jsonb)",
        (context.tenant_id, context.product_id, case, canonical_json(artifacts)),
    )


def read_memory(db, case: str, expected: str):
    row = db.execute(
        "SELECT snapshot FROM riswan_data.case_memory_snapshots WHERE investigation_id = %s",
        (case,),
    ).fetchone()
    if row is None or sha256(canonical_json(row[0])) != expected:
        raise NotFoundError("Memory archive unavailable.")
    return row[0]
