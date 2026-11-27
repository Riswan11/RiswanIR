"""Scoped PostgreSQL retrieval and append-only history for investigation memory."""

from uuid import uuid4

from riswan_ir.memory.repository import time_key
from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import canonical_json, sha256

HISTORY_QUERIES = {
    "review": ("SELECT * FROM reviews", "INSERT INTO main.reviews VALUES (?, ?, ?, ?, ?, ?)"),
    "feedback": (
        "SELECT * FROM memory_feedback",
        "INSERT INTO main.memory_feedback VALUES (?, ?, ?, ?, ?, ?)",
    ),
    "response": (
        "SELECT * FROM memory_responses",
        "INSERT INTO main.memory_responses VALUES (?, ?, ?, ?, ?, ?)",
    ),
    "audit": (
        "SELECT * FROM memory_audit",
        "INSERT INTO main.memory_audit VALUES (?, ?, ?, ?, ?, ?)",
    ),
}


def candidates(db, context, authorized, accounts, cutoff, after, current):
    if not authorized or not accounts:
        return ()
    return tuple(
        row[0]
        for row in db.execute(
            """SELECT s.investigation_id FROM riswan_data.case_memory_snapshots s
            WHERE s.tenant_id = %s AND s.product_id = %s AND s.investigation_id = ANY(%s)
            AND (s.snapshot #>> '{memory_cases,0,indexed_at}') BETWEEN %s AND %s
            AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(s.snapshot->'memory_records') r
                WHERE r->>'category' = 'episodic' AND r->>'expires_at' > %s
            )
            AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(s.snapshot->'memory_accounts') a
                WHERE a->>'account' = ANY(%s)
            )
            AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(s.snapshot->'memory_accounts') a
                WHERE NOT (a->>'account' = ANY(%s))
            )
            AND NOT EXISTS (
                SELECT 1 FROM riswan_data.investigation_memory_removals m
                WHERE (m.tenant_id, m.product_id, m.investigation_id) =
                    (s.tenant_id, s.product_id, s.investigation_id)
            )
            ORDER BY (s.snapshot #>> '{memory_cases,0,indexed_at}') DESC, s.investigation_id
            LIMIT 101""",
            (
                context.tenant_id,
                context.product_id,
                list(authorized),
                time_key(after),
                time_key(cutoff),
                time_key(current),
                sorted(accounts),
                sorted(accounts),
            ),
        )
    )


def snapshot(db, case):
    row = db.execute(
        """SELECT s.snapshot, i.artifacts->>'memory_digest'
        FROM riswan_data.case_memory_snapshots s
        JOIN riswan_data.investigations i USING (tenant_id, product_id, investigation_id)
        WHERE s.investigation_id = %s AND NOT EXISTS (
            SELECT 1 FROM riswan_data.investigation_memory_removals m
            WHERE (m.tenant_id, m.product_id, m.investigation_id) =
                (s.tenant_id, s.product_id, s.investigation_id)
        )""",
        (case,),
    ).fetchone()
    if row is None or sha256(canonical_json(row[0])) != row[1]:
        raise NotFoundError("Indexed historical profile not found.")
    return row[0]


def restore_history(db, staging, case, *, for_write=False, cutoff=None):
    selected = (
        ("review", "feedback", "response", "audit") if for_write else ("feedback", "response")
    )
    for kind, ordinal, recorded_at, entry in db.execute(
        """SELECT kind, ordinal, recorded_at, entry FROM riswan_data.case_memory_history
        WHERE investigation_id = %s AND kind = ANY(%s)
        AND (%s::text IS NULL OR recorded_at <= %s::text) ORDER BY kind, ordinal""",
        (case, list(selected), cutoff, cutoff),
    ):
        when_index = 5 if kind == "review" else 3 if kind == "audit" else 2
        if entry[0] != ordinal or entry[1] != case or time_key(entry[when_index]) != recorded_at:
            raise NotFoundError("Historical memory entry unavailable.")
        if not for_write:
            entry[0] = None  # SQLite assigns local ordinals across the authorized candidates.
        staging.execute(HISTORY_QUERIES[kind][1], entry)


def append_history(db, context, staging, case, before):
    for kind, previous in before.items():
        select, _ = HISTORY_QUERIES[kind]
        latest = db.execute(
            """SELECT COALESCE(MAX(ordinal), 0) FROM riswan_data.case_memory_history
            WHERE investigation_id = %s AND kind = %s""",
            (case, kind),
        ).fetchone()[0]
        for row in staging.execute(select):
            if row[0] <= previous:
                continue
            latest += 1
            entry = [latest, *row[1:]]
            when = row[5] if kind == "review" else row[3] if kind == "audit" else row[2]
            db.execute(
                "INSERT INTO riswan_data.case_memory_history VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    context.tenant_id,
                    context.product_id,
                    case,
                    uuid4(),
                    context.actor_id,
                    kind,
                    latest,
                    time_key(when),
                    canonical_json(entry),
                ),
            )
