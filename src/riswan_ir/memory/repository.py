"""Persist scoped and independently expiring historical memory records."""

import json
import sqlite3
from datetime import timedelta

from pydantic import ValidationError

from riswan_security_data.integrity import canonical_json, sha256

from ..core.fields import utc_timestamp
from ..storage.evidence_store import has_retained_case_payloads
from .models import Category, Feedback, MemoryPolicy, Profile, Record

SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_cases (
    case_id TEXT PRIMARY KEY REFERENCES investigations(id),
    indexed_at TEXT NOT NULL,
    policy TEXT NOT NULL,
    policy_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_accounts (
    account TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES memory_cases(case_id),
    PRIMARY KEY(account, case_id)
);
CREATE INDEX IF NOT EXISTS memory_accounts_case ON memory_accounts(case_id, account);
CREATE TABLE IF NOT EXISTS memory_records (
    case_id TEXT NOT NULL REFERENCES memory_cases(case_id),
    category TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY(case_id, category)
);
CREATE TABLE IF NOT EXISTS memory_feedback (
    ordinal INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES memory_cases(case_id),
    recorded_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS memory_feedback_case ON memory_feedback(case_id, recorded_at, ordinal);
CREATE TABLE IF NOT EXISTS memory_responses (
    ordinal INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES memory_cases(case_id),
    recorded_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS memory_responses_case ON memory_responses(case_id, recorded_at, ordinal);
CREATE TABLE IF NOT EXISTS memory_tombstones (
    case_id TEXT PRIMARY KEY REFERENCES investigations(id),
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_audit (
    ordinal INTEGER PRIMARY KEY,
    case_id TEXT REFERENCES investigations(id),
    action TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    result_digest TEXT
);
"""


def time_key(value: str) -> str:
    return utc_timestamp(value).isoformat(timespec="microseconds")


def expiry(value: str, config: MemoryPolicy, category: Category) -> str:
    days = config.category_retention.get(category, config.retention_days)
    return (utc_timestamp(value) + timedelta(days=days)).isoformat(timespec="microseconds")


def policy_digest(config: MemoryPolicy) -> str:
    data = config.model_dump(mode="json")
    data["enabled_categories"] = sorted(config.enabled_categories)
    data["cross_account_categories"] = sorted(config.cross_account_categories)
    return sha256(canonical_json(data))


def audit(
    db: sqlite3.Connection,
    case_id: str | None,
    action: str,
    current: str,
    config: MemoryPolicy,
    result: str | None = None,
) -> None:
    db.execute(
        "INSERT INTO memory_audit(case_id, action, recorded_at, policy_digest, result_digest) VALUES (?, ?, ?, ?, ?)",
        (case_id, action, time_key(current), policy_digest(config), result),
    )


def save(
    db: sqlite3.Connection,
    profile: Profile,
    config: MemoryPolicy,
    current: str,
    *,
    organizational: list[str],
) -> bool:
    if (
        not profile.complete_scope
        or not profile.raw_references
        or "episodic" not in config.enabled_categories
    ):
        return False
    if db.execute(
        "SELECT 1 FROM memory_tombstones WHERE case_id = ?", (profile.case_id,)
    ).fetchone():
        return False
    encoded_policy = config.model_dump_json()
    inserted = db.execute(
        "INSERT INTO memory_cases VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
        (profile.case_id, time_key(current), encoded_policy, sha256(encoded_policy)),
    )
    if not inserted.rowcount:
        return False
    db.executemany(
        "INSERT INTO memory_accounts VALUES (?, ?)",
        [(item, profile.case_id) for item in profile.scope],
    )
    data = profile.model_dump(mode="json", exclude={"factors", "patterns", "observations"})
    payloads: dict[Category, dict[str, object]] = {
        "episodic": data,
        "semantic": {
            "factors": {
                key: value for key, value in profile.factors.items() if key != "environment"
            },
            "patterns": profile.patterns,
        },
        "behavioral": {
            "observations": [item.model_dump(mode="json") for item in profile.observations]
        },
        "procedural": {
            "playbooks": {
                key: value for key, value in config.playbooks.items() if key in profile.patterns
            }
        },
        "organizational": {"attributes": organizational},
    }
    for category, payload in payloads.items():
        if category not in config.enabled_categories:
            continue
        record = Record(category=category, policy_version=config.version, data=payload)
        encoded = record.model_dump_json()
        db.execute(
            "INSERT INTO memory_records VALUES (?, ?, ?, ?, ?)",
            (
                profile.case_id,
                category,
                expiry(current, config, category),
                encoded,
                sha256(encoded),
            ),
        )
    audit(db, profile.case_id, "index", current, config)
    return True


def file_feedback(
    db: sqlite3.Connection,
    case_id: str,
    feedback: Feedback,
    config: MemoryPolicy,
    current: str,
) -> None:
    if "feedback" not in config.enabled_categories:
        raise ValueError("Historical feedback memory is disabled.")
    payload = feedback.model_dump_json()
    recorded = time_key(current)
    previous = classification(db, case_id, current, current)
    if previous == feedback:
        return
    db.execute(
        "INSERT INTO memory_feedback(case_id, recorded_at, expires_at, payload, digest) VALUES (?, ?, ?, ?, ?)",
        (case_id, recorded, expiry(current, config, "feedback"), payload, sha256(payload)),
    )
    audit(db, case_id, "feedback", current, config)


def archived_policy(db: sqlite3.Connection, case_id: str) -> MemoryPolicy | None:
    row = db.execute(
        "SELECT policy, policy_digest FROM memory_cases WHERE case_id = ?", (case_id,)
    ).fetchone()
    if row is None or sha256(row[0]) != row[1]:
        return None
    try:
        return MemoryPolicy.model_validate_json(row[0])
    except ValidationError:
        return None


def record_response(
    db: sqlite3.Connection,
    case_id: str,
    references: list[str],
    config: MemoryPolicy,
    current: str,
) -> None:
    if "response" not in config.enabled_categories:
        raise ValueError("Response memory is disabled.")
    record = Record(
        category="response",
        policy_version=config.version,
        data={"verified_evidence": references, "recorded_at": time_key(current)},
    )
    payload = record.model_dump_json()
    db.execute(
        "INSERT INTO memory_responses(case_id, recorded_at, expires_at, payload, digest) VALUES (?, ?, ?, ?, ?)",
        (case_id, time_key(current), expiry(current, config, "response"), payload, sha256(payload)),
    )
    audit(db, case_id, "response", current, config)


def classification(
    db: sqlite3.Connection,
    case_id: str,
    as_of: str,
    current: str,
) -> Feedback | None:
    row = db.execute(
        """SELECT payload, digest, expires_at FROM memory_feedback
        WHERE case_id = ? AND recorded_at <= ? ORDER BY recorded_at DESC, ordinal DESC LIMIT 1""",
        (case_id, time_key(as_of)),
    ).fetchone()
    if not row or row[2] <= time_key(current) or sha256(row[0]) != row[1]:
        return None
    try:
        return Feedback.model_validate_json(row[0])
    except ValidationError:
        return None


def read(
    db: sqlite3.Connection,
    case_id: str,
    config: MemoryPolicy,
    current: str,
) -> Profile | None:
    if not has_retained_case_payloads(db, case_id):
        return None
    rows = db.execute(
        "SELECT category, payload, digest FROM memory_records WHERE case_id = ? AND expires_at > ?",
        (case_id, time_key(current)),
    )
    records = {}
    for category, payload, digest in rows:
        if category not in config.enabled_categories:
            continue
        if sha256(payload) != digest:
            return None
        try:
            record = Record.model_validate_json(payload)
        except ValidationError:
            return None
        if record.category != category:
            return None
        records[category] = record.data
    if "episodic" not in records:
        return None
    semantic_factors = records.get("semantic", {}).get("factors", {})
    if not isinstance(semantic_factors, dict):
        return None
    try:
        return Profile.model_validate(
            {
                **records["episodic"],
                "factors": {
                    **semantic_factors,
                    **(
                        {"environment": records["organizational"].get("attributes", [])}
                        if "organizational" in records
                        else {}
                    ),
                },
                "patterns": records.get("semantic", {}).get("patterns", {}),
                **records.get("behavioral", {"observations": []}),
            }
        )
    except (ValidationError, TypeError):
        return None


def candidates(
    db: sqlite3.Connection,
    accounts: set[str],
    as_of: str,
    after: str,
    case_ids: tuple[str, ...] | None = None,
) -> list[str]:
    if not accounts:
        return []
    keys = json.dumps(sorted(accounts))
    authorized = json.dumps(case_ids) if case_ids is not None else None
    rows = db.execute(
        """SELECT c.case_id FROM memory_cases c
        WHERE c.indexed_at BETWEEN ? AND ?
        AND (? IS NULL OR c.case_id IN (SELECT value FROM json_each(?)))
        AND EXISTS (SELECT 1 FROM memory_accounts a WHERE a.case_id = c.case_id AND a.account IN (SELECT value FROM json_each(?)))
        AND NOT EXISTS (SELECT 1 FROM memory_accounts a WHERE a.case_id = c.case_id AND a.account NOT IN (SELECT value FROM json_each(?)))
        AND NOT EXISTS (SELECT 1 FROM memory_tombstones t WHERE t.case_id = c.case_id)
        ORDER BY c.indexed_at DESC, c.case_id LIMIT 101""",
        (time_key(after), time_key(as_of), authorized, authorized, keys, keys),
    )
    return [row[0] for row in rows]


def response(
    db: sqlite3.Connection,
    case_id: str,
    current: str,
    as_of: str,
) -> list[str]:
    row = db.execute(
        """SELECT payload, digest FROM memory_responses WHERE case_id = ?
           AND recorded_at <= ? AND expires_at > ? ORDER BY recorded_at DESC, ordinal DESC LIMIT 1""",
        (case_id, time_key(as_of), time_key(current)),
    ).fetchone()
    if not row or sha256(row[0]) != row[1]:
        return []
    try:
        record = Record.model_validate_json(row[0])
        when = record.data.get("recorded_at")
        refs = record.data.get("verified_evidence")
        if isinstance(when, str) and when <= time_key(as_of) and isinstance(refs, list):
            return [item for item in refs if isinstance(item, str)][:100]
    except ValidationError:
        pass
    return []


def remove(db: sqlite3.Connection, case_id: str, config: MemoryPolicy, current: str) -> None:
    db.execute(
        "INSERT INTO memory_tombstones VALUES (?, ?) ON CONFLICT DO NOTHING",
        (case_id, time_key(current)),
    )
    db.execute("DELETE FROM memory_feedback WHERE case_id = ?", (case_id,))
    db.execute("DELETE FROM memory_responses WHERE case_id = ?", (case_id,))
    db.execute("DELETE FROM memory_records WHERE case_id = ?", (case_id,))
    db.execute("DELETE FROM memory_accounts WHERE case_id = ?", (case_id,))
    db.execute("DELETE FROM memory_cases WHERE case_id = ?", (case_id,))
    audit(db, case_id, "remove", current, config)


def expire(db: sqlite3.Connection, config: MemoryPolicy, current: str) -> int:
    moment = time_key(current)
    rows = db.execute(
        "SELECT case_id FROM memory_records WHERE category = 'episodic' AND expires_at <= ?",
        (moment,),
    ).fetchall()
    for row in rows:
        remove(db, row[0], config, current)
    records = db.execute("DELETE FROM memory_records WHERE expires_at <= ?", (moment,)).rowcount
    feedback = db.execute("DELETE FROM memory_feedback WHERE expires_at <= ?", (moment,)).rowcount
    audit(db, None, "expire", current, config)
    responses = db.execute("DELETE FROM memory_responses WHERE expires_at <= ?", (moment,)).rowcount
    return len(rows) + records + feedback + responses
