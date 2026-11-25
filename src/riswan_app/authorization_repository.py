"""SQLite persistence for trusted authorization policy snapshots and audit decisions."""

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from uuid import UUID

from riswan_platform.authorization import (
    Assignment,
    Decision,
    Grant,
    Permission,
    Role,
    Scope,
    ScopeType,
    SubjectPolicy,
)


class AuthorizationRepository:
    def __init__(self, path: Path):
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS authorization_snapshots (
                    actor_id TEXT NOT NULL, tenant_id TEXT NOT NULL, policy TEXT NOT NULL,
                    PRIMARY KEY (actor_id, tenant_id)
                );
                CREATE TABLE IF NOT EXISTS authorization_audit_events (
                    decision_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, decision TEXT NOT NULL
                );
            """)

    def replace_snapshot(
        self, actor_id: UUID, tenant_id: UUID, policy: SubjectPolicy | None
    ) -> None:
        """Publish an entire snapshot from a trusted membership adapter, or revoke it."""
        with closing(sqlite3.connect(self.path)) as db, db:
            if policy is None:
                db.execute(
                    "DELETE FROM authorization_snapshots WHERE actor_id = ? AND tenant_id = ?",
                    (str(actor_id), str(tenant_id)),
                )
            else:
                db.execute(
                    "INSERT OR REPLACE INTO authorization_snapshots VALUES (?, ?, ?)",
                    (str(actor_id), str(tenant_id), json.dumps(asdict(policy), default=str)),
                )

    def policy_for(self, actor_id: UUID, tenant_id: UUID) -> SubjectPolicy | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT policy FROM authorization_snapshots WHERE actor_id = ? AND tenant_id = ?",
                (str(actor_id), str(tenant_id)),
            ).fetchone()
        if row is None:
            return None
        policy = json.loads(row[0])
        return SubjectPolicy(
            tuple(
                Assignment(
                    Role(item["role"]),
                    Scope(ScopeType(item["scope"]["kind"]), item["scope"]["id"]),
                    UUID(item["grantor_id"]),
                    datetime.fromisoformat(item["created_at"]),
                    datetime.fromisoformat(item["expires_at"]) if item["expires_at"] else None,
                    item["revoked"],
                )
                for item in policy["assignments"]
            ),
            tuple(
                Grant(
                    Permission(item["action"]),
                    Scope(ScopeType(item["scope"]["kind"]), item["scope"]["id"]),
                    item["deny"],
                )
                for item in policy["grants"]
            ),
        )

    def record(self, event_type: str, decision: Decision) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "INSERT INTO authorization_audit_events VALUES (?, ?, ?)",
                (str(decision.decision_id), event_type, json.dumps(asdict(decision), default=str)),
            )
