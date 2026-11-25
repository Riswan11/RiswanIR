"""SQLite identity adapter; platform identity code only knows its repository port."""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from riswan_platform.identity.models import (
    AuditEvent,
    AuthenticationError,
    ExternalIdentity,
    IdentityStatus,
    IdentityType,
    PlatformIdentity,
    Session,
    VerifiedPrincipal,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, display_name TEXT NOT NULL,
    email TEXT, status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_provider_links (
    issuer TEXT NOT NULL, subject TEXT NOT NULL, identity_id TEXT NOT NULL UNIQUE REFERENCES identities(id),
    PRIMARY KEY(issuer, subject)
);
CREATE TABLE IF NOT EXISTS identity_sessions (
    id TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES identities(id), digest TEXT NOT NULL UNIQUE,
    created REAL NOT NULL, last_seen REAL NOT NULL, expires REAL NOT NULL,
    mfa INTEGER NOT NULL, revoked REAL
);
CREATE INDEX IF NOT EXISTS identity_sessions_owner ON identity_sessions(identity_id, expires);
CREATE TABLE IF NOT EXISTS identity_status_history (
    identity_id TEXT NOT NULL REFERENCES identities(id), status TEXT NOT NULL, recorded REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS authentication_events (
    ordinal INTEGER PRIMARY KEY, event_type TEXT NOT NULL, actor_id TEXT, identity_type TEXT,
    method TEXT NOT NULL, mfa INTEGER NOT NULL, request_id TEXT NOT NULL,
    outcome TEXT NOT NULL, occurred REAL NOT NULL
);
"""


def _time(value: float) -> datetime:
    return datetime.fromtimestamp(value, timezone.utc)


def _identity(row: sqlite3.Row) -> PlatformIdentity:
    return PlatformIdentity(
        UUID(row["id"]),
        IdentityType(row["kind"]),
        row["issuer"],
        row["subject"],
        row["display_name"],
        row["email"],
        IdentityStatus(row["status"]),
        _time(row["created"]),
        _time(row["updated"]),
    )


def _session(row: sqlite3.Row) -> Session:
    return Session(
        UUID(row["id"]),
        UUID(row["identity_id"]),
        _time(row["created"]),
        _time(row["last_seen"]),
        _time(row["expires"]),
        bool(row["mfa"]),
    )


def _audit(db: sqlite3.Connection, event: AuditEvent) -> None:
    db.execute(
        """INSERT INTO authentication_events
           (event_type, actor_id, identity_type, method, mfa, request_id, outcome, occurred)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event.event_type,
            str(event.actor_id) if event.actor_id else None,
            event.identity_type,
            event.authentication_method,
            int(event.mfa_verified),
            event.request_id,
            event.outcome,
            event.occurred_at.timestamp(),
        ),
    )


class SQLiteIdentityRepository:
    def __init__(self, path: Path):
        self.path = path
        if os.name == "posix":
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def resolve(self, external: ExternalIdentity, now: datetime) -> PlatformIdentity:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT i.*, l.issuer, l.subject FROM identities i
                   JOIN identity_provider_links l ON l.identity_id = i.id
                   WHERE l.issuer = ? AND l.subject = ?""",
                (external.issuer, external.subject),
            ).fetchone()
            if row:
                identity = _identity(row)
                if (
                    identity.status != IdentityStatus.ACTIVE
                    or identity.identity_type != external.identity_type
                ):
                    raise AuthenticationError("Identity unavailable.")
                if (identity.display_name, identity.email) == (
                    external.display_name,
                    external.email,
                ):
                    return identity
                db.execute(
                    "UPDATE identities SET display_name = ?, email = ?, updated = ? WHERE id = ?",
                    (
                        external.display_name,
                        external.email,
                        now.timestamp(),
                        str(identity.identity_id),
                    ),
                )
                actor, created = identity.identity_id, identity.created_at
            else:
                actor, created = uuid4(), now
                db.execute(
                    "INSERT INTO identities VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(actor),
                        external.identity_type,
                        external.display_name,
                        external.email,
                        IdentityStatus.ACTIVE,
                        now.timestamp(),
                        now.timestamp(),
                    ),
                )
                db.execute(
                    "INSERT INTO identity_provider_links VALUES (?, ?, ?)",
                    (external.issuer, external.subject, str(actor)),
                )
            return PlatformIdentity(
                actor,
                external.identity_type,
                external.issuer,
                external.subject,
                external.display_name,
                external.email,
                IdentityStatus.ACTIVE,
                created,
                now,
            )

    def create_session(
        self,
        session: Session,
        digest: str,
        event: AuditEvent,
        previous_digest: str | None = None,
    ) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status FROM identities WHERE id = ?", (str(session.identity_id),)
            ).fetchone()
            if not row or row[0] != IdentityStatus.ACTIVE:
                raise AuthenticationError("Identity unavailable.")
            if previous_digest:
                changed = db.execute(
                    "UPDATE identity_sessions SET revoked = ? WHERE digest = ? AND identity_id = ? AND revoked IS NULL",
                    (session.created_at.timestamp(), previous_digest, str(session.identity_id)),
                )
                if changed.rowcount:
                    _audit(db, replace(event, event_type="platform.identity.session_revoked"))
            db.execute(
                "INSERT INTO identity_sessions VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    str(session.id),
                    str(session.identity_id),
                    digest,
                    session.created_at.timestamp(),
                    session.last_seen_at.timestamp(),
                    session.expires_at.timestamp(),
                    int(session.mfa_verified),
                ),
            )
            _audit(db, event)

    def authenticate_session(
        self,
        digest: str,
        now: datetime,
        idle_seconds: int,
        request_id: str,
    ) -> VerifiedPrincipal | None:
        instant = now.timestamp()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT i.*, l.issuer, l.subject, s.id AS sid, s.last_seen, s.expires, s.mfa, s.revoked
                   FROM identity_sessions s JOIN identities i ON i.id = s.identity_id
                   JOIN identity_provider_links l ON l.identity_id = i.id
                   WHERE s.digest = ?""",
                (digest,),
            ).fetchone()
            if not row or row["revoked"] is not None or row["status"] != IdentityStatus.ACTIVE:
                return None
            identity = _identity(row)
            if instant >= row["expires"] or instant >= row["last_seen"] + idle_seconds:
                db.execute(
                    "UPDATE identity_sessions SET revoked = ? WHERE id = ?", (instant, row["sid"])
                )
                _audit(
                    db,
                    AuditEvent(
                        "platform.identity.session_expired",
                        identity.identity_id,
                        identity.identity_type,
                        "session",
                        bool(row["mfa"]),
                        request_id,
                        "rejected",
                        now,
                    ),
                )
                return None
            db.execute(
                "UPDATE identity_sessions SET last_seen = MAX(last_seen, ?) WHERE id = ?",
                (instant, row["sid"]),
            )
            return VerifiedPrincipal(identity, "session", bool(row["mfa"]), UUID(row["sid"]))

    def sessions(self, actor: UUID, now: datetime, idle_seconds: int) -> list[Session]:
        instant = now.timestamp()
        with self._connect() as db:
            rows = db.execute(
                """SELECT s.* FROM identity_sessions s JOIN identities i ON i.id = s.identity_id
                   WHERE s.identity_id = ? AND i.status = 'active' AND s.revoked IS NULL
                   AND s.expires > ? AND s.last_seen > ? ORDER BY s.created DESC, s.id LIMIT 100""",
                (str(actor), instant, instant - idle_seconds),
            )
            return [_session(row) for row in rows]

    def revoke_session(self, actor: UUID, session: UUID, now: datetime, event: AuditEvent) -> bool:
        with self._connect() as db:
            updated = db.execute(
                "UPDATE identity_sessions SET revoked = ? WHERE identity_id = ? AND id = ? AND revoked IS NULL",
                (now.timestamp(), str(actor), str(session)),
            )
            if updated.rowcount:
                _audit(db, event)
            return updated.rowcount == 1

    def set_status(
        self, actor: UUID, status: IdentityStatus, now: datetime, event: AuditEvent
    ) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE identities SET status = ?, updated = ? WHERE id = ? AND status <> ?",
                (status, now.timestamp(), str(actor), status),
            )
            if changed.rowcount:
                db.execute(
                    "INSERT INTO identity_status_history VALUES (?, ?, ?)",
                    (
                        str(actor),
                        status,
                        now.timestamp(),
                    ),
                )
                if status != IdentityStatus.ACTIVE:
                    db.execute(
                        "UPDATE identity_sessions SET revoked = ? WHERE identity_id = ? AND revoked IS NULL",
                        (now.timestamp(), str(actor)),
                    )
                _audit(db, event)

    def audit(self, event: AuditEvent) -> None:
        with self._connect() as db:
            _audit(db, event)
