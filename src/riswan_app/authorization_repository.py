"""SQLite persistence for trusted authorization policy snapshots and audit decisions."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from riswan_platform.authorization import (
    ROLE_PERMISSIONS,
    Assignment,
    AuthorizationRequest,
    Decision,
    Evaluator,
    Grant,
    Permission,
    Role,
    Scope,
    ScopeType,
    SubjectPolicy,
)
from riswan_platform.authorization.enforcement import AccessDenied


class AuthorizationRepository:
    def __init__(self, path: Path):
        self.path = path
        self._transaction: ContextVar[sqlite3.Connection | None] = ContextVar(
            "authorization_transaction", default=None
        )
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

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._transaction.get() is not None:
            yield
            return
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            token = self._transaction.set(db)
            try:
                yield
            finally:
                # Audit decisions are retained when a protected operation is denied.
                self._transaction.reset(token)
                db.commit()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        transaction = self._transaction.get()
        if transaction is not None:
            yield transaction
        else:
            with closing(sqlite3.connect(self.path)) as db, db:
                yield db

    def replace_snapshot(
        self, actor_id: UUID, tenant_id: UUID, policy: SubjectPolicy | None
    ) -> None:
        """Publish an entire snapshot from a trusted membership adapter, or revoke it."""
        with self._connection() as db:
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
        with self._connection() as db:
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
        with self._connection() as db:
            db.execute(
                "INSERT INTO authorization_audit_events VALUES (?, ?, ?)",
                (str(decision.decision_id), event_type, json.dumps(asdict(decision), default=str)),
            )

    def change_assignment(
        self,
        request: AuthorizationRequest,
        target: UUID,
        assignment: Assignment,
        *,
        revoke: bool = False,
    ) -> None:
        """Delegate within exactly the grantor's scope under a policy write lock."""
        with self.transaction():
            actor = request.principal.identity.identity_id
            tenant = request.context.tenant_id
            if request.action != Permission.ROLES_ASSIGN:
                raise AccessDenied
            decision = Evaluator(self, self).evaluate(request)
            if not decision.allowed:
                raise AccessDenied
            own = self.policy_for(actor, tenant)
            recipient = self.policy_for(target, tenant)
            now = datetime.now(UTC)
            requested = ROLE_PERMISSIONS[assignment.role]
            eligible = (
                (
                    a
                    for a in own.assignments
                    if a.scope == assignment.scope
                    and a.active_at(now)
                    and (
                        a.expires_at is None
                        or (
                            assignment.expires_at is not None
                            and assignment.expires_at <= a.expires_at
                        )
                    )
                )
                if own is not None
                else ()
            )
            permissions = set().union(*(ROLE_PERMISSIONS[a.role] for a in eligible))
            denied = (
                {grant.action for grant in own.grants if grant.deny} if own is not None else set()
            )
            can_delegate = (
                target != actor
                and recipient is not None
                and not assignment.revoked
                and request.resource.scope == Scope(ScopeType.ORGANIZATION, str(tenant))
                and assignment.scope.kind != ScopeType.PLATFORM
                and assignment.role != Role.OPERATOR
                and Permission.ROLES_ASSIGN not in requested
                and requested <= permissions - denied
                and (assignment.expires_at is None or assignment.expires_at > now)
            )
            if (
                not can_delegate
                or recipient is None
                or (
                    revoke
                    and (assignment.grantor_id != actor or assignment not in recipient.assignments)
                )
            ):
                self.record(
                    "platform.authorization.privilege_escalation_denied",
                    replace(
                        decision,
                        decision_id=uuid4(),
                        effect="deny",
                        reason_code="DELEGATION_SCOPE_MISMATCH",
                    ),
                )
                raise AccessDenied
            assignments = recipient.assignments
            if revoke:
                assignments = tuple(
                    replace(item, revoked=True) if item == assignment else item
                    for item in assignments
                )
            else:
                assignments += (replace(assignment, grantor_id=actor, created_at=now),)
            self.record(
                "platform.authorization.role_revoked"
                if revoke
                else "platform.authorization.role_assigned",
                replace(decision, decision_id=uuid4(), resource_id=str(target)),
            )
            self.replace_snapshot(target, tenant, replace(recipient, assignments=assignments))
