"""Versioned control-plane storage for shared organization tenancy."""

import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from riswan_platform.authorization import (
    ROLE_PERMISSIONS,
    Assignment,
    AuthorizationRequest,
    Evaluator,
    Grant,
    Permission,
    Resource,
    Role,
    Scope,
    ScopeType,
    SubjectPolicy,
)
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import PlatformContext
from riswan_platform.identity.models import IdentityStatus, IdentityType, VerifiedPrincipal
from riswan_platform.tenancy import (
    Invitation,
    InvitationRequest,
    Membership,
    MembershipRole,
    Organization,
    OrganizationInput,
    OrganizationSettings,
    TenantStatus,
)

from .authorization_repository import AuthorizationRepository

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_migrations (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    settings TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL UNIQUE REFERENCES organizations(id),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'archived'))
);
CREATE TABLE IF NOT EXISTS organization_memberships (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    identity_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    joined_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (tenant_id, identity_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_active_owner ON organization_memberships(tenant_id)
WHERE role = 'owner' AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS organization_memberships_identity
ON organization_memberships(identity_id, tenant_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS organization_invitations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    identity_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('analyst', 'viewer')),
    inviter_id TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    closed_at TEXT
);
CREATE TABLE IF NOT EXISTS organization_audit_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    actor_id TEXT NOT NULL,
    event TEXT NOT NULL,
    target TEXT,
    occurred_at TEXT NOT NULL,
    request_id TEXT NOT NULL
);
INSERT OR IGNORE INTO tenant_migrations VALUES (1);
"""

MEMBERSHIP_ROLES = {
    MembershipRole.OWNER: (Role.OWNER, Role.COMMANDER, Role.ANALYST, Role.APPROVER),
    MembershipRole.ADMIN: (Role.ADMIN, Role.ANALYST),
    MembershipRole.ANALYST: (Role.ANALYST,),
    MembershipRole.VIEWER: (Role.VIEWER,),
}
INVITABLE = {MembershipRole.ANALYST, MembershipRole.VIEWER}


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class Tenancy:
    def __init__(
        self,
        authorization: AuthorizationRepository,
        active_human: Callable[[UUID], bool],
        active_workload: Callable[[UUID], bool] | None = None,
    ):
        self.authorization = authorization
        self._active_human = active_human
        self.active_workload = active_workload or (lambda _: False)
        self.evaluator = Evaluator(authorization, authorization)
        if authorization.initializes_sqlite_schema:
            with authorization.atomic() as db:
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)

    @staticmethod
    def _actor(principal: VerifiedPrincipal, *, human: bool = False) -> UUID:
        identity = principal.identity
        if identity.status != IdentityStatus.ACTIVE or (
            human and (identity.identity_type != IdentityType.HUMAN or not principal.mfa_verified)
        ):
            raise AccessDenied
        return identity.identity_id

    @staticmethod
    def _organization(row) -> Organization:
        return Organization(
            id=row[0],
            tenant_id=row[1],
            name=row[2],
            status=row[3],
            settings=OrganizationSettings.model_validate_json(row[4]),
            created_at=row[5],
        )

    def _audit(self, db, tenant, actor, event, request_id, target=None) -> None:
        db.execute(
            "INSERT INTO organization_audit_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid4()),
                tenant,
                str(actor),
                f"platform.tenancy.{event}",
                target,
                datetime.now(UTC).isoformat(),
                request_id,
            ),
        )

    def context_for(
        self, principal: VerifiedPrincipal, tenant_id: UUID, product_id: str, request_id: str
    ) -> PlatformContext | None:
        actor = self._actor(principal)
        with self.authorization._connection() as db:
            row = db.execute(
                """SELECT t.organization_id FROM organization_memberships m JOIN tenants t ON t.id = m.tenant_id
                WHERE m.tenant_id = ? AND m.identity_id = ? AND m.revoked_at IS NULL
                AND t.status = 'active'""",
                (str(tenant_id), str(actor)),
            ).fetchone()
        if row is None:
            return None
        self.authorization.bind_scope(str(tenant_id), row[0])
        return PlatformContext(
            tenant_id,
            str(actor),
            principal.identity.identity_type.value,
            product_id,
            request_id,
            request_id,
        )

    def organization_id(self, tenant_id: UUID) -> UUID:
        with self.authorization._connection() as db:
            row = db.execute(
                "SELECT organization_id FROM tenants WHERE id = ? AND status = 'active'",
                (str(tenant_id),),
            ).fetchone()
        if row is None:
            raise AccessDenied
        return UUID(row[0])

    def organizations(self, principal: VerifiedPrincipal) -> list[Organization]:
        actor = self._actor(principal)
        with self.authorization._connection() as db:
            return [
                self._organization(row)
                for row in db.execute(
                    """SELECT o.id, t.id, o.name, t.status, o.settings, o.created_at
                    FROM organizations o JOIN tenants t ON t.organization_id = o.id
                    JOIN organization_memberships m ON m.tenant_id = t.id
                    WHERE m.identity_id = ? AND m.revoked_at IS NULL
                    ORDER BY o.created_at, o.id""",
                    (str(actor),),
                )
            ]

    def organization(self, principal: VerifiedPrincipal, organization_id: UUID) -> Organization:
        actor = self._actor(principal)
        with self.authorization._connection() as db:
            row = db.execute(
                """SELECT o.id, t.id, o.name, t.status, o.settings, o.created_at
                FROM organizations o JOIN tenants t ON t.organization_id = o.id
                JOIN organization_memberships m ON m.tenant_id = t.id
                WHERE o.id = ? AND m.identity_id = ? AND m.revoked_at IS NULL""",
                (str(organization_id), str(actor)),
            ).fetchone()
        if row is None:
            raise AccessDenied
        return self._organization(row)

    def _set_role(
        self, db, tenant: str, identity: str, role: MembershipRole, grantor: UUID
    ) -> None:
        now = datetime.now(UTC)
        db.execute(
            """INSERT INTO organization_memberships VALUES (?, ?, ?, ?, NULL)
            ON CONFLICT(tenant_id, identity_id) DO UPDATE SET
                role = excluded.role, joined_at = excluded.joined_at, revoked_at = NULL""",
            (tenant, identity, role.value, now.isoformat()),
        )
        if role not in {MembershipRole.OWNER, MembershipRole.ADMIN}:
            db.execute(
                "UPDATE organization_invitations SET closed_at = ? WHERE tenant_id = ? AND inviter_id = ? AND closed_at IS NULL",
                (now.isoformat(), tenant, identity),
            )
        existing = self.authorization.policy_for(UUID(identity), UUID(tenant))
        assignments = tuple(
            Assignment(
                role_id,
                Scope(
                    ScopeType.ORGANIZATION
                    if role_id.value.startswith("platform.")
                    else ScopeType.PRODUCT,
                    tenant if role_id.value.startswith("platform.") else "ir",
                ),
                grantor,
                now,
            )
            for role_id in MEMBERSHIP_ROLES[role]
        )
        # Organization collaboration grants are checked only on explicitly shareable tenant resources.
        grants = tuple(
            Grant(permission, Scope(ScopeType.ORGANIZATION, tenant))
            for permission in sorted(
                set().union(*(ROLE_PERMISSIONS[item.role] for item in assignments))
            )
            if permission.value.startswith("ir.")
        )
        if existing:
            grants += tuple(grant for grant in existing.grants if grant.deny)
        self.authorization.replace_snapshot(
            UUID(identity), UUID(tenant), SubjectPolicy(assignments, grants)
        )

    def create(
        self, principal: VerifiedPrincipal, request: OrganizationInput, request_id: str
    ) -> Organization:
        actor = self._actor(principal, human=True)
        now = datetime.now(UTC)
        org, tenant = uuid4(), uuid4()
        with self.authorization.atomic() as db:
            self.authorization.bind_scope(str(tenant), str(org))
            db.execute(
                "INSERT INTO organizations VALUES (?, ?, ?, ?)",
                (str(org), request.name, request.settings.model_dump_json(), now.isoformat()),
            )
            db.execute("INSERT INTO tenants VALUES (?, ?, 'active')", (str(tenant), str(org)))
            self._set_role(db, str(tenant), str(actor), MembershipRole.OWNER, actor)
            self._audit(db, str(tenant), actor, "organization_created", request_id, str(org))
        return Organization(
            **request.model_dump(),
            id=org,
            tenant_id=tenant,
            status=TenantStatus.ACTIVE,
            created_at=now,
        )

    def _admin(
        self,
        principal,
        organization_id,
        request_id,
        *,
        owner=False,
        suspended=False,
        permission=Permission.ORGANIZATION_MANAGE,
    ):
        actor = self._actor(principal, human=True)
        with self.authorization._connection() as db:
            row = db.execute(
                """SELECT o.id, t.id, o.name, t.status, o.settings, o.created_at, m.role
                FROM organizations o JOIN tenants t ON t.organization_id = o.id
                JOIN organization_memberships m ON m.tenant_id = t.id
                WHERE o.id = ? AND m.identity_id = ? AND m.revoked_at IS NULL""",
                (str(organization_id), str(actor)),
            ).fetchone()
        if row is None or (row[3] != "active" and not (suspended and row[3] == "suspended")):
            raise AccessDenied
        if owner and row[6] != MembershipRole.OWNER:
            raise AccessDenied
        tenant = UUID(row[1])
        self.authorization.bind_scope(row[1], row[0])
        context = PlatformContext(tenant, str(actor), "human", "platform", request_id, request_id)
        resource = Resource(tenant, "platform", Scope(ScopeType.ORGANIZATION, str(tenant)))
        if not self.evaluator.evaluate(
            AuthorizationRequest(principal, context, permission, resource)
        ).allowed:
            raise AccessDenied
        return self._organization(row), actor

    def update(self, principal, organization_id: UUID, request: OrganizationInput, request_id: str):
        with self.authorization.transaction():
            org, actor = self._admin(principal, organization_id, request_id)
            with self.authorization.atomic() as db:
                db.execute(
                    "UPDATE organizations SET name = ?, settings = ? WHERE id = ?",
                    (request.name, request.settings.model_dump_json(), str(org.id)),
                )
                self._audit(db, str(org.tenant_id), actor, "organization_updated", request_id)
        return org.model_copy(update={"name": request.name, "settings": request.settings})

    def lifecycle(self, principal, organization_id: UUID, status: TenantStatus, request_id: str):
        with self.authorization.transaction():
            org, actor = self._admin(
                principal, organization_id, request_id, owner=True, suspended=True
            )
            with self.authorization.atomic() as db:
                db.execute(
                    "UPDATE tenants SET status = ? WHERE id = ?", (status, str(org.tenant_id))
                )
                if status != TenantStatus.ACTIVE:
                    db.execute(
                        "UPDATE organization_invitations SET closed_at = ? WHERE tenant_id = ? AND closed_at IS NULL",
                        (datetime.now(UTC).isoformat(), str(org.tenant_id)),
                    )
                self._audit(db, str(org.tenant_id), actor, f"tenant_{status}", request_id)
        return org.model_copy(update={"status": status})

    def members(self, principal, organization_id: UUID, request_id: str) -> list[Membership]:
        with self.authorization.transaction():
            org, _ = self._admin(principal, organization_id, request_id)
            with self.authorization._connection() as db:
                return [
                    Membership(identity_id=row[0], role=row[1], joined_at=row[2], revoked_at=row[3])
                    for row in db.execute(
                        """SELECT identity_id, role, joined_at, revoked_at FROM organization_memberships
                        WHERE tenant_id = ? ORDER BY joined_at, identity_id""",
                        (str(org.tenant_id),),
                    )
                ]

    def invite(self, principal, organization_id: UUID, request: InvitationRequest, request_id: str):
        with self.authorization.transaction():
            org, actor = self._admin(principal, organization_id, request_id)
            if (
                request.role not in INVITABLE
                or request.identity_id == actor
                or not self._active_human(request.identity_id)
            ):
                raise AccessDenied
            token, identifier = secrets.token_urlsafe(32), uuid4()
            expires = datetime.now(UTC) + timedelta(hours=24)
            with self.authorization.atomic() as db:
                db.execute(
                    "INSERT INTO organization_invitations VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        str(identifier),
                        str(org.tenant_id),
                        str(request.identity_id),
                        request.role,
                        str(actor),
                        _token_digest(token),
                        expires.isoformat(),
                    ),
                )
                self._audit(
                    db, str(org.tenant_id), actor, "invitation_created", request_id, str(identifier)
                )
        return Invitation(id=identifier, token=token, expires_at=expires)

    def accept(self, principal, token: str, request_id: str):
        actor = self._actor(principal, human=True)
        if not self._active_human(actor):
            raise AccessDenied
        now = datetime.now(UTC).isoformat()
        with self.authorization.atomic() as db:
            row = db.execute(
                """UPDATE organization_invitations SET closed_at = ?
                WHERE digest = ? AND identity_id = ? AND closed_at IS NULL AND expires_at > ?
                AND EXISTS (SELECT 1 FROM tenants WHERE id = tenant_id AND status = 'active')
                AND NOT EXISTS (
                    SELECT 1 FROM organization_memberships m
                    WHERE m.tenant_id = organization_invitations.tenant_id AND m.identity_id = ?
                    AND m.revoked_at IS NULL
                )
                RETURNING id, tenant_id, role, inviter_id""",
                (now, _token_digest(token), str(actor), now, str(actor)),
            ).fetchone()
            if row is None:
                raise AccessDenied
            identifier, tenant, role, inviter = row
            self.authorization.bind_scope(tenant)
            self._set_role(db, tenant, str(actor), MembershipRole(role), UUID(inviter))
            db.execute(
                "UPDATE organization_invitations SET closed_at = ? WHERE tenant_id = ? AND identity_id = ? AND closed_at IS NULL",
                (now, tenant, str(actor)),
            )
            self._audit(db, tenant, actor, "invitation_accepted", request_id, identifier)
        return UUID(tenant)

    def revoke_invitation(
        self, principal, organization_id: UUID, invitation_id: UUID, request_id: str
    ):
        with self.authorization.transaction():
            org, actor = self._admin(principal, organization_id, request_id)
            with self.authorization.atomic() as db:
                changed = db.execute(
                    "UPDATE organization_invitations SET closed_at = ? WHERE id = ? AND tenant_id = ? AND closed_at IS NULL",
                    (datetime.now(UTC).isoformat(), str(invitation_id), str(org.tenant_id)),
                )
                if not changed.rowcount:
                    raise AccessDenied
                self._audit(
                    db,
                    str(org.tenant_id),
                    actor,
                    "invitation_revoked",
                    request_id,
                    str(invitation_id),
                )

    def revoke_member(self, principal, organization_id: UUID, target: UUID, request_id: str):
        with self.authorization.transaction():
            org, actor = self._admin(principal, organization_id, request_id)
            with self.authorization.atomic() as db:
                now, tenant = datetime.now(UTC).isoformat(), str(org.tenant_id)
                changed = db.execute(
                    """UPDATE organization_memberships SET revoked_at = ?
                    WHERE tenant_id = ? AND identity_id = ? AND revoked_at IS NULL
                    AND (role IN ('analyst', 'viewer') OR (
                        role = 'admin' AND EXISTS (
                            SELECT 1 FROM organization_memberships owner
                            WHERE owner.tenant_id = organization_memberships.tenant_id
                            AND owner.identity_id = ? AND owner.role = 'owner' AND owner.revoked_at IS NULL
                        )
                    ))""",
                    (now, tenant, str(target), str(actor)),
                )
                if not changed.rowcount:
                    raise AccessDenied
                self.authorization.replace_snapshot(target, org.tenant_id, None)
                db.execute(
                    "UPDATE organization_invitations SET closed_at = ? WHERE tenant_id = ? AND identity_id = ? AND closed_at IS NULL",
                    (now, tenant, str(target)),
                )
                db.execute(
                    "UPDATE organization_invitations SET closed_at = ? WHERE tenant_id = ? AND inviter_id = ? AND closed_at IS NULL",
                    (now, tenant, str(target)),
                )
                self._audit(db, tenant, actor, "membership_revoked", request_id, str(target))

    def transfer(self, principal, organization_id: UUID, target: UUID, request_id: str):
        with self.authorization.transaction():
            org, actor = self._admin(principal, organization_id, request_id, owner=True)
            tenant = str(org.tenant_id)
            with self.authorization.atomic() as db:
                recipient = db.execute(
                    """SELECT 1 FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?
                    AND revoked_at IS NULL AND role <> 'owner'""",
                    (tenant, str(target)),
                ).fetchone()
                if recipient is None or not self._active_human(target):
                    raise AccessDenied
                self._set_role(db, tenant, str(actor), MembershipRole.ANALYST, actor)
                self._set_role(db, tenant, str(target), MembershipRole.OWNER, actor)
                self._audit(db, tenant, actor, "ownership_transferred", request_id, str(target))

    def change_role(
        self, principal, organization_id: UUID, request: InvitationRequest, request_id: str
    ):
        with self.authorization.transaction():
            org, actor = self._admin(
                principal,
                organization_id,
                request_id,
                owner=True,
                permission=Permission.ROLES_ASSIGN,
            )
            if request.role == MembershipRole.OWNER or request.identity_id == actor:
                raise AccessDenied
            tenant, target = str(org.tenant_id), str(request.identity_id)
            with self.authorization.atomic() as db:
                row = db.execute(
                    """SELECT 1 FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?
                    AND revoked_at IS NULL AND role <> 'owner'""",
                    (tenant, target),
                ).fetchone()
                if row is None or not self._active_human(request.identity_id):
                    raise AccessDenied
                self._set_role(db, tenant, target, request.role, actor)
                self._audit(db, tenant, actor, "membership_role_updated", request_id, target)

    def record_denial(self, principal: VerifiedPrincipal, request_id: str) -> None:
        with self.authorization.atomic() as db:
            self._audit(db, None, principal.identity.identity_id, "request_denied", request_id)

    def register_workload(
        self, principal, organization_id: UUID, target: UUID, request_id: str
    ) -> None:
        """Enroll a verified integration with an empty product policy."""
        with self.authorization.transaction():
            org, actor = self._admin(
                principal,
                organization_id,
                request_id,
                owner=True,
                permission=Permission.SECRET_POLICY,
            )
            if not self.active_workload(target):
                raise AccessDenied
            tenant = str(org.tenant_id)
            with self.authorization.atomic() as db:
                changed = db.execute(
                    """INSERT INTO organization_memberships VALUES (?, ?, 'viewer', ?, NULL)
                    ON CONFLICT(tenant_id, identity_id) DO UPDATE SET
                        joined_at = excluded.joined_at, revoked_at = NULL
                    WHERE organization_memberships.revoked_at IS NOT NULL""",
                    (tenant, str(target), datetime.now(UTC).isoformat()),
                )
                if changed.rowcount:
                    self.authorization.replace_snapshot(target, org.tenant_id, SubjectPolicy())
                    self._audit(db, tenant, actor, "workload_registered", request_id, str(target))
