"""Typed, deny-by-default policy for server-resolved actors and resources."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from riswan_platform.core.context import PlatformContext
from riswan_platform.identity.models import IdentityStatus, IdentityType, VerifiedPrincipal


class Permission(StrEnum):
    IDENTITY_READ = "platform.identity.read"
    ORGANIZATION_MANAGE = "platform.organization.manage"
    ROLES_ASSIGN = "platform.roles.assign"
    INTEGRATIONS_MANAGE = "platform.integrations.manage"
    AUDIT_READ = "platform.audit.read"
    SECRET_CREATE = "platform.secrets.create"
    SECRET_READ = "platform.secrets.read"
    SECRET_UPDATE = "platform.secrets.update"
    SECRET_ROTATE = "platform.secrets.rotate"
    SECRET_REVOKE = "platform.secrets.revoke"
    SECRET_DELETE = "platform.secrets.delete"
    SECRET_POLICY = "platform.secrets.policy"
    SECRET_AUDIT = "platform.secrets.audit"
    LEGAL_HOLD = "platform.data_protection.holds.manage"
    READ = "ir.investigation.read"
    CREATE = "ir.investigation.create"
    UPDATE = "ir.investigation.update"
    CLOSE = "ir.investigation.close"
    EVIDENCE = "ir.evidence.read"
    EXPORT = "ir.evidence.export"
    DETECTION_READ = "ir.detection.read"
    DETECTION_MANAGE = "ir.detection.manage"
    CORRELATE = "ir.correlation.execute"
    GRAPH = "ir.graph.query"
    RISK = "ir.risk.assess"
    MEMORY = "ir.memory.read"
    MEMORY_MANAGE = "ir.memory.manage"
    FEEDBACK = "ir.memory.feedback"
    PROPOSE = "ir.response.propose"
    APPROVE = "ir.response.approve"
    EXECUTE = "ir.response.execute"
    SETTINGS = "ir.settings.manage"


class Role(StrEnum):
    OPERATOR = "platform.operator"
    OWNER = "platform.organization_owner"
    ADMIN = "platform.organization_admin"
    INTEGRATION = "platform.integration_manager"
    AUDITOR = "platform.compliance_auditor"
    IR_ADMIN = "ir.administrator"
    COMMANDER = "ir.incident_commander"
    ANALYST = "ir.security_analyst"
    HUNTER = "ir.threat_hunter"
    APPROVER = "ir.response_approver"
    VIEWER = "ir.viewer"
    AGENT = "ir.investigation_agent"


P = Permission
VIEW = frozenset({P.READ, P.EVIDENCE})
ANALYZE = VIEW | {P.GRAPH, P.DETECTION_READ, P.MEMORY}
SECRET_ADMIN = frozenset(
    {
        P.SECRET_CREATE,
        P.SECRET_READ,
        P.SECRET_UPDATE,
        P.SECRET_ROTATE,
        P.SECRET_REVOKE,
        P.SECRET_DELETE,
        P.SECRET_POLICY,
        P.SECRET_AUDIT,
    }
)
ROLE_PERMISSIONS = {
    Role.OPERATOR: frozenset({P.IDENTITY_READ}),
    Role.OWNER: SECRET_ADMIN
    | frozenset({P.ORGANIZATION_MANAGE, P.ROLES_ASSIGN, P.AUDIT_READ, P.LEGAL_HOLD}),
    Role.ADMIN: {P.SECRET_READ, P.SECRET_CREATE, P.SECRET_ROTATE, P.SECRET_REVOKE}
    | frozenset({P.ORGANIZATION_MANAGE, P.ROLES_ASSIGN}),
    Role.INTEGRATION: frozenset({P.INTEGRATIONS_MANAGE}),
    Role.AUDITOR: frozenset({P.AUDIT_READ}),
    Role.IR_ADMIN: ANALYZE | {P.DETECTION_MANAGE, P.SETTINGS},
    Role.COMMANDER: ANALYZE
    | {P.CREATE, P.UPDATE, P.CLOSE, P.EXPORT, P.RISK, P.PROPOSE, P.MEMORY_MANAGE},
    Role.ANALYST: ANALYZE | {P.CREATE, P.UPDATE, P.CORRELATE, P.RISK, P.FEEDBACK, P.PROPOSE},
    Role.HUNTER: ANALYZE | {P.CORRELATE},
    Role.APPROVER: VIEW | {P.APPROVE},
    Role.VIEWER: VIEW,
    Role.AGENT: frozenset({P.READ, P.EVIDENCE, P.GRAPH, P.PROPOSE}),
}
PRIVILEGED = SECRET_ADMIN | frozenset(
    {
        P.ROLES_ASSIGN,
        P.LEGAL_HOLD,
        P.ORGANIZATION_MANAGE,
        P.INTEGRATIONS_MANAGE,
        P.AUDIT_READ,
        P.EXPORT,
        P.MEMORY_MANAGE,
        P.APPROVE,
        P.DETECTION_MANAGE,
        P.SETTINGS,
    }
)
POLICY_VERSION = "1.0.0"


class ScopeType(StrEnum):
    PLATFORM = "platform"
    ORGANIZATION = "organization"
    PRODUCT = "product"
    CLOUD_ACCOUNT = "cloud_account"
    INVESTIGATION = "investigation"
    EVIDENCE = "evidence"
    RESPONSE = "response"


@dataclass(frozen=True, slots=True)
class Scope:
    kind: ScopeType
    id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, ScopeType)
            or not isinstance(self.id, str)
            or not self.id.strip()
        ):
            raise ValueError("Invalid authorization scope.")


@dataclass(frozen=True, slots=True)
class Resource:
    tenant_id: UUID
    product_id: str
    scope: Scope
    parents: tuple[Scope, ...] = ()
    restricted: bool = False
    proposer_id: UUID | None = None
    tenant_shared: bool = False

    @property
    def scopes(self) -> frozenset[Scope]:
        return frozenset((self.scope, *self.parents))


@dataclass(frozen=True, slots=True)
class Assignment:
    role: Role
    scope: Scope
    grantor_id: UUID
    created_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.role, Role)
            or self.created_at.utcoffset() is None
            or type(self.revoked) is not bool
        ):
            raise ValueError("Invalid role assignment.")
        if self.expires_at is not None and (
            self.expires_at.utcoffset() is None or self.expires_at <= self.created_at
        ):
            raise ValueError("Invalid role expiration.")

    def active_at(self, instant: datetime) -> bool:
        return (
            not self.revoked
            and self.created_at <= instant
            and (self.expires_at is None or instant < self.expires_at)
        )


@dataclass(frozen=True, slots=True)
class Grant:
    action: Permission
    scope: Scope
    deny: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.action, Permission) or type(self.deny) is not bool:
            raise ValueError("Unregistered permission.")


@dataclass(frozen=True, slots=True)
class SubjectPolicy:
    assignments: tuple[Assignment, ...] = ()
    grants: tuple[Grant, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    principal: VerifiedPrincipal
    context: PlatformContext
    action: Permission
    resource: Resource


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: UUID
    effect: str
    reason_code: str
    policy_version: str
    actor_id: UUID
    tenant_id: UUID
    action: Permission
    resource_id: str
    correlation_id: str
    evaluated_at: datetime

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"


class PolicyRepository(Protocol):
    def policy_for(self, actor_id: UUID, tenant_id: UUID) -> SubjectPolicy | None:
        """Return current policy or None if there is no active trusted membership."""
        ...


class AuditSink(Protocol):
    def record(self, event_type: str, decision: Decision) -> None: ...


class AuthorizationEngine(Protocol):
    def evaluate(self, request: AuthorizationRequest) -> Decision: ...


class Evaluator:
    def __init__(self, repository: PolicyRepository, audit: AuditSink):
        self.repository = repository
        self.audit = audit

    def evaluate(self, request: AuthorizationRequest) -> Decision:
        instant = datetime.now(UTC)
        try:
            reason = self._reason(request, instant)
        except Exception:
            reason = "EVALUATION_FAILED"
        decision = Decision(
            uuid4(),
            "allow" if reason == "ALLOWED" else "deny",
            reason,
            POLICY_VERSION,
            request.principal.identity.identity_id,
            request.context.tenant_id,
            request.action,
            request.resource.scope.id,
            request.context.correlation_id,
            instant,
        )
        if not decision.allowed or request.action in PRIVILEGED:
            event = {
                "ALLOWED": "privileged_access_allowed",
                "CROSS_TENANT": "cross_tenant_access_denied",
                "SEPARATION_OF_DUTIES": "separation_of_duties_violation",
                "EVALUATION_FAILED": "evaluation_failed",
            }.get(reason, "access_denied")
            try:
                self.audit.record(f"platform.authorization.{event}", decision)
            except Exception:
                return replace(decision, effect="deny", reason_code="AUDIT_UNAVAILABLE")
        return decision

    def _reason(self, request: AuthorizationRequest, instant: datetime) -> str:
        identity = request.principal.identity
        context, resource, action = request.context, request.resource, request.action
        if (
            identity.status != IdentityStatus.ACTIVE
            or str(identity.identity_id) != context.actor_id
            or identity.identity_type != context.actor_type
        ):
            return "INVALID_ACTOR"
        if resource.tenant_id != context.tenant_id:
            return "CROSS_TENANT"
        if resource.product_id != context.product_id or not isinstance(action, Permission):
            return "INVALID_SCOPE"
        if action.split(".", 1)[0] != resource.product_id:
            return "INVALID_SCOPE"
        policy = self.repository.policy_for(identity.identity_id, context.tenant_id)
        if policy is None:
            return "NO_MEMBERSHIP"
        grants = tuple(
            g for g in policy.grants if g.action == action and g.scope in resource.scopes
        )
        if any(g.deny for g in grants):
            return "EXPLICIT_DENY"
        if action == P.EXECUTE:
            return "OPERATION_DISABLED"
        if identity.identity_type != IdentityType.HUMAN and (
            action in PRIVILEGED
            or (
                identity.identity_type == IdentityType.AGENT
                and action not in ROLE_PERMISSIONS[Role.AGENT]
            )
        ):
            return "WORKLOAD_RESTRICTED"
        if identity.identity_type == IdentityType.AGENT and not any(
            g.scope.kind
            in {
                ScopeType.CLOUD_ACCOUNT,
                ScopeType.INVESTIGATION,
                ScopeType.EVIDENCE,
                ScopeType.RESPONSE,
            }
            for g in grants
        ):
            return "WORKLOAD_RESTRICTED"
        if not any(
            a.scope in resource.scopes
            and a.active_at(instant)
            and action in ROLE_PERMISSIONS[a.role]
            and (a.role != Role.AGENT or identity.identity_type == IdentityType.AGENT)
            for a in policy.assignments
        ):
            return "NO_PERMISSION"
        if resource.scope.kind in {ScopeType.INVESTIGATION, ScopeType.EVIDENCE, ScopeType.RESPONSE}:
            if not any(
                (
                    g.scope.kind
                    not in {ScopeType.PLATFORM, ScopeType.ORGANIZATION, ScopeType.PRODUCT}
                    or (
                        resource.tenant_shared
                        and g.scope == Scope(ScopeType.ORGANIZATION, str(context.tenant_id))
                    )
                )
                and (not resource.restricted or g.scope == resource.scope)
                for g in grants
            ):
                return "RESOURCE_SCOPE_MISMATCH"
        if (resource.restricted or action in PRIVILEGED) and (
            identity.identity_type != IdentityType.HUMAN or not request.principal.mfa_verified
        ):
            return "MFA_REQUIRED"
        if action == P.APPROVE and (
            resource.scope.kind != ScopeType.RESPONSE
            or resource.proposer_id in {None, identity.identity_id}
        ):
            return "SEPARATION_OF_DUTIES"
        return "ALLOWED"
