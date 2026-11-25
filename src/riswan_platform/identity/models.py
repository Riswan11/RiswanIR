"""Platform identity, verified principal, session and authentication audit models."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID


class AuthenticationError(PermissionError):
    """A credential could not be verified."""


class ProviderUnavailable(AuthenticationError):
    """Trusted identity infrastructure could not be reached."""


class IdentityType(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    INTEGRATION = "integration"
    AGENT = "agent"


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class ExternalIdentity:
    issuer: str
    subject: str
    identity_type: IdentityType
    display_name: str
    email: str | None = None
    mfa_verified: bool = False


@dataclass(frozen=True, slots=True)
class PlatformIdentity:
    identity_id: UUID
    identity_type: IdentityType
    issuer: str
    subject: str
    display_name: str
    email: str | None
    status: IdentityStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    identity: PlatformIdentity
    method: Literal["oidc", "bearer", "session"]
    mfa_verified: bool
    session_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Session:
    id: UUID
    identity_id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    mfa_verified: bool


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    actor_id: UUID | None
    identity_type: IdentityType | None
    authentication_method: str
    mfa_verified: bool
    request_id: str
    outcome: Literal["success", "rejected", "error"]
    occurred_at: datetime
