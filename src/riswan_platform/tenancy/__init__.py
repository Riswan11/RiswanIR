"""Shared organization lifecycle and membership contracts."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from riswan_platform.core.context import PlatformContext
from riswan_platform.identity.models import VerifiedPrincipal

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]


class TenantStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class MembershipRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class OrganizationSettings(Model):
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = ""


class OrganizationInput(Model):
    name: Name
    settings: OrganizationSettings = Field(default_factory=OrganizationSettings)


class Organization(OrganizationInput):
    id: UUID
    tenant_id: UUID
    status: TenantStatus
    created_at: datetime


class Membership(Model):
    identity_id: UUID
    role: MembershipRole
    joined_at: datetime
    revoked_at: datetime | None = None


class InvitationRequest(Model):
    identity_id: UUID
    role: MembershipRole


class Invitation(Model):
    id: UUID
    token: Token
    expires_at: datetime


class Acceptance(Model):
    token: Token


class OwnershipTransfer(Model):
    identity_id: UUID


class LifecycleChange(Model):
    status: TenantStatus


class TenantAccess(Protocol):
    def context_for(
        self, principal: VerifiedPrincipal, tenant_id: UUID, product_id: str, request_id: str
    ) -> PlatformContext | None: ...
