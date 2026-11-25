"""Provider-independent credential types and consumer contracts."""

from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Protocol, TypeVar
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, StringConstraints

Name = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_. -]{0,119}$")]
Result = TypeVar("Result")


class SecretError(Exception):
    """Sanitized secret operation failure."""


class ProviderUnavailable(SecretError):
    """The secret value provider could not complete an operation."""


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Scope(StrEnum):
    PLATFORM = "platform"
    TENANT = "tenant"
    PRODUCT = "product"


class Kind(StrEnum):
    API_KEY = "api_key"
    OAUTH_REFRESH = "oauth_refresh"
    WEBHOOK = "webhook"
    DATABASE = "database"
    OIDC = "oidc"


class Status(StrEnum):
    CREATED = "created"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_DELETION = "pending_deletion"
    DELETED = "deleted"


class SecretReference(Model):
    id: UUID


class SecretMaterial(Model):
    value: SecretStr = Field(exclude=True, repr=False)


class RotationPolicy(Model):
    interval_days: int = Field(default=90, ge=1, le=365)


class SecretMetadata(Model):
    id: UUID
    tenant_id: UUID
    organization_id: UUID
    product_id: str
    name: Name
    kind: Kind
    scope: Scope
    provider: str
    status: Status
    current_version: UUID | None = None
    created_by: UUID
    created_at: AwareDatetime
    updated_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    rotation: RotationPolicy
    last_rotated_at: AwareDatetime | None = None
    next_rotation_at: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None


class Registration(SecretMaterial):
    id: UUID
    name: Name
    kind: Kind
    expires_at: AwareDatetime | None = None
    rotation: RotationPolicy = Field(default_factory=RotationPolicy)


class Update(Model):
    name: Name
    expires_at: AwareDatetime | None = None
    rotation: RotationPolicy = Field(default_factory=RotationPolicy)


class RollbackRequest(Model):
    version_id: UUID


class RotationRequest(SecretMaterial):
    operation_id: UUID


class SecretVersion(Model):
    id: UUID
    created_at: AwareDatetime
    state: str


class RotationOperation(Model):
    id: UUID
    secret_id: UUID
    state: str
    started_at: AwareDatetime
    base_version: UUID | None = None


class SecretAccessPolicy(Model):
    workload_id: UUID
    purpose: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,79}$")]
    expires_at: AwareDatetime


class SecretAccessEvent(Model):
    id: UUID
    secret_id: UUID
    actor_id: str
    tenant_id: UUID
    actor_type: str
    product_id: str
    request_id: str
    correlation_id: str
    action: str
    outcome: str
    reason: str
    occurred_at: AwareDatetime


class CredentialLease(Model):
    id: UUID
    expires_at: AwareDatetime


class SecretProvider(Protocol):
    name: str
    development_only: bool

    def put(self, key: str, material: SecretMaterial) -> None: ...
    def get(self, key: str) -> SecretMaterial: ...
    def schedule_delete(self, key: str) -> None: ...
    def deleted(self, key: str) -> bool: ...


class CredentialConsumer(Protocol):
    def use(
        self, reference: SecretReference, purpose: str, consume: Callable[[SecretMaterial], Result]
    ) -> Result: ...


def checked_material(material: SecretMaterial) -> bytes:
    value = material.value.get_secret_value().encode()
    if not 0 < len(value) <= 65536:
        raise SecretError("Invalid credential material.")
    return value


def validate_expiry(expires_at: datetime | None, now: datetime) -> None:
    if expires_at is not None and expires_at <= now:
        raise SecretError("Credential expiration must be in the future.")


def redact_fields(fields: Mapping[str, object], *, allowed: frozenset[str]) -> dict[str, object]:
    """Project structured telemetry onto an explicit allowlist of scalar fields."""
    return {
        key: value
        for key, value in fields.items()
        if key in allowed and (value is None or type(value) in {str, int, float, bool})
    }
