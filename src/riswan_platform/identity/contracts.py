"""Published identity provider and persistence interfaces."""

from datetime import datetime
from typing import Protocol
from uuid import UUID

from .models import (
    AuditEvent,
    ExternalIdentity,
    IdentityStatus,
    PlatformIdentity,
    Session,
    VerifiedPrincipal,
)


class IdentityProvider(Protocol):
    def authorization_redirect(self, state: str, nonce: str, challenge: str) -> str: ...
    def exchange(self, code: str, verifier: str, nonce: str) -> ExternalIdentity: ...
    def validate_access_token(self, token: str) -> ExternalIdentity: ...
    def logout_redirect(self) -> str | None: ...


class IdentityRepository(Protocol):
    def resolve(self, external: ExternalIdentity, now: datetime) -> PlatformIdentity: ...
    def create_session(
        self, session: Session, digest: str, event: AuditEvent, previous_digest: str | None = None
    ) -> None: ...
    def authenticate_session(
        self, digest: str, now: datetime, idle_seconds: int, request_id: str
    ) -> VerifiedPrincipal | None: ...
    def revoke_session(
        self, actor: UUID, session: UUID, now: datetime, event: AuditEvent
    ) -> bool: ...
    def sessions(self, actor: UUID, now: datetime, idle_seconds: int) -> list[Session]: ...
    def set_status(
        self, actor: UUID, status: IdentityStatus, now: datetime, event: AuditEvent
    ) -> None: ...
    def audit(self, event: AuditEvent) -> None: ...
