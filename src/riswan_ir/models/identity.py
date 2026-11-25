"""Cloud identity and session fields retained in evidence."""

from .base import DomainModel, Timestamp


class PrincipalIdentity(DomainModel):
    type: str | None = None
    arn: str | None = None
    principal_id: str | None = None
    account_id: str | None = None
    user_name: str | None = None


class SessionContext(DomainModel):
    issuer: PrincipalIdentity | None = None
    source_identity: str | None = None
    created_at: Timestamp | None = None
    mfa_authenticated: bool | None = None
    credential_from_console: bool | None = None


class CloudIdentity(PrincipalIdentity):
    invoked_by: str | None = None
    identity_provider: str | None = None
    session: SessionContext | None = None
