"""Normalize caller identity and session metadata without exporting credential IDs."""

from ...core.fields import mapping, text_field, utc_timestamp
from ...models import CloudTrailRecord
from ...models.identity import CloudIdentity, PrincipalIdentity, SessionContext
from .validation import cloud_bool


def principal_fields(data: dict[str, object]) -> dict[str, str | None]:
    return {
        "type": text_field(data, "type"),
        "arn": text_field(data, "arn"),
        "principal_id": text_field(data, "principalId"),
        "account_id": text_field(data, "accountId"),
        "user_name": text_field(data, "userName"),
    }


def normalize_identity(event: CloudTrailRecord) -> CloudIdentity | None:
    identity = mapping(event, "userIdentity")
    if not identity:
        return None
    session = mapping(identity, "sessionContext")
    attributes = mapping(session, "attributes")
    issuer = mapping(session, "sessionIssuer")
    created_at = text_field(attributes, "creationDate")
    if created_at:
        try:
            created_at = utc_timestamp(created_at).isoformat(timespec="microseconds")
        except (ValueError, OverflowError):
            created_at = None
    console = cloud_bool(event.get("sessionCredentialFromConsole"))
    mfa = cloud_bool(attributes.get("mfaAuthenticated"))
    if mfa is None:
        mfa = cloud_bool(mapping(event, "additionalEventData").get("MFAUsed"))
    source_identity = (
        text_field(session, "sourceIdentity")
        or text_field(identity, "sourceIdentity")
        or text_field(mapping(event, "requestParameters"), "sourceIdentity")
        or text_field(mapping(event, "responseElements"), "sourceIdentity")
    )
    return CloudIdentity(
        **principal_fields(identity),
        invoked_by=text_field(identity, "invokedBy"),
        identity_provider=text_field(identity, "identityProvider"),
        session=SessionContext(
            issuer=PrincipalIdentity(**principal_fields(issuer)) if issuer else None,
            source_identity=source_identity,
            created_at=created_at,
            mfa_authenticated=mfa,
            credential_from_console=console,
        )
        if session or console is not None or mfa is not None or source_identity
        else None,
    )
