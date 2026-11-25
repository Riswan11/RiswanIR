"""AWS-specific identity scope and STS field extraction."""

from ..core.fields import mapping, text_field
from ..evidence.integrity import canonical_json, sha256
from ..models import CloudTrailRecord
from ..models.correlation import Identity, IdentityAlias
from ..models.identity import CloudIdentity, PrincipalIdentity
from ..normalization.aws.cloudtrail import PreparedEvent
from ..normalization.aws.ocsf_mapper import map_event
from .engine import Observation


def node_id(kind: str, *fields: str | None) -> str:
    return kind + "_" + sha256(canonical_json(fields)).removeprefix("sha256:")


def arn_account(arn: str | None) -> str | None:
    parts = arn.split(":", 5) if arn else []
    return (
        parts[4]
        if len(parts) == 6
        and parts[0] == "arn"
        and (parts[1] == "aws" or parts[1].startswith("aws-"))
        and len(parts[4]) == 12
        and parts[4].isascii()
        and parts[4].isdigit()
        else None
    )


def partition(arn: str | None, region: str | None = None) -> str:
    if arn and arn_account(arn):
        return arn.split(":", 2)[1]
    if region and region.startswith("cn-"):
        return "aws-cn"
    if region and region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


class AWSIdentityResolver:
    def resolve(
        self, field: PrincipalIdentity | None, event_id: str, region: str | None = None
    ) -> Identity:
        if field is None:
            return Identity(id=node_id("unknown", event_id), account_id=None, kind=None, aliases=[])
        account = arn_account(field.arn) or field.account_id
        scope = partition(field.arn, region)
        if field.account_id and arn_account(field.arn) not in (None, field.account_id):
            return Identity(
                id=node_id("unknown", event_id), account_id=None, kind=field.type, aliases=[]
            )
        aliases = [
            IdentityAlias(kind=kind, value=value)
            for kind, value in (("arn", field.arn), ("principal_id", field.principal_id))
            if value
        ]
        stable = field.principal_id or field.arn
        if isinstance(field, CloudIdentity) and field.invoked_by and not stable and account:
            stable = field.invoked_by
            aliases.append(IdentityAlias(kind="invoked_by", value=stable))
        identifier = (
            node_id("identity", scope, account, stable)
            if account and stable
            else node_id("unknown", event_id)
        )
        return Identity(
            id=identifier, account_id=account, partition=scope, kind=field.type, aliases=aliases
        )

    def adapt(self, prepared: PreparedEvent, raw: CloudTrailRecord) -> Observation:
        event = prepared.event
        identity = event.identity
        session = identity.session if identity else None
        key, returned_arn, expires = prepared.credential
        returned_id = text_field(
            mapping(mapping(raw, "responseElements"), "assumedRoleUser"), "assumedRoleId"
        )
        target_arn = event.target if event.event == "AssumeRole" else None
        target_account = arn_account(target_arn) or arn_account(returned_arn)
        consistent = not (
            arn_account(target_arn)
            and arn_account(returned_arn)
            and (
                arn_account(target_arn) != arn_account(returned_arn)
                or partition(target_arn) != partition(returned_arn)
            )
        )
        if target_arn and returned_arn:
            parts = returned_arn.rsplit("/", 2)
            consistent = (
                consistent and len(parts) == 3 and target_arn.rsplit("/", 1)[-1] == parts[1]
            )
        resolved = self.resolve(identity, event.id, event.region)
        if event.event in ("CreateAccessKey", "GetSessionToken"):
            target_account = resolved.account_id
        return Observation(
            event=map_event(event),
            request_id=event.request_id,
            shared_request_id=event.shared_event_id,
            recipient_account_id=event.recipient_account_id,
            identity=resolved,
            issuer_arn=session.issuer.arn if session and session.issuer else None,
            session_created=session.created_at if session else None,
            source_identity=session.source_identity if session else None,
            actor_principal_id=identity.principal_id if identity else None,
            actor_username=identity.user_name or identity.arn.rsplit("/", 1)[-1]
            if identity and identity.arn and ":user/" in identity.arn
            else None,
            credential_ref=sha256(prepared.access_key_id) if prepared.access_key_id else None,
            issued_ref=sha256(key) if key and consistent else None,
            issued_arn=returned_arn if consistent else None,
            issued_principal_id=returned_id,
            issued_account=target_account,
            issued_username=event.target if event.event == "CreateAccessKey" else None,
            issued_partition=partition(target_arn or returned_arn, event.region),
            expires_at=expires,
            target_role=self.resolve(PrincipalIdentity(arn=target_arn, type="Role"), event.id)
            if target_arn and consistent
            else None,
            scope_conflict=not consistent
            or bool(
                identity
                and identity.account_id
                and arn_account(identity.arn) not in (None, identity.account_id)
            ),
        )
