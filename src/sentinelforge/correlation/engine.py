"""Provider-independent, conservative correlation over ordered observations."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from ..core.fields import utc_timestamp
from ..evidence.integrity import canonical_json, sha256
from ..models import Evidence
from ..models.correlation import (
    ActivityChain,
    CorrelationContext,
    CorrelationResult,
    CredentialReference,
    Identity,
    IdentityRelationship,
    IdentitySession,
    IdentityTimeline,
    RoleAssumption,
)
from ..models.correlation import (
    CorrelationConfidence as Confidence,
)
from ..models.security_event import Outcome, SecurityEvent


@dataclass(frozen=True)
class Observation:
    event: SecurityEvent
    identity: Identity
    issuer_arn: str | None
    session_created: str | None
    source_identity: str | None
    actor_principal_id: str | None
    actor_username: str | None
    credential_ref: str | None
    issued_ref: str | None
    issued_arn: str | None
    issued_principal_id: str | None
    issued_account: str | None
    issued_username: str | None
    issued_partition: str
    expires_at: datetime | None
    target_role: Identity | None
    scope_conflict: bool


Context = CorrelationContext(
    version="identity-correlation-1",
    session_clock_tolerance_seconds=2,
    request_clock_tolerance_seconds=5,
)
Link = tuple[str, Confidence]


def match(issuer: Observation, caller: Observation) -> Confidence | None:
    issued_at = utc_timestamp(issuer.event.observed_at)
    called_at = utc_timestamp(caller.event.observed_at)
    if called_at <= issued_at or (issuer.expires_at and called_at >= issuer.expires_at):
        return None
    if issuer.issued_account and caller.identity.account_id != issuer.issued_account:
        return None
    if issuer.issued_username and caller.actor_username != issuer.issued_username:
        return None
    if caller.identity.partition and caller.identity.partition != issuer.issued_partition:
        return None
    if (
        issuer.source_identity
        and caller.source_identity
        and issuer.source_identity != caller.source_identity
    ):
        return None
    if issuer.issued_arn and caller.event.principal and issuer.issued_arn != caller.event.principal:
        return None
    if (
        issuer.issued_principal_id
        and caller.actor_principal_id
        and issuer.issued_principal_id != caller.actor_principal_id
    ):
        return None
    if (
        caller.issuer_arn
        and issuer.target_role
        and not any(
            alias.kind == "arn" and alias.value == caller.issuer_arn
            for alias in issuer.target_role.aliases
        )
    ):
        return None
    if not issuer.issued_ref or not caller.credential_ref:
        corroborated = (
            issuer.target_role is not None
            and caller.issuer_arn is not None
            and any(
                alias.kind == "arn" and alias.value == caller.issuer_arn
                for alias in issuer.target_role.aliases
            )
            and issuer.issued_principal_id is not None
            and issuer.issued_principal_id == caller.actor_principal_id
        )
        if (
            issuer.issued_arn
            and issuer.issued_arn == caller.event.principal
            and corroborated
            and caller.session_created
            and abs((utc_timestamp(caller.session_created) - issued_at).total_seconds())
            <= Context.session_clock_tolerance_seconds
            and utc_timestamp(caller.session_created) <= called_at
        ):
            return Confidence.HIGH
    elif issuer.issued_ref == caller.credential_ref:
        return Confidence.CONFIRMED
    return None


def select(
    observations: list[Observation], principal: str
) -> tuple[list[Observation], dict[str, Link], list[str]]:
    keys: dict[str, list[Observation]] = defaultdict(list)
    arns: dict[str, list[Observation]] = defaultdict(list)
    picked: dict[str, Observation] = {}
    links: dict[str, Link] = {}
    unresolved = []
    for item in sorted(observations, key=lambda row: (row.event.observed_at, row.event.id)):
        event = item.event
        candidates: dict[str, tuple[Observation, Confidence]] = {}
        possible = keys.get(item.credential_ref or "", []) + arns.get(event.principal or "", [])
        if not item.scope_conflict:
            for issuer in possible:
                confidence = match(issuer, item)
                if confidence:
                    paired = issuer.event.shared_event_id
                    group = (
                        canonical_json(
                            (
                                paired,
                                issuer.event.event_source,
                                issuer.event.operation,
                                issuer.issued_account,
                                issuer.issued_ref,
                                issuer.issued_arn,
                                issuer.issued_principal_id,
                                issuer.event.observed_at,
                            )
                        )
                        if paired
                        and issuer.event.recipient_account_id
                        and issuer.event.event_source
                        else issuer.event.id
                    )
                    prior = candidates.get(group)
                    if (
                        prior
                        and prior[0].event.id != issuer.event.id
                        and (
                            prior[0].event.recipient_account_id == issuer.event.recipient_account_id
                        )
                    ):
                        group = issuer.event.id
                        prior = candidates.get(group)
                    if prior is None or (
                        issuer.event.id in picked and prior[0].event.id not in picked
                    ):
                        candidates[group] = issuer, confidence
        related = any(issuer.event.id in picked for issuer in possible)
        relevant = event.principal == principal or related
        if relevant:
            if item.scope_conflict or len(candidates) > 1:
                unresolved.append(
                    f"{event.id}: conflicting identity or issuance; no inferred link."
                )
            elif related and not candidates:
                unresolved.append(f"{event.id}: issuance evidence is insufficient or inconsistent.")
            matched = next(iter(candidates.values())) if len(candidates) == 1 else None
            if event.principal == principal or (matched and matched[0].event.id in picked):
                picked[event.id] = item
                if matched:
                    issuer, confidence = matched
                    if issuer.event.id in picked:
                        links[event.id] = issuer.event.id, confidence
        if event.outcome == Outcome.SUCCESS and not item.scope_conflict:
            if item.issued_ref:
                keys[item.issued_ref].append(item)
            if item.issued_arn:
                arns[item.issued_arn].append(item)
    return list(picked.values()), links, unresolved


def session_id(*parts: str | None) -> str:
    return "session_" + sha256(canonical_json(parts)).removeprefix("sha256:")


def describe(
    observations: list[Observation],
    evidence: list[Evidence],
    links: dict[str, Link],
    unresolved: list[str],
) -> CorrelationResult:
    identities: dict[str, Identity] = {}
    sessions: dict[str, IdentitySession] = {}
    assumptions = []
    relationships = []
    timelines: dict[str, list[str]] = defaultdict(list)
    chains: dict[str, list[str]] = defaultdict(list)
    roots: dict[str, str] = {}
    actor_sessions: dict[str, str] = {}
    issued_sessions: dict[str, str] = {}
    evidence_by_id = {item.id: item for item in evidence}
    requests: dict[tuple[str | None, ...], Observation] = {}

    def add(
        source: str,
        relation: str,
        target: str,
        ids: list[str],
        reason: str,
        confidence: Confidence = Confidence.CONFIRMED,
    ) -> None:
        relationships.append(
            IdentityRelationship(
                source=source,
                relationship=relation,
                target=target,
                confidence=confidence,
                reason=reason,
                evidence_ids=ids,
            )
        )

    for observation in observations:
        event = evidence_by_id[observation.event.id]
        actor = observation.identity
        event_id = event.id
        parent, confidence = links.get(event_id, ("", Confidence.UNKNOWN))
        roots[event_id] = roots.get(parent, event_id)
        chains[roots[event_id]].append(event_id)
        identities.setdefault(actor.id, actor)
        timelines[actor.id].append(event_id)
        if actor.account_id:
            add(
                actor.id,
                "BELONGS_TO_ACCOUNT",
                "account:" + actor.account_id,
                [event_id],
                "Account-scoped principal",
            )
        sid = issued_sessions.get(parent) or session_id(
            actor.id, observation.credential_ref or observation.session_created or event_id
        )
        actor_sessions[event_id] = sid
        if sid not in sessions:
            credential = (
                CredentialReference(id=observation.credential_ref)
                if observation.credential_ref
                else None
            )
            sessions[sid] = IdentitySession(
                id=sid,
                identity_id=actor.id,
                credential=credential,
                created_at=observation.session_created,
                source_identity=observation.source_identity,
            )
        add(
            sid,
            "AUTHENTICATED_AS",
            actor.id,
            [event_id],
            "Recorded caller identity",
            Confidence.UNKNOWN if not actor.aliases else Confidence.CONFIRMED,
        )
        add(sid, "PERFORMED_ACTION", event_id, [event_id], "Recorded API operation")
        if parent:
            add(
                actor_sessions[parent],
                "CHAINED_TO",
                sid,
                [parent, event_id],
                "Matching issued credential"
                if confidence == Confidence.CONFIRMED
                else "Session ARN, issuer, principal ID and creation time",
                confidence,
            )
        role = observation.target_role
        if (
            role
            and not observation.scope_conflict
            and event.outcome == Outcome.SUCCESS
            and (observation.issued_ref or observation.issued_arn)
        ):
            identities.setdefault(role.id, role)
            created = session_id(event_id, "issued")
            issued_sessions[event_id] = created
            credential = (
                CredentialReference(id=observation.issued_ref) if observation.issued_ref else None
            )
            sessions[created] = IdentitySession(
                id=created,
                identity_id=role.id,
                credential=credential,
                created_at=event.observed_at,
                source_identity=observation.source_identity,
            )
            assumptions.append(
                RoleAssumption(
                    event_id=event_id,
                    actor_id=actor.id,
                    role_id=role.id,
                    session_id=created,
                    cross_account=bool(
                        actor.account_id and role.account_id and actor.account_id != role.account_id
                    ),
                )
            )
            add(actor.id, "ASSUMED_ROLE", role.id, [event_id], "Successful STS role assumption")
            add(
                actor.id,
                "ESTABLISHED_SESSION",
                created,
                [event_id],
                "STS response identifies issued session",
            )
            if parent:
                add(
                    sid,
                    "CHAINED_TO",
                    created,
                    [parent, event_id],
                    "Successful STS call from a linked session",
                    confidence,
                )
            if credential:
                add(
                    created,
                    "ISSUED_CREDENTIAL",
                    credential.id,
                    [event_id],
                    "Credential identifier fingerprint",
                )
        if event.outcome == Outcome.SUCCESS and event.read_only is not None:
            resources = sorted(
                {resource.arn for resource in event.resources if resource.arn}
                | ({event.target} if event.target else set())
            )
            for resource in resources:
                add(
                    sid,
                    "ACCESSED_RESOURCE" if event.read_only else "MODIFIED_RESOURCE",
                    resource,
                    [event_id],
                    "Successful call with explicit CloudTrail readOnly flag",
                )
        for namespace, value, scope in (
            ("SHARED_EVENT", event.shared_event_id, (event.event_source, event.operation)),
            (
                "RELATED_REQUEST",
                event.request_id,
                (actor.id, actor.account_id, event.region, event.event_source, event.operation),
            ),
        ):
            if not value or not event.event_source or not event.operation:
                continue
            key = (namespace, value, *scope)
            previous = requests.setdefault(key, observation).event
            if (
                previous.id != event_id
                and abs(
                    (
                        utc_timestamp(event.observed_at) - utc_timestamp(previous.observed_at)
                    ).total_seconds()
                )
                <= Context.request_clock_tolerance_seconds
            ):
                if (
                    namespace == "SHARED_EVENT"
                    and event.recipient_account_id
                    and previous.recipient_account_id
                    and event.recipient_account_id != previous.recipient_account_id
                ):
                    add(
                        previous.id,
                        namespace,
                        event_id,
                        [previous.id, event_id],
                        "Shared cross-account event ID",
                    )
                elif namespace == "RELATED_REQUEST" and actor.account_id and event.region:
                    add(
                        previous.id,
                        namespace,
                        event_id,
                        [previous.id, event_id],
                        "Scoped provider request ID",
                        Confidence.HIGH,
                    )
    return CorrelationResult(
        context=Context,
        identities=list(identities.values()),
        sessions=list(sessions.values()),
        assumptions=assumptions,
        relationships=relationships,
        chains=[ActivityChain(root_event_id=root, event_ids=ids) for root, ids in chains.items()],
        timelines=[
            IdentityTimeline(identity_id=identity, event_ids=ids)
            for identity, ids in timelines.items()
        ],
        unresolved=unresolved,
    )
