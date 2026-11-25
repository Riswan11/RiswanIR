"""Project canonical evidence into scoped, minimized history features."""

from collections import defaultdict

from ..core.fields import utc_timestamp
from ..correlation.aws import arn_account, partition
from ..correlation.temporal.models import TemporalResult
from ..detection.enrichment import enrich
from ..knowledge_graph.models import SecurityGraph
from ..knowledge_graph.ontology import Entity, Relation
from ..knowledge_graph.resolver import identifier
from ..models import InvestigationReport
from ..models.detection import DetectionContext
from ..normalization.aws.ocsf_mapper import map_event
from .models import Observation, Profile


def scope(account: str | None, partition_id: str) -> str | None:
    if account and len(account) == 12 and account.isascii() and account.isdigit():
        return f"{partition_id}:{account}"
    return None


def extract(
    report: InvestigationReport,
    graph: SecurityGraph,
    temporal: TemporalResult | None,
    context: DetectionContext,
) -> Profile:
    canonical = report.canonical_events
    if canonical is None:
        canonical = [
            map_event(item, parent=item.linked_from_evidence_id, evidence=item.reference)
            for item in report.evidence
        ]
    events = sorted(canonical, key=lambda item: (utc_timestamp(item.observed_at), item.id))
    factors: dict[str, set[str]] = defaultdict(set)
    patterns: dict[str, set[str]] = defaultdict(set)
    accounts: set[str] = set()
    complete_scope = bool(events)
    observations = []
    refs = {item.id: item.evidence.evidence_id if item.evidence else item.id for item in events}
    for finding in report.detection.findings if report.detection else []:
        factors["rules"].add(finding.id)
        patterns[finding.id].update(refs[item] for item in finding.evidence_ids)
        if finding.mitre:
            factors["mitre"].update(finding.mitre.techniques)
    if temporal:
        for incident in temporal.incidents:
            factors["attack_patterns"].add("sequence:" + incident.id)
            factors["rules"].add(incident.id)
            patterns[incident.id].update(refs[item.event_id] for item in incident.timeline)
            if incident.mitre:
                factors["mitre"].update(incident.mitre.techniques)
    nodes = {node.id: node for node in graph.nodes}
    sessions = {
        nodes[edge.target].key: edge.source
        for edge in graph.relationships
        if edge.relation == Relation.PERFORMED_ACTION and nodes[edge.source].kind == Entity.SESSION
    }
    targets: dict[str, list[str]] = defaultdict(list)
    for edge in graph.relationships:
        left, right = nodes[edge.source], nodes[edge.target]
        if edge.relation in {
            Relation.ASSUMED_ROLE,
            Relation.ESTABLISHED_SESSION,
            Relation.CHAINED_TO,
            Relation.HAS_PERMISSION,
            Relation.ACCESSED_RESOURCE,
            Relation.MODIFIED,
            Relation.ORIGINATED_FROM,
        }:
            factors["graph"].add(f"{left.kind}/{edge.relation}/{right.kind}")
        if edge.relation == Relation.TARGETED:
            targets[left.key].append(right.id)
    preceding: dict[str, str] = {}
    for event in events:
        attrs = enrich(event, context, set())
        actor = event.actor.user if event.actor else None
        actor_account = actor.account_uid if actor else None
        parsed = arn_account(event.principal_arn)
        region = event.cloud.region if event.cloud else None
        cloud_account = event.cloud.account_uid if event.cloud else None
        actor_scope = scope(parsed or actor_account, partition(event.principal_arn, region))
        event_scope = scope(
            cloud_account or parsed,
            partition(None, region) if region else partition(event.principal_arn),
        )
        if (
            not actor_scope
            or not event_scope
            or (parsed and actor_account and parsed != actor_account)
        ):
            complete_scope = False
        accounts.update(value for value in (actor_scope, event_scope) if value)
        reference = refs[event.id]
        operation = event.activity.operation
        service = event.activity.service
        kind = attrs["actor.kind"]
        if isinstance(kind, str):
            factors["identity_privilege"].add("kind:" + kind)
        privilege = attrs["context.role_privileged"]
        if isinstance(privilege, bool):
            factors["identity_privilege"].add("privileged:" + str(privilege))
        if event.actor and event.actor.mfa is not None:
            factors["identity_privilege"].add("mfa:" + str(event.actor.mfa))
        if actor and event.principal_arn and ":assumed-role/" in event.principal_arn:
            factors["identity_privilege"].add("kind:assumed-role")
        for key in ("context.environment", "cloud.region"):
            item = attrs[key]
            if isinstance(item, str):
                factors["environment"].add(f"{key}:{item}")
        resources = sorted(set(targets[event.id]))[:8]
        for target in resources:
            resource = nodes[target]
            if (
                resource.account
                and resource.partition
                and (scoped := scope(resource.account, resource.partition))
            ):
                accounts.add(scoped)
            subtype = resource.metadata.get("type")
            if isinstance(subtype, str):
                factors["resources"].add(subtype)
            patterns["resource:" + target].add(reference)
        criticality = attrs["resource.criticality"]
        if isinstance(criticality, str):
            factors["resources"].add(criticality)
        if event_scope is None or not event.evidence or service is None:
            patterns["gap:attribution_or_source"].add(reference)
            continue
        operation_key = f"{service}/{operation}"
        if len(operation_key) > 300:
            operation_key = identifier(operation_key)
        factors["attack_patterns"].add(operation_key)
        session = sessions.get(event.id)
        if session and (prior := preceding.get(session)):
            factors["attack_patterns"].add("ordered:" + identifier(prior, operation_key))
        if session:
            preceding[session] = operation_key
        time = utc_timestamp(event.observed_at)
        dimensions = {
            "account": identifier(event_scope),
            "service": identifier(event_scope, service),
        }
        actor_id = (actor.uid or actor.arn) if actor else None
        if actor_scope and actor_id:
            dimensions["identity"] = identifier(actor_scope, actor_id)
            patterns["identity:" + identifier(actor_scope, actor_id, operation_key)].add(reference)
        if session:
            dimensions["session"] = session
        if resources:
            dimensions["resource"] = resources[0]
        network = None
        if event.network and event.network.source_ip:
            network = identifier(event_scope, str(event.network.source_ip))
            patterns["indicator:" + network].add(reference)
        else:
            patterns["gap:network"].add(reference)
        authentication = None
        if event.actor and event.actor.mfa is not None:
            authentication = "mfa" if event.actor.mfa else "no_mfa"
        observations.append(
            Observation(
                reference=reference,
                raw_reference=event.evidence.parent_evidence_id,
                observed_at=time.isoformat(),
                scope=event_scope,
                dimensions=dimensions,
                operation=operation,
                service=service,
                hour=time.hour,
                weekday=time.weekday(),
                network=network,
                authentication=authentication,
            )
        )
    complete_scope &= 0 < len(accounts) <= 20
    return Profile(
        case_id=report.id,
        lineage_id=temporal.lineage_id
        if temporal
        else report.previous_investigation_id or report.id,
        created_at=report.created_at,
        scope=sorted(accounts) if complete_scope else [],
        complete_scope=complete_scope,
        factors={name: sorted(values)[:2000] for name, values in factors.items()},
        patterns={name: sorted(values)[:100] for name, values in sorted(patterns.items())[:5000]},
        observations=observations,
        evidence_references=sorted(refs.values()),
        raw_references=sorted(
            {event.evidence.parent_evidence_id for event in events if event.evidence}
        ),
    )
