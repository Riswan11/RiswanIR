"""Bounded event-time sequence matching over canonical evidence and graph proofs."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from riswan_security_data.canonical_event import SecurityEvent
from riswan_security_data.integrity import canonical_json, sha256

from ...core.fields import utc_timestamp
from ...detection.engine import equals, matches
from ...detection.enrichment import Attributes, enrich
from ...knowledge_graph.models import SecurityGraph
from ...knowledge_graph.resolver import identifier
from ...models import InvestigationReport
from ...models.detection import DetectionRuleVersion
from ...normalization.aws.ocsf_mapper import map_event
from .graph import GraphLinks, Proof
from .models import (
    CorrelationMetrics,
    PartialMatch,
    SecurityIncident,
    Stage,
    TemporalPolicy,
    TemporalResult,
    TemporalRule,
    TimelineEntry,
)

MAX_ACTIVE = 128
MAX_GRAPH_CHECKS = 250_000
MAX_INCIDENTS = 500
MAX_PARTIALS = 1000


@dataclass(frozen=True)
class Event:
    canonical: SecurityEvent
    time: datetime
    attributes: Attributes
    findings: frozenset[str]
    finding_keys: frozenset[str]


@dataclass(frozen=True)
class Match:
    group: str
    start: datetime
    end: datetime
    next_stage: int
    repeat: int
    timeline: tuple[TimelineEntry, ...]


def accepts(stage: Stage, event: Event) -> bool:
    return (
        event.canonical.metadata.provider.casefold() == "aws"
        and event.canonical.activity.service
        in {
            f"{stage.service}.amazonaws.com",
            f"{stage.service}.amazonaws.com.cn",
        }
        and event.canonical.activity.operation in stage.operations
        and event.canonical.outcome.status_id.name.lower() in stage.outcomes
        and all(matches(condition, event.attributes) for condition in stage.conditions)
        and (not stage.findings or not event.findings.isdisjoint(stage.findings))
    )


def entry(
    event: Event,
    stage: Stage,
    links: GraphLinks,
    received: dict[str, str],
    proof: Proof | None = None,
) -> TimelineEntry:
    record = event.canonical
    edges = proof.edges if proof else ()
    return TimelineEntry(
        stage=stage.name,
        event_id=record.id,
        observed_at=event.time.isoformat(),
        ingested_at=received.get(record.id),
        evidence_id=record.evidence.evidence_id if record.evidence else None,
        operation=record.activity.operation,
        account=links.event_scope(record.id),
        supporting_findings=sorted(event.finding_keys),
        relationship_ids=sorted({edge.id for edge in edges}),
        relationship_evidence_ids=sorted(
            {
                item.evidence_id or item.event_id
                for edge in edges
                for item in edge.observations
                if utc_timestamp(item.observed_at) <= event.time
            }
        ),
    )


def run(
    report: InvestigationReport,
    graph: SecurityGraph,
    rules: list[TemporalRule],
    policy: TemporalPolicy,
    received: dict[str, str],
    lineage: str,
) -> TemporalResult:
    if graph.investigation_id != report.id:
        raise ValueError("Correlation graph belongs to another investigation.")
    canonical = report.canonical_events
    if canonical is None:
        canonical = [
            map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
            for item in report.evidence
        ]
    evidence_findings: dict[str, set[str]] = defaultdict(set)
    finding_keys: dict[str, set[str]] = defaultdict(set)
    if report.detection:
        for finding in report.detection.findings:
            for event_id in finding.evidence_ids:
                evidence_findings[event_id].add(finding.id)
                finding_keys[event_id].add(finding.idempotency_key)
    events = [
        Event(
            record,
            utc_timestamp(record.observed_at),
            enrich(record, policy.enrichment, set()),
            frozenset(evidence_findings[record.id]),
            frozenset(finding_keys[record.id]),
        )
        for record in canonical
    ]
    events.sort(key=lambda event: (event.time, event.canonical.id))
    links = GraphLinks(graph, policy)
    metrics = CorrelationMetrics(
        events=len(events),
        stage_checks=0,
        graph_checks=0,
        suppressed=0,
        excluded=0,
        truncated_states=0,
    )
    incidents: list[SecurityIncident] = []
    incident_ids: set[str] = set()
    partials: list[PartialMatch] = []
    rules = sorted(rules, key=lambda rule: (rule.id, rule.version))
    for rule in rules:
        if not rule.enabled:
            continue
        failures = [
            (utc_timestamp(item.starts_at), utc_timestamp(item.expires_at), item.match)
            for item in policy.enrichment.exceptions
            if item.rule_id == rule.id
        ]
        active: list[Match] = []
        last: dict[str, datetime] = {}
        window = timedelta(minutes=rule.window_minutes)
        suppression = timedelta(minutes=rule.suppression_minutes or 0)
        for event in events:
            if metrics.graph_checks >= MAX_GRAPH_CHECKS:
                metrics.truncated_states += 1
                break
            identifier_ = event.canonical.id
            active = [item for item in active if event.time - item.start <= window]
            accepted = [accepts(stage, event) for stage in rule.stages]
            metrics.stage_checks += len(accepted)
            if not any(accepted):
                continue
            if any(
                begin <= event.time < end
                and all(
                    (value := event.attributes.get(field)) is not None and equals(value, expected)
                    for field, expected in selectors.items()
                )
                for begin, end, selectors in failures
            ):
                metrics.excluded += 1
                continue
            next_active: list[Match] = []
            for current in active:
                if event.time <= current.end:  # Equal timestamps cannot prove sequential order.
                    next_active.append(current)
                    continue
                position = current.next_stage
                while rule.stages[position].optional and not accepted[position]:
                    position += 1
                if not accepted[position]:
                    next_active.append(current)
                    continue
                stage = rule.stages[position]
                metrics.graph_checks += 1
                proof = links.connect(
                    current.timeline[-1].event_id,
                    identifier_,
                    event.time,
                    rule.group_by,
                    current.group,
                    cross_account=rule.cross_account,
                    requires_chain=stage.requires_chain,
                )
                if proof is None:
                    next_active.append(current)
                    continue
                repeat = (current.repeat if position == current.next_stage else 0) + 1
                position += int(repeat >= stage.count)
                timeline = (*current.timeline, entry(event, stage, links, received, proof))
                if position < len(rule.stages):
                    next_active.append(
                        Match(
                            current.group,
                            current.start,
                            event.time,
                            position,
                            0 if repeat >= stage.count else repeat,
                            timeline,
                        )
                    )
                    if stage.optional:
                        next_active.append(current)
                    continue
                if len({item.stage for item in timeline}) < rule.minimum_stages:
                    next_active.append(current)
                    continue
                incident_id = identifier(
                    lineage, rule.id, rule.version, current.group, timeline[0].event_id
                )
                if incident_id in incident_ids:
                    continue
                incident_ids.add(incident_id)
                previous_match = last.get(current.group)
                if previous_match and event.time - previous_match < suppression:
                    metrics.suppressed += 1
                elif len(incidents) >= MAX_INCIDENTS:
                    metrics.truncated_states += 1
                else:
                    last[current.group] = event.time
                    incidents.append(
                        SecurityIncident(
                            id=rule.id,
                            version=rule.version,
                            incident_id=incident_id,
                            title=rule.name,
                            severity=rule.severity,
                            mitre=rule.mitre,
                            timeline=list(timeline),
                            recommendation=rule.recommendation,
                        )
                    )
            for group in links.groups(identifier_, rule.group_by) if accepted[0] else []:
                stage = rule.stages[0]
                next_active.append(
                    Match(
                        group,
                        event.time,
                        event.time,
                        int(stage.count == 1),
                        int(stage.count > 1),
                        (entry(event, stage, links, received),),
                    )
                )
            if len(next_active) > MAX_ACTIVE:
                metrics.truncated_states += len(next_active) - MAX_ACTIVE
                next_active = next_active[-MAX_ACTIVE:]
            active = next_active
        remaining = MAX_PARTIALS - len(partials)
        metrics.truncated_states += max(0, len(active) - remaining)
        partials.extend(
            PartialMatch(
                id=rule.id,
                version=rule.version,
                group=item.group,
                next_stage=item.next_stage,
                repeat=item.repeat,
                timeline=list(item.timeline),
            )
            for item in active[:remaining]
        )
    return TemporalResult(
        investigation_id=report.id,
        lineage_id=lineage,
        rules=[DetectionRuleVersion(id=rule.id, version=rule.version) for rule in rules],
        configuration_digest=sha256(
            canonical_json(
                {
                    "rules": [rule.model_dump(mode="json") for rule in rules],
                    "policy": policy.model_dump(mode="json"),
                }
            )
        ),
        incidents=sorted(
            incidents, key=lambda item: (item.timeline[-1].observed_at, item.incident_id)
        ),
        partial_matches=partials,
        metrics=metrics,
    )
