"""Project Security Intelligence observations into provider-neutral scoring factors."""

from collections import defaultdict
from collections.abc import Iterable
from typing import TypeVar

from ..core.fields import utc_timestamp
from ..correlation.temporal.models import TemporalResult
from ..detection.enrichment import enrich
from ..knowledge_graph.models import SecurityGraph, SecurityRelationship
from ..knowledge_graph.ontology import Entity, Relation
from ..models import Disposition, InvestigationReport
from ..models.canonical_event import SecurityEvent
from ..models.canonical_event import Status as Outcome
from ..models.chain_of_custody import EvidenceIntegrity
from ..models.detection import DetectionContext
from ..models.provenance import EvidenceProvenance
from ..normalization.aws.ocsf_mapper import map_event
from .models import AssessmentInputs, Factor, RiskInventory, Severity, Status, Subject

THREAT = {"informational": 10, "low": 25, "medium": 55, "high": 80, "critical": 100}
CRITICALITY = {"standard": 25, "sensitive": 80, "critical": 100}
CORRELATION = {"confirmed": 100, "high": 75, "medium": 50, "low": 25}
S3 = {"s3.amazonaws.com", "s3.amazonaws.com.cn"}


def subjects(report: InvestigationReport, temporal: TemporalResult | None) -> Iterable[Subject]:
    if report.detection:
        for finding in report.detection.findings:
            yield Subject(
                kind="finding",
                id=finding.idempotency_key,
                rule_id=finding.id,
                declared_severity=Severity(finding.severity),
                event_ids=finding.evidence_ids,
            )
    if temporal:
        for incident in temporal.incidents:
            yield Subject(
                kind="incident",
                id=incident.incident_id,
                rule_id=incident.id,
                declared_severity=Severity(incident.severity),
                event_ids=[item.event_id for item in incident.timeline],
                stages=len({item.stage for item in incident.timeline}),
                relationships=sorted(
                    {key for item in incident.timeline for key in item.relationship_ids}
                ),
            )


def factor(
    value: int | None,
    explanation: str,
    refs: list[str],
    status: Status = "observed",
) -> Factor:
    return Factor(
        value=value,
        status=status if value is not None else "unknown",
        explanation=explanation,
        evidence_references=refs if value is not None else [],
    )


def highest(values: Iterable[int | None]) -> int | None:
    return max((value for value in values if value is not None), default=None)


T = TypeVar("T")


def inventory_value(values: dict[str, T], account: str | None, key: str | None) -> T | None:
    if key is None:
        return None
    return values.get(f"{account}/{key}", values.get(key)) if account else values.get(key)


class Observations:
    def __init__(
        self,
        report: InvestigationReport,
        graph: SecurityGraph,
        context: DetectionContext,
        inventory: RiskInventory,
        integrity: EvidenceIntegrity,
        receipts: list[EvidenceProvenance],
    ) -> None:
        self.context = context
        self.inventory = inventory
        self.integrity = integrity
        canonical = report.canonical_events
        if canonical is None:
            canonical = [
                map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
                for item in report.evidence
            ]
        self.events = {event.id: event for event in canonical}
        self.refs = {
            event.id: event.evidence.evidence_id if event.evidence else event.id
            for event in canonical
        }
        self.by_ref = {reference: event_id for event_id, reference in self.refs.items()}
        self.attributes = {event.id: enrich(event, context, set()) for event in canonical}
        self.edges = {edge.id: edge for edge in graph.relationships}
        event_keys = {node.id: node.key for node in graph.nodes if node.kind == Entity.EVENT}
        self.identity_proofs: dict[str, list[str]] = defaultdict(list)
        self.targets: dict[str, set[str]] = defaultdict(set)
        self.scoped_targets = {
            node.id
            for node in graph.nodes
            if node.kind == Entity.RESOURCE and node.account and node.partition
        }
        for edge in graph.relationships:
            if edge.relation == Relation.AUTHENTICATED_AS:
                for observation in edge.observations:
                    self.identity_proofs[observation.event_id].append(edge.id)
            if edge.relation == Relation.TARGETED and edge.source in event_keys:
                self.targets[event_keys[edge.source]].add(edge.target)
        self.authentic_origins: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for receipt in receipts:
            if receipt.source_authenticity_verified:
                self.authentic_origins[receipt.source_event_id.strip()].add(
                    (receipt.source_provider, receipt.source_service)
                )

    def criticality(self, events: list[SecurityEvent]) -> int | None:
        scores: list[int | None] = []
        for event in events:
            attrs = self.attributes[event.id]
            resource, account = attrs["resource.uid"], attrs["cloud.account"]
            configured = (
                inventory_value(
                    self.inventory.asset_criticality,
                    account if isinstance(account, str) else None,
                    resource if isinstance(resource, str) else None,
                )
                or attrs["resource.criticality"]
            )
            if isinstance(configured, str):
                scores.append(CRITICALITY.get(configured))
        return highest(scores)

    def privilege(self, events: list[SecurityEvent]) -> int | None:
        scores: list[int | None] = []
        for event in events:
            attrs = self.attributes[event.id]
            if attrs["actor.kind"] == "Root":
                scores.append(100)
            for key in ("actor.uid", "actor.session_issuer"):
                name = attrs[key]
                if isinstance(name, str):
                    scores.append(self.inventory.identity_privilege.get(name))
            if attrs["context.role_privileged"] is not None:
                scores.append(90 if attrs["context.role_privileged"] else 20)
        return highest(scores)

    def resource_setting(self, values: dict[str, int], events: list[SecurityEvent]) -> int | None:
        return highest(
            inventory_value(
                values,
                event.cloud.account_uid if event.cloud else None,
                str(resource)
                if (resource := self.attributes[event.id]["resource.uid"]) is not None
                else None,
            )
            for event in events
        )

    def proofs(self, subject: Subject) -> list[SecurityRelationship]:
        keys = subject.relationships or sorted(
            {key for event_id in subject.event_ids for key in self.identity_proofs[event_id]}
        )
        return [self.edges[key] for key in keys if key in self.edges]

    def public_grant(self, event: SecurityEvent) -> bool:
        return self.attributes[event.id]["context.public_policy"] is True and self.s3_success(
            event,
            "PutBucketPolicy",
        )

    @staticmethod
    def s3_success(event: SecurityEvent, operation: str) -> bool:
        return (
            event.activity.service in S3
            and event.activity.operation == operation
            and event.outcome.status_id == Outcome.SUCCESS
        )

    def containment(
        self,
        events: list[SecurityEvent],
        containment_id: str,
    ) -> SecurityEvent:
        candidate = self.events.get(containment_id)
        if candidate is None or not self.integrity.valid or not self.integrity.custody_checked:
            raise ValueError("Containment must reference verified investigation evidence.")
        resource = self.targets[candidate.id]
        if (
            not self.s3_success(candidate, "DeleteBucketPolicy")
            or len(resource) != 1
            or not resource <= self.scoped_targets
            or not any(
                self.public_grant(event) and self.targets[event.id] == resource for event in events
            )
        ):
            raise ValueError(
                "Containment requires removal of the evidenced public policy on the same scoped resource."
            )
        instant = utc_timestamp(candidate.observed_at)
        if instant <= max(utc_timestamp(event.observed_at) for event in events) or any(
            self.public_grant(event)
            and self.targets[event.id] == resource
            and utc_timestamp(event.observed_at) >= instant
            for event in self.events.values()
        ):
            raise ValueError(
                "Containment was superseded or does not follow the supporting evidence."
            )
        return candidate

    def project(
        self,
        subject: Subject,
        disposition: Disposition | None,
        containment_reference: str | None = None,
    ) -> AssessmentInputs:
        events = [self.events[key] for key in subject.event_ids]
        proofs = self.proofs(subject)
        cutoff = max(utc_timestamp(event.observed_at) for event in events)
        observations = [
            item
            for edge in proofs
            for item in edge.observations
            if utc_timestamp(item.observed_at) <= cutoff
            and (subject.relationships or item.event_id in subject.event_ids)
        ]
        refs = sorted(
            {self.refs[event.id] for event in events}
            | {self.refs[item.event_id] for item in observations if item.event_id in self.refs}
        )
        public = any(self.public_grant(event) for event in events)
        configured_exposure = self.resource_setting(self.inventory.resource_exposure, events)
        exposure = 100 if public else configured_exposure
        risk = {
            "threat_impact": factor(
                THREAT[subject.declared_severity],
                "Potential harm indicated by the rule's declared impact.",
                refs,
                "inferred",
            ),
            "asset_criticality": factor(
                self.criticality(events),
                "Highest curated resource criticality among affected events.",
                refs,
            ),
            "identity_privilege": factor(
                self.privilege(events),
                "Root use, configured actor privilege, or a catalogued privileged role.",
                refs,
            ),
            "resource_exposure": factor(
                exposure, "Observed public policy grant or configured resource exposure.", refs
            ),
            "attack_progression": factor(
                min(100, subject.stages * 20) if subject.stages else None,
                "Distinct stages supported by the correlated incident.",
                refs,
                "inferred",
            ),
            "business_impact": factor(
                self.resource_setting(self.inventory.business_impact, events),
                "Operator-assessed operational or data consequence; separate from asset importance.",
                refs,
            ),
            "historical_recurrence": factor(
                self.inventory.historical_recurrence.get(subject.rule_id),
                "Operator-supplied recurrence indicator for this rule.",
                refs,
                "inferred",
            ),
        }
        auth = [self.authentic_origins[event.id] for event in events]
        if not self.integrity.valid:
            integrity = factor(
                0, "Evidence or custody verification reported a conflict.", refs, "conflicting"
            )
        elif not self.integrity.custody_checked:
            integrity = factor(None, "Evidence custody was unavailable.", refs)
        elif self.integrity.expired_raw:
            integrity = factor(
                50, "Custody verified, with expired raw evidence in this case.", refs, "inferred"
            )
        elif all(auth):
            integrity = factor(100, "Custody and source-authenticity metadata were verified.", refs)
        else:
            integrity = factor(
                75,
                "Custody verified against recorded hashes; source authenticity remains unverified.",
                refs,
            )
        chain = [
            CORRELATION[item.confidence]
            for item in observations
            if item.confidence and item.confidence in CORRELATION
        ]
        completeness = sum(
            bool(event.evidence)
            + bool(event.actor and event.actor.user)
            + bool(event.cloud and event.cloud.account_uid)
            + (event.outcome.status_id != Outcome.UNKNOWN)
            for event in events
        )
        confidence = {
            "evidence_integrity": integrity,
            "correlation_reliability": factor(
                min(chain, default=None),
                "Weakest attributed identity or session proof used for this assessment.",
                refs,
                "inferred",
            ),
            "rule_reliability": factor(
                self.inventory.rule_reliability.get(subject.rule_id),
                "Operator-supplied rule reliability judgment.",
                refs,
                "inferred",
            ),
            "independent_corroboration": factor(
                100 if any(len(origins) >= 2 for origins in auth) else None,
                "Independent, authenticated telemetry sources for a supporting event.",
                refs,
            ),
            "telemetry_completeness": factor(
                completeness * 25 // len(events),
                "Availability of evidence reference, actor, account, and outcome for supporting events.",
                refs,
            ),
        }
        residual = None
        containment_event_id = None
        if containment_reference:
            candidate = self.containment(events, self.by_ref.get(containment_reference, ""))
            containment_event_id = candidate.id
            refs = sorted({*refs, self.refs[candidate.id]})
            residual = {
                **risk,
                "resource_exposure": factor(
                    max(25, configured_exposure or 0),
                    "Custody-backed removal of the observed public bucket policy; other controls remain uncertain.",
                    [self.refs[candidate.id]],
                    "inferred",
                ),
            }
        return AssessmentInputs(
            subject=subject,
            risk=risk,
            confidence=confidence,
            evidence_references=refs,
            disposition=disposition,
            containment_reference=containment_reference,
            containment_event_id=containment_event_id,
            residual_risk=residual,
        )
