"""Compose the investigation report from the domain modules."""

from ..detection.engine import evaluate
from ..detection.registry import default_registry
from ..detection.rules import assess
from ..knowledge_graph.edges import build_graph
from ..knowledge_graph.identity_relationships import identity_edges
from ..models import InvestigationRequest, InvestigationResult
from ..models.canonical_event import Status
from ..models.detection import DetectionContext, DetectionRule
from ..models.security_event import Outcome
from ..normalization.aws.detection_signals import project
from ..normalization.aws.ocsf_mapper import map_event
from ..response.advisory import recommend
from .correlation import correlate_with_context


def analyze(
    request: InvestigationRequest,
    *,
    rules: list[DetectionRule] | None = None,
    context: DetectionContext | None = None,
) -> InvestigationResult:
    evidence, correlation = correlate_with_context(request.records, request.principal)
    records = {
        identifier.strip(): record
        for record in request.records
        if isinstance(record, dict) and isinstance(identifier := record.get("eventID"), str)
    }
    canonical = [
        map_event(
            item,
            parent=item.linked_from_evidence_id,
            detection_signals=project(
                records.get(item.id, {}),
                item.operation or item.event,
                item.recipient_account_id or item.account_id,
            ),
        )
        for item in evidence
    ]
    detection = evaluate(
        canonical,
        default_registry().select() if rules is None else rules,
        context if context is not None else DetectionContext(),
    )
    successful = [item for item in evidence if item.outcome == Outcome.SUCCESS]
    return InvestigationResult(
        title=request.title,
        principal=request.principal,
        plan=[
            "Match the supplied events to the principal",
            "Follow credentials issued by matching events",
        ],
        evidence=evidence,
        graph=build_graph(canonical) + identity_edges(correlation),
        assessment=assess([item for item in canonical if item.outcome.status_id == Status.SUCCESS]),
        action=recommend(successful),
        correlation=correlation,
        canonical_events=canonical,
        detection=detection.result,
    )
