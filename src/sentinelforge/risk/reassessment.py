"""Evaluate case subjects and add immutable assessments for changed inputs."""

import sqlite3

from ..core.errors import NotFoundError
from ..correlation.temporal.models import TemporalResult
from ..knowledge_graph.models import SecurityGraph
from ..models import Disposition, InvestigationReport
from ..models.detection import DetectionContext
from ..storage import evidence_store
from . import repository
from .engine import calculate
from .enrichment import Observations, subjects
from .models import Assessment, Reassessment, Trigger
from .registry import active_policy, inventory


def score_case(
    db: sqlite3.Connection,
    report: InvestigationReport,
    graph: SecurityGraph,
    temporal: TemporalResult | None,
    context: DetectionContext,
    timestamp: str,
    trigger: Trigger,
    *,
    disposition: Disposition | None = None,
    request: Reassessment | None = None,
) -> Assessment | None:
    candidates = [
        subject
        for subject in subjects(report, temporal)
        if request is None
        or (subject.kind, subject.id) == (request.subject_kind, request.subject_id)
    ]
    if not candidates:
        if request:
            raise NotFoundError("Risk subject not found.")
        return None
    policy = active_policy()
    configuration = inventory()
    analysis = Observations(
        report,
        graph,
        context,
        configuration,
        evidence_store.verify(db, report.id, report),
        evidence_store.receipts(db, report.id),
    )
    current = repository.latest(db, report.id)
    prior = (
        repository.latest(db, report.previous_investigation_id)
        if report.previous_investigation_id
        else {}
    )
    last = None
    for subject in candidates:
        key = (subject.kind, subject.id)
        previous = current.get(key) or prior.get(key)
        inherited_containment = previous.inputs.containment_event_id if previous else None
        explicit = request.containment_evidence_id if request else None
        containment_reference = explicit or analysis.refs.get(inherited_containment or "")
        if explicit:
            inputs = analysis.project(subject, disposition, explicit)
        elif containment_reference:
            try:
                inputs = analysis.project(subject, disposition, containment_reference)
            except ValueError:
                # A new revision may invalidate a previously accepted containment observation.
                inputs = analysis.project(subject, disposition)
        else:
            inputs = analysis.project(subject, disposition)
        if previous and key in current and previous.inputs == inputs and previous.policy == policy:
            last = previous.assessment
            continue
        predecessor = previous.assessment if previous else None
        archived = calculate(
            report.id,
            inputs,
            policy,
            timestamp,
            "containment" if explicit else trigger,
            original=predecessor,
            predecessor_id=predecessor.id if predecessor else None,
        )
        repository.append(db, archived)
        last = archived.assessment
    return last
