"""Ingest custody-checked profiles and validate promotions into historical memory."""

import sqlite3

from ..core.errors import NotFoundError
from ..correlation.temporal.models import TemporalResult
from ..knowledge_graph.models import SecurityGraph
from ..models import Disposition, InvestigationReport
from ..models.detection import DetectionContext
from ..risk.repository import latest as risk_history
from ..storage import evidence_store
from ..storage.review_store import latest_disposition
from . import repository
from .features import extract
from .models import AssessmentCategory, Feedback, MemoryPolicy, Profile

REVIEW: dict[Disposition, AssessmentCategory] = {
    Disposition.CONFIRMED: "confirmed_threat",
    Disposition.BENIGN: "inconclusive",
    Disposition.SUSPICIOUS: "inconclusive",
    Disposition.INCONCLUSIVE: "inconclusive",
}


def index(
    db: sqlite3.Connection,
    report: InvestigationReport,
    graph: SecurityGraph,
    temporal: TemporalResult | None,
    context: DetectionContext,
    config: MemoryPolicy,
    current: str,
) -> Profile:
    profile = extract(report, graph, temporal, context)
    if profile.complete_scope and profile.raw_references:
        status = evidence_store.verify(db, report.id, report)
        if status.valid and status.custody_checked and not status.expired_raw:
            inserted = repository.save(
                db,
                profile,
                config,
                current,
                organizational=profile.factors.get("environment", []),
            )
            if inserted and "feedback" in config.enabled_categories:
                disposition = latest_disposition(db, report.id)
                if disposition is not None:
                    capture_review(db, report.id, disposition, config, current)
    return profile


def capture_review(
    db: sqlite3.Connection,
    case_id: str,
    disposition: Disposition,
    config: MemoryPolicy,
    current: str,
) -> None:
    profile = repository.read(db, case_id, config, current)
    if profile and profile.evidence_references and "feedback" in config.enabled_categories:
        repository.file_feedback(
            db,
            case_id,
            Feedback(
                classification=REVIEW[disposition],
                evidence_references=profile.evidence_references[:100],
            ),
            config,
            current,
        )


def promote(
    db: sqlite3.Connection,
    report: InvestigationReport,
    feedback: Feedback,
    config: MemoryPolicy,
    current: str,
) -> None:
    profile = repository.read(db, report.id, config, current)
    if profile is None:
        raise NotFoundError("Indexed historical profile not found.")
    status = evidence_store.verify(db, report.id, report)
    if not status.valid or not status.custody_checked or status.expired_raw:
        raise ValueError("Memory feedback requires verified retained evidence.")
    if len(set(feedback.evidence_references)) != len(feedback.evidence_references):
        raise ValueError("Duplicate feedback evidence references.")
    if not set(feedback.evidence_references) <= set(profile.evidence_references):
        raise ValueError("Feedback must reference evidence from the selected investigation.")
    disposition = latest_disposition(db, report.id)
    if disposition is None:
        raise ValueError("Record an analyst disposition before submitting historical feedback.")
    if feedback.classification == "confirmed_threat" and disposition != Disposition.CONFIRMED:
        raise ValueError("Confirmed memory requires a confirmed analyst disposition.")
    if (
        feedback.classification in {"authorized_activity", "false_positive"}
        and disposition != Disposition.BENIGN
    ):
        raise ValueError(
            "Authorized activity and false positives require a benign analyst disposition."
        )
    if feedback.classification == "successful_remediation":
        approved = {
            item.assessment.containment_reference
            for item in risk_history(db, report.id).values()
            if item.assessment.residual_risk is not None
        }
        if not set(feedback.evidence_references) <= approved:
            raise ValueError("Response memory requires verified containment evidence.")
        repository.record_response(db, report.id, feedback.evidence_references, config, current)
    repository.file_feedback(db, report.id, feedback, config, current)
