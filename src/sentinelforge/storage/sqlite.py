"""Persist investigations, analyst feedback, and action decisions in SQLite."""

import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime
from uuid import uuid4

from pydantic import ValidationError

from ..core.errors import NotFoundError
from ..core.fields import now, utc_timestamp
from ..evidence.redaction import redact_record
from ..investigation.analysis import analyze
from ..memory.similarity import similar_investigations
from ..models import (
    ActionDecision,
    AnalystFeedback,
    AnalystReview,
    Disposition,
    EvidenceSubmission,
    InvestigationReport,
    InvestigationRequest,
    InvestigationSummary,
)
from ..models.chain_of_custody import EvidenceIntegrity, EvidenceRetentionPolicy
from ..models.provenance import EvidenceProvenance
from . import checkpoint_store, evidence_store

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(id),
    reviewer TEXT NOT NULL, disposition TEXT NOT NULL, notes TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    reviewer TEXT NOT NULL, decision TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


def deserialize_report(payload: str) -> InvestigationReport:
    try:
        return InvestigationReport.model_validate_json(payload)
    except ValidationError as exc:
        raise RuntimeError("Invalid stored investigation report.") from exc


class Store:
    def __init__(self, path):
        self.path = path
        # Existing databases keep their operating-system permissions.
        if os.name == "posix":
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        with self.connect() as db:
            db.executescript(SCHEMA + evidence_store.EVIDENCE_SCHEMA + checkpoint_store.SCHEMA)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def create(self, request: InvestigationRequest) -> InvestigationReport:
        with self.connect() as db:
            case_id = self.create_in_transaction(db, request)
        return self.get(case_id)

    def create_in_transaction(
        self,
        db: sqlite3.Connection,
        request: InvestigationRequest,
        *,
        previous: str | None = None,
        inherited: tuple[EvidenceProvenance, ...] = (),
    ) -> str:
        request = request.model_copy(
            update={"records": [redact_record(record) for record in request.records]}
        )
        case_id, timestamp = uuid4().hex, now()
        db.execute("INSERT INTO investigations VALUES (?, ?, ?)", (case_id, timestamp, "{}"))
        origins = evidence_store.ingest(db, case_id, request, timestamp, inherited)
        result = analyze(request)
        result.evidence = evidence_store.record_transformations(
            db, case_id, request, timestamp, result.evidence, origins, result.correlation
        )
        report = InvestigationReport(id=case_id, created_at=timestamp, **dict(result))
        if previous:
            report.previous_investigation_id = previous
            evidence_store.append_custody(
                db, case_id, "revised", timestamp, {"previous_investigation_id": previous}
            )
        db.execute(
            "UPDATE investigations SET report = ? WHERE id = ?",
            (report.model_dump_json(by_alias=True, exclude_unset=True), case_id),
        )
        return case_id

    def revise(self, case_id: str, supplement: EvidenceSubmission) -> InvestigationReport:
        if not supplement.records:
            raise ValueError("A revision requires supplemental records.")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            previous = deserialize_report(row["report"])
            status = evidence_store.verify(db, case_id, previous.evidence, previous.correlation)
            if not status.valid or status.expired_raw:
                raise ValueError("A revision requires intact original raw evidence and custody.")
            records = evidence_store.original_records(db, case_id)
            origins = tuple(evidence_store.receipts(db, case_id))
            request = InvestigationRequest(
                title=previous.title,
                principal=previous.principal,
                records=[*records, *supplement.records],
                provenance=supplement.provenance,
            )
            revised = self.create_in_transaction(db, request, previous=case_id, inherited=origins)
        return self.get(revised)

    def verify_evidence(self, case_id: str) -> EvidenceIntegrity:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return self._verify_evidence(db, case_id)

    def _verify_evidence(self, db: sqlite3.Connection, case_id: str) -> EvidenceIntegrity:
        row = db.execute("SELECT report FROM investigations WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        try:
            report = InvestigationReport.model_validate_json(row["report"])
            result = evidence_store.verify(db, case_id, report.evidence, report.correlation)
        except (ValueError, TypeError):
            return EvidenceIntegrity(
                raw_checked=0,
                normalized_checked=0,
                expired_raw=0,
                custody_checked=0,
                problems=["Stored evidence or custody metadata is invalid."],
            )
        if result.custody_checked:
            evidence_store.append_custody(db, case_id, "verified", now(), {"valid": result.valid})
        return result

    def export_evidence(self, case_id: str) -> dict[str, object]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            verification = self._verify_evidence(db, case_id)
            if verification.valid:
                evidence_store.append_custody(
                    db, case_id, "export_prepared", now(), {"format": "json-v1"}
                )
                report = db.execute(
                    "SELECT report FROM investigations WHERE id = ?", (case_id,)
                ).fetchone()
                return {
                    "format": "sentinelforge-evidence-v1",
                    "report": deserialize_report(report["report"]).payload(),
                    "raw_evidence": [
                        item.payload() for item in evidence_store.raw_records(db, case_id)
                    ],
                    "provenance": [
                        item.model_dump(mode="json")
                        for item in evidence_store.receipts(db, case_id)
                    ],
                    "transformations": [
                        item.payload() for item in evidence_store.transformations(db, case_id)
                    ],
                    "custody": [item.payload() for item in evidence_store.custody(db, case_id)],
                    "verification": verification.payload(),
                }
        raise ValueError("Export requires valid evidence custody and integrity.")

    def expire_evidence(
        self, policy: EvidenceRetentionPolicy, timestamp: datetime | None = None
    ) -> int:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return evidence_store.expire(db, policy, timestamp or utc_timestamp(now()))

    def get(self, investigation_id: str) -> InvestigationReport:
        with self.connect() as db:
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = deserialize_report(row["report"])
            report.reviews = [
                AnalystReview.model_validate(dict(item))
                for item in db.execute(
                    "SELECT reviewer, disposition, notes, created_at FROM reviews WHERE investigation_id = ? ORDER BY id",
                    (investigation_id,),
                )
            ]
            decision = db.execute(
                "SELECT reviewer, decision, created_at FROM decisions WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
            report.decision = ActionDecision.model_validate(dict(decision)) if decision else None
            history = db.execute(
                """
                SELECT i.report, r.disposition FROM investigations i JOIN reviews r
                    ON r.id = (SELECT max(id) FROM reviews WHERE investigation_id = i.id)
                WHERE i.id <> ? ORDER BY r.id DESC LIMIT 100
            """,
                (investigation_id,),
            )
            report.similar_investigations = similar_investigations(
                report,
                (
                    (deserialize_report(item["report"]), Disposition(item["disposition"]))
                    for item in history
                ),
            )
        return report

    def list(self) -> list[InvestigationSummary]:
        with self.connect() as db:
            return [
                InvestigationSummary.model_validate_json(row["report"])
                for row in db.execute(
                    "SELECT report FROM investigations ORDER BY created_at DESC LIMIT 50"
                )
            ]

    def feedback(self, investigation_id: str, feedback: AnalystFeedback) -> InvestigationReport:
        self.get(investigation_id)
        review = AnalystReview(**dict(feedback), created_at=now())
        with self.connect() as db:
            db.execute(
                "INSERT INTO reviews (investigation_id, reviewer, disposition, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    investigation_id,
                    review.reviewer,
                    review.disposition,
                    review.notes,
                    review.created_at,
                ),
            )
        return self.get(investigation_id)

    def decide(
        self, investigation_id: str, action_id: str, decision: ActionDecision
    ) -> InvestigationReport:
        action = self.get(investigation_id).action
        if action is None or action.id != action_id:
            raise NotFoundError("Action not found.")
        with self.connect() as db:
            result = db.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (investigation_id, decision.reviewer, decision.decision, decision.created_at),
            )
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
        return self.get(investigation_id)
