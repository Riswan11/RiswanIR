"""Persist investigations, analyst feedback, and action decisions in SQLite."""

import sqlite3
from contextlib import closing, contextmanager
from uuid import uuid4

from pydantic import ValidationError

from ..core.errors import NotFoundError
from ..core.fields import now
from ..investigation.analysis import analyze
from ..memory.similarity import similar_investigations
from ..models import (
    ActionDecision, AnalystFeedback, AnalystReview, Disposition,
    InvestigationReport, InvestigationRequest, InvestigationSummary,
)


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
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def create(self, request: InvestigationRequest) -> InvestigationReport:
        result = analyze(request)
        report = InvestigationReport(id=uuid4().hex, created_at=now(), **dict(result))
        with self.connect() as db:
            db.execute("INSERT INTO investigations VALUES (?, ?, ?)",
                       (report.id, report.created_at, report.model_dump_json(by_alias=True, exclude_unset=True)))
        return self.get(report.id)

    def get(self, investigation_id: str) -> InvestigationReport:
        with self.connect() as db:
            row = db.execute("SELECT report FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = deserialize_report(row["report"])
            report.reviews = [AnalystReview.model_validate(dict(item)) for item in db.execute(
                "SELECT reviewer, disposition, notes, created_at FROM reviews WHERE investigation_id = ? ORDER BY id",
                (investigation_id,))]
            decision = db.execute(
                "SELECT reviewer, decision, created_at FROM decisions WHERE investigation_id = ?",
                (investigation_id,)).fetchone()
            report.decision = ActionDecision.model_validate(dict(decision)) if decision else None
            history = db.execute("""
                SELECT i.report, r.disposition FROM investigations i JOIN reviews r
                    ON r.id = (SELECT max(id) FROM reviews WHERE investigation_id = i.id)
                WHERE i.id <> ? ORDER BY r.id DESC LIMIT 100
            """, (investigation_id,))
            report.similar_investigations = similar_investigations(
                report, ((deserialize_report(item["report"]), Disposition(item["disposition"])) for item in history)
            )
        return report

    def list(self) -> list[InvestigationSummary]:
        with self.connect() as db:
            return [InvestigationSummary.model_validate_json(row["report"]) for row in db.execute(
                "SELECT report FROM investigations ORDER BY created_at DESC LIMIT 50")]

    def feedback(self, investigation_id: str, feedback: AnalystFeedback) -> InvestigationReport:
        self.get(investigation_id)
        review = AnalystReview(**dict(feedback), created_at=now())
        with self.connect() as db:
            db.execute("INSERT INTO reviews (investigation_id, reviewer, disposition, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                       (investigation_id, review.reviewer, review.disposition, review.notes, review.created_at))
        return self.get(investigation_id)

    def decide(self, investigation_id: str, action_id: str, decision: ActionDecision) -> InvestigationReport:
        action = self.get(investigation_id).action
        if action is None or action.id != action_id:
            raise NotFoundError("Action not found.")
        with self.connect() as db:
            result = db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                (investigation_id, decision.reviewer, decision.decision, decision.created_at))
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
        return self.get(investigation_id)
