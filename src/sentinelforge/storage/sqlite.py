"""Persist investigations, analyst feedback, and action decisions in SQLite."""

import json
import sqlite3
from contextlib import closing, contextmanager
from uuid import uuid4

from ..core.errors import NotFoundError
from ..core.fields import now, required
from ..investigation.analysis import analyze
from ..memory.similarity import similar_investigations


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

    def create(self, data):
        report = {"id": uuid4().hex, "created_at": now(), **analyze(data)}
        with self.connect() as db:
            db.execute("INSERT INTO investigations VALUES (?, ?, ?)",
                       (report["id"], report["created_at"], json.dumps(report)))
        return self.get(report["id"])

    def get(self, investigation_id):
        with self.connect() as db:
            row = db.execute("SELECT report FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = json.loads(row["report"])
            report["reviews"] = [dict(item) for item in db.execute(
                "SELECT reviewer, disposition, notes, created_at FROM reviews WHERE investigation_id = ? ORDER BY id",
                (investigation_id,))]
            decision = db.execute(
                "SELECT reviewer, decision, created_at FROM decisions WHERE investigation_id = ?",
                (investigation_id,)).fetchone()
            report["decision"] = dict(decision) if decision else None
            history = db.execute("""
                SELECT i.report, r.disposition FROM investigations i JOIN reviews r
                    ON r.id = (SELECT max(id) FROM reviews WHERE investigation_id = i.id)
                WHERE i.id <> ? ORDER BY r.id DESC LIMIT 100
            """, (investigation_id,))
            report["similar_investigations"] = similar_investigations(report, history)
        return report

    def list(self):
        with self.connect() as db:
            reports = [json.loads(row["report"]) for row in db.execute(
                "SELECT report FROM investigations ORDER BY created_at DESC LIMIT 50")]
        return [{key: report[key] for key in ("id", "title", "created_at")} for report in reports]

    def feedback(self, investigation_id, data):
        self.get(investigation_id)
        reviewer = required(data, "reviewer", 100)
        disposition = required(data, "disposition")
        if disposition not in {"benign", "suspicious", "confirmed", "inconclusive"}:
            raise ValueError("Unknown disposition.")
        notes = data.get("notes", "")
        if not isinstance(notes, str) or len(notes) > 2000:
            raise ValueError("Notes must be text with at most 2,000 characters.")
        with self.connect() as db:
            db.execute("INSERT INTO reviews (investigation_id, reviewer, disposition, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                       (investigation_id, reviewer, disposition, notes, now()))
        return self.get(investigation_id)

    def decide(self, investigation_id, action_id, decision, data):
        action = self.get(investigation_id)["action"]
        if action is None or action["id"] != action_id:
            raise NotFoundError("Action not found.")
        reviewer = required(data, "reviewer", 100)
        with self.connect() as db:
            result = db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                (investigation_id, reviewer, decision, now()))
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
        return self.get(investigation_id)
