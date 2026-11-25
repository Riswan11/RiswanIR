"""Deterministic CloudTrail investigation and review storage."""

import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from uuid import uuid4


RULES = {
    "AssumeRole": (20, "Role assumption observed", "T1078"),
    "GetObject": (20, "Successful object read recorded", None),
    "CreateAccessKey": (15, "Access key creation recorded", "T1098.001"),
    "AttachUserPolicy": (15, "User policy attachment recorded", "T1098"),
}

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


def now():
    return datetime.now(timezone.utc).isoformat()


def required(data, key, limit=300):
    value = data.get(key) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Provide {key} as text of at most {limit} characters.")
    return value.strip()


def mapping(data, key):
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def normalize(event, principal):
    if not isinstance(event, dict):
        raise ValueError("Each CloudTrail record must be an object.")
    identity = mapping(event, "userIdentity")
    if identity.get("arn") != principal or event.get("errorCode"):
        return None
    event_id = required(event, "eventID")
    timestamp = datetime.fromisoformat(required(event, "eventTime").replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("CloudTrail eventTime must include a timezone.")
    name = required(event, "eventName")
    params = mapping(event, "requestParameters")
    allowed_targets = {
        "AssumeRole": "roleArn",
        "GetObject": "bucketName",
        "CreateAccessKey": "userName",
        "AttachUserPolicy": "policyArn",
    }
    target = params.get(allowed_targets.get(name))
    normalized = {
        "id": event_id,
        "source": "aws.cloudtrail",
        "observed_at": timestamp.astimezone(timezone.utc).isoformat(),
        "event": name,
        "principal": principal,
        "target": target[:300] if isinstance(target, str) else None,
        "query": "Exact principal ARN match against supplied CloudTrail records",
    }
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return {**normalized, "integrity_hash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()}


def analyze(data):
    title = required(data, "title")
    principal = required(data, "principal")
    records = data.get("records")
    if not isinstance(records, list) or len(records) > 2000:
        raise ValueError("Provide a records array with at most 2,000 CloudTrail events.")
    by_id = {}
    for record in records:
        item = normalize(record, principal)
        if item:
            previous = by_id.setdefault(item["id"], item)
            if previous != item:
                raise ValueError("Conflicting CloudTrail records share an eventID.")
    evidence = sorted(by_id.values(), key=lambda item: (item["observed_at"], item["id"]))
    claims = []
    score = 0
    for event, (weight, summary, technique) in RULES.items():
        event_ids = [item["id"] for item in evidence if item["event"] == event]
        if event_ids:
            score += weight
            claims.append({"summary": summary, "evidence_ids": event_ids, "possible_attack_technique": technique})
    severity = "high" if score >= 50 else "medium" if score >= 25 else "low" if score else "unrated"
    targets = sorted({item["target"] for item in evidence if item["target"]})
    persistence = [item["id"] for item in evidence if item["event"] == "CreateAccessKey"]
    return {
        "title": title, "principal": principal,
        "plan": ["Match the supplied events to the principal", "Correlate successful calls and review possible persistence"],
        "evidence": evidence,
        "graph": [{"from": principal, "relationship": "CALLED", "to": item["id"]} for item in evidence]
        + [{"from": item["id"], "relationship": "TARGETED", "to": item["target"]} for item in evidence if item["target"]],
        "assessment": {"severity": severity, "score": score, "score_max": 70, "claims": claims,
                       "open_questions": ["Was the activity authorized?", "What happened outside the supplied records?"],
                       "observed_targets": targets},
        "action": {"id": "review-access-key", "summary": "Verify the new key and its owners before considering containment.",
                   "mode": "advisory", "evidence_ids": persistence} if persistence else None,
    }


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
                raise LookupError("Investigation not found.")
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
            events = {item["event"] for item in report["evidence"]}
            similar = []
            for item in history:
                prior = json.loads(item["report"])
                shared = sorted(events.intersection(event["event"] for event in prior["evidence"]))
                if shared:
                    similar.append({"id": prior["id"], "title": prior["title"],
                                    "disposition": item["disposition"], "shared_events": shared})
            report["similar_investigations"] = sorted(
                similar, key=lambda item: len(item["shared_events"]), reverse=True)[:5]
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
            raise LookupError("Action not found.")
        reviewer = required(data, "reviewer", 100)
        with self.connect() as db:
            result = db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                (investigation_id, reviewer, decision, now()))
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
        return self.get(investigation_id)
