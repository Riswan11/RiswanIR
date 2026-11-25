"""Deterministic CloudTrail investigation and review storage."""

import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from uuid import uuid4


RULES = (
    ("role-assumption", 20, "Role assumption observed", "T1078", ("AssumeRole",), 1),
    ("object-read", 20, "Successful object read recorded", None, ("GetObject",), 1),
    ("key-creation", 15, "Access key creation recorded", "T1098.001", ("CreateAccessKey",), 1),
    ("policy-attachment", 15, "User policy attachment recorded", "T1098", ("AttachUserPolicy",), 1),
    ("repeated-key-creation", 10, "Multiple access key creations recorded", "T1098.001", ("CreateAccessKey",), 2),
    ("role-then-key", 20, "Access key created downstream of a role assumption", "T1098.001",
     ("AssumeRole", "CreateAccessKey"), 1),
)

ROLE_CALLS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}


class NotFoundError(LookupError):
    pass

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


def text_field(data, name, limit=300):
    value = data.get(name)
    return value[:limit] if isinstance(value, str) and value else None


def utc_timestamp(value):
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.utcoffset() is None:
        raise ValueError("CloudTrail eventTime must include a timezone.")
    return timestamp.astimezone(timezone.utc)


def normalize(event):
    if not isinstance(event, dict):
        raise ValueError("Each CloudTrail record must be an object.")
    identity = mapping(event, "userIdentity")
    event_id = required(event, "eventID")
    timestamp = utc_timestamp(required(event, "eventTime"))
    name = required(event, "eventName")
    params = mapping(event, "requestParameters")
    allowed_targets = {
        **dict.fromkeys(ROLE_CALLS, "roleArn"),
        "GetObject": "bucketName",
        "CreateAccessKey": "userName",
        "AttachUserPolicy": "policyArn",
    }
    return {
        "id": event_id,
        "source": "aws.cloudtrail",
        "observed_at": timestamp.isoformat(timespec="microseconds"),
        "event": "AssumeRole" if name in ROLE_CALLS else name,
        "operation": name,
        "principal": text_field(identity, "arn"),
        "target": text_field(params, allowed_targets.get(name)),
        "source_ip": text_field(event, "sourceIPAddress"),
        "user_agent": text_field(event, "userAgent", 1024),
        "region": text_field(event, "awsRegion"),
        "account_id": text_field(identity, "accountId"),
        "recipient_account_id": text_field(event, "recipientAccountId"),
    }


def issued_credential(event, item):
    response = mapping(event, "responseElements")
    if item["event"] == "AssumeRole" and event.get("eventSource", "sts.amazonaws.com") == "sts.amazonaws.com":
        credentials = mapping(response, "credentials")
        expiry = text_field(credentials, "expiration")
        expires_at = None
        if expiry:
            try:
                expires_at = utc_timestamp(expiry)
            except ValueError:
                try:
                    expires_at = datetime.strptime(expiry, "%b %d, %Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
        return (text_field(credentials, "accessKeyId"),
                text_field(mapping(response, "assumedRoleUser"), "arn"), expires_at)
    if item["event"] == "CreateAccessKey" and event.get("eventSource", "iam.amazonaws.com") == "iam.amazonaws.com":
        return text_field(mapping(response, "accessKey"), "accessKeyId"), None, None
    return None, None, None


def correlate(records, principal):
    unique = {}
    for record in records:
        item = normalize(record)
        identity = mapping(record, "userIdentity")
        row = (item, text_field(identity, "accessKeyId"), issued_credential(record, item), bool(record.get("errorCode")))
        if unique.setdefault(item["id"], row) != row:
            raise ValueError("Conflicting CloudTrail records share an eventID.")
    ordered = sorted(unique.values(), key=lambda row: (row[0]["observed_at"], row[0]["id"]))
    evidence = []
    issued = {}
    for item, key, credential, failed in ordered:
        if failed:
            continue
        parent = None
        timestamp = utc_timestamp(item["observed_at"])
        for origin, expected_arn, expires_at in issued.get(key, ()):
            if origin["observed_at"] >= item["observed_at"]:
                continue
            if expected_arn and item["principal"] and expected_arn != item["principal"]:
                continue
            if expires_at and timestamp >= expires_at:
                continue
            parent = origin
            break
        if item["principal"] != principal and parent is None:
            continue
        item["query"] = "Issued access key match" if parent else "Exact principal ARN match"
        item["linked_from_evidence_id"] = parent["id"] if parent else None
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
        item["integrity_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        evidence.append(item)
        issued_key, session_arn, expires_at = credential
        if issued_key:
            issued.setdefault(issued_key, []).append((item, session_arn, expires_at))
    return evidence


def rule_evidence(evidence, events, minimum):
    if len(events) == 1:
        ids = [item["id"] for item in evidence if item["event"] == events[0]]
        return ids if len(ids) >= minimum else []
    by_id = {item["id"]: item for item in evidence}
    for item in evidence:
        if item["event"] != events[-1]:
            continue
        matched = [item["id"]]
        ancestor = item["linked_from_evidence_id"]
        for event in reversed(events[:-1]):
            while ancestor and by_id[ancestor]["event"] != event:
                ancestor = by_id[ancestor]["linked_from_evidence_id"]
            if not ancestor:
                break
            matched.append(ancestor)
            ancestor = by_id[ancestor]["linked_from_evidence_id"]
        if len(matched) == len(events):
            return list(reversed(matched))
    return []


def export_records(records):
    if isinstance(records, dict) and "Events" in records:
        entries = records["Events"]
        if not isinstance(entries, list) or len(entries) > 2000:
            raise ValueError("Provide at most 2,000 CloudTrail lookup events.")
        try:
            return [json.loads(required(entry, "CloudTrailEvent", 8_000_000)) for entry in entries]
        except json.JSONDecodeError as exc:
            raise ValueError("Malformed CloudTrailEvent in lookup export.") from exc
    return records.get("Records") if isinstance(records, dict) else records


def analyze(data):
    title = required(data, "title")
    principal = required(data, "principal")
    records = export_records(data.get("records"))
    if not isinstance(records, list) or len(records) > 2000:
        raise ValueError("Provide a records array with at most 2,000 CloudTrail events.")
    evidence = correlate(records, principal)
    claims = []
    score = 0
    for rule_id, weight, summary, technique, events, minimum in RULES:
        event_ids = rule_evidence(evidence, events, minimum)
        if event_ids:
            score += weight
            claims.append({"rule_id": rule_id, "summary": summary, "evidence_ids": event_ids,
                           "possible_attack_technique": technique})
    severity = "high" if score >= 50 else "medium" if score >= 25 else "low" if score else "unrated"
    targets = sorted({item["target"] for item in evidence if item["target"]})
    persistence = [item["id"] for item in evidence if item["event"] == "CreateAccessKey"]
    return {
        "title": title, "principal": principal,
        "plan": ["Match the supplied events to the principal", "Follow credentials issued by matching events"],
        "evidence": evidence,
        "graph": [{"from": item["principal"], "relationship": "CALLED", "to": item["id"]}
                  for item in evidence if item["principal"]]
        + [{"from": item["id"], "relationship": "TARGETED", "to": item["target"]} for item in evidence if item["target"]]
        + [{"from": item["linked_from_evidence_id"], "relationship": "ISSUED_CREDENTIAL_USED_IN", "to": item["id"]}
           for item in evidence if item["linked_from_evidence_id"]],
        "assessment": {"severity": severity, "score": score, "score_max": sum(rule[1] for rule in RULES), "claims": claims,
                       "open_questions": ["Was the activity authorized?", "What happened outside the supplied records?",
                                          "Were any credential identifiers or issuance events missing from the export?"],
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
            raise NotFoundError("Action not found.")
        reviewer = required(data, "reviewer", 100)
        with self.connect() as db:
            result = db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                                (investigation_id, reviewer, decision, now()))
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
        return self.get(investigation_id)
